"""Explicit loopback-only model adapter. No cloud fallback, tools, or downloads.

The local server must itself be configured to use local weights, not proxy a cloud
provider. This client cannot audit the server's downstream network behaviour.
"""

import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel


@dataclass(frozen=True)
class LocalCompletion:
    content: str
    model: str
    usage: dict


class LocalLLM:
    def __init__(
        self,
        model,
        *,
        base_url="http://127.0.0.1:11434",
        protocol="ollama",
        timeout=120.0,
        max_tokens=512,
        max_bytes=1_000_000,
        context_tokens=8192,
        keep_alive="5m",
        _transport=None,
    ):
        url = urlsplit(base_url)
        try:
            local = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            local = False
        if (
            not local
            or url.scheme not in ("http", "https")
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in ("", "/")
        ):
            raise ValueError(
                "Use an explicit loopback IP origin, without credentials, query or path"
            )
        if (
            protocol not in ("ollama", "openai")
            or not isinstance(model, str)
            or not model.strip()
        ):
            raise ValueError("Explicit model and supported local protocol required")
        if (
            not 0 < timeout <= 600
            or type(max_tokens) is not int
            or not 1 <= max_tokens <= 32768
            or not 1 <= max_bytes <= 10_000_000
        ):
            raise ValueError("Invalid local inference resource limits")
        if type(context_tokens) is not int or not 512 <= context_tokens <= 131072:
            raise ValueError("Invalid context token budget")
        self.context_tokens = context_tokens
        self.model = model
        self.protocol = protocol
        self.max_tokens = max_tokens
        self.max_bytes = max_bytes
        self.keep_alive = keep_alive
        self.client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
            transport=_transport,
        )

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def complete(self, messages, *, response_model: type[BaseModel] | None = None):
        if not messages or any(
            set(m) != {"role", "content"}
            or m["role"] not in ("system", "user", "assistant")
            or not isinstance(m["content"], str)
            for m in messages
        ):
            raise ValueError("Use nonempty text messages with role/content only")
        schema = response_model.model_json_schema() if response_model else None
        body = {"model": self.model, "messages": messages, "stream": False}
        if self.protocol == "ollama":
            path = "/api/chat"
            body.update(
                think=False,
                keep_alive=self.keep_alive,
                options={
                    "num_predict": self.max_tokens,
                    "num_ctx": self.context_tokens,
                    "temperature": 0,
                },
            )
            if schema:
                body["format"] = schema
        else:
            path = "/v1/chat/completions"
            body.update(max_tokens=self.max_tokens, temperature=0)
            if schema:
                body["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": response_model.__name__,
                        "schema": schema,
                        "strict": True,
                    },
                }
        if len(json.dumps(body).encode()) > self.max_bytes:
            raise ValueError("Request exceeds byte budget")
        with self.client.stream("POST", path, json=body) as response:
            response.raise_for_status()
            parts = []
            size = 0
            for part in response.iter_bytes():
                size += len(part)
                if size > self.max_bytes:
                    raise ValueError("Response exceeds byte budget")
                parts.append(part)
        data = json.loads(b"".join(parts))
        if self.protocol == "ollama":
            if data.get("done") is not True or data.get("done_reason") == "length":
                raise ValueError("Incomplete local generation")
            message = data["message"]
            usage = {
                k: data[k] for k in ("prompt_eval_count", "eval_count") if k in data
            }
        else:
            choice = data["choices"][0]
            if choice.get("finish_reason") != "stop":
                raise ValueError("Incomplete or tool-directed generation")
            message = choice["message"]
            usage = data.get("usage", {})
        if message.get("tool_calls"):
            raise ValueError("Tool calls require an explicit governed tool executor")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Empty model response")
        if response_model:
            response_model.model_validate_json(content)
        return LocalCompletion(content, data.get("model", self.model), usage)

    def structured(self, messages, response_model):
        return response_model.model_validate_json(
            self.complete(messages, response_model=response_model).content
        )

    def primitive(self, primitive_ref="local.model"):
        from pydantic import ConfigDict

        from lightbulb.primitive_runtime import FunctionBusinessProcessPrimitive

        local = self

        class Input(BaseModel):
            model_config = ConfigDict(extra="forbid")
            messages: list[dict[str, str]]

        class Output(BaseModel):
            content: str
            model: str
            usage: dict
            executed: bool

        def handler(context, inputs):
            if context.preview_only:
                return Output(content="", model=local.model, usage={}, executed=False)
            result = local.complete(inputs.messages)
            return Output(
                content=result.content,
                model=result.model,
                usage=result.usage,
                executed=True,
            )

        return FunctionBusinessProcessPrimitive(
            primitive_ref=primitive_ref,
            title="Local LLM",
            input_model=Input,
            output_model=Output,
            handler=handler,
        )

import json
import os
import unittest
import httpx
from pydantic import BaseModel
from lightbulb.local_llm import LocalLLM


class Answer(BaseModel):
    value: int


class LocalLLMTests(unittest.TestCase):
    @unittest.skipUnless(
        os.getenv("LIGHTBULB_TEST_LOCAL_MODEL"), "Opt-in installed local model test"
    )
    def test_live_installed_local_model_structured_output(self):
        with LocalLLM(
            os.environ["LIGHTBULB_TEST_LOCAL_MODEL"], max_tokens=128
        ) as client:
            result = client.structured(
                [
                    {
                        "role": "user",
                        "content": "Return the integer value 7 in the required JSON schema.",
                    }
                ],
                Answer,
            )
            self.assertEqual(result.value, 7)

    def client(self, handler, **kwargs):
        return LocalLLM("test-local", _transport=httpx.MockTransport(handler), **kwargs)

    def test_local_only_origins(self):
        for url in [
            "https://example.com",
            "http://localhost:11434",
            "http://127.0.0.1.evil.test",
            "http://127.0.0.1/?token=x",
            "http://user:pass@127.0.0.1",
            "http://127.0.0.1/path",
        ]:
            with self.assertRaises(ValueError):
                LocalLLM("test", base_url=url)

    def test_ollama_structured_and_request_bounds(self):
        def serve(request):
            body = json.loads(request.content)
            self.assertFalse(body["stream"])
            self.assertFalse(body["think"])
            self.assertEqual(body["options"]["temperature"], 0)
            self.assertIn("format", body)
            return httpx.Response(
                200,
                json={
                    "done": True,
                    "message": {"content": '{"value":7}'},
                    "model": "test-local",
                },
            )

        with self.client(serve) as client:
            self.assertEqual(
                client.structured([{"role": "user", "content": "seven"}], Answer).value,
                7,
            )

    def test_openai_local_compatibility(self):
        def serve(request):
            self.assertEqual(request.url.path, "/v1/chat/completions")
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {"finish_reason": "stop", "message": {"content": "hello"}}
                    ]
                },
            )

        with self.client(serve, protocol="openai") as client:
            self.assertEqual(
                client.complete([{"role": "user", "content": "hi"}]).content, "hello"
            )

    def test_fail_closed_for_incomplete_tools_redirect_invalid_schema_and_large_response(
        self,
    ):
        messages = [{"role": "user", "content": "hi"}]
        for response in [
            dict(done=False, message={"content": "x"}),
            dict(done=True, done_reason="length", message={"content": "x"}),
            dict(done=True, message={"content": "x", "tool_calls": [{}]}),
            dict(done=True, message={"content": ""}),
        ]:
            with self.client(lambda r: httpx.Response(200, json=response)) as client:
                with self.assertRaises(ValueError):
                    client.complete(messages)
        with self.client(
            lambda r: httpx.Response(302, headers={"location": "https://example.com"})
        ) as client:
            with self.assertRaises(httpx.HTTPStatusError):
                client.complete(messages)
        with self.client(
            lambda r: httpx.Response(
                200,
                json={"done": True, "message": {"content": '{"value":"not-an-int"}'}},
            )
        ) as client:
            with self.assertRaises(ValueError):
                client.structured(messages, Answer)
        with self.client(
            lambda r: httpx.Response(200, content=b"x" * 2000), max_bytes=1000
        ) as client:
            with self.assertRaisesRegex(ValueError, "Response exceeds"):
                client.complete(messages)

    def test_timeout_is_not_cloud_fallback_or_retry(self):
        calls = []

        def serve(request):
            calls.append(request)
            raise httpx.ReadTimeout("timeout")

        with self.client(serve) as client:
            with self.assertRaises(httpx.ReadTimeout):
                client.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()

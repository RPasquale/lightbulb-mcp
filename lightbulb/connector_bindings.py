"""One declarative Connector Binding registry for every Executable Primitive.

Each built-in primitive used to carry a private ``_TOOLS`` dictionary that
mapped a selector value -- the primitive's ``provider``, ``systems``, or
``artifact_type`` input -- to the Lightbulb Tool name it dispatches.  Nine
copies of the same idea lived in three modules, drifted independently from the
``connector_tools`` each primitive declares, and raised a bare ``KeyError``
when a selector value had no Tool.

This module replaces those nine dictionaries with one table.  A capability is
keyed by the owning ``primitive_ref``; one selector value resolves to exactly
one Tool name.

The registry is a *routing* table only.  It grants nothing:

* :class:`lightbulb.primitive_runtime._DeclaredConnectorExecutor` stays the
  authority.  A resolved Tool is still blocked unless the primitive declares it
  in ``connector_tools`` and -- inside a Project run -- the Lightbulb Project
  declares it too.
* :mod:`lightbulb.connector_execution` keeps its fail-closed hosted READ gate.

Provider naming stays consistent with
:class:`lightbulb.connector_conformance.ConnectorToolContract`, where the
provider is the Tool-name prefix.  For capabilities selected by ``provider``
the registry enforces that the selector value *is* that prefix, so the two
views of "provider" can never disagree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping

from lightbulb.errors import LightbulbError


CONNECTOR_BINDING_REGISTRY_SCHEMA = "lightbulb.connector_binding_registry.v1"

# Mirrors ``connector_execution._TOOL_NAME_RE``; the request model remains the
# enforcement point, this only keeps the table honest at import time.
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$")
_PROVIDER_SELECTOR = "provider"


def _normalize(value: Any) -> str:
    return str(value).strip().lower()


class ConnectorBindingError(LightbulbError, LookupError):
    """No Tool is bound for a requested capability or selector value.

    Multiply-inherits :class:`LookupError` so the old ``KeyError``-shaped
    control flow keeps working for callers that catch ``LookupError``, and
    :class:`~lightbulb.errors.LightbulbError` so SDK users can catch every
    Lightbulb failure in one place.  Unlike the bare ``KeyError`` it replaces,
    it names the capability, the selector, and the values that *are* declared.
    """

    def __init__(
        self,
        message: str,
        *,
        capability: str,
        selector: str,
        requested: str,
        available: Iterable[str] = (),
    ) -> None:
        super().__init__(message)
        self.capability = capability
        self.selector = selector
        self.requested = requested
        self.available = tuple(available)


@dataclass(frozen=True)
class ConnectorBinding:
    """One resolved row of the registry."""

    capability: str
    selector: str
    selector_value: str
    tool: str

    @property
    def provider(self) -> str:
        """Provider derived exactly as ``ConnectorToolContract.provider`` does."""

        return self.tool.split(".", 1)[0]


@dataclass(frozen=True)
class ConnectorCapability:
    """Every Tool one Executable Primitive may route to, keyed by selector value."""

    capability: str
    selector: str
    bindings: Mapping[str, str]

    def __post_init__(self) -> None:
        capability = _normalize(self.capability)
        if not capability or "." not in capability:
            raise ValueError(
                "capability must be a dotted business capability name"
            )
        selector = _normalize(self.selector)
        if not selector.isidentifier():
            raise ValueError("selector must be the primitive input field name")
        normalized: Dict[str, str] = {}
        for raw_value, raw_tool in self.bindings.items():
            selector_value = _normalize(raw_value)
            tool = _normalize(raw_tool)
            if not selector_value:
                raise ValueError(f"{capability} has a blank {selector} value")
            if not _TOOL_NAME_RE.fullmatch(tool) or ".." in tool:
                raise ValueError(
                    f"{capability} binds {selector}={selector_value!r} to an "
                    "invalid Tool name"
                )
            if selector_value in normalized:
                raise ValueError(
                    f"{capability} declares {selector}={selector_value!r} twice"
                )
            if selector == _PROVIDER_SELECTOR and tool.split(".", 1)[0] != selector_value:
                raise ValueError(
                    f"{capability} binds provider {selector_value!r} to {tool!r}; "
                    "a provider selector value must be the Tool-name prefix"
                )
            normalized[selector_value] = tool
        if not normalized:
            raise ValueError(f"{capability} declares no Connector Bindings")
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "selector", selector)
        object.__setattr__(self, "bindings", MappingProxyType(normalized))

    def rows(self) -> tuple[ConnectorBinding, ...]:
        return tuple(
            ConnectorBinding(
                capability=self.capability,
                selector=self.selector,
                selector_value=selector_value,
                tool=tool,
            )
            for selector_value, tool in self.bindings.items()
        )


class ConnectorBindingRegistry:
    """Resolve ``(capability, selector value)`` to one declared Tool name."""

    def __init__(self, capabilities: Iterable[ConnectorCapability]) -> None:
        declared: Dict[str, ConnectorCapability] = {}
        for capability in capabilities:
            if capability.capability in declared:
                raise ValueError(
                    f"Connector Binding capability already declared: "
                    f"{capability.capability}"
                )
            declared[capability.capability] = capability
        self._capabilities: Mapping[str, ConnectorCapability] = MappingProxyType(
            declared
        )

    def capabilities(self) -> tuple[str, ...]:
        return tuple(self._capabilities)

    def supports(self, capability: str) -> bool:
        return _normalize(capability) in self._capabilities

    def declaration(self, capability: str) -> ConnectorCapability:
        key = _normalize(capability)
        declared = self._capabilities.get(key)
        if declared is None:
            raise ConnectorBindingError(
                f"No Connector Binding capability is declared for {capability!r}. "
                f"Declared capabilities: {', '.join(self.capabilities())}.",
                capability=key,
                selector="capability",
                requested=key,
                available=self.capabilities(),
            )
        return declared

    def selector(self, capability: str) -> str:
        return self.declaration(capability).selector

    def providers(self, capability: str) -> tuple[str, ...]:
        """Selector values declared for a capability, in declaration order."""

        return tuple(self.declaration(capability).bindings)

    def tools(self, capability: str) -> tuple[str, ...]:
        """Distinct Tool names a capability may route to, in declaration order."""

        return tuple(
            dict.fromkeys(self.declaration(capability).bindings.values())
        )

    def rows(self) -> tuple[ConnectorBinding, ...]:
        return tuple(
            row
            for capability in self._capabilities.values()
            for row in capability.rows()
        )

    def resolve(self, capability: str, selector_value: str) -> str:
        """Return the single Tool bound to this capability and selector value.

        Raises :class:`ConnectorBindingError` -- never a bare ``KeyError`` --
        when the capability is unknown or the selector value has no binding.
        """

        declared = self.declaration(capability)
        requested = _normalize(selector_value)
        tool = declared.bindings.get(requested)
        if tool is None:
            raise ConnectorBindingError(
                f"{declared.capability} has no Connector Binding for "
                f"{declared.selector}={selector_value!r}. Declared "
                f"{declared.selector} values: "
                f"{', '.join(declared.bindings)}.",
                capability=declared.capability,
                selector=declared.selector,
                requested=requested,
                available=tuple(declared.bindings),
            )
        return tool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": CONNECTOR_BINDING_REGISTRY_SCHEMA,
            "capabilities": [
                {
                    "capability": declared.capability,
                    "selector": declared.selector,
                    "bindings": dict(declared.bindings),
                }
                for declared in self._capabilities.values()
            ],
        }


# The whole routing table.  Each entry replaces one former ``_TOOLS`` dict and
# keeps its provider/Tool pairs verbatim, so this file is the single place a
# new connector is bound to an existing capability.
_CAPABILITY_DECLARATIONS: tuple[tuple[str, str, Mapping[str, str]], ...] = (
    # lightbulb/domain_primitives.py
    (
        "finance.ingest_supplier_invoice",
        "provider",
        {
            "xero": "xero.create_bill",
            "quickbooks": "quickbooks.create_bill",
        },
    ),
    (
        "legal.draft_contract",
        "provider",
        {
            "docs": "docs.create_document",
            "microsoft": "microsoft.create_document",
        },
    ),
    (
        "legal.review_contract",
        "provider",
        {
            "docs": "docs.read_document",
            "drive": "drive.download_file",
            "microsoft": "microsoft.download_file",
        },
    ),
    (
        "crm.qualify_lead",
        "provider",
        {
            "hubspot": "hubspot.get_contact",
            "salesforce": "salesforce.get_contact",
        },
    ),
    (
        "hr.onboard_employee",
        "systems",
        {
            "bamboohr": "bamboohr.create_employee",
            "google_workspace": "google_workspace.create_user",
            "microsoft": "microsoft.create_user",
        },
    ),
    # lightbulb/executable_primitives.py
    (
        "communication.write_email",
        "provider",
        {
            "gmail": "gmail.send_email",
            "microsoft": "microsoft.send_email",
            "notifications": "notifications.send_email",
            "ses": "ses.send_email",
        },
    ),
    (
        "finance.create_invoice",
        "provider",
        {
            "xero": "xero.create_invoice",
            "quickbooks": "quickbooks.create_invoice",
            "stripe": "stripe.create_invoice",
            "square": "square.create_invoice",
        },
    ),
    (
        "calendar.schedule_meeting",
        "provider",
        {
            "calendar": "calendar.create_event",
            "microsoft": "microsoft.create_event",
        },
    ),
    # lightbulb/growth_primitives.py
    (
        "documents.generate_business_artifact",
        "artifact_type",
        {
            "docx": "docs.create_document",
            "pdf": "docs.create_document",
            "markdown": "docs.create_document",
            "xlsx": "sheets.create_spreadsheet",
            "pptx": "slides.create_presentation",
        },
    ),
)


CONNECTOR_BINDINGS = ConnectorBindingRegistry(
    ConnectorCapability(capability=capability, selector=selector, bindings=bindings)
    for capability, selector, bindings in _CAPABILITY_DECLARATIONS
)


def resolve_connector_tool(capability: str, selector_value: str) -> str:
    """Resolve one Tool name through the default Connector Binding registry."""

    return CONNECTOR_BINDINGS.resolve(capability, selector_value)


__all__ = [
    "CONNECTOR_BINDINGS",
    "CONNECTOR_BINDING_REGISTRY_SCHEMA",
    "ConnectorBinding",
    "ConnectorBindingError",
    "ConnectorBindingRegistry",
    "ConnectorCapability",
    "resolve_connector_tool",
]

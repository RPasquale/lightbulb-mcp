"""Normalized discovery contract for Lightbulb actions and workers.

The marketplace is deliberately a discovery surface.  Listings describe how a
capability can be addressed, but execution still re-checks tenant, company,
RBAC, plan entitlement, connector policy, and HITL approval in the platform.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence


CATALOG_SCHEMA = "lightbulb.agent_marketplace_catalog.v1"
LISTING_SCHEMA = "lightbulb.agent_marketplace_listing.v1"
SYNTHETIC_LIFECYCLE_UNAVAILABLE_REASON = (
    "synthetic_discovery_listing_not_persisted"
)
PERSISTED_LIFECYCLE_LISTING_TOOL = "list_agent_marketplace_listings"
_KINDS = {"action", "worker"}
_MAX_LIMIT = 200


def _text(value: Any) -> str:
    return str(value or "").strip()


def _token(value: Any) -> str:
    return _text(value).lower().replace("-", "_").replace(" ", "_")


def _strings(value: Any) -> List[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [item for item in (_text(row) for row in value) if item]


def _field_schema(value: Any, *, include_inputs: bool) -> List[Dict[str, Any]]:
    if not include_inputs or not isinstance(value, list):
        return []
    fields: List[Dict[str, Any]] = []
    for row in value:
        if not isinstance(row, Mapping):
            continue
        name = _text(row.get("name"))
        if not name:
            continue
        field: Dict[str, Any] = {
            "name": name,
            "type": _text(row.get("type")) or "string",
            "required": bool(row.get("required", False)),
        }
        description = _text(row.get("description"))
        if description:
            field["description"] = description
        enum_values = _strings(row.get("enum_values") or row.get("enumValues"))
        if enum_values:
            field["enum_values"] = enum_values
        fields.append(field)
    return fields


def _unknown_governance() -> Dict[str, Any]:
    return {
        "risk_level": "not_declared",
        "approval_required": "not_declared",
        "tenant_scope": "revalidated_at_execution",
        "company_scope": "revalidated_at_execution",
        "rbac": "revalidated_at_execution",
        "consequential_writes": "subject_to_platform_hitl_policy",
    }


def _unknown_commercials() -> Dict[str, Any]:
    return {"status": "not_declared"}


def _listing_base(
    *,
    listing_id: str,
    kind: str,
    title: str,
    summary: str,
    domain: str,
    source_type: str,
) -> Dict[str, Any]:
    return {
        "schema": LISTING_SCHEMA,
        "id": listing_id,
        "kind": kind,
        "title": title,
        "summary": summary,
        "domain": domain,
        "source": {
            "publisher": "Lightbulb",
            "type": source_type,
            "version": "not_declared",
            "lifecycle": "not_declared",
        },
        "pricing": _unknown_commercials(),
        "evaluation": _unknown_commercials(),
        "installable": False,
        "lifecycle_installable": False,
        "install_blockers": [SYNTHETIC_LIFECYCLE_UNAVAILABLE_REASON],
        "lifecycle_unavailable_reason": SYNTHETIC_LIFECYCLE_UNAVAILABLE_REASON,
        "lifecycle_listing_tool": PERSISTED_LIFECYCLE_LISTING_TOOL,
    }


def _primitive_rows(value: Any) -> List[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        value = value.get("primitives", value.get("items", []))
    if not isinstance(value, (list, tuple)):
        return []
    return [row for row in value if isinstance(row, Mapping)]


def _primitive_listing(row: Mapping[str, Any], *, include_inputs: bool) -> Dict[str, Any] | None:
    primitive_id = _text(row.get("id") or row.get("primitive_ref"))
    if not primitive_id:
        return None
    domain = _token(row.get("category"))
    preferred = row.get("preferred_domain_action")
    if not isinstance(preferred, Mapping):
        preferred = {}
    preferred_domain = _token(preferred.get("domain"))
    preferred_action = _token(preferred.get("action"))

    listing = _listing_base(
        listing_id=f"lightbulb:business-primitive:{primitive_id}",
        kind="action",
        title=_text(row.get("title")) or primitive_id,
        summary=_text(row.get("summary") or row.get("description")),
        domain=domain,
        source_type="sdk_builtin_business_primitive",
    )
    execution: Dict[str, Any] = {
        "route": "backbone_business_primitive",
        "primitive_ref": primitive_id,
        "default_mode": _text(row.get("default_mode")) or "not_declared",
    }
    if preferred_domain and preferred_action:
        execution["preferred_domain_action_ref"] = (
            f"lightbulb:domain-action:{preferred_domain}:{preferred_action}"
        )
    listing["execution"] = execution
    fields = _field_schema(row.get("input_fields"), include_inputs=include_inputs)
    if include_inputs:
        listing["input_schema"] = fields
    workflow = row.get("agentic_workflow")
    if not isinstance(workflow, Mapping):
        workflow = {}
    listing["dependencies"] = {
        "preferred_tools": _strings(row.get("preferred_connector_tools")),
        "setup_requirements": _strings(workflow.get("setup_requirements")),
    }
    governance = _unknown_governance()
    governance["risk_level"] = (
        _text(row.get("risk_level")) if "risk_level" in row else "not_declared"
    ) or "not_declared"
    governance["approval_required"] = (
        bool(row.get("approval_required"))
        if "approval_required" in row
        else "not_declared"
    )
    listing["governance"] = governance
    listing["availability"] = {
        "status": "catalogued",
        "basis": "sdk_builtin_contract",
        "entitlement": "not_evaluated",
        "execution_revalidation_required": True,
    }
    return listing


def _domain_rows(value: Any) -> List[tuple[str, Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        for wrapper in ("domains", "contracts", "items"):
            if wrapper in value and isinstance(value[wrapper], (Mapping, list, tuple)):
                return _domain_rows(value[wrapper])
        if _text(value.get("domain")):
            return [(_token(value.get("domain")), value)]
        rows: List[tuple[str, Mapping[str, Any]]] = []
        for key, row in value.items():
            if isinstance(row, Mapping):
                domain = _token(row.get("domain") or key)
                if domain:
                    rows.append((domain, row))
        return rows
    if isinstance(value, (list, tuple)):
        rows = []
        for row in value:
            if not isinstance(row, Mapping):
                continue
            domain = _token(row.get("domain") or row.get("id"))
            if domain:
                rows.append((domain, row))
        return rows
    return []


def _action_rows(value: Any) -> List[tuple[str, Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        for wrapper in ("actions", "items"):
            if wrapper in value and isinstance(value[wrapper], (Mapping, list, tuple)):
                return _action_rows(value[wrapper])
        rows: List[tuple[str, Mapping[str, Any]]] = []
        for key, row in value.items():
            if isinstance(row, Mapping):
                action = _token(row.get("action") or key)
                if action:
                    rows.append((action, row))
        return rows
    if isinstance(value, (list, tuple)):
        rows = []
        for row in value:
            if not isinstance(row, Mapping):
                continue
            action = _token(row.get("action") or row.get("name"))
            if action:
                rows.append((action, row))
        return rows
    return []


def _action_listing(
    domain: str,
    action: str,
    row: Mapping[str, Any],
    *,
    include_inputs: bool,
    scoped: bool,
) -> Dict[str, Any]:
    listing = _listing_base(
        listing_id=f"lightbulb:domain-action:{domain}:{action}",
        kind="action",
        title=_text(row.get("title")) or action.replace("_", " ").title(),
        summary=_text(row.get("description")),
        domain=domain,
        source_type="authenticated_domain_action" if scoped else "global_domain_contract",
    )
    listing["execution"] = {
        "route": "domain_agent_dispatch",
        "domain": domain,
        "action": action,
        "workflow_type": _text(row.get("workflow_type") or row.get("workflowType"))
        or "not_declared",
    }
    if include_inputs:
        listing["input_schema"] = _field_schema(
            row.get("input_schema") or row.get("inputSchema"),
            include_inputs=True,
        )
    listing["dependencies"] = {
        "required_tools": _strings(row.get("required_tools") or row.get("requiredTools")),
        "optional_tools": _strings(row.get("optional_tools") or row.get("optionalTools")),
        "preferred_integrations": _strings(
            row.get("preferred_integrations") or row.get("preferredIntegrations")
        ),
    }
    listing["governance"] = _unknown_governance()
    listing["availability"] = {
        "status": "rbac_visible" if scoped else "unverified",
        "basis": (
            "authenticated_tenant_company_action_listing"
            if scoped
            else "global_platform_contract"
        ),
        "entitlement": "not_evaluated",
        "execution_revalidation_required": True,
    }
    return listing


def _worker_listing(
    domain: str,
    row: Mapping[str, Any],
    action_refs: Sequence[str],
) -> Dict[str, Any]:
    listing = _listing_base(
        listing_id=f"lightbulb:domain-worker:{domain}",
        kind="worker",
        title=_text(row.get("label") or row.get("title")) or domain.replace("_", " ").title(),
        summary=_text(row.get("description")),
        domain=domain,
        source_type="global_domain_contract",
    )
    listing["execution"] = {
        "route": "domain_agent",
        "domain": domain,
        "action_count": len(action_refs),
        "action_refs": list(action_refs),
    }
    listing["dependencies"] = {
        "required_tools": [],
        "optional_tools": [],
        "preferred_integrations": [],
    }
    listing["governance"] = _unknown_governance()
    listing["availability"] = {
        "status": "unverified",
        "basis": "global_platform_contract",
        "entitlement": "not_evaluated",
        "execution_revalidation_required": True,
    }
    return listing


def _kind_filter(kinds: str | Iterable[str] | None) -> List[str]:
    if kinds is None:
        return []
    values = [kinds] if isinstance(kinds, str) else list(kinds)
    normalized = [_token(value) for value in values if _text(value)]
    invalid = sorted(set(normalized) - _KINDS)
    if invalid:
        raise ValueError(f"Unsupported marketplace kind(s): {', '.join(invalid)}")
    return sorted(set(normalized))


def agent_marketplace_catalog(
    *,
    business_primitives: Any = (),
    domain_contracts: Any = (),
    scoped_domain: str | None = None,
    scoped_actions: Any = (),
    query: str | None = None,
    kinds: str | Iterable[str] | None = None,
    domain: str | None = None,
    include_inputs: bool = True,
    limit: int = 50,
) -> Dict[str, Any]:
    """Build a bounded, deterministic marketplace discovery catalog.

    ``scoped_actions`` must come from the authenticated
    ``/api/domain-agents/{domain}/actions`` endpoint.  Only those exact rows are
    labelled ``rbac_visible``; static contracts remain unverified.
    """

    normalized_kinds = _kind_filter(kinds)
    normalized_domain = _token(domain)
    normalized_scoped_domain = _token(scoped_domain)
    if normalized_scoped_domain and normalized_domain and normalized_scoped_domain != normalized_domain:
        raise ValueError("scoped_domain must match the marketplace domain filter")
    try:
        bounded_limit = max(1, min(int(limit), _MAX_LIMIT))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc

    listings: Dict[str, Dict[str, Any]] = {}
    for row in _primitive_rows(business_primitives):
        listing = _primitive_listing(row, include_inputs=include_inputs)
        if listing:
            listings[listing["id"]] = listing

    domain_map = {key: row for key, row in _domain_rows(domain_contracts)}
    for domain_key, row in sorted(domain_map.items()):
        actions = _action_rows(row.get("actions", {}))
        action_refs: List[str] = []
        for action, action_row in actions:
            listing = _action_listing(
                domain_key,
                action,
                action_row,
                include_inputs=include_inputs,
                scoped=False,
            )
            listings[listing["id"]] = listing
            action_refs.append(listing["id"])
        worker = _worker_listing(domain_key, row, sorted(action_refs))
        listings[worker["id"]] = worker

    if normalized_scoped_domain:
        scoped_refs: List[str] = []
        for action, row in _action_rows(scoped_actions):
            listing = _action_listing(
                normalized_scoped_domain,
                action,
                row,
                include_inputs=include_inputs,
                scoped=True,
            )
            listings[listing["id"]] = listing
            scoped_refs.append(listing["id"])

        if scoped_refs:
            worker_id = f"lightbulb:domain-worker:{normalized_scoped_domain}"
            worker = listings.get(worker_id)
            if worker is None:
                worker = _worker_listing(
                    normalized_scoped_domain,
                    {"domain": normalized_scoped_domain},
                    sorted(scoped_refs),
                )
                worker["source"]["type"] = "authenticated_domain_action_catalog"
                listings[worker_id] = worker
            else:
                known_refs = set(worker["execution"].get("action_refs", []))
                known_refs.update(scoped_refs)
                worker["execution"]["action_refs"] = sorted(known_refs)
                worker["execution"]["action_count"] = len(known_refs)

    query_text = _text(query).lower()
    query_terms = query_text.split()
    matches: List[tuple[int, Dict[str, Any]]] = []
    for listing in listings.values():
        if normalized_kinds and listing["kind"] not in normalized_kinds:
            continue
        if normalized_domain and listing["domain"] != normalized_domain:
            continue
        dependencies = listing.get("dependencies", {})
        haystack = " ".join(
            [
                listing["id"],
                listing["title"],
                listing["summary"],
                listing["domain"],
                " ".join(
                    item
                    for values in dependencies.values()
                    if isinstance(values, list)
                    for item in values
                ),
            ]
        ).lower()
        if query_terms and not all(term in haystack for term in query_terms):
            continue
        score = 0
        if query_text:
            title = listing["title"].lower()
            listing_id = listing["id"].lower()
            score += 100 if query_text in (title, listing_id) else 0
            score += 40 if title.startswith(query_text) else 0
            score += sum(haystack.count(term) for term in query_terms)
        matches.append((score, listing))

    kind_order = {"action": 0, "worker": 1}
    matches.sort(
        key=lambda item: (
            -item[0],
            kind_order[item[1]["kind"]],
            item[1]["domain"],
            item[1]["id"],
        )
    )
    total_matches = len(matches)
    selected = [listing for _, listing in matches[:bounded_limit]]
    return {
        "schema": CATALOG_SCHEMA,
        "catalog_mode": "discovery_only",
        "scope": {
            "static_contracts": "global_unverified",
            "scoped_actions": (
                "authenticated_tenant_company_rbac_visible"
                if normalized_scoped_domain
                else "not_requested"
            ),
            "execution": "tenant_company_rbac_entitlement_and_hitl_revalidated",
            "lifecycle": {
                "synthetic_listing_ids": "not_accepted_by_persisted_lifecycle_tools",
                "persisted_listing_source": PERSISTED_LIFECYCLE_LISTING_TOOL,
                "persisted_id_format": "uuid",
            },
        },
        "filters": {
            "query": query_text,
            "kinds": normalized_kinds,
            "domain": normalized_domain,
            "include_inputs": bool(include_inputs),
            "limit": bounded_limit,
        },
        "total_matches": total_matches,
        "count": len(selected),
        "truncated": total_matches > len(selected),
        "listings": selected,
    }


__all__ = [
    "CATALOG_SCHEMA",
    "LISTING_SCHEMA",
    "PERSISTED_LIFECYCLE_LISTING_TOOL",
    "SYNTHETIC_LIFECYCLE_UNAVAILABLE_REASON",
    "agent_marketplace_catalog",
]

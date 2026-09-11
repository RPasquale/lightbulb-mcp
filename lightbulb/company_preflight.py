"""Offline checks for the exact company-worker configuration, without credentials.

This report is configuration evidence, never host compatibility or permission
attestation. The worker calls the same validator before authenticating.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping
from uuid import UUID

from lightbulb.company_cadence_runner import build_bundle
from lightbulb.company_engine_core import parsed, stable_digest, detached
from lightbulb.company_recurring_observations import RecurringObservationBinding


def validate_worker_signals(signals):
    from lightbulb.company_operating_system import CompanySignal
    if not isinstance(signals, (list, tuple)) or len(signals) > 100:
        raise ValueError("COMPANY_SIGNALS_INVALID")
    return tuple(CompanySignal.model_validate(detached(signal)).to_dict() for signal in signals)


def validate_worker_configuration(bundle, sources, *, growth_config=None, interval_seconds=86400, signals=(), sales_config=None, capability_waits=(), native_connection_id=None, capability_development=None, customer_lifecycle=None):
    """Validate executable bindings and return canonical objects; performs no I/O."""
    from lightbulb.company_capability_waits import validate_capability_waits
    waits = validate_capability_waits(capability_waits)
    if capability_development is not None:
        from lightbulb.company_capability_development import CapabilityDevelopmentPolicy
        CapabilityDevelopmentPolicy.model_validate(capability_development)
        if not native_connection_id:
            raise ValueError("CAPABILITY_DEVELOPMENT_RUNTIME_REQUIRED")
    if native_connection_id:
        UUID(str(native_connection_id))
    if waits and not native_connection_id:
        raise ValueError("CAPABILITY_WAIT_RUNTIME_REQUIRED")
    if any(w.domain == "sales" for w in waits) and sales_config is None:
        raise ValueError("CAPABILITY_WAIT_SALES_OWNER_REQUIRED")
    if any(w.domain in {"finance", "marketing"} for w in waits) and growth_config is None:
        raise ValueError("CAPABILITY_WAIT_GROWTH_OWNER_REQUIRED")
    bundle = build_bundle(bundle)
    from lightbulb.company_operating_system import route_signal
    for signal in validate_worker_signals(signals):
        route_signal(bundle.operating_plan, signal)
    if type(interval_seconds) is not int or not 60 <= interval_seconds <= 604800:
        raise ValueError("WORKER_INTERVAL_INVALID")
    if not isinstance(sources, (list, tuple)) or len(sources) > 100:
        raise ValueError("OBSERVATION_BINDINGS_INVALID")
    start = parsed(bundle.start_at)
    if sources and (start.hour or start.minute or start.second or start.microsecond):
        raise ValueError("COMPANY_INTAKE_MIDNIGHT_REQUIRED")
    for field in ("project_id",):
        UUID(str(bundle.scope[field]))
    bindings = tuple(RecurringObservationBinding.model_validate(detached(s)) for s in sources)
    if len({s.source_ref for s in bindings}) != len(bindings):
        raise ValueError("OBSERVATION_BINDINGS_INVALID")
    currency = bundle.operating_plan.blueprint.currency
    billing_customers = set()
    for source in bindings:
        source.job(start=bundle.start_at, end=(start + timedelta(days=1)).isoformat().replace("+00:00", "Z"))
        if source.kind == "customer_cohort" and source.arguments.get("currency") != currency:
            raise ValueError("COHORT_CURRENCY_MISMATCH")
        if source.kind == "channel_spend" and bundle.growth_plan is not None and bundle.growth_plan.blueprint.require_demand_registry and not source.demand_registry_ref:
            raise ValueError("DEMAND_DESTINATION_REQUIRED")
        if source.kind == "marketing_touches":
            import re
            if any(re.fullmatch(r"[a-f0-9]{64}", k) is None or re.fullmatch(r"[a-f0-9]{64}", v) is None for k, v in source.identity_links.items()):
                raise ValueError("IDENTITY_COMMITMENT_INVALID")
            if source.arguments["event"] not in source.event_bindings:
                raise ValueError("TOUCH_EVENT_POLICY_REQUIRED")
        if source.kind == "invoice_health":
            route = bundle.operating_plan.route("signals.payment_overdue")
            if route is None or "service_delivery" not in route.consumers or bundle.service_delivery_plan is None:
                raise ValueError("BILLING_RETENTION_PLAN_REQUIRED")
            from lightbulb.billing_health import minor_units_to_amount
            minor_units_to_amount(0, currency)
            key = (source.connector_account_ref, source.arguments["customer_id"])
            if key in billing_customers:
                raise ValueError("BILLING_CUSTOMER_DUPLICATE")
            billing_customers.add(key)
    if growth_config is not None:
        validate_growth_configuration(bundle, bindings, growth_config)
    if sales_config is not None:
        from lightbulb.company_sales_configuration import validate_sales_configuration
        validate_sales_configuration(sales_config, bundle=bundle, sources=bindings)
    if customer_lifecycle is not None:
        from lightbulb.company_customer_lifecycle import CustomerLifecycleConfiguration
        from lightbulb.company_sales_configuration import validate_sales_configuration
        if sales_config is None:
            raise ValueError("CUSTOMER_LIFECYCLE_SALES_REQUIRED")
        lifecycle=CustomerLifecycleConfiguration.model_validate(customer_lifecycle).validate_bindings(
            validate_sales_configuration(sales_config,bundle=bundle,sources=bindings),bindings)
        if lifecycle.crm_sources and (start.hour or start.minute or start.second or start.microsecond):
            raise ValueError("COMPANY_INTAKE_MIDNIGHT_REQUIRED")
        if any(row.goal=="renewal" for row in lifecycle.enrollments):
            from lightbulb.company_chain_catalog import plan_for_chain
            plan_for_chain(bundle,"retention_chain")
    return bundle, bindings


def validate_growth_configuration(bundle, sources, configuration):
    """Check configuration structure before any hosted reads or writes."""
    from lightbulb.growth_engine_loop import CampaignPortfolio
    from lightbulb.company_growth_host import _days
    if not isinstance(configuration, dict) or set(configuration) - {"periods", "reallocations"}:
        raise ValueError("GROWTH_HOST_CONFIGURATION_INVALID")
    if bundle.growth_plan is None:
        raise ValueError("GROWTH_PLAN_REQUIRED")
    periods, decisions = configuration.get("periods", []), configuration.get("reallocations", [])
    if not isinstance(periods, list) or not isinstance(decisions, list):
        raise ValueError("GROWTH_HOST_CONFIGURATION_INVALID")
    items = periods + decisions
    if len(items) > 32 or any(not isinstance(x, dict) or not isinstance(x.get("ref"), str) or not x["ref"].strip() for x in items):
        raise ValueError("GROWTH_HOST_CONFIGURATION_INVALID")
    if len({x["ref"] for x in items}) != len(items):
        raise ValueError("GROWTH_HOST_CONFIGURATION_INVALID")
    sources_by_ref = {s.source_ref: s for s in sources}
    for spec in items:
        portfolio = CampaignPortfolio.model_validate(spec["portfolio"])
        if portfolio.plan_digest != bundle.growth_plan.plan_digest:
            raise ValueError("GROWTH_PLAN_MISMATCH")
        list(_days(portfolio.period_start, portfolio.period_end))
    for spec in periods:
        required = spec.get("required_source_refs")
        if not isinstance(required, list) or not required or len(set(required)) != len(required) or not set(required) <= sources_by_ref.keys():
            raise ValueError("SOURCE_CENSUS_REQUIRED")
        if not spec.get("register_ref") or not spec.get("revenue_engines"):
            raise ValueError("REVENUE_SOURCE_CENSUS_REQUIRED")
        if spec.get("cohort_source_ref") and (spec["cohort_source_ref"] not in required or sources_by_ref[spec["cohort_source_ref"]].kind != "customer_cohort"):
            raise ValueError("COHORT_SOURCE_INVALID")
        if spec.get("content_asset_refs") and "content_allocations" not in spec:
            raise ValueError("CONTENT_ALLOCATION_REQUIRED")
    for spec in decisions:
        if not spec.get("economic_period_ref"):
            raise ValueError("ECONOMIC_PERIOD_REQUIRED")


def worker_preflight(bundle, sources, *, company_id=None, growth_config=None, interval_seconds=86400, signals=(), sales_config=None, capability_waits=(), native_connection_id=None, capability_development=None, customer_lifecycle=None):
    """Return a sanitized, non-authoritative readiness report suitable for sharing."""
    from lightbulb.company_capability_waits import validate_capability_waits
    issues = []
    try:
        bundle, sources = validate_worker_configuration(bundle, sources, growth_config=growth_config, interval_seconds=interval_seconds, signals=signals, sales_config=sales_config, capability_waits=capability_waits, native_connection_id=native_connection_id, capability_development=capability_development, customer_lifecycle=customer_lifecycle)
        if company_id is not None:
            UUID(company_id)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        # Pydantic messages can include credentials supplied in invalid config.
        code = str(exc).split(":", 1)[0]
        if not code.isupper() or len(code) > 100 or not code.replace("_", "").isalnum():
            code = "CONFIGURATION_INVALID"
        checks = [{"code": code, "status": "failed"}]
        from pydantic import ValidationError
        if isinstance(exc, ValidationError):
            allowed = {"source_ref", "kind", "tool", "connector_account_ref", "arguments", "target_entity_ref", "centre_ref",
                       "demand_registry_ref", "pacing_controls", "channel", "event_bindings", "identity_links", "portfolio",
                       "scope", "project_id", "operating_plan", "growth_plan", "start_at", "currency"}
            checks = [{"code": "CONFIGURATION_FIELD_INVALID", "status": "failed",
                       "field": ".".join(str(x) if type(x) is int or x in allowed else "field" for x in e["loc"]) or "configuration"}
                      for e in exc.errors(include_input=False, include_context=False, include_url=False)[:20]]
        return {"schema": "lightbulb.company_preflight.v1", "configuration_valid": False,
                "deployment_ready": False, "checks": checks,
                "validation_basis": "offline_configuration"}
    for source in sources:
        if source.kind == "marketing_touches" and not source.identity_links:
            issues.append({"code": "IDENTITY_MAPPING_EMPTY", "status": "warning", "source_ref": source.source_ref})
        if source.kind == "channel_spend" and source.demand_registry_ref and not source.pacing_controls:
            issues.append({"code": "PACING_TARGETS_MISSING", "status": "warning", "source_ref": source.source_ref})
    for code in ("HOST_CONTRACT_COMPATIBILITY", "COMPANY_PROJECT_PERMISSION", "CONNECTOR_ACCOUNT_CUSTODY",
                 "PROTECTED_ENGINE_RECORDS", "RENEWABLE_IDENTITY", "RECEIPT_KEY_CUSTODY", "PROVIDER_CERTIFICATION"):
        issues.append({"code": code, "status": "not_checked"})
    return {"schema": "lightbulb.company_preflight.v1", "configuration_valid": True, "deployment_ready": False,
            "validation_basis": "offline_configuration", "bundle_digest": bundle.plan_digest,
            "configuration_digest": stable_digest({"bundle": bundle.plan_digest, "sources": [s.to_dict() for s in sources],
                                                   "growth": growth_config, "interval": interval_seconds,
                                                   "signals": list(validate_worker_signals(signals)),
                                                   **({"customer_lifecycle": detached(customer_lifecycle)} if customer_lifecycle is not None else {}),
                                                   **({"capability_development": dict(capability_development) if isinstance(capability_development, dict) else capability_development.model_dump(mode="json")} if capability_development is not None else {}),
                                                   **({"sales": detached(sales_config)} if sales_config is not None else {}),
                                                   **({"capability_waits": [w.model_dump(mode="json") for w in validate_capability_waits(capability_waits)], "native_connection_id": native_connection_id} if capability_waits or native_connection_id else {})}),
            "source_count": len(sources), "checks": issues}


def source_template():
    """Non-secret example; placeholders must be replaced before connected use."""
    return [{"source_ref": "marketing", "kind": "marketing_touches", "tool": "posthog.query_events",
             "connector_account_ref": "replace-with-company-connection", "arguments": {"project_id": "12345", "event": "marketing_click"},
             "event_bindings": {"marketing_click": {"channel": "paid_search_google"}}, "identity_links": {}}]

"""Deployment eligibility from an authenticated profile, never billing or RBAC authority."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Sequence

DEPLOYMENT_PROFILE_SCHEMA = "lightbulb.deployment_profile.v1"
SERVICES = ("spark", "automl", "clickhouse")
TIER_CAPABILITIES = MappingProxyType({
    tier: MappingProxyType({service: tier != "lite" for service in SERVICES})
    for tier in ("lite", "cloud", "full")
})


def required_service_names(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)) or not value:
        raise ValueError("required_services must be a non-empty list or tuple")
    if any(not isinstance(v, str) or v not in SERVICES for v in value):
        raise ValueError("required_services supports spark, automl and clickhouse")
    return tuple(sorted(set(value)))


def learning_required_services(runtime: str) -> tuple[str, ...]:
    """Reuse the canonical runtime registry; other runtimes have no K-6 assertion."""
    from lightbulb.project_learning_runs import PROJECT_CAPACITY_RUNTIMES
    if runtime not in PROJECT_CAPACITY_RUNTIMES:
        raise ValueError("Unknown learning runtime")
    service = PROJECT_CAPACITY_RUNTIMES[runtime]
    return (service,) if service in SERVICES else ()


@dataclass(frozen=True)
class DeploymentAvailability:
    status: str
    code: str
    message: str
    tenant_id: str
    company_id: str
    required_services: tuple[str, ...]
    tier: str | None = None
    unavailable_services: tuple[str, ...] = ()
    unknown_services: tuple[str, ...] = ()

    @property
    def available(self) -> bool:
        return self.status == "available"

    def to_dict(self) -> dict[str, Any]:
        return {"schema": "lightbulb.deployment_availability.v1", "status": self.status, "code": self.code,
                "message": self.message, "tenant_id": self.tenant_id, "company_id": self.company_id,
                "tier": self.tier, "required_services": list(self.required_services),
                "unavailable_services": list(self.unavailable_services), "unknown_services": list(self.unknown_services),
                "authorization_granted": False}


def deployment_availability(identity: Mapping[str, Any], *, tenant_id: str, company_id: str,
                            required_services: Sequence[str]) -> DeploymentAvailability:
    """Evaluate a fresh /users/me response bound to trusted request scope.

    deploymentProfile is a proposed platform contract. Missing information is
    unknown; Cloud/Full eligibility alone never establishes installed services.
    This pure function cannot authenticate a caller-created mapping.
    """
    required = required_service_names(required_services)
    def result(status, code, message, tier=None, unavailable=(), unknown=()):
        return DeploymentAvailability(status, code, message, tenant_id, company_id, required, tier, unavailable, unknown)
    if not isinstance(identity, Mapping) or identity.get("tenantId") != tenant_id:
        return result("unknown", "DEPLOYMENT_PROFILE_SCOPE_MISMATCH", "The deployment profile is not bound to the authenticated tenant.", unknown=required)
    profile = identity.get("deploymentProfile")
    if profile is None:
        return result("unknown", "DEPLOYMENT_PROFILE_REQUIRED", "The platform has not exposed a deployment profile for this company.", unknown=required)
    if not isinstance(profile, Mapping) or profile.get("schema") != DEPLOYMENT_PROFILE_SCHEMA:
        return result("unknown", "DEPLOYMENT_PROFILE_INVALID", "The platform deployment profile is invalid or unsupported.", unknown=required)
    if profile.get("tenantId") != tenant_id or profile.get("companyId") != company_id:
        return result("unknown", "DEPLOYMENT_PROFILE_SCOPE_MISMATCH", "The deployment profile does not match the selected tenant and company.", unknown=required)
    tier = profile.get("tier")
    tier = tier.strip().lower() if isinstance(tier, str) else None
    if tier not in TIER_CAPABILITIES:
        return result("unknown", "DEPLOYMENT_TIER_UNKNOWN", "The deployment tier is unknown; no service availability was assumed.", unknown=required)
    excluded = tuple(s for s in required if not TIER_CAPABILITIES[tier][s])
    if excluded:
        return result("unavailable", "NOT_AVAILABLE_ON_LITE", "Not available on Lite: " + ", ".join(excluded) + ".", tier, excluded)
    services = profile.get("services")
    if not isinstance(services, Mapping):
        services = {}
    unavailable = tuple(s for s in required if services.get(s) is False)
    unknown = tuple(s for s in required if type(services.get(s)) is not bool)
    if unavailable:
        return result("unavailable", "SERVICE_UNAVAILABLE", "The platform reports unavailable services: " + ", ".join(unavailable) + ".", tier, unavailable, unknown)
    if unknown:
        return result("unknown", "SERVICE_STATUS_UNKNOWN", "The platform has not confirmed services: " + ", ".join(unknown) + ".", tier, unknown=unknown)
    return result("available", "AVAILABLE", "Deployment prerequisites are present; platform authorization and capacity checks still apply.", tier)


__all__ = ["DeploymentAvailability", "TIER_CAPABILITIES", "deployment_availability"]

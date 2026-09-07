"""Host bindings for recurring, governed company observations.

These bindings are deployment/operator configuration. They contain exact
connector account references and provider query parameters, never credentials.
Spring remains the execution authority for every resulting request.
"""
from datetime import timedelta
import re
from typing import Any, Literal
from pydantic import Field, model_validator
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, seal, stable_digest
from lightbulb.company_observation_jobs import ObservationJob, lane_for

SOURCES = {
    "channel_spend": {"google_ads.get_metrics", "meta_ads.get_insights"},
    "marketing_touches": {"posthog.query_events"},
    "local_profile": {"gbp.get_location"},
    "local_verification": {"gbp.get_voice_of_merchant_state"},
    "local_performance": {"gbp.get_location_performance"},
    "content_observation": {"search_console.query_analytics"},
    "customer_cohort": {"shopify.analytics_query"},
}

class RecurringObservationBinding(StrictModel):
    source_ref: OpaqueRef
    kind: Literal["channel_spend", "marketing_touches", "local_profile", "local_verification", "local_performance", "content_observation", "customer_cohort"]
    tool: str
    connector_account_ref: OpaqueRef
    arguments: dict[str, Any] = Field(default_factory=dict)
    target_entity_ref: OpaqueRef | None = None
    centre_ref: OpaqueRef | None = None
    demand_registry_ref: OpaqueRef | None = None
    pacing_controls: dict[str,dict[str,Any]] = Field(default_factory=dict)
    channel: str | None = None
    event_bindings: dict[str, dict[str, Any]] = Field(default_factory=dict)
    identity_links: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def exact(self):
        if self.tool not in SOURCES[self.kind] or lane_for(self.tool) != "governed_read":
            raise ValueError("OBSERVATION_SOURCE_NOT_GOVERNED")
        from lightbulb.observation_runtime import _assert_no_secret_keys
        _assert_no_secret_keys(self.arguments)
        _assert_no_secret_keys(self.pacing_controls)
        if self.kind == "channel_spend":
            expected = {"google_ads.get_metrics":"paid_search_google", "meta_ads.get_insights":"paid_social_meta"}[self.tool]
            if self.channel != expected or not self.target_entity_ref or not self.centre_ref:
                raise ValueError("SPEND_DESTINATION_REQUIRED")
        if self.kind in {"local_profile", "local_verification", "local_performance", "content_observation"} and not self.target_entity_ref:
            raise ValueError("OBSERVATION_DESTINATION_REQUIRED")
        if self.kind == "marketing_touches" and (not self.event_bindings or not self.arguments.get("event")):
            raise ValueError("TOUCH_EVENT_POLICY_REQUIRED")
        return self

    def job(self, *, start: str, end: str) -> ObservationJob:
        # Provider daily reports have inclusive calendar end dates. The SDK
        # contract is always half-open UTC; never include a partial day.
        if self.kind in {"channel_spend", "local_performance", "content_observation"}:
            if any(parsed(t).hour or parsed(t).minute or parsed(t).second or parsed(t).microsecond for t in (start,end)):
                raise ValueError("OBSERVATION_REQUIRES_CLOSED_UTC_DAYS")
        arguments = dict(self.arguments)
        if self.tool == "google_ads.get_metrics":
            if arguments.get("segment", "campaign_daily") != "campaign_daily":
                raise ValueError("GOOGLE_SPEND_SEGMENT_INVALID")
            arguments["segment"] = "campaign_daily"
        if self.tool == "meta_ads.get_insights":
            arguments.setdefault("level", "campaign")
            arguments.setdefault("attribution", "unified")
        if self.kind in {"channel_spend", "local_performance", "content_observation"}:
            arguments.update(window_start=parsed(start).date().isoformat(), window_end=(parsed(end)-timedelta(days=1)).date().isoformat())
        elif self.kind == "marketing_touches":
            project = arguments.get("project_id")
            if type(project) not in (str, int) or re.fullmatch(r"[0-9]{1,12}", str(project)) is None:
                raise ValueError("TOUCH_PROVIDER_PROJECT_REQUIRED")
            # The registered Tool requires a decimal string even when the host
            # configuration uses the provider dashboard's numeric project ID.
            arguments.update(project_id=str(project), after=start, before=end, limit=100)
        elif self.kind == "customer_cohort":
            # The registered ShopifyQL query is host-owned and must declare
            # its exact acquisition bounds, checked again after normalization.
            arguments.update(target_metric="new_customer_cohort", window_start=start, window_end=end)
        engine = {"channel_spend":"company_cost_centres", "marketing_touches":"conversion_attribution",
                  "local_profile":"local_presence_engine", "local_verification":"local_presence_engine", "local_performance":"local_presence_engine",
                  "content_observation":"content_asset_lifecycle", "customer_cohort":"growth_period_fold"}[self.kind]
        identity = stable_digest({"binding":self.to_dict(),"start":start,"end":end})
        return seal(ObservationJob, {"job_ref":"recurring-"+identity, "kind":"recurring_observation", "engine":engine,
            "event":self.kind, "tool":self.tool, "lane":"governed_read", "adapter":self.kind,
            "arguments":arguments, "adapter_inputs":{"binding":self.to_dict()}, "window_start":start,"window_end":end,
            "summary":f"Read and ingest {self.kind} for configured source {self.source_ref}"}, "job_digest")
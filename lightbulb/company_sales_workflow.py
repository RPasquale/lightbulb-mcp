"""Read-only handoffs over the existing sales host and pipeline lifecycle.

These instructions are evidence requirements, not commands or execution grants.
They never infer reply intent, a deal win, or revenue from a sent message.
"""
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class _Handoff:
    action: str
    owner: str
    required_evidence: tuple[str, ...]
    automatic: bool = False


def sales_workflow_handoff(*, prospect_status, status, reason, active_proposal, sequence_complete, purpose="sales"):
    """Project a next step; an unresolved proposal takes precedence over selling."""
    if active_proposal:
        # The real endpoint includes normal source-state descriptions in reason.
        # They are not holds; unknown descriptions still require review.
        normal_reason = reason in {None, "communication_source_ready_proposal", "communication_source_available",
            "communication_source_viewed", "communication_source_approved", "communication_source_dispatch_claimed",
            "communication_source_dispatching"}
        if not normal_reason or status in {"blocked", "stopped"}:
            handoff = _Handoff("reconcile_delivery", "communication_runtime",
                               ("original_proposal", "canonical_delivery_outcome"))
        elif status == "pending_approval":
            handoff = _Handoff("review_exact_proposal", "human_reviewer",
                               ("current_approval_preview", "independent_approval_decision"))
        else:
            handoff = _Handoff("observe_delivery", "company_worker",
                               ("canonical_delivery_outcome",), True)
    elif prospect_status in {"suppressed", "lost", "disqualified"}:
        handoff = _Handoff("closed", "operator", ("reviewed_new_intake_before_any_new_outreach",))
    elif reason == "SALES_BILLING_NATIVE_OWNED":
        handoff = _Handoff("observe_invoice", "billing_runtime", ("fresh_complete_invoice_observation",))
    elif purpose == "billing_recovery" and (reason in {"SALES_THREAD_REPLY", "SALES_BILLING_STOPPED"}
            or prospect_status in {"replied", "qualified", "meeting_booked", "handed_off"}):
        handoff = _Handoff("review_billing_case", "finance_agent",
                           ("fresh_complete_invoice_observation", "reviewed_customer_response_or_stop_reason"))
    elif reason and reason != "SALES_THREAD_REPLY":
        handoff = _Handoff("review_hold", "operator", ("resolved_hold", "current_permission"))
    elif prospect_status == "handed_off":
        handoff = _Handoff("track_deal_outcome", "crm_agent",
                           ("actual_deal_outcome", "separate_payment_evidence_before_counting_revenue"))
    elif prospect_status == "meeting_booked":
        handoff = _Handoff("hand_off_deal", "crm_agent", ("actual_crm_deal_reference",))
    elif prospect_status == "qualified":
        handoff = _Handoff("arrange_meeting", "crm_agent",
                           ("customer_agreed_time", "governed_calendar_execution", "actual_meeting_reference"))
    elif prospect_status == "replied":
        handoff = _Handoff("qualify_reply", "crm_agent", ("reviewed_reply", "complete_qualification_rubric"))
    elif reason == "SALES_THREAD_REPLY":
        handoff = _Handoff("review_reply", "crm_agent", ("fresh_governed_thread_read", "reviewed_reply_classification"))
    elif status in {"blocked", "stopped"}:
        handoff = _Handoff("review_hold", "operator", ("resolved_hold", "current_permission"))
    elif prospect_status is None:
        handoff = _Handoff("review_intake", "operator", ("reviewed_intake_candidate", "current_permission"))
    elif sequence_complete:
        handoff = _Handoff("review_sequence_outcome", "crm_agent", ("fresh_governed_thread_read", "reviewed_disposition"))
    elif prospect_status in {"sequenced", "engaged"}:
        handoff = _Handoff("evaluate_next_touch", "company_worker",
                           ("current_permission", "fresh_thread_read", "spacing_and_caps", "exact_approval"), True)
    else:
        handoff = _Handoff("complete_intake", "operator", ("reviewed_facts", "reviewed_sequence"))
    return {**asdict(handoff), "execution_authorized": False}

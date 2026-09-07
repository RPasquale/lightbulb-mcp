"""Lazy beta contracts for the production-dark finance lighthouse.

The curated journey covers journal controls, preparation, governed write
results, independent readback reconciliation, and a bounded period-close
proposal. Provider-backed effects remain quarantined until Spring admits and
certifies the exact capability version.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lightbulb.finance_accounting import (
        AccountingPeriodContext,
        CompanyAccountingContext,
        EvaluateJournalEntryControlsPrimitive,
        JournalEntryControlEvaluation,
        JournalEntryControlInput,
        JournalEntryLine,
        evaluate_journal_entry_controls,
    )
    from lightbulb.finance_close_lifecycle import (
        PeriodCloseLifecycleInput,
        PeriodCloseLifecycleResult,
        PeriodCloseScope,
        PeriodCloseTransitionCommand,
        PeriodCloseTransitionReceipt,
        ProposePeriodCloseTransitionPrimitive,
        materialize_period_close_candidate,
    )
    from lightbulb.finance_journal_lifecycle import (
        GovernedJournalWriteResult,
        GovernedLedgerReadReceipt,
        JournalEntryPreparation,
        JournalPostReadback,
        PostJournalEntryInput,
        PostJournalEntryPrimitive,
        PostJournalEntryResult,
        PrepareJournalEntryInput,
        PrepareJournalEntryPrimitive,
        ReconcileJournalPostInput,
        ReconcileJournalPostPrimitive,
        ReconcileJournalPostResult,
        prepare_journal_entry,
        reconcile_journal_post,
    )


_ACCOUNTING_MODULE = "lightbulb.finance_accounting"
_JOURNAL_MODULE = "lightbulb.finance_journal_lifecycle"
_CLOSE_MODULE = "lightbulb.finance_close_lifecycle"

_EXPORTS: dict[str, tuple[str, str]] = {
    "CompanyAccountingContext": (_ACCOUNTING_MODULE, "CompanyAccountingContext"),
    "AccountingPeriodContext": (_ACCOUNTING_MODULE, "AccountingPeriodContext"),
    "JournalEntryLine": (_ACCOUNTING_MODULE, "JournalEntryLine"),
    "JournalEntryControlInput": (_ACCOUNTING_MODULE, "JournalEntryControlInput"),
    "JournalEntryControlEvaluation": (
        _ACCOUNTING_MODULE,
        "JournalEntryControlEvaluation",
    ),
    "EvaluateJournalEntryControlsPrimitive": (
        _ACCOUNTING_MODULE,
        "EvaluateJournalEntryControlsPrimitive",
    ),
    "evaluate_journal_entry_controls": (
        _ACCOUNTING_MODULE,
        "evaluate_journal_entry_controls",
    ),
    "GovernedLedgerReadReceipt": (_JOURNAL_MODULE, "GovernedLedgerReadReceipt"),
    "GovernedJournalWriteResult": (_JOURNAL_MODULE, "GovernedJournalWriteResult"),
    "PrepareJournalEntryInput": (_JOURNAL_MODULE, "PrepareJournalEntryInput"),
    "JournalEntryPreparation": (_JOURNAL_MODULE, "JournalEntryPreparation"),
    "PostJournalEntryInput": (_JOURNAL_MODULE, "PostJournalEntryInput"),
    "PostJournalEntryResult": (_JOURNAL_MODULE, "PostJournalEntryResult"),
    "JournalPostReadback": (_JOURNAL_MODULE, "JournalPostReadback"),
    "ReconcileJournalPostInput": (_JOURNAL_MODULE, "ReconcileJournalPostInput"),
    "ReconcileJournalPostResult": (_JOURNAL_MODULE, "ReconcileJournalPostResult"),
    "PrepareJournalEntryPrimitive": (_JOURNAL_MODULE, "PrepareJournalEntryPrimitive"),
    "PostJournalEntryPrimitive": (_JOURNAL_MODULE, "PostJournalEntryPrimitive"),
    "ReconcileJournalPostPrimitive": (
        _JOURNAL_MODULE,
        "ReconcileJournalPostPrimitive",
    ),
    "prepare_journal_entry": (_JOURNAL_MODULE, "prepare_journal_entry"),
    "reconcile_journal_post": (_JOURNAL_MODULE, "reconcile_journal_post"),
    "PeriodCloseScope": (_CLOSE_MODULE, "PeriodCloseScope"),
    "PeriodCloseTransitionCommand": (_CLOSE_MODULE, "PeriodCloseTransitionCommand"),
    "PeriodCloseLifecycleInput": (_CLOSE_MODULE, "PeriodCloseLifecycleInput"),
    "PeriodCloseLifecycleResult": (_CLOSE_MODULE, "PeriodCloseLifecycleResult"),
    "PeriodCloseTransitionReceipt": (
        _CLOSE_MODULE,
        "PeriodCloseTransitionReceipt",
    ),
    "ProposePeriodCloseTransitionPrimitive": (
        _CLOSE_MODULE,
        "ProposePeriodCloseTransitionPrimitive",
    ),
    "materialize_period_close_candidate": (
        _CLOSE_MODULE,
        "materialize_period_close_candidate",
    ),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Resolve a declared finance-lighthouse contract on first access."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))

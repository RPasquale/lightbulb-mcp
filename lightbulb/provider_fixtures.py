"""The recorded provider corpus: fixture pages shaped exactly like the platform's reads, with their digests pinned.

Until the live run yields real recordings, every observer and read the
platform admits has one fixture here shaped to its documented contract:
the QuickBooks invoice, payment, bill, and bill-payment pages the observers
read; the evidence outputs those observers emit; the Stripe settlement
observation; the Airwallex, bill.com, GitHub, PostHog, and Xero pages the
treasury, SaaS, and compliance loops consume; the Gmail send receipt.

``load_fixture`` returns a fixture by name and refuses one whose digest has
drifted from the manifest, so a fixture cannot change without the manifest
changing with it.  The Spring side keeps a byte-identical copy under its
test resources and asserts the same digests, which is what makes the corpus
a contract between the two sides rather than a convenience.  Nothing here
touches a provider.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from typing import Any

from lightbulb.company_engine_core import stable_digest

FIXTURE_PACKAGE = "lightbulb.data.provider_fixtures"
CORPUS_SCHEMA = "lightbulb.provider_fixture_corpus.v1"

# name -> (file, the tool whose contract the fixture follows, the schema or provider shape it carries)
FIXTURE_INDEX: dict[str, dict[str, str]] = {
    "quickbooks.invoice_page": {"file": "quickbooks_invoice_page.json", "tool": "quickbooks.list_invoices", "shape": "QueryResponse.Invoice"},
    "quickbooks.payment_page": {"file": "quickbooks_payment_page.json", "tool": "quickbooks.list_payments", "shape": "QueryResponse.Payment"},
    "quickbooks.bill_page": {"file": "quickbooks_bill_page.json", "tool": "quickbooks.list_bills", "shape": "QueryResponse.Bill"},
    "quickbooks.bill_payment_page": {"file": "quickbooks_bill_payment_page.json", "tool": "quickbooks.observe_bill_payment_applied", "shape": "QueryResponse.BillPayment"},
    "quickbooks.invoice_issued_observation": {"file": "quickbooks_invoice_issued_observation.json", "tool": "quickbooks.observe_invoice_issued", "shape": "lightbulb.quickbooks_invoice_issued_observation.v1"},
    "quickbooks.invoice_payment_observation": {"file": "quickbooks_invoice_payment_observation.json", "tool": "quickbooks.observe_invoice_payment_applied", "shape": "lightbulb.quickbooks_invoice_payment_observation.v1"},
    "quickbooks.bill_payment_observation": {"file": "quickbooks_bill_payment_observation.json", "tool": "quickbooks.observe_bill_payment_applied", "shape": "lightbulb.quickbooks_bill_payment_observation.v1"},
    "stripe.cash_settlement_observation": {"file": "stripe_cash_settlement_observation.json", "tool": "stripe.observe_cash_settlement", "shape": "lightbulb.stripe_cash_settlement_observation.v1"},
    "stripe.account_readiness_observation": {"file": "stripe_account_readiness_observation.json", "tool": "stripe.observe_account_readiness", "shape": "lightbulb.stripe_account_readiness_observation.v1"},
    "stripe.invoice_list": {"file": "stripe_invoice_list.json", "tool": "stripe.list_invoices", "shape": "list.invoice"},
    "airwallex.balances": {"file": "airwallex_balances.json", "tool": "airwallex.list_balances", "shape": "items[balance]"},
    "airwallex.transactions": {"file": "airwallex_transactions.json", "tool": "airwallex.list_transactions", "shape": "items[financial_transaction]"},
    "airwallex.global_account_observation": {"file": "airwallex_global_account_observation.json", "tool": "airwallex.get_global_account", "shape": "lightbulb.airwallex_global_account_observation.v1"},
    "billcom.bill_list": {"file": "billcom_bill_list.json", "tool": "billcom.list_bills", "shape": "response_data[Bill]"},
    "github.deployment_page": {"file": "github_deployment_page.json", "tool": "github.list_deployments", "shape": "lightbulb.github_deployment_page.v1"},
    "posthog.event_page": {"file": "posthog_event_page.json", "tool": "posthog.query_events", "shape": "lightbulb.posthog_event_page.v1"},
    "search_console.organic_observation": {"file": "search_console_organic_observation.json", "tool": "search_console.query_analytics", "shape": "lightbulb.search_console_organic_observation.v1"},
    "anthropic_admin.cost_observation": {"file": "inference_cost_observation_anthropic.json", "tool": "anthropic_admin.get_cost_report", "shape": "lightbulb.inference_cost_observation.v1"},
    "openai_admin.cost_observation": {"file": "inference_cost_observation_openai.json", "tool": "openai_admin.get_costs", "shape": "lightbulb.inference_cost_observation.v1"},
    "xero.bas_report": {"file": "xero_bas_report.json", "tool": "xero.bas_report", "shape": "Reports[Rows]"},
    "xero.payrun_observation": {"file": "xero_payrun_observation.json", "tool": "xero.observe_payrun", "shape": "lightbulb.xero_payrun_observation.v1"},
    "xero.timesheet_page": {"file": "xero_timesheet_page.json", "tool": "xero.observe_timesheets", "shape": "lightbulb.xero_timesheet_page.v1"},
    "xero.leave_page": {"file": "xero_leave_page.json", "tool": "xero.observe_leave", "shape": "lightbulb.xero_leave_page.v1"},
    "xero.headcount_page": {"file": "xero_headcount_page.json", "tool": "xero.observe_headcount", "shape": "lightbulb.xero_headcount_page.v1"},
    "xero.quote_observation": {"file": "xero_quote_observation.json", "tool": "xero.observe_quote", "shape": "lightbulb.xero_quote_observation.v1"},
    "square.booking_page": {"file": "square_booking_page.json", "tool": "square.observe_bookings", "shape": "lightbulb.square_booking_page.v1"},
    "square.invoice_payment_observation": {"file": "square_invoice_payment_observation.json", "tool": "square.observe_invoice_payment", "shape": "lightbulb.square_invoice_payment_observation.v1"},
    "gmail.send_receipt": {"file": "gmail_send_receipt.json", "tool": "gmail.send_email", "shape": "id+threadId(+labelIds)"},
    "docusign.envelope_observation": {"file": "docusign_envelope_observation.json", "tool": "docusign.observe_envelope_status", "shape": "lightbulb.docusign_envelope_observation.v1"},
    "square.location_page": {"file": "square_location_page.json", "tool": "square.observe_locations", "shape": "lightbulb.square_location_page.v1"},
    "platform.provisioning_receipt_stripe": {"file": "company_provisioning_receipt_stripe.json", "tool": "company_provisioning.stripe_connect_account", "shape": "lightbulb.company_provisioning_receipt.v1"},
    "platform.provisioning_receipt_site": {"file": "company_provisioning_receipt_site.json", "tool": "company_provisioning.site", "shape": "lightbulb.company_provisioning_receipt.v1"},
    "platform.provisioning_receipt_phone": {"file": "company_provisioning_receipt_phone.json", "tool": "company_provisioning.phone_number", "shape": "lightbulb.company_provisioning_receipt.v1"},
}

# Pinned canonical digests; regenerate with ``python -m lightbulb.provider_fixtures`` after an intentional change.
FIXTURE_DIGESTS: dict[str, str] = {
    "quickbooks.invoice_page": "b97325017308de05e4d91dc004e6d44aef57a07cfc6d38e3b0eb083e8a9c8600",
    "quickbooks.payment_page": "db508b07511efc134a8fc72dff81eb9dfe67058f03ddd24519ebe843755a65ed",
    "quickbooks.bill_page": "c08381c58373e94846aba0be2935f92be6ce5361a58273791794fe32621cf9ae",
    "quickbooks.bill_payment_page": "0192f07105edafa0053f36319614032c35f052a6378e7a6d8f99aebca1c62306",
    "quickbooks.invoice_issued_observation": "77ec187278a72bd86334038a2316b2bec8ec54902d93d15a47ed22a9c045a494",
    "quickbooks.invoice_payment_observation": "49ea6c2c22607a030475c0f8c36fdc41b23d9d6858a2cdf7671771923b27b737",
    "quickbooks.bill_payment_observation": "477af4b5c372ab103055d6c3ea0e9dd0d4fd5b82da8f6759d88d4b43a60a92b5",
    "stripe.cash_settlement_observation": "b2424be6a3c5e3dafd9319becdd7f2d23dddaf72a4d84048ce7b5a34d769c71e",
    "stripe.account_readiness_observation": "40b6deed7dd8e030bdefae48ef2c5a647976ad9b93d52e8b23914d5c5e23772c",
    "stripe.invoice_list": "42d9c61dbff2d0b2519acb06b80ab028abdabe343258d46798394969860f56eb",
    "airwallex.balances": "ae45a216f06ceabd9a81dea22c22229b733cd67a2db1e70722ac222b3acaab15",
    "airwallex.transactions": "9d8d1e62da1eedd36754497f387a9126a249ec4a3a25f70dc1b1a9349363555a",
    "airwallex.global_account_observation": "5fb03ce5b7ce87c07c6686d6f9302ea3aed0a4323f069354c845b97e129d43db",
    "billcom.bill_list": "e3a88eaedf66ce620a57c63cdfd1b6316a88a62b6b63d389653ecb3ca41b4683",
    "github.deployment_page": "54bdc574070d9987252777c5021804d3c4ee75f90dec161ce95285d221ee52cb",
    "posthog.event_page": "d39b3a29569aae54b1db0268c6246e16e229da078fc2491d58d3851ae676f9ef",
    "search_console.organic_observation": "7576e0c2d448a3d6029ef04b45201321d6904b064806878a320892692d7d58a6",
    "anthropic_admin.cost_observation": "e65382d9aef91fa9a71a18e88f0463b7729c62f0c1797946c9874b5d8a7d06f8",
    "openai_admin.cost_observation": "99dfc22e954b029e591f2eb56eb061af4fd10ebd1cacac5d685bfcdcb6e7fb2f",
    "xero.bas_report": "4645e9e1b13af4dd8208a846c5dd8cf15a3ee357453b8d233c81735c5197160f",
    "xero.payrun_observation": "28acd2b7b29551acb40068bfa73226f4db1cd59ac3768fda28e43b5c468c30b6",
    "xero.timesheet_page": "ea0193ba9c087d7334e7d06b5e3649b2710962b27c8cefa29136d3a5767aa9d5",
    "xero.leave_page": "2fb282a1143c95cf0861c2aa61bf2a226f9f63598d00ee63741eee4befe78d64",
    "xero.headcount_page": "821d86240d275615911aa102bf9ba2c92b6db8cf36b9cb4f451016a527fe0909",
    "xero.quote_observation": "2d63da4fa5e0b71357f1c0c4ce017ac5a58dbb9cf066eb032e8e09943afc7ba8",
    "square.booking_page": "1da44a83fd66cdb958ab6442013737fe7f4a03519b0e18bf3e4334cef51dc343",
    "square.invoice_payment_observation": "4242611e2dc496425110c9066714cc607f1c9c388758ad8bb6ea68dd47ff32de",
    "gmail.send_receipt": "c5408b73a2b9a8d9263c017acabf59664550bcf7eed27cc1d80eb268b73c5888",
    "docusign.envelope_observation": "5bf86ab90ad5c7c5a10c87bb1e462117ae24d7203262b0c55907e7d2aaa658ad",
    "square.location_page": "4599be5f1e27b3ebab25c6ad60699799cda126d7cec74aded29d37ab9cd6d00f",
    "platform.provisioning_receipt_stripe": "8c80382b403816e4eeec0e56ceda90414acda40e17ed5171c6dd9bf8de24f0bb",
    "platform.provisioning_receipt_site": "bdc357548d4ccecbbed438271793de401781d8cc799ff392541f5cd5cfec0930",
    "platform.provisioning_receipt_phone": "5c2819a28585190c67c51611c2d4efc8f2902b04e599854c2441802489b58f9c",
}


class FixtureDrift(ValueError):
    pass


def _read(name: str) -> dict[str, Any]:
    entry = FIXTURE_INDEX.get(name)
    if entry is None:
        raise KeyError(f"unknown fixture {name!r}; known: {sorted(FIXTURE_INDEX)}")
    text = resources.files(FIXTURE_PACKAGE).joinpath(entry["file"]).read_text(encoding="utf-8")
    return json.loads(text)


def fixture_digest(name: str) -> str:
    return stable_digest(_read(name))


def load_fixture(name: str, *, verify: bool = True) -> dict[str, Any]:
    """The fixture document; refused when its digest is not the pinned one."""

    document = _read(name)
    if verify and FIXTURE_DIGESTS:
        expected = FIXTURE_DIGESTS.get(name)
        actual = stable_digest(document)
        if expected is None or expected != actual:
            raise FixtureDrift(f"fixture {name} digest {actual[:16]} is not the pinned {str(expected)[:16]}; update FIXTURE_DIGESTS deliberately")
    return document


def corpus_manifest() -> dict[str, Any]:
    entries = {name: {**entry, "digest": fixture_digest(name)} for name, entry in FIXTURE_INDEX.items()}
    return {"schema": CORPUS_SCHEMA, "fixtures": entries, "corpus_digest": stable_digest({name: item["digest"] for name, item in entries.items()})}


def provenance_for(name: str, *, lane: str = "governed_read", completed_at: str = "2026-09-03T12:00:00Z") -> Mapping[str, Any]:
    """An ``ObservationProvenance`` document for the fixture, so adapters can be exercised exactly as on a real read."""

    entry = FIXTURE_INDEX[name]
    digest = fixture_digest(name)
    return {"lane": lane, "source_tool": entry["tool"], "observation_ref": f"fixture:{name}", "provenance_digest": stable_digest({"fixture": name, "digest": digest}), "output_digest": digest, "completed_at": completed_at}


def _main() -> int:
    manifest = corpus_manifest()
    lines = ["FIXTURE_DIGESTS: dict[str, str] = {"]
    for name, item in manifest["fixtures"].items():
        lines.append(f'    "{name}": "{item["digest"]}",')
    lines.append("}")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())


__all__ = ["CORPUS_SCHEMA", "FIXTURE_DIGESTS", "FIXTURE_INDEX", "FIXTURE_PACKAGE", "FixtureDrift", "corpus_manifest", "fixture_digest", "load_fixture", "provenance_for"]

"""Rule engine — six independent, explainable checks.

Every rule returns a list of Flag: which rule fired, a severity, and a
plain-language message saying WHY. There is deliberately no aggregate
"fraud score" — a score with no explanation gets ignored or, worse,
trusted blindly.

Contract: run analyze() BEFORE recording the invoice in history,
otherwise the duplicate check matches the invoice against itself.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date
from statistics import median, stdev

from .history import HistoryStore
from .schema import Invoice

# Tunables — per business in a later version.
LARGE_AMOUNT = 100_000     # "large" for new-vendor risk
ROUND_THRESHOLD = 50_000   # round-number scrutiny above this
MIN_HISTORY_FOR_STATS = 4
URGENCY = re.compile(
    r"\b(urgent|urgently|immediate|immediately|asap|today only|pay today|"
    r"wire transfer|tt transfer)\b", re.IGNORECASE)


@dataclass
class Flag:
    rule: str        # machine id, e.g. "bank_change"
    severity: str    # info | warning | high
    message: str     # plain language, names the reason
    details: dict


def fmt(amount: float, currency: str) -> str:
    if amount == int(amount):
        return f"{currency} {int(amount):,}"
    return f"{currency} {amount:,.2f}"


def check_duplicate(inv: Invoice, store: HistoryStore, business_id: str) -> list[Flag]:
    hit = store.find_duplicate(business_id, inv.vendor_name,
                               inv.invoice_number, inv.total)
    if not hit:
        return []
    return [Flag(
        "duplicate", "high",
        f"This invoice ({inv.invoice_number} for {fmt(inv.total, inv.currency)} "
        f"from {inv.vendor_name}) was already recorded on {hit['invoice_date']}. "
        "Paying it again would be a duplicate payment.",
        {"previous_date": hit["invoice_date"], "previous_row": hit["id"]})]


def check_bank_change(inv: Invoice, store: HistoryStore, business_id: str) -> list[Flag]:
    past = store.vendor_invoices(business_id, inv.vendor_name, limit=3)
    if not past:
        return []
    new_key = inv.bank.key()
    if not new_key.strip("|"):
        return []  # no bank details on this invoice — nothing to compare
    old_keys = {p["bank_key"] for p in past if p["bank_key"].strip("|")}
    if not old_keys or new_key in old_keys:
        return []
    return [Flag(
        "bank_change", "high",
        f"The bank account on this invoice differs from the last {len(past)} "
        f"invoice(s) from {inv.vendor_name}. Bank-detail swaps are a top "
        "invoice-fraud method — call the vendor on a number you already trust "
        "to confirm before paying.",
        {"previous_bank": json.loads(past[0]["bank_json"])})]


def check_math(inv: Invoice, store: HistoryStore, business_id: str) -> list[Flag]:
    if not inv.line_items:
        return []
    line_sum = sum(i.amount for i in inv.line_items)
    base = inv.subtotal if inv.subtotal is not None else line_sum
    expected = base + (inv.tax_amount or 0.0)
    diff = abs(expected - inv.total)
    if diff <= max(1.0, inv.total * 0.001):
        return []
    return [Flag(
        "math", "warning",
        f"The line items add up to {fmt(expected, inv.currency)} but the invoice "
        f"total says {fmt(inv.total, inv.currency)} "
        f"(difference {fmt(diff, inv.currency)}). Ask the vendor for a corrected invoice.",
        {"computed": round(expected, 2), "stated": inv.total,
         "difference": round(diff, 2)})]


def check_outlier(inv: Invoice, store: HistoryStore, business_id: str) -> list[Flag]:
    totals = [p["total"] for p in
              store.vendor_invoices(business_id, inv.vendor_name, limit=24)]
    flags: list[Flag] = []
    if len(totals) >= MIN_HISTORY_FOR_STATS:
        med = median(totals)
        sd = stdev(totals) if len(totals) > 1 else 0.0
        if inv.total > med + 3 * sd or (med > 0 and inv.total > 4 * med):
            flags.append(Flag(
                "outlier", "warning",
                f"{fmt(inv.total, inv.currency)} is far above {inv.vendor_name}'s "
                f"usual range (median {fmt(med, inv.currency)} over {len(totals)} "
                "invoices). Verify the amount with the vendor.",
                {"median": med, "stdev": round(sd, 2),
                 "history_count": len(totals)}))
    if inv.total >= ROUND_THRESHOLD and inv.total % 1000 == 0:
        flags.append(Flag(
            "round_number", "info",
            f"{fmt(inv.total, inv.currency)} is a round number. Round figures on "
            "large invoices are worth a second look — not proof of anything on "
            "their own.",
            {}))
    return flags


def check_new_vendor(inv: Invoice, store: HistoryStore, business_id: str) -> list[Flag]:
    if store.vendor_invoice_count(business_id, inv.vendor_name) > 0:
        return []
    reasons = []
    if inv.total >= LARGE_AMOUNT:
        reasons.append(f"large amount ({fmt(inv.total, inv.currency)})")
    if URGENCY.search(inv.notes or ""):
        reasons.append("urgent payment language")
    if not reasons:
        return []
    return [Flag(
        "new_vendor", "warning",
        f"First invoice from {inv.vendor_name}, requesting {' and '.join(reasons)}. "
        "Verify the vendor exists independently (call a known number, check their "
        "address) before paying.",
        {"reasons": reasons})]


def _signature(s: str) -> str:
    s = re.sub(r"\d", "#", s)
    return re.sub(r"[A-Za-z]", "A", s)


def check_pattern(inv: Invoice, store: HistoryStore, business_id: str) -> list[Flag]:
    flags: list[Flag] = []
    past = store.vendor_invoices(business_id, inv.vendor_name, limit=12)
    if len(past) >= 2:
        sigs = Counter(_signature(p["invoice_number"]) for p in past)
        usual, _ = sigs.most_common(1)[0]
        if _signature(inv.invoice_number) != usual:
            flags.append(Flag(
                "pattern", "info",
                f"Invoice number '{inv.invoice_number}' doesn't match "
                f"{inv.vendor_name}'s usual format (usually like "
                f"'{past[0]['invoice_number']}'). Could be a new billing system — "
                "or a forged invoice.",
                {"usual_example": past[0]["invoice_number"]}))
    try:
        d = date.fromisoformat(inv.invoice_date)
    except ValueError:
        return flags
    today = date.today()
    if d > today:
        flags.append(Flag(
            "pattern", "warning",
            f"This invoice is dated {inv.invoice_date}, in the future. "
            "Check the date with the vendor.",
            {}))
    elif (today - d).days > 730:
        flags.append(Flag(
            "pattern", "info",
            f"This invoice is dated {inv.invoice_date} (over 2 years old). Make "
            "sure it isn't a re-submitted old invoice.",
            {}))
    return flags


RULES = [check_duplicate, check_bank_change, check_math,
         check_outlier, check_new_vendor, check_pattern]


def analyze(data: dict, business_id: str, store: HistoryStore) -> dict:
    """Validate + run every rule. Returns flags, never a bare score."""
    inv = Invoice.from_dict(data)
    flags: list[Flag] = []
    for rule in RULES:
        flags.extend(rule(inv, store, business_id))
    order = {"info": 0, "warning": 1, "high": 2}
    severities = [f.severity for f in flags]
    return {
        "vendor": inv.vendor_name,
        "invoice_number": inv.invoice_number,
        "total": inv.total,
        "currency": inv.currency,
        "flags": [asdict(f) for f in flags],
        "flag_count": len(flags),
        "highest_severity": max(severities, key=lambda s: order[s])
        if severities else None,
    }

"""Rule engine tests — each rule independently testable, as designed."""
import unittest
from datetime import date, timedelta

from fraudcheck.history import HistoryStore
from fraudcheck.rules import analyze
from fraudcheck.schema import Invoice

BIZ = "test-biz"
BANK = {"account_name": "Himal Traders", "account_number": "1234-567890",
        "bank_name": "Nabil Bank", "branch": "Urlabari"}


def inv(vendor="Himal Traders", number="HT-999", inv_date="2026-09-01",
        total=47000.0, bank=None, items=None, notes="", **kw):
    d = {"vendor_name": vendor, "invoice_number": number,
         "invoice_date": inv_date, "currency": "NPR", "total": total,
         "bank": bank if bank is not None else dict(BANK), "notes": notes}
    d["line_items"] = items if items is not None else [
        {"description": "goods", "quantity": 1,
         "unit_price": total, "amount": total}]
    d.update(kw)
    return d


def seed_traders(store):
    """5 clean past invoices: HT-101..105, totals ~45-51k, same bank."""
    for num, day, total in [("HT-101", "2026-05-02", 45250.0),
                            ("HT-102", "2026-05-28", 48900.0),
                            ("HT-103", "2026-06-25", 47120.0),
                            ("HT-104", "2026-07-22", 51300.0),
                            ("HT-105", "2026-08-20", 46780.0)]:
        store.record_invoice(BIZ, Invoice.from_dict(inv(number=num,
                                                         inv_date=day,
                                                         total=total)))


def rules_of(result):
    return [f["rule"] for f in result["flags"]]


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.store = HistoryStore(":memory:")
        seed_traders(self.store)

    def test_clean_invoice_no_flags(self):
        r = analyze(inv(number="HT-106", inv_date="2026-09-15", total=47500.0),
                    BIZ, self.store)
        self.assertEqual(r["flags"], [])
        self.assertIsNone(r["highest_severity"])

    def test_duplicate_high(self):
        r = analyze(inv(number="HT-103", total=47120.0), BIZ, self.store)
        self.assertIn("duplicate", rules_of(r))
        f = next(f for f in r["flags"] if f["rule"] == "duplicate")
        self.assertEqual(f["severity"], "high")
        self.assertIn("HT-103", f["message"])
        self.assertEqual(r["highest_severity"], "high")

    def test_duplicate_tolerates_tiny_rounding(self):
        r = analyze(inv(number="ht-103", total=47121.0), BIZ, self.store)
        self.assertIn("duplicate", rules_of(r))

    def test_no_duplicate_for_new_number(self):
        r = analyze(inv(number="HT-106", total=47120.0), BIZ, self.store)
        self.assertNotIn("duplicate", rules_of(r))

    def test_bank_change_high(self):
        new_bank = dict(BANK, account_number="9999-888888")
        r = analyze(inv(number="HT-106", bank=new_bank), BIZ, self.store)
        self.assertIn("bank_change", rules_of(r))
        f = next(f for f in r["flags"] if f["rule"] == "bank_change")
        self.assertEqual(f["severity"], "high")
        self.assertIn("differs", f["message"])

    def test_bank_change_ignores_dash_spacing(self):
        same_bank = dict(BANK, account_number="1234 567890")
        r = analyze(inv(number="HT-106", bank=same_bank), BIZ, self.store)
        self.assertNotIn("bank_change", rules_of(r))

    def test_math_ok(self):
        r = analyze(inv(number="HT-106", total=46000.0, items=[
            {"description": "a", "quantity": 2, "unit_price": 20000, "amount": 40000},
            {"description": "b", "quantity": 1, "unit_price": 6000, "amount": 6000}],
            subtotal=46000.0), BIZ, self.store)
        self.assertNotIn("math", rules_of(r))

    def test_math_mismatch_warning(self):
        r = analyze(inv(number="HT-106", total=50000.0, items=[
            {"description": "a", "quantity": 2, "unit_price": 20000, "amount": 40000},
            {"description": "b", "quantity": 1, "unit_price": 6000, "amount": 6000}]),
            BIZ, self.store)
        self.assertIn("math", rules_of(r))
        f = next(f for f in r["flags"] if f["rule"] == "math")
        self.assertEqual(f["severity"], "warning")
        self.assertIn("4,000", f["message"].replace("4,000.0", "4,000"))

    def test_math_with_tax(self):
        r = analyze(inv(number="HT-106", total=52030.0, items=[
            {"description": "a", "quantity": 1, "unit_price": 46000, "amount": 46000}],
            subtotal=46000.0, tax_amount=6030.0), BIZ, self.store)
        self.assertNotIn("math", rules_of(r))

    def test_outlier_warning(self):
        r = analyze(inv(number="HT-106", total=487500.0), BIZ, self.store)
        self.assertIn("outlier", rules_of(r))
        f = next(f for f in r["flags"] if f["rule"] == "outlier")
        self.assertEqual(f["severity"], "warning")

    def test_round_number_info(self):
        r = analyze(inv(vendor="New Vendor Co", number="NV-1", total=100000.0),
                    BIZ, self.store)
        self.assertIn("round_number", rules_of(r))
        f = next(f for f in r["flags"] if f["rule"] == "round_number")
        self.assertEqual(f["severity"], "info")

    def test_new_vendor_large_warning(self):
        r = analyze(inv(vendor="Everest Supplies", number="ES-1", total=200000.0),
                    BIZ, self.store)
        self.assertIn("new_vendor", rules_of(r))
        f = next(f for f in r["flags"] if f["rule"] == "new_vendor")
        self.assertEqual(f["severity"], "warning")

    def test_new_vendor_urgent_warning(self):
        r = analyze(inv(vendor="Everest Supplies", number="ES-1", total=8000.0,
                        notes="URGENT: pay today via wire transfer"), BIZ, self.store)
        self.assertIn("new_vendor", rules_of(r))

    def test_new_vendor_small_quiet_no_flag(self):
        r = analyze(inv(vendor="Everest Supplies", number="ES-1", total=8000.0),
                    BIZ, self.store)
        self.assertNotIn("new_vendor", rules_of(r))

    def test_pattern_number_mismatch_info(self):
        r = analyze(inv(number="2026/9917", total=47000.0), BIZ, self.store)
        self.assertIn("pattern", rules_of(r))
        f = next(f for f in r["flags"] if f["rule"] == "pattern")
        self.assertEqual(f["severity"], "info")
        self.assertIn("HT-10", f["message"])

    def test_pattern_future_date_warning(self):
        future = (date.today() + timedelta(days=30)).isoformat()
        r = analyze(inv(number="HT-106", inv_date=future), BIZ, self.store)
        severities = [f["severity"] for f in r["flags"] if f["rule"] == "pattern"]
        self.assertIn("warning", severities)

    def test_schema_rejects_missing_total(self):
        d = inv()
        del d["total"]
        with self.assertRaises(ValueError):
            analyze(d, BIZ, self.store)

    def test_businesses_are_isolated(self):
        other = HistoryStore(":memory:")
        r = analyze(inv(number="HT-103", total=47120.0), "other-biz", other)
        self.assertNotIn("duplicate", rules_of(r))

    def test_analyze_before_record_contract(self):
        # analyzing then recording the same invoice must not self-flag
        data = inv(number="HT-106", total=47500.0)
        r1 = analyze(data, BIZ, self.store)
        self.assertNotIn("duplicate", rules_of(r1))
        self.store.record_invoice(BIZ, Invoice.from_dict(data))
        r2 = analyze(data, BIZ, self.store)
        self.assertIn("duplicate", rules_of(r2))


if __name__ == "__main__":
    unittest.main()

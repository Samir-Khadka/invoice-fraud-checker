"""Extraction accuracy harness.

1. Unit tests for each field parser on fixed OCR-like strings (always run).
2. Full pipeline test on synthetic invoice images (needs tesseract; skipped
   if the binary is missing). Reports per-field accuracy — the honest number
   for "how good is v1".

The synthetic set measures the CEILING (clean renders). Real phone photos
will score lower; the 50-real-invoice pilot is still required before launch.
"""
import json
import unittest
from pathlib import Path

from fraudcheck import extract as E

TMP = Path(__file__).parent / "tmp_synth"


def norm(s):
    return " ".join(str(s).split()).casefold()


class ParserTests(unittest.TestCase):
    def test_invoice_number(self):
        self.assertEqual(E.extract_invoice_number("Invoice No: HT-104\nDate: x"),
                         "HT-104")
        self.assertEqual(E.extract_invoice_number("INV/2026/9917"), "INV/2026/9917")
        self.assertIsNone(E.extract_invoice_number("no number here"))

    def test_date_iso(self):
        self.assertEqual(E.extract_date("Invoice Date: 2026-09-10"), "2026-09-10")

    def test_date_dmy(self):
        self.assertEqual(E.extract_date("Dated: 10/09/2026"), "2026-09-10")

    def test_date_rejects_impossible(self):
        self.assertIsNone(E.extract_date("version 1.2.3 released"))

    def test_totals(self):
        t = E.extract_totals("Subtotal: Rs. 46,000.00\nVAT (13%): Rs. 5,980.00\n"
                             "Grand Total: Rs. 51,980.00")
        self.assertAlmostEqual(t["total"], 51980.0)
        self.assertAlmostEqual(t["subtotal"], 46000.0)
        self.assertAlmostEqual(t["tax_amount"], 5980.0)

    def test_totals_ignores_subtotal_line(self):
        t = E.extract_totals("Subtotal: 46000\nTotal: 51980")
        self.assertAlmostEqual(t["total"], 51980.0)

    def test_bank(self):
        b = E.extract_bank("Bank: Nabil Bank\nA/C No: 1234-567890\nBranch: Urlabari")
        self.assertEqual(b["account_number"], "1234567890")
        self.assertEqual(b["bank_name"], "Nabil Bank")

    def test_bank_account_variants(self):
        b = E.extract_bank("Account Number: 1122 3344 55")
        self.assertEqual(b["account_number"], "1122334455")

    def test_vendor_skips_headers(self):
        v = E.extract_vendor("TAX INVOICE\nPAN: 123\nHimal Traders Pvt. Ltd.\nUrlabari")
        self.assertEqual(v, "Himal Traders Pvt. Ltd.")

    def test_currency(self):
        self.assertEqual(E.extract_currency("Total: Rs. 500"), "NPR")
        self.assertEqual(E.extract_currency("Total: $500"), "USD")

    def test_line_items(self):
        text = ("Description Qty Unit Price Amount\n"
                "Cement bags 50 900.00 45000.00\n"
                "Paint 4L 8 2400.00 19200.00\n"
                "Subtotal: Rs. 64,200.00")
        items = E.extract_line_items(text)
        self.assertEqual(len(items), 2)
        self.assertAlmostEqual(sum(i["amount"] for i in items), 64200.0)


def field_scores(truth, got):
    """Per-field 0/1 scores between ground truth and extracted dict."""
    s = {}
    s["invoice_number"] = int(norm(truth["invoice_number"]) == norm(got.get("invoice_number", "")))
    s["invoice_date"] = int(truth["invoice_date"] == got.get("invoice_date"))
    t, g = truth["total"], got.get("total")
    s["total"] = int(g is not None and abs(t - g) <= max(1.0, t * 0.01))
    if truth.get("subtotal"):
        g = got.get("subtotal")
        s["subtotal"] = int(g is not None and abs(truth["subtotal"] - g) <= max(1.0, truth["subtotal"] * 0.01))
    if truth.get("tax_amount"):
        g = got.get("tax_amount")
        s["tax_amount"] = int(g is not None and abs(truth["tax_amount"] - g) <= max(1.0, truth["tax_amount"] * 0.01))
    gv, ev = norm(truth["vendor_name"]), norm(got.get("vendor_name", ""))
    s["vendor"] = int(gv == ev or (gv and gv in ev) or (ev and ev in gv))
    s["bank_account"] = int(truth["bank"]["account_number"] ==
                            (got.get("bank") or {}).get("account_number", ""))
    gi = truth["line_items"]
    ei = got.get("line_items") or []
    s["line_item_count"] = int(len(gi) == len(ei))
    if ei:
        s["line_item_sum"] = int(abs(sum(i["amount"] for i in gi) -
                                     sum(i["amount"] for i in ei)) <= max(1.0, t * 0.01))
    else:
        s["line_item_sum"] = 0
    return s


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fraudcheck import ocr as O
        if not (O.tesseract_available() or O.rapidocr_available()):
            raise unittest.SkipTest("no OCR backend installed")

    def test_synthetic_set_accuracy(self):
        from fraudcheck import ocr as O
        from tests.synth import make_set
        pairs = make_set(TMP, n=12)
        agg, denom = {}, {}
        n = 0
        for png, truth in pairs:
            text = O.ocr_image(str(png))
            got = E.extract_fields(text)
            # must at least validate when the key fields land
            for field, score in field_scores(truth, got).items():
                agg[field] = agg.get(field, 0) + score
                denom[field] = denom.get(field, 0) + 1
            n += 1
        print("\n--- synthetic pipeline accuracy (n=12, clean renders) ---")
        for field in ["invoice_number", "invoice_date", "vendor", "total",
                      "subtotal", "tax_amount", "bank_account",
                      "line_item_count", "line_item_sum"]:
            if field in agg:
                d = denom[field]
                print(f"  {field:<16} {agg[field]}/{d} = {agg[field]/d:.0%}")
        # hard gates: the fields the fraud rules depend on most
        self.assertGreaterEqual(agg["invoice_number"] / denom["invoice_number"], 0.8,
                                "invoice_number accuracy below 80%")
        self.assertGreaterEqual(agg["total"] / denom["total"], 0.8,
                                "total accuracy below 80%")

    def test_end_to_end_extract_validate_analyze(self):
        """Image -> fields -> Invoice -> rules: the full v1 contract."""
        from fraudcheck import ocr as O
        from fraudcheck.history import HistoryStore
        from fraudcheck.rules import analyze
        from fraudcheck.schema import Invoice
        from tests.synth import make_set

        pairs = make_set(TMP, n=3, seed=99)
        store = HistoryStore(":memory:")
        for idx, (png, truth) in enumerate(pairs):
            data = E.extract_fields(O.ocr_image(str(png)))
            inv = Invoice.from_dict(data)  # must validate cleanly
            result = analyze(data, "e2e-biz", store)
            rules = [f["rule"] for f in result["flags"]]
            if idx == 1:
                # layout 2 carries an "URGENT: pay today" note: the note must
                # survive OCR -> extraction and trip the new-vendor rule
                self.assertIn("new_vendor", rules,
                              f"urgent note lost in pipeline for {png.name}")
            else:
                self.assertEqual(result["flags"], [],
                                 f"clean invoice {png.name} flagged: {result['flags']}")
            store.record_invoice("e2e-biz", inv)
        # now the same invoice twice -> duplicate must fire
        png, _ = pairs[0]
        data = E.extract_fields(O.ocr_image(str(png)))
        result = analyze(data, "e2e-biz", store)
        self.assertIn("duplicate", [f["rule"] for f in result["flags"]])


if __name__ == "__main__":
    unittest.main()

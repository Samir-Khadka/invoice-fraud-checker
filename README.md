# Invoice Fraud Checker

Small businesses without an accountant lose money to errors and fraud that
nobody catches: duplicate payments, inflated totals, math errors, and
**vendor bank-detail swaps** — when an attacker intercepts an invoice and
changes the payment account.

This tool takes an invoice, checks it against that business's own invoice
history, and returns **plain-language flags naming exactly what fired and why**
— never a bare "fraud score" nobody can act on.

## The six checks (v0.1)

| Rule | Severity | What it says |
|---|---|---|
| `duplicate` | high | Same invoice number + amount from this vendor was already recorded |
| `bank_change` | high | Bank account differs from the vendor's last 3 invoices |
| `math` | warning | Line items don't sum to the stated total |
| `outlier` | warning | Amount far outside this vendor's historical range |
| `round_number` | info | Large round-figure amount — worth a second look |
| `new_vendor` | warning | First invoice from a vendor + large amount or urgent language |
| `pattern` | info/warning | Unusual invoice-number format; future or very old date |

## Quickstart

```bash
python -m unittest discover -s tests   # 19 tests
python demo.py                          # watch it catch a swapped bank account
```

```python
from fraudcheck.history import HistoryStore
from fraudcheck.rules import analyze

store = HistoryStore("invoices.db")
result = analyze(invoice_dict, business_id="my-shop", store=store)
for flag in result["flags"]:
    print(flag["severity"], "-", flag["message"])
# ...human reviews the flags, THEN:
store.record_invoice("my-shop", Invoice.from_dict(invoice_dict))
```

**Contract:** run `analyze()` *before* `record_invoice()` — otherwise the
duplicate check matches the invoice against itself. Each business's history
is fully isolated by `business_id`.

## OCR extraction pipeline (v0.2)

`image -> fraudcheck/ocr.py -> fraudcheck/extract.py -> Invoice`

- **OCR backends:** Tesseract binary first (install: `apt install tesseract-ocr`,
  or the UB Mannheim build on Windows); falls back to RapidOCR
  (`pip install rapidocr_onnxruntime`) when tesseract is absent.
- **Field extraction** (`extract.py`) is heuristic and regex-based — every
  parser returns `None` when unsure instead of guessing. A wrong invoice
  number is worse than a missing one for fraud checks.
- **Measured accuracy** on 12 clean synthetic invoices
  (`tests/synth.py` renders them with known ground truth,
  `tests/test_extract.py` scores field-by-field):

  invoice_number / date / vendor / total / bank_account: **100%** ·
  subtotal / tax_amount: **100%** (of invoices that have them) ·
  line items: **100%** count and sums

- **Honest caveat:** synthetic renders are the *ceiling* — clean fonts, no
  skew, no shadows. Real phone photos will score lower. The spec's
  50-real-invoice pilot is still required before this touches real money;
  `tests/synth.py` + the harness give you the rig to run that pilot.

## Honest limits

- This is a **flagging tool, not an accountant.** It surfaces items for human
  review — it never auto-rejects or auto-pays. It doesn't replace professional
  accounting or tax advice.
- v0.1 is the schema + rule engine + history store (SQLite). OCR field
  extraction, Postgres, and a mobile/WhatsApp interface come next — in that
  order, after the extraction pipeline is tested against ~50 real invoices.

## Layout

- `fraudcheck/schema.py` — invoice data model + validation
- `fraudcheck/history.py` — per-business history (SQLite; narrow interface so
  Postgres can replace it later)
- `fraudcheck/rules.py` — the six rules + `analyze()`
- `fraudcheck/ocr.py` — OCR wrapper (Tesseract primary, RapidOCR fallback)
- `fraudcheck/extract.py` — heuristic field extraction from OCR text
- `tests/test_rules.py` — 19 tests, one fixture history, each rule tested alone
- `tests/test_extract.py` — 11 parser unit tests + 12-image pipeline accuracy
  harness + image-to-flag end-to-end test
- `tests/synth.py` — synthetic invoice renderer with ground truth (test rig)
- `demo.py` — end-to-end example

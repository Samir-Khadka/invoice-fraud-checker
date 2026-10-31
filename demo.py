"""Demo: seed a business history, then check a suspicious invoice.

Run:  python demo.py
"""
import json

from fraudcheck.history import HistoryStore
from fraudcheck.rules import analyze
from fraudcheck.schema import Invoice

BIZ = "demo-biz"
BANK = {"account_name": "Himal Traders", "account_number": "1234567890",
        "bank_name": "Nabil Bank", "branch": "Urlabari"}

store = HistoryStore(":memory:")
for num, day, total in [("HT-101", "2026-05-02", 45250.0),
                        ("HT-102", "2026-05-28", 48900.0),
                        ("HT-103", "2026-06-25", 47120.0)]:
    store.record_invoice(BIZ, Invoice.from_dict({
        "vendor_name": "Himal Traders", "invoice_number": num,
        "invoice_date": day, "total": total, "bank": dict(BANK),
        "line_items": [{"description": "goods", "quantity": 1,
                        "unit_price": total, "amount": total}]}))

# An intercepted invoice: same vendor, but the bank account was swapped
# and the line items don't add up.
suspect = {
    "vendor_name": "Himal Traders",
    "invoice_number": "HT-104",
    "invoice_date": "2026-09-10",
    "currency": "NPR",
    "total": 48000.0,
    "line_items": [
        {"description": "cement bags", "quantity": 100,
         "unit_price": 450, "amount": 45000},
    ],
    "bank": {"account_name": "Himal Traders", "account_number": "9876543210",
             "bank_name": "Nabil Bank", "branch": "Urlabari"},
    "notes": "urgent, pay today",
}

result = analyze(suspect, BIZ, store)
print(json.dumps(result, indent=2, ensure_ascii=False))

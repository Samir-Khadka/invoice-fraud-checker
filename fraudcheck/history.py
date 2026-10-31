"""Per-business invoice history.

SQLite for v1 (zero infra, tests run anywhere). The method surface is
deliberately narrow so it can be re-implemented on Postgres later
without touching the rules:
    record_invoice, vendor_invoices, find_duplicate, vendor_invoice_count

Every method is scoped by business_id — one business's history never
leaks into another's checks.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict

from .schema import Invoice

SCHEMA = """
CREATE TABLE IF NOT EXISTS invoices (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  business_id    TEXT NOT NULL,
  vendor_key     TEXT NOT NULL,   -- normalized vendor name (matching)
  vendor_name    TEXT NOT NULL,   -- display name as first seen
  invoice_number TEXT NOT NULL,
  invoice_date   TEXT NOT NULL,   -- ISO YYYY-MM-DD
  currency       TEXT NOT NULL DEFAULT 'NPR',
  subtotal       REAL,
  tax_amount     REAL,
  total          REAL NOT NULL,
  bank_key       TEXT NOT NULL DEFAULT '',
  bank_json      TEXT NOT NULL DEFAULT '{}',
  notes          TEXT NOT NULL DEFAULT '',
  raw_json       TEXT NOT NULL DEFAULT '{}',
  created_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_lookup
  ON invoices (business_id, vendor_key, invoice_date);
"""


class HistoryStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    @staticmethod
    def vendor_key(name: str) -> str:
        return " ".join(name.split()).casefold()

    def record_invoice(self, business_id: str, inv: Invoice) -> int:
        """Store an invoice AFTER it has been reviewed. Returns row id."""
        cur = self.db.execute(
            """INSERT INTO invoices
               (business_id, vendor_key, vendor_name, invoice_number, invoice_date,
                currency, subtotal, tax_amount, total, bank_key, bank_json,
                notes, raw_json, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (business_id, self.vendor_key(inv.vendor_name), inv.vendor_name,
             inv.invoice_number, inv.invoice_date, inv.currency,
             inv.subtotal, inv.tax_amount, inv.total, inv.bank.key(),
             json.dumps(asdict(inv.bank)), inv.notes,
             json.dumps(asdict(inv), default=str), time.time()),
        )
        self.db.commit()
        return cur.lastrowid

    def vendor_invoices(self, business_id: str, vendor_name: str,
                        limit: int = 50) -> list[dict]:
        """Newest first."""
        rows = self.db.execute(
            """SELECT * FROM invoices
               WHERE business_id = ? AND vendor_key = ?
               ORDER BY invoice_date DESC, id DESC LIMIT ?""",
            (business_id, self.vendor_key(vendor_name), limit)).fetchall()
        return [dict(r) for r in rows]

    def vendor_invoice_count(self, business_id: str, vendor_name: str) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) c FROM invoices WHERE business_id = ? AND vendor_key = ?",
            (business_id, self.vendor_key(vendor_name))).fetchone()
        return row["c"]

    def find_duplicate(self, business_id: str, vendor_name: str,
                       invoice_number: str, total: float) -> dict | None:
        """Same vendor + invoice number + (near-)same total seen before."""
        tol = max(1.0, abs(total) * 0.001)
        row = self.db.execute(
            """SELECT * FROM invoices
               WHERE business_id = ?
                 AND vendor_key = ?
                 AND TRIM(LOWER(invoice_number)) = TRIM(LOWER(?))
                 AND ABS(total - ?) <= ?
               ORDER BY id DESC LIMIT 1""",
            (business_id, self.vendor_key(vendor_name),
             invoice_number.strip(), total, tol)).fetchone()
        return dict(row) if row else None

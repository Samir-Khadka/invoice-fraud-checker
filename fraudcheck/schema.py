"""Invoice schema for the Fraud Checker.

Invoices come in as plain dicts (from OCR, a form, or a bot) and are
validated into dataclasses. The rules only ever read these objects,
so the OCR layer can be swapped without touching detection logic.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BankDetails:
    account_name: str = ""
    account_number: str = ""
    bank_name: str = ""
    branch: str = ""

    @staticmethod
    def normalize_acct(raw: str) -> str:
        """Digits only — spaces/dashes in account numbers are noise."""
        return "".join(ch for ch in (raw or "") if ch.isdigit())

    def key(self) -> str:
        """Identity used for bank-change detection."""
        return (f"{self.normalize_acct(self.account_number)}"
                f"|{self.bank_name.strip().casefold()}")


@dataclass
class LineItem:
    description: str = ""
    quantity: float = 0.0
    unit_price: float = 0.0
    amount: float = 0.0  # as stated on the invoice


@dataclass
class Invoice:
    vendor_name: str
    invoice_number: str
    invoice_date: str          # ISO YYYY-MM-DD
    currency: str = "NPR"
    line_items: list[LineItem] = field(default_factory=list)
    subtotal: float | None = None
    tax_amount: float | None = None
    total: float = 0.0
    bank: BankDetails = field(default_factory=BankDetails)
    notes: str = ""            # free text — scanned for urgency language

    @staticmethod
    def _num(value, field_name: str) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            raise ValueError(f"invoice field '{field_name}' must be a number, "
                             f"got {value!r}")

    @classmethod
    def from_dict(cls, d: dict) -> "Invoice":
        if not isinstance(d, dict):
            raise ValueError("invoice must be a dict")
        for req in ("vendor_name", "invoice_number", "invoice_date", "total"):
            if req not in d or d[req] in (None, ""):
                raise ValueError(f"invoice is missing required field '{req}'")

        items = []
        for i, li in enumerate(d.get("line_items") or []):
            if not isinstance(li, dict):
                raise ValueError(f"line_items[{i}] must be a dict")
            items.append(LineItem(
                description=str(li.get("description", "")),
                quantity=cls._num(li.get("quantity", 0), f"line_items[{i}].quantity"),
                unit_price=cls._num(li.get("unit_price", 0), f"line_items[{i}].unit_price"),
                amount=cls._num(li.get("amount", 0), f"line_items[{i}].amount"),
            ))

        bank = d.get("bank") or {}
        if not isinstance(bank, dict):
            raise ValueError("invoice field 'bank' must be a dict")

        subtotal = d.get("subtotal")
        tax = d.get("tax_amount")
        return cls(
            vendor_name=str(d["vendor_name"]).strip(),
            invoice_number=str(d["invoice_number"]).strip(),
            invoice_date=str(d["invoice_date"]).strip(),
            currency=str(d.get("currency", "NPR")).strip() or "NPR",
            line_items=items,
            subtotal=cls._num(subtotal, "subtotal") if subtotal is not None else None,
            tax_amount=cls._num(tax, "tax_amount") if tax is not None else None,
            total=cls._num(d["total"], "total"),
            bank=BankDetails(
                account_name=str(bank.get("account_name", "")),
                account_number=str(bank.get("account_number", "")),
                bank_name=str(bank.get("bank_name", "")),
                branch=str(bank.get("branch", "")),
            ),
            notes=str(d.get("notes", "")),
        )

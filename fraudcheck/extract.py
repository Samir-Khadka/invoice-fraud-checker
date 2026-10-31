"""Field extraction: OCR text -> invoice dict.

Heuristic, regex-based v1 — explainable and testable. Every parser returns
None when unsure rather than guessing; the accuracy harness
(tests/test_extract.py) measures exactly how unsure it is.

Pipeline: image -> ocr.py (text) -> extract_fields(text) -> Invoice.from_dict
"""
from __future__ import annotations

import re

# (regex pattern, display name) — patterns match inside longer names too.
NEPAL_BANKS = [
    (r"nabil\s+bank", "Nabil Bank"),
    (r"nic\s+asia", "NIC Asia"),
    (r"himalayan\s+bank", "Himalayan Bank"),
    (r"everest\s+bank", "Everest Bank"),
    (r"kumari\s+bank", "Kumari Bank"),
    (r"prabhu\s+bank", "Prabhu Bank"),
    (r"global\s+ime\s+bank", "Global IME Bank"),
    (r"\bnmb\s+bank", "NMB Bank"),
    (r"siddhartha\s+bank", "Siddhartha Bank"),
    (r"machhapuchchhre\s+bank", "Machhapuchchhre Bank"),
    (r"sanima\s+bank", "Sanima Bank"),
    (r"citizens\s+bank", "Citizens Bank"),
    (r"prime\s+commercial\s+bank", "Prime Commercial Bank"),
    (r"rastriya\s+banijya\s+bank", "Rastriya Banijya Bank"),
    (r"nepal\s+bank", "Nepal Bank"),
    (r"laxmi\s+sunrise", "Laxmi Sunrise"),
]

CURRENCY_WORDS = {"rs": "NPR", "rs.": "NPR", "npr": "NPR", "re": "NPR",
                  "usd": "USD", "$": "USD", "inr": "INR", "₹": "INR"}


def _amount(raw: str) -> float | None:
    """'47,120.00' / 'Rs 47120' / 'Rs. 5,980.00' -> float; None if unparseable."""
    if not raw:
        return None
    s = re.sub(r"(?i)^(rs\.?|npr|usd|inr|₹|\$)\s*", "", raw.strip())
    s = s.split()[0] if " " in s else s
    cleaned = re.sub(r"[^\d.]", "", s)
    # guard against version-like "1.2.3" or lone dots
    if cleaned.count(".") > 1 or not re.search(r"\d", cleaned):
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def _first(pattern: str, text: str, flags=re.IGNORECASE) -> re.Match | None:
    return re.search(pattern, text, flags)


def extract_invoice_number(text: str) -> str | None:
    # NOTE: the separator after the label is [ \t:]* — deliberately NOT \s,
    # so "TAX INVOICE\\nHimal Traders" can't match with capture "Himal".
    # A missed number (None) beats a wrong number for fraud checks.
    m = _first(
        r"\b(?:invoice[ \t]+(?:no\.?|number|#)|invoice[ \t]*:|"
        r"inv[ \t]*(?:no\.?|#|:)|bill[ \t]*(?:no\.?|number|:))"
        r"[ \t:]*([A-Za-z0-9][A-Za-z0-9\-/]{1,24})", text)
    if m:
        return m.group(1).strip(" -/:")
    # standalone PREFIX/number style with no label, e.g. INV/2026/9917
    m = _first(r"\b([A-Za-z]{2,5}/\d[A-Za-z0-9\-/]{1,20})", text)
    if m:
        return m.group(1)
    return None


def _to_iso(y: str, m_: str, d: str) -> str | None:
    try:
        y, m_, d = int(y), int(m_), int(d)
    except ValueError:
        return None
    if not (2000 <= y <= 2100 and 1 <= m_ <= 12 and 1 <= d <= 31):
        return None
    return f"{y:04d}-{m_:02d}-{d:02d}"


def extract_date(text: str) -> str | None:
    # labeled first: "Invoice Date: 2026-09-10"
    m = _first(
        r"(?:invoice\s*date|date\s*(?:of\s*)?(?:issue|issued)|dated|bill\s*date)"
        r"[\s:]*(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{4})", text)
    candidates = [m.group(1)] if m else []
    # then any plausible date
    for pat in (r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})",
                r"(\d{1,2})[-/](\d{1,2})[-/](\d{4})"):
        for mm in re.finditer(pat, text):
            candidates.append("-".join(mm.groups()))
    for c in candidates:
        parts = re.split(r"[-/]", c)
        iso = (_to_iso(*parts) if len(parts[0]) == 4
               else _to_iso(parts[2], parts[1], parts[0]))
        if iso:
            return iso
    return None


def _money_near(label_pat: str, text: str) -> float | None:
    m = _first(label_pat + r"[\s:]*((?:rs\.?|npr|usd|\$)?\s*[\d,]+(?:\.\d{1,2})?)",
               text)
    if not m:
        return None
    return _amount(re.sub(r"(?i)^(rs\.?|npr|usd|\$)\s*", "", m.group(1)))


def extract_totals(text: str) -> dict:
    out: dict = {}
    # grand total / net payable / amount due — but not subtotal
    for line in text.splitlines():
        low = line.lower()
        if "subtotal" in low or "sub total" in low:
            continue
        m = re.search(
            r"(?:grand\s+total|net\s+(?:total|payable)|amount\s+(?:due|payable)|"
            r"total\s+amount|balance\s+due)\b[\s:]*"
            r"((?:rs\.?|npr|usd|\$)?\s*[\d,]+(?:\.\d{1,2})?)", line,
            re.IGNORECASE)
        if m:
            v = _amount(m.group(1))
            if v is not None:
                out["total"] = v
                break
    if "total" not in out:
        # fallback: a line that is just "Total: X"
        v = _money_near(r"(?<![a-z])total(?![a-z])", text)
        if v is not None:
            out["total"] = v
    sub = _money_near(r"sub\s*total", text)
    if sub is not None:
        out["subtotal"] = sub
    # tax: only from a line that also mentions 13% or a currency — this keeps
    # "VAT: 987654321" (a PAN/VAT registration number) from matching.
    for line in text.splitlines():
        low = line.lower()
        if re.search(r"\b(vat|tax)\b", low) and re.search(r"13\s*%|rs\.?|npr", low):
            m = re.search(r"((?:rs\.?|npr)?\s*[\d,]+(?:\.\d{1,2})?)\s*$", line,
                          re.IGNORECASE)
            if m:
                v = _amount(m.group(1))
                if v is not None and v != out.get("subtotal"):
                    out["tax_amount"] = v
                    break
    return out


def extract_bank(text: str) -> dict:
    out: dict = {}
    m = _first(
        r"(?:a/?c\s*(?:no\.?|number)?|account\s*(?:no\.?|number)?)"
        r"[\s:]*([\d][\d\s\-]{5,20}\d)", text)
    if m:
        out["account_number"] = re.sub(r"\D", "", m.group(1))
    low = text.lower()
    for pattern, display in NEPAL_BANKS:
        if re.search(pattern, low):
            out["bank_name"] = display
            break
    m = _first(r"account\s*(?:name|holder|title)[\s:]*([A-Za-z][A-Za-z .&]{2,40})",
               text)
    if m:
        out["account_name"] = m.group(1).strip()
    return out


def extract_vendor(text: str) -> str | None:
    skip = re.compile(
        r"tax\s*invoice|taxinvoice|^invoice$|^\s*inv\s|\bpan\b|\bvat\b|"
        r"^\s*original|duplicate|for\s+(?:customer|recipient)",
        re.IGNORECASE)
    for line in text.splitlines():
        s = line.strip(" |-\t")
        if len(s) < 3 or skip.search(s):
            continue
        if re.fullmatch(r"[\d\s\-/.,:]+", s):
            continue
        if not re.search(r"[A-Za-z\u0900-\u097F]", s):
            continue
        return s[:80]
    return None


def extract_currency(text: str) -> str:
    # \b fails around "$", so use lookarounds; "$" needs a digit after it.
    m = re.search(r"(?<!\w)(rs\.?|npr|usd|inr|₹)(?!\w)|\$(?=\s*\d)",
                  text, re.IGNORECASE)
    if m:
        return CURRENCY_WORDS.get(m.group(0).lower(), "NPR")
    return "NPR"


HEADER_WORDS = {"description", "descriptions", "particulars", "item", "items",
                "qty", "quantity", "unit price", "price", "rate", "amount"}

FOOTER_PAT = re.compile(
    r"sub\s*total|grand\s+total|\bvat\b|\btax\b|^bank\s*:|a/?c\s*(no|number)",
    re.IGNORECASE)

NUM_LINE = re.compile(r"^[\d\s,.]+$")


def _emit(desc, nums):
    if not nums or nums[-1] <= 0:
        return None
    if len(nums) >= 3:
        qty, unit, amount = nums[0], nums[-2], nums[-1]
    elif len(nums) == 2:
        qty, unit, amount = 1.0, nums[0], nums[1]
    else:
        qty, unit, amount = 1.0, nums[0], nums[0]
    return {"description": (desc or "item")[:60], "quantity": qty,
            "unit_price": unit, "amount": amount}


def extract_line_items(text: str) -> list[dict]:
    """Best-effort table parsing, two OCR layouts:

    - single-line rows:  "Cement bags  50  900.00  45000.00"
    - split rows (RapidOCR/PaddleOCR style): description on its own line,
      then qty / unit-price / amount on following lines.

    Honest limits: merged columns and wrapped descriptions defeat this;
    the harness measures it per-invoice.
    """
    items = []
    in_table = False
    desc, nums = None, []
    for raw in text.splitlines():
        line = raw.strip(" |-\t")
        low = line.lower()
        if not in_table:
            if "description" in low or "particulars" in low:
                in_table = True
            continue
        if not line:
            continue
        if FOOTER_PAT.search(line):
            break
        if low in HEADER_WORDS:
            continue
        if NUM_LINE.match(line) and re.search(r"\d", line):
            v = _amount(line)
            if v is not None:
                nums.append(v)
            continue
        # single-line row? (2+ numbers on one line)
        found = re.findall(r"[\d,]+(?:\.\d{1,2})?", line)
        if len(found) >= 2:
            if desc and nums:
                item = _emit(desc, nums)
                if item:
                    items.append(item)
            vals = [_amount(n) for n in found]
            if all(v is not None for v in vals):
                d = re.sub(r"[\d,.\s]+$", "", line).strip(" |-")
                item = _emit(d, vals)
                if item:
                    items.append(item)
                desc, nums = None, []
                continue
        # text line -> starts (or continues) a description
        if re.search(r"[A-Za-z\u0900-\u097F]", line):
            if desc and nums:
                item = _emit(desc, nums)
                if item:
                    items.append(item)
                nums = []
            desc = (desc + " " + line).strip() if desc else line
    if desc and nums:
        item = _emit(desc, nums)
        if item:
            items.append(item)
    return items


def extract_fields(text: str) -> dict:
    """OCR text -> invoice dict (may be partial; Invoice.from_dict validates)."""
    d: dict = {"currency": extract_currency(text)}
    num = extract_invoice_number(text)
    if num:
        d["invoice_number"] = num
    dt = extract_date(text)
    if dt:
        d["invoice_date"] = dt
    vendor = extract_vendor(text)
    if vendor:
        d["vendor_name"] = vendor
    d.update(extract_totals(text))
    bank = extract_bank(text)
    if bank:
        d["bank"] = bank
    items = extract_line_items(text)
    if items:
        d["line_items"] = items
    notes_m = _first(r"(urgent|pay today|asap)", text)
    if notes_m:
        d["notes"] = notes_m.group(0)
    return d

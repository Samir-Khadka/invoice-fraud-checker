"""Synthetic invoice image generator (PIL) for pipeline testing.

Renders clean invoice pages with KNOWN ground truth, so the OCR +
extraction pipeline can be scored without waiting on 50 real invoices.
Real photos will be noisier — these measure the ceiling, not the floor.
"""
import json
import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 1500
MARGIN = 90


def font(size):
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # very old Pillow
        return ImageFont.load_default()


VENDORS = [
    ("Himal Traders Pvt. Ltd.", "Urlabari, Morang", "PAN: 123456789"),
    ("Everest Suppliers", "Biratnagar", "VAT: 987654321"),
    ("Koshi Hardware Store", "Damak, Jhapa", "PAN: 555666777"),
]

BANKS = [
    ("Nabil Bank", "1234567890", "Urlabari Branch"),
    ("NIC Asia Bank", "1122334455", "Biratnagar"),
    ("Global IME Bank", "9988776655", "Damak"),
]


def render(inv: dict, path: Path):
    """inv: dict with vendor lines, number, date, items[(desc, qty, price)],
    tax_rate, bank tuple, notes. Writes PNG, returns ground-truth dict."""
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    f_title, f_big, f_med, f_small = font(44), font(34), font(28), font(24)
    y = MARGIN

    def line(text, f=f_med, gap=44, bold=False):
        nonlocal y
        d.text((MARGIN, y), text, fill="black", font=f)
        y += gap

    line("TAX INVOICE", f_title, 70)
    for vline in inv["vendor_lines"]:
        line(vline, f_big, 48)
    y += 10
    line(f"Invoice No: {inv['number']}", gap=44)
    line(f"Invoice Date: {inv['date']}", gap=44)
    y += 20
    line("Description            Qty      Unit Price      Amount", f_small, 40)
    line("-" * 62, f_small, 36)
    gt_items = []
    for desc, qty, price in inv["items"]:
        amt = round(qty * price, 2)
        gt_items.append({"description": desc, "quantity": qty,
                         "unit_price": price, "amount": amt})
        line(f"{desc:<22} {qty:>5}    {price:>10.2f}    {amt:>10.2f}",
             f_small, 38)
    y += 10
    subtotal = round(sum(i["amount"] for i in gt_items), 2)
    tax = round(subtotal * inv["tax_rate"], 2)
    total = round(subtotal + tax, 2)
    if inv["tax_rate"]:
        line(f"Subtotal: Rs. {subtotal:,.2f}", gap=44)
        line(f"VAT (13%): Rs. {tax:,.2f}", gap=44)
    line(f"Grand Total: Rs. {total:,.2f}", f_big, 60)
    y += 10
    bank_name, acct, branch = inv["bank"]
    line(f"Bank: {bank_name}", f_small, 38)
    line(f"A/C No: {acct}", f_small, 38)
    line(f"Branch: {branch}", f_small, 38)
    if inv.get("notes"):
        y += 10
        line(inv["notes"], f_small, 38)

    img.save(path)
    return {
        "vendor_name": inv["vendor_lines"][0],
        "invoice_number": inv["number"],
        "invoice_date": inv["date"],
        "currency": "NPR",
        "line_items": gt_items,
        "subtotal": subtotal if inv["tax_rate"] else None,
        "tax_amount": tax if inv["tax_rate"] else None,
        "total": total,
        "bank": {"account_name": "", "account_number": acct,
                 "bank_name": bank_name, "branch": branch},
    }


LAYOUTS = [
    # (number-style, tax?, bank idx, notes)
    ("HT-####", 0.13, 0, ""),
    ("INV/####", 0.13, 1, "URGENT: pay today"),
    ("####", 0.0, 2, ""),
]


def make_set(outdir: Path, n: int = 12, seed: int = 7):
    """Render n invoices across layout variants. Returns [(png, truth)]."""
    rng = random.Random(seed)
    outdir.mkdir(parents=True, exist_ok=True)
    items_pool = [("Cement bags", 50, 900), ("Steel rod kg", 120, 95),
                  ("Paint 4L", 8, 2400), ("Pipes 2in", 30, 450),
                  ("Bricks", 2000, 18), ("Sand cubic ft", 100, 85)]
    out = []
    for i in range(n):
        num_style, tax_rate, bank_idx, notes = LAYOUTS[i % len(LAYOUTS)]
        number = num_style.replace("####", f"{1000 + i * 7}")
        vendor = VENDORS[i % len(VENDORS)]
        items = rng.sample(items_pool, k=3)
        inv = {
            "vendor_lines": list(vendor),
            "number": number,
            "date": f"2026-{rng.randint(1, 9):02d}-{rng.randint(1, 28):02d}",
            "items": items,
            "tax_rate": tax_rate,
            "bank": BANKS[bank_idx],
            "notes": notes,
        }
        png = outdir / f"inv_{i:02d}.png"
        truth = render(inv, png)
        (outdir / f"inv_{i:02d}.json").write_text(
            json.dumps(truth, ensure_ascii=False, indent=1))
        out.append((png, truth))
    return out

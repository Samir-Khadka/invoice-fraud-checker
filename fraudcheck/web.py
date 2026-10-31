"""Invoice Fraud Checker web app (v0.3) — mobile-first upload and review.

Journey: pick a business name -> photograph/upload an invoice -> OCR +
extract -> see plain-language flags -> human reviews -> save to history.

Run:  uvicorn fraudcheck.web:app --host 127.0.0.1 --port 8000

v1 notes: no login — the business name scopes the history (cookie).
Meant for one small business per deployment, or local use.
"""
from __future__ import annotations

import html
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import Cookie, FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from .history import HistoryStore
from .rules import analyze
from .schema import Invoice

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
UPLOADS = DATA / "uploads"
DB = DATA / "invoices.db"
MAX_BYTES = 10 * 1024 * 1024
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".bmp"}

# token -> extracted invoice dict, awaiting human review (in-memory, v1)
PENDING: dict[str, dict] = {}

app = FastAPI(title="Invoice Fraud Checker")


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.strip().casefold()).strip("-")
    return s[:40] or "default"


SEV_STYLE = {
    "high": ("#b3261e", "#fdecea", "High"),
    "warning": ("#8a5a00", "#fff4d6", "Warning"),
    "info": ("#1a56db", "#e8effd", "Info"),
}

CSS = """
:root{--bg:#faf6ed;--ink:#2b2620;--card:#ffffff;--line:#e8dfcc;--violet:#5b4b8a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;line-height:1.5}
.wrap{max-width:640px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:1.4rem;margin:.2em 0}.sub{color:#6b6156;margin-top:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:18px;margin:14px 0;box-shadow:0 1px 3px rgba(60,45,20,.06)}
label{display:block;font-weight:600;margin:.6em 0 .3em}
input[type=text],input[type=file]{width:100%;padding:12px;border:1px solid var(--line);
border-radius:10px;font-size:1rem;background:#fffdf8}
button,.btn{display:inline-block;background:var(--violet);color:#fff;border:0;
border-radius:10px;padding:13px 22px;font-size:1rem;font-weight:600;cursor:pointer;
text-decoration:none;margin-top:12px}
button.secondary{background:#fff;color:var(--violet);border:1px solid var(--violet)}
.flag{border-left:5px solid;padding:12px 14px;border-radius:0 10px 10px 0;margin:10px 0}
.flag .sev{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.flag p{margin:.3em 0 0}
.kv{display:grid;grid-template-columns:130px 1fr;gap:4px 10px;font-size:.95rem}
.kv dt{color:#6b6156}.kv dd{margin:0;font-weight:600}
.ok{background:#e9f7ee;border:1px solid #bfe6cc;border-radius:10px;padding:14px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
.note{font-size:.85rem;color:#6b6156}
"""


def page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang='en-GB'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{esc(title)} — Invoice Fraud Checker</title>"
            f"<style>{CSS}</style></head><body><div class='wrap'>"
            f"<h1>🧾 Invoice Fraud Checker</h1>{body}</div></body></html>")


def store() -> HistoryStore:
    DATA.mkdir(parents=True, exist_ok=True)
    return HistoryStore(str(DB))


@app.get("/", response_class=HTMLResponse)
def index(business: str | None = Cookie(default=None)):
    biz = esc(business or "")
    return page("Check an invoice", f"""
<p class='sub'>Photograph or upload an invoice. We'll read it and flag
anything that looks off — <b>you</b> decide what to do.</p>
<div class='card'><form action='/check' method='post' enctype='multipart/form-data'>
<label for='business'>Business name</label>
<input type='text' id='business' name='business' value='{biz}' required
  placeholder='e.g. Himal Traders' autocomplete='organization'>
<label for='invoice'>Invoice photo or scan</label>
<input type='file' id='invoice' name='invoice' accept='image/*' required>
<button type='submit'>Check invoice</button>
</form></div>
<p class='note'><a href='/history'>View saved history</a> · Flags are a second
pair of eyes, not an accountant. Nothing is auto-rejected or auto-paid.</p>""")


@app.post("/check", response_class=HTMLResponse)
async def check(business: str = Form(...),
                invoice: UploadFile = File(...)):
    biz = slugify(business)
    ext = Path(invoice.filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        return page("Unsupported file", f"""
<div class='card'><p>Sorry — <b>{esc(ext or '(no extension)')}</b> isn't a
supported image type. Please upload a PNG, JPG, WEBP, TIFF or BMP photo.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""")
    raw = await invoice.read()
    if len(raw) > MAX_BYTES:
        return page("File too large", """
<div class='card'><p>That file is over 10&nbsp;MB. Please use a smaller photo.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""")
    UPLOADS.mkdir(parents=True, exist_ok=True)
    fname = f"{int(time.time())}_{secrets.token_hex(6)}{ext}"
    (UPLOADS / fname).write_bytes(raw)

    from .ocr import pipeline as ocr_pipeline
    try:
        data = ocr_pipeline(str(UPLOADS / fname))
    except Exception as e:  # OCR backend missing etc. — say so plainly
        return page("Couldn't read it", f"""
<div class='card'><p>We couldn't read that image ({esc(str(e)[:120])}).
Try a straighter, better-lit photo.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""")

    try:
        inv = Invoice.from_dict(data)
    except ValueError as e:
        missing = esc(str(e))
        return page("Missing details", f"""
<div class='card'><p>We read the photo but couldn't find: <b>{missing}</b>.</p>
<p class='note'>Tip: make sure the vendor name, invoice number, date and total
are clearly visible.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""")

    result = analyze(data, biz, store())
    token = secrets.token_hex(12)
    PENDING[token] = {"business": business.strip(), "biz": biz, "data": data}

    fields = f"""
<dl class='kv'>
<dt>Vendor</dt><dd>{esc(inv.vendor_name)}</dd>
<dt>Invoice no.</dt><dd>{esc(inv.invoice_number)}</dd>
<dt>Date</dt><dd>{esc(inv.invoice_date)}</dd>
<dt>Total</dt><dd>{esc(inv.currency)} {inv.total:,.2f}</dd>
</dl>"""
    if result["flags"]:
        flag_html = ""
        for f in result["flags"]:
            colour, bg, label = SEV_STYLE[f["severity"]]
            flag_html += (f"<div class='flag' style='border-color:{colour};"
                          f"background:{bg}'><span class='sev' "
                          f"style='color:{colour}'>{label} · {esc(f['rule'])}</span>"
                          f"<p>{esc(f['message'])}</p></div>")
        verdict = (f"<h2>⚠️ {result['flag_count']} thing(s) to review</h2>"
                   f"{flag_html}")
    else:
        verdict = ("<div class='ok'><b>✓ Nothing flagged.</b> This invoice looks "
                   "consistent with the business's history.</div>")

    body = f"""
<p class='sub'>Results for <b>{esc(business.strip())}</b> — reviewed by you, not us.</p>
<div class='card'><h2>What we read</h2>{fields}
<p class='note'>If anything above is misread, retake the photo — don't save it.</p></div>
<div class='card'>{verdict}</div>
<div class='card'><h2>Save to history?</h2>
<p class='note'>Only save invoices you've reviewed and accept. Saved invoices
become the history future checks compare against.</p>
<form action='/record' method='post'>
<input type='hidden' name='token' value='{token}'>
<button type='submit'>Looks right — save to history</button>
<a class='btn secondary' href='/'>Discard</a>
</form></div>"""
    resp = HTMLResponse(page("Results", body))
    resp.set_cookie("business", business.strip(), max_age=365 * 24 * 3600)
    return resp


@app.post("/record", response_class=HTMLResponse)
def record(token: str = Form(...)):
    pending = PENDING.pop(token, None)
    if not pending:
        return page("Expired", """
<div class='card'><p>That review has expired or was already saved.</p>
<p><a class='btn' href='/'>Check another invoice</a></p></div>""")
    inv = Invoice.from_dict(pending["data"])
    store().record_invoice(pending["biz"], inv)
    return page("Saved", f"""
<div class='card'><div class='ok'><b>✓ Saved.</b> Invoice
<b>{esc(inv.invoice_number)}</b> ({esc(inv.currency)} {inv.total:,.2f}) is now
part of <b>{esc(pending['business'])}</b>'s history.</div>
<p><a class='btn' href='/'>Check another invoice</a> ·
<a href='/history'>View history</a></p></div>""")


@app.get("/history", response_class=HTMLResponse)
def history(business: str | None = Cookie(default=None)):
    biz = slugify(business or "")
    if not DB.exists():
        rows = []
    else:
        con = sqlite3.connect(DB)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT vendor_name, invoice_number, invoice_date, currency, total,"
            " created_at FROM invoices WHERE business_id=? ORDER BY id DESC LIMIT 100",
            (biz,)).fetchall()
        con.close()
    if rows:
        trs = "".join(
            f"<tr><td>{esc(r['invoice_date'])}</td><td>{esc(r['vendor_name'])}</td>"
            f"<td>{esc(r['invoice_number'])}</td>"
            f"<td>{esc(r['currency'])} {r['total']:,.2f}</td></tr>" for r in rows)
        table = f"<table><tr><th>Date</th><th>Vendor</th><th>No.</th><th>Total</th></tr>{trs}</table>"
    else:
        table = "<p class='note'>No invoices saved yet for this business.</p>"
    return page("History", f"""
<p class='sub'>Saved invoices for <b>{esc(business or '—')}</b>.</p>
<div class='card'>{table}</div>
<p><a class='btn secondary' href='/'>Back</a></p>""")

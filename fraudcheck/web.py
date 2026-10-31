"""Invoice Fraud Checker web app — upload, check, review, save. With login.

Roles:
- admin: sees every business, manages users (create / disable / delete /
  reset password) at /admin.
- user: scoped to their own business only.

First run: visit /setup to create the admin account. After that /setup
is disabled.

Run:  uvicorn fraudcheck.web:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from .auth import AuthStore, valid_username
from .history import HistoryStore
from .rules import analyze
from .schema import Invoice

ROOT = Path(__file__).resolve().parent.parent
# IFC_DATA_DIR overrides the data dir (e.g. /tmp on Vercel serverless,
# where the filesystem is ephemeral — history resets on cold starts).
DATA = Path(os.environ.get("IFC_DATA_DIR", ROOT / "data"))
UPLOADS = DATA / "uploads"
DB = DATA / "invoices.db"
MAX_BYTES = 10 * 1024 * 1024
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".bmp"}

# Review tokens are stateless: the extracted invoice is JSON-serialised into
# a hidden form field, HMAC-signed with IFC_SECRET. No server-side session
# state, so /check -> /record works across serverless instances. Set
# IFC_SECRET as an env var in production; unset = a per-process secret
# (fine locally, may flake under multi-instance load).
IFC_SECRET = os.environ.get("IFC_SECRET", secrets.token_hex(32))

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
.topbar{display:flex;justify-content:space-between;align-items:center;
font-size:.85rem;color:#6b6156;margin-bottom:6px}
.topbar a{color:var(--violet)}
h1{font-size:1.4rem;margin:.2em 0}.sub{color:#6b6156;margin-top:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:18px;margin:14px 0;box-shadow:0 1px 3px rgba(60,45,20,.06)}
label{display:block;font-weight:600;margin:.6em 0 .3em}
input[type=text],input[type=password],select{width:100%;padding:12px;
border:1px solid var(--line);border-radius:10px;font-size:1rem;background:#fffdf8}
input[type=file]{width:100%;padding:12px;font-size:1rem}
button,.btn{display:inline-block;background:var(--violet);color:#fff;border:0;
border-radius:10px;padding:13px 22px;font-size:1rem;font-weight:600;cursor:pointer;
text-decoration:none;margin-top:12px}
button.secondary,.btn.secondary{background:#fff;color:var(--violet);
border:1px solid var(--violet)}
button.danger{background:#b3261e}
button.small,.btn.small{padding:8px 14px;font-size:.85rem}
.flag{border-left:5px solid;padding:12px 14px;border-radius:0 10px 10px 0;margin:10px 0}
.flag .sev{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.flag p{margin:.3em 0 0}
.kv{display:grid;grid-template-columns:130px 1fr;gap:4px 10px;font-size:.95rem}
.kv dt{color:#6b6156}.kv dd{margin:0;font-weight:600}
.ok{background:#e9f7ee;border:1px solid #bfe6cc;border-radius:10px;padding:14px}
.err{background:#fdecea;border:1px solid #f5c6c0;border-radius:10px;padding:14px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
.note{font-size:.85rem;color:#6b6156}
.inline{display:inline}.inline button{margin:0 4px 0 0}
.badge{display:inline-block;font-size:.72rem;font-weight:700;border-radius:20px;
padding:2px 10px;background:#ece5f5;color:var(--violet)}
"""


def _sign_data(data: dict) -> str:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    sig = hmac.new(IFC_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(raw).decode() + "." + sig


def _unsign_data(token: str) -> dict | None:
    try:
        payload, sig = token.rsplit(".", 1)
        raw = base64.urlsafe_b64decode(payload.encode())
    except Exception:
        return None
    expect = hmac.new(IFC_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None
    try:
        data = json.loads(raw.decode())
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def page(title: str, body: str, user: dict | None = None) -> str:
    if user:
        admin_link = (f" · <a href='/admin'>Admin</a>"
                      if user["role"] == "admin" else "")
        top = (f"<div class='topbar'><span>Signed in as <b>{esc(user['username'])}</b> "
               f"<span class='badge'>{esc(user['role'])}</span>{admin_link}</span>"
               f"<span><a href='/logout'>Log out</a></span></div>")
    else:
        top = ""
    return (f"<!doctype html><html lang='en-GB'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{esc(title)} — Invoice Fraud Checker</title>"
            f"<style>{CSS}</style></head><body><div class='wrap'>{top}"
            f"<h1>🧾 Invoice Fraud Checker</h1>{body}</div></body></html>")


def store() -> HistoryStore:
    DATA.mkdir(parents=True, exist_ok=True)
    return HistoryStore(str(DB))


def authdb() -> AuthStore:
    DATA.mkdir(parents=True, exist_ok=True)
    return AuthStore(str(DB))


def current_user(session: str | None = Cookie(default=None)) -> dict | None:
    if not session:
        return None
    return authdb().get_session_user(session)


def require_user(user: dict | None = Depends(current_user)) -> dict:
    if not user:
        raise _LoginRedirect()
    return user


class _LoginRedirect(Exception):
    pass


@app.exception_handler(_LoginRedirect)
def _to_login(request, exc):
    return RedirectResponse("/login", status_code=303)


def require_admin(user: dict = Depends(require_user)) -> dict:
    if user["role"] != "admin":
        raise _Forbidden()
    return user


class _Forbidden(Exception):
    pass


@app.exception_handler(_Forbidden)
def _to_403(request, exc):
    return HTMLResponse(page("Not allowed",
                             "<div class='card err'><p>Admins only.</p></div>"),
                        status_code=403)


# ---------- first-run setup ----------

@app.get("/setup", response_class=HTMLResponse)
def setup_form():
    if authdb().user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    return page("Set up", """
<p class='sub'>First run — create the <b>admin</b> account. The admin manages
users and sees every business.</p>
<div class='card'><form method='post' action='/setup'>
<label>Username</label><input type='text' name='username' required
  placeholder='e.g. samir' pattern='[A-Za-z0-9_.-]{3,30}'>
<label>Password (min 8 characters)</label>
<input type='password' name='password' required minlength='8'>
<label>Confirm password</label><input type='password' name='confirm' required>
<label>Your business name</label><input type='text' name='business' required
  placeholder='e.g. Himal Traders'>
<button type='submit'>Create admin account</button>
</form></div>""")


@app.post("/setup", response_class=HTMLResponse)
def setup_do(username: str = Form(...), password: str = Form(...),
             confirm: str = Form(...), business: str = Form(...)):
    db = authdb()
    if db.user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    if password != confirm:
        return page("Set up", "<div class='card err'><p>Passwords don't match.</p>"
                               "<p><a class='btn' href='/setup'>Back</a></p></div>")
    try:
        db.create_user(username.strip(), password, role="admin",
                       business_id=slugify(business),
                       business_name=business.strip())
    except ValueError as e:
        return page("Set up", f"<div class='card err'><p>{esc(e)}</p>"
                               "<p><a class='btn' href='/setup'>Back</a></p></div>")
    return RedirectResponse("/login?created=1", status_code=303)


# ---------- login / logout ----------

@app.get("/login", response_class=HTMLResponse)
def login_form(created: str | None = None):
    if authdb().user_count() == 0:
        return RedirectResponse("/setup", status_code=303)
    msg = ("<div class='ok'><b>Account created.</b> Please log in.</div>"
           if created else "")
    return page("Log in", f"""{msg}
<div class='card'><form method='post' action='/login'>
<label>Username</label><input type='text' name='username' required autofocus>
<label>Password</label><input type='password' name='password' required>
<button type='submit'>Log in</button>
</form></div>""")


@app.post("/login")
def login_do(username: str = Form(...), password: str = Form(...)):
    db = authdb()
    user = db.authenticate(username.strip(), password)
    if not user:
        return page("Log in", """
<div class='card'><div class='err'><b>Wrong username or password.</b></div>
<p><a class='btn' href='/login'>Try again</a></p></div>""")
    db.prune_sessions()
    token = db.create_session(user["id"])
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("session", token, max_age=7 * 24 * 3600, httponly=True,
                    samesite="lax")
    return resp


@app.get("/logout")
def logout(session: str | None = Cookie(default=None)):
    if session:
        authdb().delete_session(session)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("session")
    return resp


# ---------- main journey ----------

@app.get("/", response_class=HTMLResponse)
def index(user: dict = Depends(require_user)):
    return page("Check an invoice", f"""
<p class='sub'>Photograph or upload an invoice for
<b>{esc(user['business_name'] or 'your business')}</b>. We'll read it and flag
anything that looks off — <b>you</b> decide what to do.</p>
<div class='card'><form action='/check' method='post' enctype='multipart/form-data'>
<label for='invoice'>Invoice photo or scan</label>
<input type='file' id='invoice' name='invoice' accept='image/*' required>
<button type='submit'>Check invoice</button>
</form></div>
<p class='note'><a href='/history'>View saved history</a> · Flags are a second
pair of eyes, not an accountant. Nothing is auto-rejected or auto-paid.</p>""",
                user)


@app.post("/check", response_class=HTMLResponse)
async def check(invoice: UploadFile = File(...),
                user: dict = Depends(require_user)):
    biz, business_name = user["business_id"], user["business_name"]
    ext = Path(invoice.filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        return page("Unsupported file", f"""
<div class='card'><p>Sorry — <b>{esc(ext or '(no extension)')}</b> isn't a
supported image type. Please upload a PNG, JPG, WEBP, TIFF or BMP photo.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""", user)
    raw = await invoice.read()
    if len(raw) > MAX_BYTES:
        return page("File too large", """
<div class='card'><p>That file is over 10&nbsp;MB. Please use a smaller photo.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""", user)
    UPLOADS.mkdir(parents=True, exist_ok=True)
    fname = f"{int(time.time())}_{secrets.token_hex(6)}{ext}"
    (UPLOADS / fname).write_bytes(raw)

    from .ocr import pipeline as ocr_pipeline
    try:
        data = ocr_pipeline(str(UPLOADS / fname))
    except Exception as e:
        return page("Couldn't read it", f"""
<div class='card'><p>We couldn't read that image ({esc(str(e)[:120])}).
Try a straighter, better-lit photo.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""", user)

    try:
        inv = Invoice.from_dict(data)
    except ValueError as e:
        return page("Missing details", f"""
<div class='card'><p>We read the photo but couldn't find: <b>{esc(e)}</b>.</p>
<p class='note'>Tip: make sure the vendor name, invoice number, date and total
are clearly visible.</p>
<p><a class='btn' href='/'>Try again</a></p></div>""", user)

    result = analyze(data, biz, store())
    token = _sign_data({"user_id": user["id"], "invoice": data})

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

    return page("Results", f"""
<p class='sub'>Results for <b>{esc(business_name)}</b> — reviewed by you, not us.</p>
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
</form></div>""", user)


@app.post("/record", response_class=HTMLResponse)
def record(token: str = Form(...), user: dict = Depends(require_user)):
    payload = _unsign_data(token)
    data = payload.get("invoice") if payload else None
    if not data or payload.get("user_id") != user["id"]:
        return page("Expired", """
<div class='card'><p>That review has expired or belongs to another session.
Please check the invoice again.</p>
<p><a class='btn' href='/'>Check another invoice</a></p></div>""", user)
    try:
        inv = Invoice.from_dict(data)
    except ValueError:
        return page("Expired", """
<div class='card'><p>That review is no longer valid. Please check the invoice
again.</p>
<p><a class='btn' href='/'>Check another invoice</a></p></div>""", user)
    store().record_invoice(user["business_id"], inv)
    return page("Saved", f"""
<div class='card'><div class='ok'><b>✓ Saved.</b> Invoice
<b>{esc(inv.invoice_number)}</b> ({esc(inv.currency)} {inv.total:,.2f}) is now
part of <b>{esc(user['business_name'])}</b>'s history.</div>
<p><a class='btn' href='/'>Check another invoice</a> ·
<a href='/history'>View history</a></p></div>""", user)


@app.get("/history", response_class=HTMLResponse)
def history(user: dict = Depends(require_user)):
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    if user["role"] == "admin":
        rows = con.execute(
            "SELECT business_id, vendor_name, invoice_number, invoice_date,"
            " currency, total FROM invoices ORDER BY id DESC LIMIT 200").fetchall()
        extra_th, extra_td = "<th>Business</th>", lambda r: f"<td>{esc(r['business_id'])}</td>"
        scope = "every business"
    else:
        rows = con.execute(
            "SELECT vendor_name, invoice_number, invoice_date, currency, total"
            " FROM invoices WHERE business_id=? ORDER BY id DESC LIMIT 100",
            (user["business_id"],)).fetchall()
        extra_th, extra_td = "", lambda r: ""
        scope = esc(user["business_name"])
    con.close()
    if rows:
        trs = "".join(
            f"<tr>{extra_td(r)}<td>{esc(r['invoice_date'])}</td>"
            f"<td>{esc(r['vendor_name'])}</td><td>{esc(r['invoice_number'])}</td>"
            f"<td>{esc(r['currency'])} {r['total']:,.2f}</td></tr>" for r in rows)
        table = (f"<table><tr>{extra_th}<th>Date</th><th>Vendor</th><th>No.</th>"
                 f"<th>Total</th></tr>{trs}</table>")
    else:
        table = "<p class='note'>No invoices saved yet.</p>"
    return page("History", f"""
<p class='sub'>Saved invoices — {scope}.</p>
<div class='card'>{table}</div>
<p><a class='btn secondary' href='/'>Back</a></p>""", user)


# ---------- admin ----------

@app.get("/admin", response_class=HTMLResponse)
def admin_home(user: dict = Depends(require_admin)):
    db = authdb()
    users = db.list_users()
    inv_count = store().db.execute("SELECT COUNT(*) c FROM invoices").fetchone()["c"]
    biz_count = store().db.execute(
        "SELECT COUNT(DISTINCT business_id) c FROM invoices").fetchone()["c"]
    rows = ""
    for u in users:
        self_tag = " (you)" if u["id"] == user["id"] else ""
        status = "active" if u["active"] else "disabled"
        actions = ""
        if u["id"] != user["id"]:
            toggle = ("disable" if u["active"] else "enable")
            actions = (f"<form class='inline' method='post' action='/admin/toggle'>"
                       f"<input type='hidden' name='user_id' value='{u['id']}'>"
                       f"<button class='small secondary' type='submit'>{toggle}</button></form>"
                       f"<form class='inline' method='post' action='/admin/delete' "
                       f"onsubmit=\"return confirm('Delete {esc(u['username'])}?')\">"
                       f"<input type='hidden' name='user_id' value='{u['id']}'>"
                       f"<button class='small danger' type='submit'>delete</button></form>"
                       f"<form class='inline' method='post' action='/admin/resetpw'>"
                       f"<input type='hidden' name='user_id' value='{u['id']}'>"
                       f"<input type='password' name='password' placeholder='new password' "
                       f"required minlength='8' style='width:130px;padding:8px'>"
                       f"<button class='small secondary' type='submit'>reset pw</button></form>")
        rows += (f"<tr><td>{esc(u['username'])}{self_tag}</td><td>{esc(u['role'])}</td>"
                 f"<td>{esc(u['business_name'] or '—')}</td><td>{status}</td>"
                 f"<td>{actions}</td></tr>")
    return page("Admin", f"""
<div class='card'><h2>Overview</h2>
<dl class='kv'><dt>Saved invoices</dt><dd>{inv_count}</dd>
<dt>Businesses</dt><dd>{biz_count}</dd>
<dt>Users</dt><dd>{len(users)}</dd></dl></div>
<div class='card'><h2>Users</h2>
<table><tr><th>Username</th><th>Role</th><th>Business</th><th>Status</th><th>Actions</th></tr>
{rows}</table></div>
<div class='card'><h2>Add user</h2>
<form method='post' action='/admin/create'>
<label>Username</label><input type='text' name='username' required
  pattern='[A-Za-z0-9_.-]{{3,30}}'>
<label>Password (min 8 characters)</label>
<input type='password' name='password' required minlength='8'>
<label>Role</label><select name='role'>
<option value='user'>User — sees only their business</option>
<option value='admin'>Admin — sees everything, manages users</option></select>
<label>Business name</label><input type='text' name='business' required
  placeholder='e.g. Himal Traders'>
<button type='submit'>Create user</button>
</form></div>
<p><a class='btn secondary' href='/history'>All invoices</a></p>""", user)


@app.post("/admin/create", response_class=HTMLResponse)
def admin_create(username: str = Form(...), password: str = Form(...),
                 role: str = Form("user"), business: str = Form(...),
                 user: dict = Depends(require_admin)):
    try:
        authdb().create_user(username.strip(), password, role=role,
                             business_id=slugify(business),
                             business_name=business.strip())
    except ValueError as e:
        return page("Admin", f"<div class='card err'><p>{esc(e)}</p>"
                             "<p><a class='btn' href='/admin'>Back</a></p></div>",
                    user)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/toggle")
def admin_toggle(user_id: int = Form(...), user: dict = Depends(require_admin)):
    db = authdb()
    target = db.get_by_id(user_id)
    if not target:
        return RedirectResponse("/admin", status_code=303)
    if target["id"] == user["id"]:
        return _admin_err(user, "You can't disable your own account.")
    if target["active"] and target["role"] == "admin" and db.admin_count() <= 1:
        return _admin_err(user, "Can't disable the last admin.")
    db.set_active(user_id, not target["active"])
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/delete")
def admin_delete(user_id: int = Form(...), user: dict = Depends(require_admin)):
    db = authdb()
    target = db.get_by_id(user_id)
    if not target:
        return RedirectResponse("/admin", status_code=303)
    if target["id"] == user["id"]:
        return _admin_err(user, "You can't delete your own account.")
    if target["role"] == "admin" and db.admin_count() <= 1:
        return _admin_err(user, "Can't delete the last admin.")
    db.delete_user(user_id)
    return RedirectResponse("/admin", status_code=303)


def _admin_err(user: dict, msg: str) -> HTMLResponse:
    return HTMLResponse(page(
        "Admin", f"<div class='card err'><p>{esc(msg)}</p>"
                 "<p><a class='btn' href='/admin'>Back</a></p></div>", user),
        status_code=400)


@app.post("/admin/resetpw", response_class=HTMLResponse)
def admin_resetpw(user_id: int = Form(...), password: str = Form(...),
                  user: dict = Depends(require_admin)):
    try:
        authdb().set_password(user_id, password)
    except ValueError as e:
        return page("Admin", f"<div class='card err'><p>{esc(e)}</p>"
                             "<p><a class='btn' href='/admin'>Back</a></p></div>",
                    user)
    return RedirectResponse("/admin", status_code=303)

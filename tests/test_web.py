"""Web + auth tests: setup, login, roles, business isolation, admin controls.

Uses FastAPI TestClient against a temp DB. The upload journey test needs
an OCR backend (RapidOCR in the venv); it is skipped otherwise.
"""
import unittest
from pathlib import Path

import fraudcheck.web as web
from fraudcheck.auth import AuthStore, hash_password, verify_password
from fastapi.testclient import TestClient


class PasswordTests(unittest.TestCase):
    def test_hash_verify_roundtrip(self):
        h, salt = hash_password("correct-horse-8")
        self.assertTrue(verify_password("correct-horse-8", salt, h))
        self.assertFalse(verify_password("wrong", salt, h))

    def test_salts_differ(self):
        h1, s1 = hash_password("same-password-1")
        h2, s2 = hash_password("same-password-1")
        self.assertNotEqual(h1, h2)


class WebAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__file__).parent / "tmp_web"
        self.tmp.mkdir(exist_ok=True)
        for p in self.tmp.glob("*.db"):
            p.unlink()
        web.DATA = self.tmp
        web.DB = self.tmp / "t.db"
        web.UPLOADS = self.tmp / "uploads"
        self.client = TestClient(web.app, follow_redirects=False)

    def _setup_admin(self, username="boss", password="admin-pass-1",
                     business="Himal Traders"):
        r = self.client.post("/setup", data={
            "username": username, "password": password,
            "confirm": password, "business": business})
        self.assertIn(r.status_code, (303, 307), r.text[:200])
        return r

    def _login(self, username, password):
        r = self.client.post("/login", data={
            "username": username, "password": password})
        self.assertIn(r.status_code, (303, 307), r.text[:200])
        return r

    def test_setup_then_login(self):
        self.assertEqual(self.client.get("/setup").status_code, 200)
        self._setup_admin()
        # setup closes after first admin
        self.assertIn(self.client.get("/setup").status_code, (303, 307))
        # wrong password rejected
        r = self.client.post("/login",
                             data={"username": "boss", "password": "nope"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Wrong username", r.text)
        # right password -> session cookie + home
        self._login("boss", "admin-pass-1")
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Himal Traders", r.text)

    def test_unauthenticated_redirects(self):
        r = self.client.get("/")
        self.assertIn(r.status_code, (303, 307))
        self.assertIn("/login", r.headers["location"])

    def test_non_admin_cannot_reach_admin(self):
        self._setup_admin()
        # admin creates a plain user
        self._login("boss", "admin-pass-1")
        r = self.client.post("/admin/create", data={
            "username": "staff", "password": "staff-pass-1",
            "role": "user", "business": "Everest Supplies"})
        self.assertIn(r.status_code, (303, 307))
        self.client.get("/logout")
        self._login("staff", "staff-pass-1")
        r = self.client.get("/admin")
        self.assertEqual(r.status_code, 403)

    def test_business_isolation(self):
        self._setup_admin(business="Biz A")
        self._login("boss", "admin-pass-1")
        self.client.post("/admin/create", data={
            "username": "staff", "password": "staff-pass-1",
            "role": "user", "business": "Biz B"})
        # boss records an invoice for Biz A directly in the store
        from fraudcheck.schema import Invoice
        web.store().record_invoice("biz-a", Invoice.from_dict({
            "vendor_name": "V1", "invoice_number": "A-1",
            "invoice_date": "2026-01-01", "total": 100.0}))
        self.client.get("/logout")
        self._login("staff", "staff-pass-1")
        r = self.client.get("/history")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("A-1", r.text)  # Biz B must not see Biz A's invoice
        # admin sees everything
        self.client.get("/logout")
        self._login("boss", "admin-pass-1")
        r = self.client.get("/history")
        self.assertIn("A-1", r.text)
        self.assertIn("biz-a", r.text)

    def test_disable_user_blocks_login(self):
        self._setup_admin()
        self._login("boss", "admin-pass-1")
        self.client.post("/admin/create", data={
            "username": "staff", "password": "staff-pass-1",
            "role": "user", "business": "Biz B"})
        staff = web.authdb().get_by_username("staff")
        r = self.client.post("/admin/toggle", data={"user_id": staff["id"]})
        self.assertIn(r.status_code, (303, 307))
        self.client.get("/logout")
        r = self.client.post("/login",
                             data={"username": "staff", "password": "staff-pass-1"})
        self.assertIn("Wrong username", r.text)

    def test_cannot_remove_last_admin(self):
        self._setup_admin()
        self._login("boss", "admin-pass-1")
        boss = web.authdb().get_by_username("boss")
        r = self.client.post("/admin/delete", data={"user_id": boss["id"]})
        self.assertEqual(r.status_code, 400)
        self.assertIn("own account", r.text)
        r = self.client.post("/admin/toggle", data={"user_id": boss["id"]})
        self.assertEqual(r.status_code, 400)
        # and with a second admin present, deleting the first is still
        # blocked only when it would leave zero admins
        self.client.post("/admin/create", data={
            "username": "boss2", "password": "admin-pass-2",
            "role": "admin", "business": "HQ"})
        r = self.client.post("/admin/delete", data={"user_id": boss["id"]})
        self.assertEqual(r.status_code, 400)  # self-delete always blocked
        # the other admin CAN remove boss (one admin remains)
        self.client.get("/logout")
        self._login("boss2", "admin-pass-2")
        r = self.client.post("/admin/delete", data={"user_id": boss["id"]})
        self.assertIn(r.status_code, (303, 307))
        self.assertIsNone(web.authdb().get_by_username("boss"))

    def test_password_validation(self):
        db = AuthStore(str(self.tmp / "pw.db"))
        with self.assertRaises(ValueError):
            db.create_user("u1", "short", role="user")
        with self.assertRaises(ValueError):
            db.create_user("bad name!", "long-enough-1", role="user")

    def test_upload_journey(self):
        from fraudcheck import ocr as O
        if not (O.tesseract_available() or O.rapidocr_available()):
            self.skipTest("no OCR backend")
        from tests.synth import make_set
        self._setup_admin(business="Himal Traders")
        self._login("boss", "admin-pass-1")
        (self.tmp / "img").mkdir(exist_ok=True)
        png, _ = make_set(self.tmp / "img", n=1, seed=5)[0]
        with open(png, "rb") as f:
            r = self.client.post("/check", files={"invoice": ("inv.png", f)})
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("Himal Traders Pvt. Ltd.", r.text)
        self.assertIn("Looks right", r.text)
        import re
        token = re.search(r"name='token' value='([^']+)'", r.text).group(1)
        r = self.client.post("/record", data={"token": token})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Saved", r.text)
        r = self.client.get("/history")
        self.assertIn("HT-1000", r.text)


if __name__ == "__main__":
    unittest.main()

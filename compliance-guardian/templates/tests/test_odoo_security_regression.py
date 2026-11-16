"""Example Odoo security regression tests (copy into your addon's tests/ and adapt).

Run: odoo-bin -d testdb -i your_module --test-enable --test-tags /your_module:SecurityRegression --stop-after-init
Each test must FAIL on the vulnerable implementation and PASS after the fix.
"""
from odoo.exceptions import AccessError
from odoo.tests import HttpCase, TransactionCase, new_test_user, tagged


@tagged("post_install", "-at_install", "SecurityRegression")
class TestPortalIsolation(HttpCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alice = new_test_user(cls.env, login="alice_sec", groups="base.group_portal")
        cls.bob = new_test_user(cls.env, login="bob_sec", groups="base.group_portal")
        cls.bob_invoice = cls.env["account.move"].create({
            "move_type": "out_invoice", "partner_id": cls.bob.partner_id.id,
            "invoice_line_ids": [(0, 0, {"name": "x", "quantity": 1, "price_unit": 10})],
        })

    def test_portal_cannot_read_foreign_invoice_route(self):
        """CG-ODOO-SUDO-001 regression: IDOR on /my/invoice/<id>."""
        self.authenticate("alice_sec", "alice_sec")
        res = self.url_open(f"/my/invoice/{self.bob_invoice.id}", allow_redirects=False)
        self.assertNotIn(self.bob_invoice.name or "INV", res.text if res.status_code == 200 else "")
        self.assertIn(res.status_code, (302, 303, 403, 404))

    def test_portal_cannot_read_foreign_invoice_orm(self):
        with self.assertRaises(AccessError):
            self.bob_invoice.with_user(self.alice).check_access("read")  # Odoo 18+; <=17: check_access_rule("read")


@tagged("post_install", "-at_install", "SecurityRegression")
class TestSqlInjection(HttpCase):

    def test_search_payload_is_literal(self):
        """CG-PY-SQLI-001 regression: payload must not alter the query."""
        self.authenticate("admin", "admin")
        res = self.url_open("/api/search?q=%27%20OR%201%3D1--")
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("Administrator", res.text)


@tagged("post_install", "-at_install", "SecurityRegression")
class TestFieldAccess(TransactionCase):

    def test_internal_user_cannot_read_health_field(self):
        """CG-PRIV-001 regression: special-category field restricted by groups=."""
        user = new_test_user(self.env, login="clerk_sec", groups="base.group_user")
        patient = self.env["clinic.patient"].create({"name": "P", "medical_diagnosis": "secret"})
        with self.assertRaises(AccessError):
            patient.with_user(user).read(["medical_diagnosis"])

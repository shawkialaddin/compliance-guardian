# INTENTIONALLY VULNERABLE TEST FIXTURE - do not deploy.
import hashlib
import random

from markupsafe import Markup
from odoo import fields, models


class ClinicPatient(models.Model):
    _name = "clinic.patient"
    _description = "Patient"
    _inherit = ["mail.thread"]

    name = fields.Char(required=True)
    email = fields.Char()
    national_id = fields.Char(tracking=True)              # VULN CG-ODOO-PRIV-002 (tracked identifier)
    medical_diagnosis = fields.Text()                     # VULN CG-PRIV-001 (health data, no groups)
    religion = fields.Char()                              # VULN CG-PRIV-001
    notes_html = fields.Html(sanitize=False)              # VULN CG-ODOO-XSS-003
    access_token = fields.Char()

    def get_summary(self):
        # VULN CG-ODOO-XSS-001
        return Markup(f"<b>{self.name}</b>: {self.medical_diagnosis}")

    def action_share_with_all(self):
        # VULN CG-ODOO-SUDO-004: RPC-callable public method elevating privileges
        self.sudo().write({"access_token": self._make_token()})
        return True

    def _make_token(self):
        token = str(random.randint(100000, 999999))       # VULN CG-PY-CRYPTO-002
        return hashlib.md5(token.encode()).hexdigest()    # VULN CG-PY-CRYPTO-001

    def _search_raw(self, term):
        self.env.cr.execute(f"SELECT id FROM clinic_patient WHERE name = '{term}'")   # VULN CG-PY-SQLI-001
        return self.env.cr.fetchall()

    def _count_rows(self):
        # NOT VULN (identifier only) -> LOW/low informational
        self.env.cr.execute("SELECT count(*) FROM %s" % self._table)
        return self.env.cr.fetchone()[0]

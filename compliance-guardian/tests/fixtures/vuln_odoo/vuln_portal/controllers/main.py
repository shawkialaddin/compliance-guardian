# INTENTIONALLY VULNERABLE TEST FIXTURE - do not deploy.
import logging
import pickle
import subprocess

import requests
from odoo import SUPERUSER_ID, http
from odoo.http import request

_logger = logging.getLogger(__name__)
PAYMENT_API_KEY = "pk_9f8a7Bc6D5e4F3g2H1"   # VULN: hard-coded credential


class VulnPortal(http.Controller):

    @http.route("/my/invoice/<int:invoice_id>", type="http", auth="user", website=True)
    def invoice(self, invoice_id, **kw):
        # VULN CG-ODOO-SUDO-001: IDOR - any logged-in user reads any invoice
        invoice = request.env["account.move"].sudo().browse(invoice_id)
        return request.render("vuln_portal.invoice", {"invoice": invoice})

    @http.route("/api/partners", type="json", auth="public")
    def partners(self, **kw):
        # VULN CG-ODOO-SUDO-002: unauthenticated dump of all partners, all fields
        return request.env["res.partner"].sudo().search_read([])

    @http.route("/api/lead", type="http", auth="public", methods=["POST"], csrf=False)
    def create_lead(self, **post):
        # VULN CG-ODOO-SUDO-003 (mass assignment) + CG-ODOO-CSRF-001
        lead = request.env["crm.lead"].sudo().create(post)
        return str(lead.id)

    @http.route("/api/search", type="http", auth="public")
    def search(self, q="", **kw):
        # VULN CG-PY-SQLI-001: SQL injection from request input
        request.env.cr.execute("SELECT id, name FROM res_partner WHERE name ILIKE '%%%s%%'" % q)
        return str(request.env.cr.fetchall())

    @http.route("/api/report", type="http", auth="user")
    def report(self, name, **kw):
        # VULN CG-PY-CMDI-001 + CG-PY-PATH-001
        subprocess.call("wkhtmltopdf /tmp/" + name + " /tmp/out.pdf", shell=True)
        with open("/var/reports/" + name) as fh:
            return fh.read()

    @http.route("/api/fetch", type="http", auth="public")
    def fetch(self, url, **kw):
        # VULN CG-PY-SSRF-001 + CG-PY-TLS-001 + CG-PY-TIMEOUT-001
        return requests.get(url, verify=False).text

    @http.route("/api/import", type="http", auth="user", methods=["POST"], csrf=False)
    def import_data(self, **kw):
        # VULN CG-PY-DESER-001
        data = pickle.loads(request.httprequest.get_data())
        return str(data)

    @http.route("/api/admin_login", type="http", auth="none")
    def admin_login(self, **kw):
        # VULN CG-ODOO-AUTH-002 + CG-ODOO-AUTH-001
        env = request.env(user=SUPERUSER_ID)
        request.update_env(user=SUPERUSER_ID)
        return str(env.user.id)

    @http.route("/api/upload", type="http", auth="user", methods=["POST"], cors="*")
    def upload(self, **kw):
        # VULN CG-ODOO-UPLOAD-001 + CG-ODOO-CORS-001
        f = request.httprequest.files.get("file")
        request.env["ir.attachment"].create({"name": f.filename, "raw": f.read()})
        return "ok"

    @http.route("/web/login/otp", type="http", auth="public")
    def otp_login(self, login, password, **kw):
        # VULN CG-PY-LOG-001 (credential logged) + CG-ODOO-RATE-001
        _logger.info("OTP login attempt %s with %s", login, password)
        try:
            return eval(kw.get("expr", "1"))   # VULN CG-PY-EVAL-001
        except Exception as e:
            return "error: %s" % str(e)        # VULN CG-ODOO-INFO-001

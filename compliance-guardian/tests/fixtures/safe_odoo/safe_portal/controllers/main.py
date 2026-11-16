# Secure counterpart fixture: the same features implemented safely. Expect no MEDIUM+ findings.
import hashlib
import hmac
import logging
import os

import requests
from odoo import http
from odoo.addons.portal.controllers.portal import CustomerPortal
from odoo.exceptions import AccessError, MissingError
from odoo.http import request

_logger = logging.getLogger(__name__)
ALLOWED_LEAD_FIELDS = {"name", "email_from", "phone"}


class SafePortal(CustomerPortal):

    @http.route("/my/invoice/<int:invoice_id>", type="http", auth="user", website=True)
    def invoice(self, invoice_id, access_token=None, **kw):
        try:
            invoice_sudo = self._document_check_access("account.move", invoice_id, access_token=access_token)
        except (AccessError, MissingError):
            return request.redirect("/my")
        return request.render("safe_portal.invoice", {"invoice": invoice_sudo})

    @http.route("/api/products", type="json", auth="public")
    def products(self, **kw):
        return request.env["product.template"].sudo().search_read(
            [("website_published", "=", True)], ["name", "list_price"], limit=50)

    @http.route("/api/lead", type="http", auth="public", methods=["POST"])
    def create_lead(self, **post):
        vals = {k: v for k, v in post.items() if k in ALLOWED_LEAD_FIELDS}
        lead = request.env["crm.lead"].sudo().create(vals)
        return str(lead.id)

    @http.route("/api/search", type="http", auth="user")
    def search(self, q="", **kw):
        request.env.cr.execute("SELECT id, name FROM res_partner WHERE name ILIKE %s", ("%" + q + "%",))
        return str(request.env.cr.fetchall())

    @http.route("/hook/payment", type="http", auth="public", methods=["POST"], csrf=False)
    def payment_hook(self, **kw):
        secret = os.environ["PAYMENT_WEBHOOK_SECRET"].encode()
        sig = request.httprequest.headers.get("X-Signature", "")
        expected = hmac.new(secret, request.httprequest.get_data(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return request.make_response("forbidden", status=403)
        _logger.info("Payment webhook accepted for reference id %s", kw.get("reference_id"))
        return "ok"

    @http.route("/api/rates", type="json", auth="user")
    def rates(self, **kw):
        return requests.get("https://rates.example.com/v1/latest", timeout=10).json()

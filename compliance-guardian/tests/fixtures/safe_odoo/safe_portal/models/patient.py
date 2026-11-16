import secrets

from markupsafe import Markup
from odoo import fields, models


class ClinicPatient(models.Model):
    _name = "clinic.patient"
    _description = "Patient"

    name = fields.Char(required=True)
    email = fields.Char()
    national_id = fields.Char(groups="clinic.group_clinic_manager")
    medical_diagnosis = fields.Text(groups="clinic.group_clinic_doctor")
    notes_html = fields.Html()
    access_token = fields.Char(groups="base.group_system")

    def get_summary(self):
        return Markup("<b>%s</b>") % self.name

    def _make_token(self):
        return secrets.token_urlsafe(32)

    def _cron_anonymize_expired(self):
        expired = self.search([("create_date", "<", fields.Datetime.subtract(fields.Datetime.now(), years=10))])
        expired.write({"national_id": False, "medical_diagnosis": False, "email": False})

# INTENTIONALLY VULNERABLE TEST FIXTURE - do not deploy.
{
    "name": "Vulnerable Portal (fixture)",
    "version": "17.0.1.0.0",
    "depends": ["portal", "website"],
    "data": ["security/ir.model.access.csv", "security/rules.xml", "views/templates.xml"],
    "uninstall_hook": "drop_all_data",
    "license": "LGPL-3",
}

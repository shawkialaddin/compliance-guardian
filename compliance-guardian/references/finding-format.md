# Finding format

```
### CG-F-0007 — sudo().browse() with request-supplied id (IDOR)
- Severity / confidence / verification: HIGH / high / confirmed (reviewed: no ownership check in route or helpers)
- Framework mapping: GDPR Art. 32 (VERIFIED); PDPL Art. 19 + IR Art. 23 (VERIFIED); NCA ECC-2:2024 2-2 (VERIFIED, applies only if in scope); OWASP Top 10:2025 A01; API1:2023; CWE-639
- Location: addons/x_portal/controllers/main.py:19
- Explanation: route auth='user' reads account.move with sudo() using the URL id.
- Exploit scenario: any portal user iterates /my/invoice/<id> and reads other customers' invoices (personal + financial data).
- Fix (smallest safe): use `_document_check_access('account.move', invoice_id, access_token)`; code below.
- Test: tests/test_portal_access.py::test_portal_cannot_read_foreign_invoice (fails before fix, passes after) — state if NOT RUN.
- Verification: re-scan clean + test result (actual output, or "not executed: <reason>").
```

Rules: reference numbers only from `registry/` and labelled with their verification status; jurisdiction mapping is conditional on applicability; never present a candidate as confirmed; never invent test output.

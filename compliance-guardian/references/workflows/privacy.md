# Workflow: privacy (personal-data processing assessment)

1. `python3 "$CG" report .` and open `compliance/reports/privacy-assessment.md` (inventory is a name-based hint).
2. Confirm/correct the inventory by reading models, forms, controllers, imports, exports, logs, attachments, mail templates, analytics and third-party integrations.
3. Data flow map: collection points → storage (fields, attachments, logs, backups) → disclosures (APIs, subprocessors, emails, exports) → deletion. Note trust boundaries and countries.
4. For each jurisdiction INDICATED/DECLARED: map obligations via `registry/controls/<framework>.yaml`; cite only VERIFIED references; everything else LEGAL_REVIEW_REQUIRED.
5. Rights support: access/export, rectification, erasure/anonymisation (respecting legal retention such as accounting records — deletion is not unconditional), restriction/objection, portability where applicable, consent records only where consent is the basis.
6. Retention, privacy-preserving logging, breach detection/escalation (GDPR Art. 33; PDPL IR Art. 24; Egypt timeline unverified), DPIA/PIA need (legal decision).
7. Do not assert that encryption, consent, localisation or anonymisation is mandatory unless the applicable verified requirement, risk or contract says so.

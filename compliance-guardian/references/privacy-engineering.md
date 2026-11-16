# Privacy engineering checks

| Area | Engineering check | Decision owner |
|---|---|---|
| Identification & classification | Inventory fields/attachments/logs holding personal data (scanner hint + manual) and classify; sensitive categories defined by each law | Engineering + legal (classification) |
| Purpose limitation & minimisation | Each field mapped to a purpose; remove/optional-ise unnecessary fields | Product + DPO |
| Lawful basis | Documented per purpose (not inferred by engineers) | Legal |
| Consent | Only where consent is the basis: record text/version/time/actor; withdrawal path; no pre-ticked boxes | Legal decides need; engineering implements |
| Transparency | Notice at collection points; link in portal/website forms | Legal content, engineering placement |
| Access / portability | Export of a subject's data (machine-readable where applicable) | Engineering |
| Rectification | Authorised edit paths; audit trail | Engineering |
| Erasure / anonymisation | Path that respects statutory retention (accounting/tax); anonymise rather than delete linked business records | Legal (retention) + engineering |
| Retention & disposal | Scheduled jobs per category; documented periods | DPO + engineering |
| Privacy-preserving logs | No credentials/tokens/identifiers in logs, tracebacks, chatter tracking | Engineering |
| Cross-border transfers | Inventory hosting/backup/subprocessor/support-access countries; mechanism per law | Legal |
| Processors / subprocessors | List with DPAs; data sent to each integration | Legal + engineering |
| Breach detection & escalation | Security logging, alerting, runbook with regulatory timelines (GDPR Art. 33 72h; PDPL IR Art. 24 72h; Egypt: verify) | Security + legal |
| Impact assessment | DPIA/PIA trigger assessment | Legal/DPO |

Encryption, anonymisation, consent and localisation are context-dependent: recommend them based on verified legal requirements, risk, classification or contract — not as universal mandates.

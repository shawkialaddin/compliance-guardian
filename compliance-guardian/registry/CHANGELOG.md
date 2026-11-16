# Regulatory registry changelog

Changes to sources or control mappings are proposed here with evidence before the registry version is bumped.
A newer regulatory edition is never adopted silently (`baseline_locked: true`).

## 2026.11.16 — initial baseline
- Sources verified via official sites where reachable (EUR-Lex, nca.gov.sa CDN, dgp.sdaia.gov.sa, owasp.org, cwe.mitre.org, csrc.nist.gov).
- ECC-2:2024: 4 domains / 28 subdomains / 108 controls; subdomain titles verified; ICS domain moved to OTCC.
- PDPL: Law and Implementing Regulation article numbers are separate; breach notification = IR Art. 24 (72h, where harm is potential).
- NCNICC-1:2025: Arabic official text only; all mappings UNVERIFIED.
- Egypt Law 151/2020, ER Decision 816/2025, Law 175/2018: official Arabic texts not retrieved; THIRD_PARTY_ONLY metadata; no article numbers cited.
- OWASP Top 10 baseline set to 2025 edition; rule tags still carry 2021 IDs (explicitly labelled) pending remap.
- NIST SSDF: v1.1 final retained; SP 800-218 Rev.1 (v1.2) is a draft and NOT adopted.

## Pending proposals
- Remap rule-level OWASP tags from 2021 to 2025 IDs (needs review).
- Extract CCC-2:2024 and DCC-1:2022 control numbers from the official PDFs and promote references to VERIFIED.
- Obtain official Arabic texts for Egypt Law 151/2020 + ER 816/2025 and Law 175/2018; add verified article references.

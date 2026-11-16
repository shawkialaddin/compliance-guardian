# Workflow: update-rules (regulatory intelligence)

1. `python3 "$CG" registry` — list sources, verification status and age.
2. If internet access is available (ask before using it), check each source's **official** page first (EUR-Lex, nca.gov.sa, sdaia.gov.sa / dgp.sdaia.gov.sa, laws.boe.gov.sa, pdpc.gov.eg, mcit.gov.eg, tra.gov.eg, owasp.org, cwe.mitre.org, csrc.nist.gov). Third-party summaries only as leads, marked THIRD_PARTY_ONLY.
3. Capture: regulator, document, edition, publication date, effective date, URL, verification date, binding language.
4. Produce a **proposal** (do not overwrite the baseline): a diff to `registry/sources.yaml` / `registry/controls/*.yaml` plus a CHANGELOG.md entry with evidence. `baseline_locked: true` means a newer edition is adopted only after the user approves.
5. Promote a reference to `VERIFIED` only when the exact number and wording were seen in the official text. Never invent clause numbers, deadlines or conclusions; if a document is inaccessible, record the limitation.
6. After approval: apply, bump `registry_version`, run the self-tests (`python3 -m pytest tests`).

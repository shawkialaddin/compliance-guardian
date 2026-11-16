"""SARIF 2.1.0 export."""
from __future__ import annotations

from . import VERSION, catalog

LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}


def to_sarif(findings, meta) -> dict:
    rules, idx = [], {}
    for f in findings:
        if f.rule_id in idx:
            continue
        r = catalog.R.get(f.rule_id, {})
        idx[f.rule_id] = len(rules)
        cwe_num = (f.cwe[0].split("-")[-1] if f.cwe else None)
        rules.append({
            "id": f.rule_id,
            "name": f.rule_id.replace("-", ""),
            "shortDescription": {"text": f.title[:200]},
            "fullDescription": {"text": (r.get("remediation") or f.message)[:1000]},
            "help": {"text": f"Remediation: {r.get('remediation', '')}\nVerify before confirming: {r.get('verify', '')}"},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html" if cwe_num else
            "https://owasp.org/www-project-top-ten/",
            "properties": {"tags": ["security", *f.cwe, *f.owasp, f.category], "security-severity": SCORE[f.severity]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": idx[f.rule_id],
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.severity}/{f.confidence}/{f.verification}] {f.message}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                "region": {"startLine": max(1, f.line)}}}],
            "partialFingerprints": {"cgFingerprint/v1": f.fingerprint},
            "properties": {"findingId": f.id, "severity": f.severity, "confidence": f.confidence,
                           "verification": f.verification, "exception": f.exception_id, "tool": f.tool},
            **({"suppressions": [{"kind": "external", "status": "accepted",
                                  "justification": f"Approved exception {f.exception_id}"}]} if f.exception_id else {}),
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "compliance-guardian", "version": VERSION,
                                "informationUri": "https://owasp.org/www-project-application-security-verification-standard/",
                                "rules": rules}},
            "results": results,
            "properties": {"scanId": meta.get("scan_id"), "mode": meta.get("mode"),
                           "disclaimer": "Automated technical findings; not a legal compliance determination."},
        }],
    }

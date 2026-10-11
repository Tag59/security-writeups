# Security write-ups — Ethan Joets

Technical analyses of vulnerabilities in the ML / AI software ecosystem:
root-cause breakdowns, local reproductions, and defensive takeaways. Everything
here is done against code I am allowed to analyze, with benign local proofs and
responsible-disclosure hygiene.

Focus: **AI/ML security** — unsafe deserialization, sandbox escapes, path
traversal and injection in ML libraries and MLOps tooling.

## Write-ups

| Write-up | Target | Class | Status |
|---|---|---|---|
| [Breaking out of a RestrictedPython "sandbox" (Aim)](aim-cve-2025-5321/) | Aim ML tracker ≤3.29.1 | Sandbox escape → RCE (CWE-94) | Public CVE, educational analysis |
| [A deserialization bug that came back (BentoML)](bentoml-cve-2025-32375/) | BentoML runner server | Insecure deserialization → RCE (CWE-502) | Public CVE, regression + root-cause analysis |

## Related

- [mlsast](https://github.com/Tag59/mlsast) — my small static scanner for the
  vulnerability classes that produce CVEs in ML Python libraries.

## Ethics

I only analyze code I am permitted to, reproduce issues locally with benign
proofs, and follow responsible disclosure (private report first, public details
only after a fix or an agreed deadline). Write-ups of already-public CVEs are
educational analyses, not new disclosures.

---
© 2026 Ethan Joets · [GitHub](https://github.com/Tag59)

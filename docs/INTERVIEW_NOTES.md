# Technical interview notes

## Why split Spring Boot and FastAPI?
Spring Boot owns the application/control-plane concerns: project validation, scan orchestration, persistence, history, and exports. FastAPI owns the Python-heavy archive parsing and security-analysis workflow. This separates product API concerns from analysis logic and lets the scanner evolve independently.

## Why do you not execute repository code?
A repository is untrusted input. Running install scripts, build tools, or tests could execute arbitrary code on the scanner host. The MVP analyzes a bounded archive as data only. Deeper dynamic analysis would need isolated ephemeral workers, strict network egress policy, resource limits, and disposable filesystems.

## How is archive handling bounded?
The scanner caps the compressed archive size, number of archive entries, size of each inspected file, path depth, and number of extracted dependencies. It ignores path traversal entries and does not extract arbitrary paths onto the host filesystem.

## Why OSV?
OSV gives a package/ecosystem/version query model and a machine-readable advisory format. TrustForge batches lookups, then hydrates abbreviated records from canonical OSV advisory endpoints when severity/details are missing. The application preserves source identifiers and references for auditability.

## How is severity determined?
The scanner prefers severity labels supplied by OSV database/ecosystem metadata. If those are absent, it accepts numeric CVSS values or calculates a CVSS v3.0/v3.1 base score from a complete vector. CVSS v4 is not passed through the v3 formula. If there is insufficient evidence, severity stays UNKNOWN.

## Is the risk score a probability?
No. It is a deliberately simple, documented prioritization heuristic with fixed weights by finding severity and a 0–100 cap. It is useful for ordering review, not a calibrated probability of compromise or business impact.

## Why H2?
H2 allows the MVP to run locally without a database server. The code includes a PostgreSQL profile as a later deployment option. A production version would use managed PostgreSQL, migrations, backups, authentication, authorization, and retention controls.

## What would you build next for production?
Private repository support through a GitHub App, user/org authorization, a queue and isolated scan workers, more manifest types, engine integrations (Semgrep/Gitleaks/Trivy), persistent audit logs, and policy gates. A grounded AI assistant could be added later with strict source citations and no autonomous code changes.

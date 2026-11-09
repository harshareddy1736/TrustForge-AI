# Feature matrix — v1.1.0

| Capability | Status | Notes |
|---|---|---|
| Public GitHub repository registration | Implemented | Strict HTTPS GitHub URL shape |
| Repository ZIP acquisition | Implemented | 20 MB compressed / 50 MB expanded limits; no repository code execution |
| npm inventory | Implemented | `package.json`, `package-lock.json`; lockfile version priority |
| Python inventory | Implemented | Pinned `requirements.txt` entries (`==`) |
| Maven inventory | Implemented | Explicit dependency versions from `pom.xml` |
| OSV dependency matching | Implemented | Batch package + ecosystem + version requests |
| OSV canonical advisory hydration | Implemented | Used for incomplete/unknown querybatch records; capped per scan |
| Severity/CVSS enrichment | Implemented | Vendor severity, numeric score, CVSS v3.0/v3.1 vectors |
| Fixed-version extraction | Implemented | OSV range events when supplied |
| Secret-like pattern detection | Implemented | AWS, private-key headers, GitHub, Google, Slack, npm and generic assignments |
| Dockerfile static checks | Implemented | Root user, remote ADD, unpinned base image, remote shell pipe |
| Risk prioritization | Implemented | Transparent heuristic weights and risk bands |
| Scan history | Implemented | H2 file persistence |
| CycloneDX 1.5 export | Implemented | Components plus supported vulnerability records |
| Markdown security report | Implemented | Summary, findings, fixes, advisory references, warnings |
| GitHub Actions CI definition | Implemented | Python, Java 25/Maven, frontend checks; must run in user's repo |
| Private GitHub repositories | Not implemented | Requires GitHub App/OAuth integration |
| User accounts and organization tenancy | Not implemented | Local developer workspace only |
| Background job queue / isolated workers | Not implemented | Synchronous local scan flow |
| Semgrep / Gitleaks / Trivy execution | Not implemented | Not claimed as part of the current checks |
| LLM-based security copilot | Not implemented | No model provider or autonomous AI remediation in this release |
| Automated dependency updates / pull requests | Not implemented | Recommendations only |

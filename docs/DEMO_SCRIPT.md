# 3–4 minute portfolio demo script

## Before recording

1. Start Python, Java, and the frontend using the three scripts in the README.
2. Confirm both `/health` endpoints respond with `UP`.
3. Register a public repository you are authorized to demonstrate. The Express repository has previously been used as a working baseline.
4. Run one scan and wait for the scan record to appear in history.
5. Avoid recording terminal paths containing personal usernames or any secret values.

## Demo flow

1. **Overview (20–30 sec):** Introduce the workspace and registered repositories.
2. **Repository registration (20 sec):** Explain that the scanner currently accepts public GitHub repositories and inspects archives without executing project code.
3. **Scan (30–45 sec):** Start a scan; point out dependency inventory, findings, and advisory enrichment.
4. **Findings (60 sec):** Show severity, CVSS score/vector when available, OSV advisory ID/reference, installed version, fixed versions, evidence, and recommendation. Explain that `UNKNOWN` means the available source metadata was insufficient.
5. **Dependencies (20 sec):** Show the discovered npm/PyPI/Maven package inventory.
6. **Exports (30 sec):** Download the CycloneDX 1.5 SBOM and Markdown report. Point out that vulnerability records affect the matching component in the SBOM.
7. **Architecture (20 sec):** Explain React → Spring Boot → FastAPI → GitHub/OSV, with H2 persistence.

## Suggested closing statement

“TrustForge AI gives developers a traceable view of dependency and selected repository security risks. The current MVP is deliberately evidence-first: it retains OSV references, avoids running untrusted code, and exports SBOM and review artifacts. The next production step would be authenticated private-repository support, queue-backed isolated workers, and deeper analysis integrations.”

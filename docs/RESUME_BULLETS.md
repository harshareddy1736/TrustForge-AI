# Resume-ready project description

## Recommended resume entry

**TrustForge AI — Software Supply-Chain Security Platform** | React, TypeScript, Java 25, Spring Boot, Python, FastAPI, H2, OSV, CycloneDX

- Built a full-stack security platform that scans public GitHub repositories, inventories npm/PyPI/Maven dependencies, and enriches package-version matches with OSV vulnerability advisories.
- Implemented CVSS v3 severity enrichment, fixed-version extraction, evidence-linked remediation guidance, secret-pattern checks, and Dockerfile security heuristics without executing untrusted repository code.
- Developed Spring Boot scan orchestration and H2 scan-history persistence, plus CycloneDX 1.5 SBOM and downloadable Markdown security-report exports.
- Added bounded archive inspection (20 MB compressed / 50 MB expanded), redacted secret-pattern evidence, and documented security limitations; repository code is never executed.

**Optional measured-result line:** An earlier v1.0.3 baseline scan of `expressjs/express` inspected 216 files, discovered 44 dependencies, and returned 3 advisory findings. Re-run the v1.1.0 release before using these numbers as current results because OSV enrichment and finding classification may change.

## Shorter version (two bullets)

- Developed TrustForge AI, a React/TypeScript + Spring Boot + FastAPI platform for public GitHub software-supply-chain scanning, dependency inventory, OSV advisory enrichment, secret-pattern detection, and Dockerfile checks.
- Added CVSS v3 severity enrichment, fixed-version recommendations, scan-history persistence, and CycloneDX 1.5 SBOM plus Markdown security-report exports.

## Interview explanation

**Problem:** Teams need visibility into vulnerable third-party packages and common repository-level security mistakes before shipping software.

**Approach:** The React dashboard registers public GitHub repositories. Spring Boot orchestrates scans and stores complete results. FastAPI downloads a bounded ZIP archive, inspects supported manifests and selected configuration files, matches exact package versions against OSV, enriches incomplete advisory records, and returns evidence and recommendations. The API persists the result and makes details, CycloneDX SBOM, and Markdown report exports available.

**Engineering choices:** Repository code is never executed; archive/file/dependency limits constrain input; OSV references are retained; unknown severity stays unknown; score weights are documented as a heuristic rather than exploit probability; the scan result JSON is kept intact for traceability.

**Limitations to discuss honestly:** Public repositories only; supported manifest set is intentionally small; secret/Docker checks are static heuristics; synchronous local H2 deployment; no authentication, private-repository integration, isolated scan workers, external static-analysis engine, LLM copilot, or automatic fix PRs in this release.

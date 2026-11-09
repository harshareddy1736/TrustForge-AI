# Validation report — v1.1.0

**Validation date:** 2026-11-02

## Checks completed in the packaging environment

| Check | Result | Evidence / limitation |
|---|---|---|
| Python syntax compilation | Passed | `python -m py_compile app/scanner.py app/main.py` |
| Python unit suite | **31 passed** | `python -m pytest -q` in `ai-service` (31 passed) |
| CVSS v3.1 calculation fixtures | Passed | Verified 7.5 / HIGH, 5.3 / MEDIUM, and 4.0 / MEDIUM test vectors |
| OSV hydration fallback | Passed with mocked OSV responses | Confirms missing batch metadata is hydrated from a canonical advisory response |
| Dependency lockfile precedence | Passed | Lockfile version wins regardless of archive entry order |
| CycloneDX vulnerability linkage | Passed | Python test checks `affects.ref` points to the component PURL; Java exporter also carries CWE IDs |
| Archive expansion limit | Passed | Test rejects archives whose uncompressed payload exceeds 50 MB |
| ZIP integrity | Passed after packaging | `unzip -t` completed with no errors; checksum generated alongside the ZIP |
| Java source syntax parse | Passed | JDK 21 compiler parse-only pass found no syntax errors in `ScanController.java`; semantic compilation still requires the Maven/Java 25 job |
| Java Maven build | Not run in this environment | Maven is not installed and the available JDK is Java 21, while the project targets Java 25 |
| Frontend TypeScript syntax | Passed | TypeScript transpile parser reported no syntax errors for `App.tsx`, `security.ts`, `App.test.ts`, and `vite.config.ts` |
| Frontend production build | Not run in this environment | `npm install` timed out in this network-restricted environment; Node.js 22 is present |
| Full v1.1.0 end-to-end scan | Not run in this environment | The user's Mac previously verified scan persistence and SBOM generation on v1.0.3; new v1.1.0 additions still require a local acceptance test |

## Required local/GitHub verification before calling the release fully build-verified

On a Mac with Java 25, Maven 3.9+, Python 3.9+, Node.js 20+, and internet access:

1. Run `bash scripts/verify.sh` and confirm Python, Maven, frontend tests, and production build pass.
2. Start each service with the scripts in the README.
3. Register a public repository and complete a scan.
4. Confirm a previously unclassified OSV advisory is enriched when its canonical OSV record contains severity/CVSS metadata.
5. Verify the finding page shows CVSS, affected ranges, fixed versions, advice and advisory links.
6. Download the CycloneDX SBOM and validate the JSON structure with a CycloneDX-compatible validator.
7. Download the Markdown security report and inspect severity counts and references.
8. Push to GitHub and confirm the Actions workflow passes all three jobs.

Do not mark CI, Maven, Vite, or the full v1.1.0 end-to-end acceptance checks as passed until they have actually run.

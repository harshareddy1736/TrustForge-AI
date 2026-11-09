# Security model

## Intended security properties

- Accept repository URLs only from the public GitHub HTTPS URL shape supported by the scanner.
- Inspect downloaded archives as data; never run repository code, package scripts, builds, tests, or installation hooks.
- Bound compressed archive bytes (20 MB), total uncompressed content (50 MB), entry count (2,500), individual file size (1 MB), path depth, and dependency count (500).
- Ignore parent-traversal archive entries and avoid writing untrusted archive paths to the filesystem.
- Redact detected credential values from finding evidence.
- Store OSV references and advisory IDs so humans can verify the source.
- Preserve unknown severity instead of translating missing metadata into low/no severity.
- Surface advisory enrichment failures as warnings.

## Controls in this MVP

| Area | Implemented control | Remaining limitation |
|---|---|---|
| Repository input | Strict public GitHub URL parser | Private repository auth not supported |
| Archive | 20 MB compressed limit, 50 MB expanded limit, 2,500-entry limit, 1 MB per file and path bounds | Not a hardened isolated worker |
| Code execution | No build/install/script execution | Static analysis cannot discover runtime behavior |
| Secret detection | Pattern matching; matched value redacted | False positives/negatives; not a full secrets engine |
| Dependencies | npm, PyPI, Maven manifest parsing | Not every manifest/lockfile format supported |
| Vulnerabilities | OSV package/version match and canonical advisory hydration | OSV is not the only advisory source |
| Severity | Vendor severity + numeric CVSS + CVSS v3.0/v3.1 vector calculation | CVSS v4 vector scoring not implemented in the custom v3 calculator |
| Risk | Transparent fixed point weights | Not calibrated to exploitability or business impact |
| Persistence | Local H2 file | No authentication, tenant isolation, or production backup plan |

## Safe use

- Use public repositories you are authorized to assess.
- Do not add private tokens or credentials to the repository URL.
- Verify each finding against its advisory reference and your actual runtime usage before prioritizing remediation.
- Rotate confirmed leaked credentials and remove them from repository history; deleting a file from the latest commit is not sufficient.
- Treat `UNKNOWN` severity as requiring investigation, not as safe.
- Do not expose the local API or H2 console publicly without adding authentication and deployment hardening.

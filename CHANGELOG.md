# Changelog

## 1.1.0 — Portfolio milestone

- Added canonical OSV advisory hydration for incomplete querybatch responses, with bounded concurrency and request limits.
- Added CVSS v3.0/v3.1 vector base-score calculation and severity normalization; unsupported CVSS v4 vectors are not guessed.
- Added affected-range/fixed-version extraction, aliases, CWE IDs, timestamps, recommendation text, and more advisory references.
- Added severity breakdown, risk band, per-finding contribution and recommendation summary.
- Expanded selected secret-token patterns and Dockerfile checks; finding evidence does not expose matched credential values.
- Corrected npm lockfile version precedence so resolved versions take priority regardless of ZIP entry order.
- Added CycloneDX 1.5 vulnerability records linked to component PURLs.
- Added downloadable Markdown security reports and expanded dashboard finding presentation.
- Added GitHub Actions CI workflow, release/security documentation, demo script, interview notes, and resume bullets.
- Added a 50 MB total uncompressed archive-content ceiling to reduce ZIP expansion risk.
- Added duplicate-process checks to local startup scripts and made the combined verification script prepare Python dependencies automatically.
- Normalized CycloneDX CVSS rating method labels to the schema `CVSSv3` value.
- Added CWE identifiers to Java-generated CycloneDX vulnerability entries.
- Added Python tests for CVSS, OSV hydration, fixed versions, lockfile precedence, static checks, risk scoring, archive expansion, and SBOM vulnerability linkage.

## 1.0.3 — Stable integration baseline

- Java-to-Python HTTP/1.1 integration, explicit JSON request payload and repository URL header compatibility fallback.
- Local H2 persistence, public GitHub repository scanning, dependency inventory, OSV querybatch, selected static checks, scan history, and CycloneDX component export.

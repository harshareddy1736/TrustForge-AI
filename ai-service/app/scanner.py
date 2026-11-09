from __future__ import annotations
import asyncio, io, json, math, re, zipfile, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Optional
from urllib.parse import quote
import httpx

GITHUB_REPO_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?$")
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_FILES = 2500
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_DEPENDENCIES = 500

def parse_github_url(url: str) -> tuple[str, str]:
    match = GITHUB_REPO_RE.fullmatch(url.strip())
    if not match:
        raise ValueError("Only public GitHub repository URLs in https://github.com/owner/repo format are supported.")
    return match.group(1), match.group(2).removesuffix(".git")

def safe_read_archive(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("Repository archive exceeds the 20 MB download limit.")
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("Repository archive contains too many entries.")
        total_uncompressed = sum(item.file_size for item in entries if not item.is_dir())
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ValueError("Repository archive expands beyond the 50 MB inspection limit.")
        for item in entries:
            if item.is_dir():
                continue
            path = PurePosixPath(item.filename)
            if path.is_absolute() or ".." in path.parts:
                continue
            if item.file_size > MAX_FILE_BYTES:
                continue
            # GitHub ZIP archives have one leading root directory.
            relative = "/".join(path.parts[1:]) if len(path.parts) > 1 else path.name
            if not relative:
                continue
            if relative.count("/") > 12:
                continue
            try:
                files[relative] = archive.read(item)
            except (KeyError, RuntimeError, zipfile.BadZipFile):
                continue
    return files

def _add_dep(out: list[dict], name: str, version: str, ecosystem: str, priority: int = 1):
    name, version = name.strip(), version.strip()
    if not name or not version or version in ("*", "latest", "x", "X"):
        return
    version = re.sub(r"^[=~^><! ]+", "", version).strip()
    if not version or any(ch in version for ch in " *|"):
        return
    out.append({"name": name, "version": version, "ecosystem": ecosystem, "_priority": priority})

def extract_dependencies(files: dict[str, bytes]) -> tuple[list[dict], list[str]]:
    deps: list[dict] = []
    manifests: list[str] = []
    for path, raw in files.items():
        name = PurePosixPath(path).name
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        if name == "package.json":
            try:
                data = json.loads(text)
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    for pkg, ver in (data.get(section) or {}).items():
                        _add_dep(deps, pkg, str(ver), "npm", priority=1)
                manifests.append(path)
            except (json.JSONDecodeError, AttributeError):
                pass
        elif name == "package-lock.json":
            try:
                data = json.loads(text)
                packages = data.get("packages") or {}
                if packages:
                    for pkg_path, item in packages.items():
                        if not pkg_path or not pkg_path.startswith("node_modules/"):
                            continue
                        pkg_name = pkg_path.split("node_modules/")[-1]
                        if item.get("version"):
                            _add_dep(deps, pkg_name, str(item["version"]), "npm", priority=3)
                else:
                    def walk(obj):
                        for pkg, item in (obj or {}).items():
                            if item.get("version"):
                                _add_dep(deps, pkg, str(item["version"]), "npm", priority=3)
                            walk(item.get("dependencies"))
                    walk(data.get("dependencies"))
                manifests.append(path)
            except (json.JSONDecodeError, AttributeError):
                pass
        elif name == "requirements.txt":
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)", line)
                if m:
                    _add_dep(deps, m.group(1), m.group(2), "PyPI", priority=3)
            manifests.append(path)
        elif name == "pom.xml":
            try:
                root = ET.fromstring(text)
                ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
                def find_text(parent, tag):
                    node = parent.find(f"m:{tag}", ns) if ns else parent.find(tag)
                    return node.text.strip() if node is not None and node.text else ""
                for node in root.iter():
                    if node.tag.endswith("dependency"):
                        group = find_text(node, "groupId")
                        artifact = find_text(node, "artifactId")
                        version = find_text(node, "version")
                        if group and artifact and version and "${" not in version:
                            _add_dep(deps, f"{group}:{artifact}", version, "Maven", priority=2)
                manifests.append(path)
            except ET.ParseError:
                pass
    # Prefer exact lockfile versions over package.json ranges regardless of ZIP order.
    unique: dict[tuple[str, str], dict] = {}
    for dep in deps:
        key = (dep["ecosystem"], dep["name"].lower())
        current = unique.get(key)
        if current is None or dep["_priority"] > current["_priority"]:
            unique[key] = dep
    normalized = []
    for dep in unique.values():
        item = dict(dep)
        item.pop("_priority", None)
        normalized.append(item)
    return normalized[:MAX_DEPENDENCIES], sorted(set(manifests))

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic high-entropy token assignment", re.compile(r"(?i)(?:api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*['\"][A-Za-z0-9_./+=-]{20,}['\"]")),
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
]

def scan_secrets(files: dict[str, bytes]) -> list[dict]:
    findings = []
    for path, raw in files.items():
        if len(raw) > 250_000:
            continue
        text = raw.decode("utf-8", errors="ignore")
        if "\x00" in text:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "SECRET", "title": f"Possible {label}",
                        "severity": "HIGH", "packageName": None, "installedVersion": None,
                        "cve": None, "summary": "A credential-like pattern was found. Verify whether it is a real secret, revoke/rotate it if confirmed, and remove it from repository history.",
                        "filePath": path, "lineNumber": line_no,
                        "evidence": f"{label} pattern matched at {path}:{line_no}; matched value is redacted.",
                        "recommendation": "Validate whether this is an active credential. If confirmed, revoke or rotate it, remove it from the repository and its history, and move secrets into a managed secret store.",
                        "source": "TrustForge pattern detector", "references": []
                    })
                    break
    return findings[:100]

def scan_dockerfiles(files: dict[str, bytes]) -> list[dict]:
    findings = []
    for path, raw in files.items():
        if PurePosixPath(path).name.lower() != "dockerfile":
            continue
        text = raw.decode("utf-8", errors="ignore")
        checks = [
            (r"(?im)^\s*USER\s+root\s*$", "Container explicitly runs as root", "HIGH",
             "Use a dedicated non-root user in the final image."),
            (r"(?im)^\s*ADD\s+https?://", "Dockerfile downloads remote content with ADD", "MEDIUM",
             "Fetch and verify remote artifacts explicitly with checksums, preferably in a controlled build stage."),
            (r"(?im)^\s*FROM\s+[^@\s]+(?::latest)?\s*$", "Base image is not pinned by digest", "LOW",
             "Pin base images by immutable digest for reproducible builds."),
            (r"(?im)^\s*RUN\s+.*(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash)\b", "Docker build executes a remotely downloaded script", "HIGH",
             "Avoid piping remote content directly to a shell. Pin the artifact, verify its checksum/signature, and review it before execution."),
        ]
        for pattern, title, severity, advice in checks:
            m = re.search(pattern, text)
            if m:
                line_no = text[:m.start()].count("\n") + 1
                findings.append({
                    "type": "CONFIGURATION", "title": title, "severity": severity,
                    "packageName": None, "installedVersion": None, "cve": None,
                    "summary": advice, "filePath": path, "lineNumber": line_no,
                    "evidence": f"Static Dockerfile rule matched at {path}:{line_no}.",
                    "recommendation": advice,
                    "source": "TrustForge Dockerfile rules", "references": []
                })
    return findings

def _normalise_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().upper()
    aliases = {
        "MODERATE": "MEDIUM",
        "IMPORTANT": "HIGH",
        "SEVERE": "CRITICAL",
    }
    text = aliases.get(text, text)
    return text if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else None


def cvss31_score_from_vector(vector: Any) -> Optional[float]:
    """Calculate CVSS v3.0/v3.1 base score from a complete vector.

    Unsupported or incomplete vectors return None instead of guessing. CVSS v4
    vectors are deliberately not approximated by this v3 calculator.
    """
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        if not required.issubset(metrics):
            return None
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope = metrics["S"]
        pr = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50},
        }[scope][metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        c, i, a = (impact_values[metrics[key]] for key in ("C", "I", "A"))
        isc = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope == "U":
            impact = 6.42 * isc
        elif scope == "C":
            impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
        else:
            return None
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        base = min(impact + exploitability, 10.0) if scope == "U" else min(1.08 * (impact + exploitability), 10.0)
        return math.ceil((base - 1e-10) * 10) / 10
    except (KeyError, TypeError, ValueError):
        return None


def cvss_score_from_osv(vuln: dict) -> tuple[Optional[float], Optional[str]]:
    """Return the highest supported numeric/CVSSv3 score and vector."""
    candidates: list[tuple[float, Optional[str]]] = []
    for item in vuln.get("severity", []) or []:
        if not isinstance(item, dict):
            continue
        raw = item.get("score")
        vector = raw if isinstance(raw, str) and raw.startswith("CVSS:") else None
        if isinstance(raw, dict):
            raw = raw.get("baseScore", raw.get("score"))
        numeric: Optional[float] = cvss31_score_from_vector(vector) if vector else None
        if numeric is None:
            try:
                value = float(raw)
                if 0 <= value <= 10:
                    numeric = value
            except (TypeError, ValueError):
                pass
        if numeric is None:
            try:
                value = float(item.get("baseScore"))
                if 0 <= value <= 10:
                    numeric = value
            except (TypeError, ValueError):
                pass
        if numeric is not None:
            candidates.append((numeric, vector))
    return max(candidates, key=lambda entry: entry[0]) if candidates else (None, None)


def _severity_from_score(value: Any) -> Optional[str]:
    if value is None:
        return None
    score: Optional[float]
    if isinstance(value, str) and value.startswith("CVSS:"):
        score = cvss31_score_from_vector(value)
    else:
        try:
            score = float(value)
        except (TypeError, ValueError):
            return None
    if score is None or not 0 <= score <= 10:
        return None
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return None


def severity_from_osv(vuln: dict) -> str:
    """Resolve severity from OSV database/ecosystem fields then CVSS data."""
    direct_sources = [vuln.get("database_specific") or {}]
    for affected in vuln.get("affected", []) or []:
        if isinstance(affected, dict):
            direct_sources.extend([
                affected.get("database_specific") or {},
                affected.get("ecosystem_specific") or {},
            ])
    for source in direct_sources:
        if not isinstance(source, dict):
            continue
        for key in ("severity", "severity_level", "severityLevel"):
            resolved = _normalise_severity(source.get(key))
            if resolved:
                return resolved
    score, _ = cvss_score_from_osv(vuln)
    return _severity_from_score(score) or "UNKNOWN"


def _affected_metadata(vuln: dict, dependency: dict) -> tuple[list[str], list[str]]:
    """Extract OSV fixed versions and affected event ranges for a dependency."""
    fixed: list[str] = []
    ranges: list[str] = []
    for affected in vuln.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        if package:
            pkg_name = str(package.get("name", "")).lower()
            pkg_ecosystem = str(package.get("ecosystem", "")).lower()
            if pkg_name and pkg_name != dependency["name"].lower():
                continue
            expected = dependency["ecosystem"].lower()
            if pkg_ecosystem and pkg_ecosystem != expected:
                continue
        for version_range in affected.get("ranges", []) or []:
            if not isinstance(version_range, dict):
                continue
            parts: list[str] = []
            for event in version_range.get("events", []) or []:
                if not isinstance(event, dict):
                    continue
                for event_name in ("introduced", "fixed", "last_affected", "limit"):
                    if event_name in event:
                        value = str(event[event_name])
                        parts.append(f"{event_name.replace('_', ' ')} {value}")
                        if event_name == "fixed" and value not in {"0", ""}:
                            fixed.append(value)
            if parts:
                ranges.append(" → ".join(parts))
    return sorted(set(fixed)), sorted(set(ranges))


async def _hydrate_osv_vulnerability(client: httpx.AsyncClient, vuln: dict) -> tuple[dict, Optional[str]]:
    """Fetch canonical OSV record when querybatch omits useful metadata."""
    vuln_id = vuln.get("id")
    if not vuln_id:
        return vuln, None
    try:
        response = await client.get(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=12.0)
        response.raise_for_status()
        full = response.json()
        if not isinstance(full, dict):
            return vuln, f"OSV detail lookup for {vuln_id} returned an unexpected format."
        merged = dict(vuln)
        merged.update({key: value for key, value in full.items() if value not in (None, "", [], {})})
        return merged, None
    except (httpx.HTTPError, ValueError) as exc:
        return vuln, f"OSV detail lookup for {vuln_id} failed ({type(exc).__name__})."


async def query_osv(dependencies: list[dict]) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    errors: list[str] = []
    if not dependencies:
        return findings, errors
    queries = [
        {"package": {"name": dep["name"], "ecosystem": dep["ecosystem"]}, "version": dep["version"]}
        for dep in dependencies
    ]
    try:
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True, limits=limits) as client:
            raw_matches: list[tuple[dict, dict]] = []
            for start in range(0, len(queries), 100):
                response = await client.post(
                    "https://api.osv.dev/v1/querybatch", json={"queries": queries[start:start + 100]}
                )
                response.raise_for_status()
                results = response.json().get("results", [])
                for offset, result in enumerate(results):
                    index = start + offset
                    if index >= len(dependencies):
                        continue
                    for vuln in result.get("vulns", []) or []:
                        if isinstance(vuln, dict):
                            raw_matches.append((dependencies[index], vuln))

            # OSV batch responses can be abbreviated. Fetch the canonical
            # vulnerability document for records missing severity or details.
            to_hydrate: dict[str, dict] = {}
            for _, vuln in raw_matches:
                vuln_id = vuln.get("id")
                if vuln_id and (severity_from_osv(vuln) == "UNKNOWN" or not vuln.get("details")):
                    to_hydrate.setdefault(str(vuln_id), vuln)
            hydrated: dict[str, dict] = {}
            if len(to_hydrate) > 30:
                errors.append("OSV canonical detail enrichment was capped at 30 advisories for scan-time control; remaining querybatch records are retained as returned.")
                to_hydrate = dict(list(to_hydrate.items())[:30])
            semaphore = asyncio.Semaphore(8)
            if to_hydrate:
                async def hydrate_limited(vuln_id: str, item: dict):
                    async with semaphore:
                        return vuln_id, await _hydrate_osv_vulnerability(client, item)
                responses = await asyncio.gather(*(
                    hydrate_limited(vuln_id, item) for vuln_id, item in to_hydrate.items()
                ))
                for vuln_id, (full, warning) in responses:
                    hydrated[vuln_id] = full
                    if warning:
                        errors.append(warning)

            seen: set[tuple[str, str, str]] = set()
            for dep, original in raw_matches:
                vuln_id = str(original.get("id") or "unknown-advisory")
                vuln = hydrated.get(vuln_id, original)
                dedupe_key = (dep["ecosystem"], dep["name"].lower(), vuln_id)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                severity = severity_from_osv(vuln)
                cvss_score, cvss_vector = cvss_score_from_osv(vuln)
                fixed_versions, affected_ranges = _affected_metadata(vuln, dep)
                database_specific = vuln.get("database_specific") or {}
                aliases = vuln.get("aliases", []) or []
                cve = next((alias for alias in aliases if str(alias).startswith("CVE-")), None)
                title = vuln.get("summary") or f"Vulnerable dependency: {dep['name']}"
                details = (vuln.get("details") or vuln.get("summary") or "")[:4000]
                references = [
                    item.get("url") for item in vuln.get("references", []) or []
                    if isinstance(item, dict) and item.get("url")
                ][:12]
                advisory_url = f"https://osv.dev/vulnerability/{vuln_id}"
                if advisory_url not in references:
                    references.insert(0, advisory_url)
                if fixed_versions:
                    recommendation = (
                        f"Upgrade {dep['name']} to a fixed version: {', '.join(fixed_versions)}. "
                        "Confirm compatibility and run regression tests."
                    )
                else:
                    recommendation = (
                        "OSV did not provide a fixed version for this affected range. Review the "
                        "advisory and maintainer guidance; assess whether the vulnerable code path is used."
                    )
                if severity == "UNKNOWN":
                    recommendation += " Severity is unclassified; UNKNOWN does not mean safe."
                findings.append({
                    "type": "DEPENDENCY_VULNERABILITY",
                    "title": title,
                    "severity": severity,
                    "packageName": dep["name"],
                    "installedVersion": dep["version"],
                    "ecosystem": dep["ecosystem"],
                    "cve": cve or vuln_id,
                    "advisoryId": vuln_id,
                    "aliases": aliases[:12],
                    "summary": details,
                    "cvssScore": cvss_score,
                    "cvssVector": cvss_vector,
                    "fixedVersions": fixed_versions,
                    "affectedRanges": affected_ranges,
                    "published": vuln.get("published"),
                    "modified": vuln.get("modified"),
                    "cwes": (database_specific.get("cwe_ids") or [])[:12],
                    "filePath": None,
                    "lineNumber": None,
                    "evidence": f"OSV matched advisory {vuln_id} to {dep['name']} {dep['version']} ({dep['ecosystem']}).",
                    "recommendation": recommendation,
                    "source": "OSV",
                    "references": references,
                })
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        errors.append(f"OSV enrichment unavailable: {type(exc).__name__}. Dependency inventory was still collected.")
    return findings, errors

def _finding_points(severity: str) -> int:
    return {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "UNKNOWN": 5}.get(severity, 0)


def _risk_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MODERATE"
    if score > 0:
        return "LOW"
    return "NONE"


async def _download_github_archive(client: httpx.AsyncClient, archive_url: str) -> bytes:
    """Stream the ZIP and stop reading as soon as the configured limit is crossed."""
    chunks: list[bytes] = []
    total = 0
    async with client.stream("GET", archive_url) as response:
        response.raise_for_status()
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except (TypeError, ValueError):
                declared_size = None
            if declared_size is not None and declared_size > MAX_ARCHIVE_BYTES:
                raise ValueError("Repository archive exceeds the 20 MB download limit.")
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("Repository archive exceeds the 20 MB download limit.")
            chunks.append(chunk)
    return b"".join(chunks)


async def scan_github_repository(url: str) -> dict[str, Any]:
    owner, repo = parse_github_url(url)
    archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "TrustForge-AI"}
    async with httpx.AsyncClient(timeout=40.0, follow_redirects=True, headers=headers) as client:
        archive_bytes = await _download_github_archive(client, archive_url)
    files = safe_read_archive(archive_bytes)
    dependencies, manifests = extract_dependencies(files)
    osv_findings, errors = await query_osv(dependencies)
    findings = osv_findings + scan_secrets(files) + scan_dockerfiles(files)

    severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    counts = {severity: sum(1 for finding in findings if finding["severity"] == severity)
              for severity in severity_order}
    points_by_severity = {
        severity: counts[severity] * _finding_points(severity)
        for severity in severity_order
    }
    total_before_cap = sum(points_by_severity.values())
    risk_score = min(100, total_before_cap)
    for finding in findings:
        finding["riskContribution"] = _finding_points(finding["severity"])
    recommendations = []
    for finding in findings:
        recommendation = finding.get("recommendation")
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
    return {
        "repository": f"{owner}/{repo}",
        "scanStatus": "COMPLETED",
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "filesInspected": len(files),
        "manifests": manifests,
        "dependencyCount": len(dependencies),
        "dependencies": dependencies,
        "findings": findings,
        "severityCounts": counts,
        "riskScore": risk_score,
        "riskLevel": _risk_level(risk_score),
        "riskBreakdown": {
            "severityCounts": counts,
            "pointsBySeverity": points_by_severity,
            "totalBeforeCap": total_before_cap,
        },
        "topRecommendations": recommendations[:20],
        "riskScoreNote": "Heuristic prioritization score from detected findings; not a probability of compromise. UNKNOWN findings contribute review priority and must not be interpreted as safe.",
        "enrichmentWarnings": errors,
    }

def make_cyclonedx(repository: str, dependencies: list[dict], findings: Optional[list[dict]] = None) -> dict:
    components = []
    ref_by_package: dict[tuple[str, str, str], str] = {}
    for dep in dependencies:
        ecosystem = dep["ecosystem"]
        purl_type = {"npm": "npm", "PyPI": "pypi", "Maven": "maven"}.get(ecosystem, ecosystem.lower())
        name = dep["name"]
        if purl_type == "maven" and ":" in name:
            group, artifact = name.split(":", 1)
            purl = f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='.-_')}@{quote(dep['version'], safe='.+-_')}"
        else:
            purl = f"pkg:{purl_type}/{quote(name, safe='/.-_')}@{quote(dep['version'], safe='.+-_')}"
        ref_by_package[(ecosystem.lower(), name.lower(), dep["version"])] = purl
        components.append({
            "type": "library", "name": name, "version": dep["version"],
            "purl": purl, "bom-ref": purl
        })

    vulnerabilities = []
    for finding in findings or []:
        if finding.get("type") != "DEPENDENCY_VULNERABILITY":
            continue
        key = (
            str(finding.get("ecosystem", "")).lower(),
            str(finding.get("packageName", "")).lower(),
            str(finding.get("installedVersion", "")),
        )
        package_ref = ref_by_package.get(key)
        if not package_ref:
            continue
        vulnerability: dict[str, Any] = {
            "id": finding.get("advisoryId") or finding.get("cve") or finding.get("title"),
            "source": {"name": "OSV", "url": (finding.get("references") or ["https://osv.dev"])[0]},
            "description": finding.get("summary") or finding.get("title") or "Dependency vulnerability",
            "recommendation": finding.get("recommendation") or "Review the upstream advisory and update when a fix is available.",
            "affects": [{"ref": package_ref}],
        }
        if finding.get("cvssScore") is not None:
            rating: dict[str, Any] = {
                "source": {"name": "OSV"},
                "score": finding["cvssScore"],
                "severity": str(finding.get("severity", "unknown")).lower(),
                "method": "CVSSv3",
            }
            if finding.get("cvssVector"):
                rating["vector"] = finding["cvssVector"]
            vulnerability["ratings"] = [rating]
        if finding.get("cwes"):
            cwe_numbers = []
            for cwe in finding["cwes"]:
                match = re.search(r"(\d+)", str(cwe))
                if match:
                    cwe_numbers.append(int(match.group(1)))
            if cwe_numbers:
                vulnerability["cwes"] = sorted(set(cwe_numbers))
        if finding.get("references"):
            vulnerability["advisories"] = [{"url": ref} for ref in finding["references"][:12]]
        vulnerabilities.append(vulnerability)

    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": repository}},
        "components": components,
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom

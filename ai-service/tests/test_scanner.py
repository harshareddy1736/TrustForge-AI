import asyncio, io, json, zipfile
import pytest
from app.scanner import (parse_github_url, safe_read_archive, extract_dependencies, scan_secrets, scan_dockerfiles, make_cyclonedx, severity_from_osv, cvss31_score_from_vector, cvss_score_from_osv, _affected_metadata, _finding_points, _risk_level, _hydrate_osv_vulnerability, _download_github_archive, scan_github_repository)

def make_zip(items):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in items.items():
            z.writestr("owner-repo-main/" + name, content)
    return buf.getvalue()

def test_parse_github_url():
    assert parse_github_url("https://github.com/openai/example")[0] == "openai"
    with pytest.raises(ValueError):
        parse_github_url("https://example.com/a/b")

def test_extract_npm_and_python_dependencies():
    files = {
        "package.json": json.dumps({"dependencies": {"express": "^4.18.2"}}).encode(),
        "requirements.txt": b"requests==2.31.0\nflask>=2.0\n",
    }
    deps, manifests = extract_dependencies(files)
    assert any(d["name"] == "express" and d["ecosystem"] == "npm" for d in deps)
    assert any(d["name"] == "requests" and d["ecosystem"] == "PyPI" for d in deps)
    assert len(manifests) == 2

def test_safe_archive_ignores_parent_paths():
    archive = make_zip({"package.json": '{"dependencies":{}}', "../escape.txt": "bad"})
    files = safe_read_archive(archive)
    assert "package.json" in files
    assert all(".." not in path for path in files)

def test_secret_detector_redacts_matched_value():
    files = {"config.txt": b'api_key = "abcdefghijklmnopqrstuvwxyz1234567890"'}
    findings = scan_secrets(files)
    assert findings and "redacted" in findings[0]["evidence"]
    assert "abcdefghijklmnopqrstuvwxyz" not in findings[0]["evidence"]

def test_dockerfile_rule():
    findings = scan_dockerfiles({"Dockerfile": b"FROM ubuntu:latest\nUSER root\n"})
    assert len(findings) >= 1

def test_sbom_is_cyclonedx():
    bom = make_cyclonedx("owner/repo", [{"name":"requests","version":"2.31.0","ecosystem":"PyPI"}])
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["components"][0]["version"] == "2.31.0"


def test_osv_severity_from_vulnerability_database_specific():
    assert severity_from_osv({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"


def test_osv_severity_from_affected_ecosystem_specific():
    vuln = {"affected": [{"ecosystem_specific": {"severity": "CRITICAL"}}]}
    assert severity_from_osv(vuln) == "CRITICAL"


def test_osv_severity_from_cvss_numeric_score():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "8.1"}]}
    assert severity_from_osv(vuln) == "HIGH"


def test_osv_cvss_vector_is_parsed_instead_of_misread_as_plain_float():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert severity_from_osv(vuln) == "CRITICAL"


@pytest.mark.parametrize(("vector", "expected", "severity"), [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N", 4.0, "MEDIUM"),
])
def test_cvss31_vector_scoring(vector, expected, severity):
    from app.scanner import _severity_from_score
    assert cvss31_score_from_vector(vector) == expected
    assert _severity_from_score(vector) == severity


def test_cvss4_vector_is_not_guessed_by_cvss3_calculator():
    assert cvss31_score_from_vector("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N") is None


def test_cvss_score_extracts_vector_and_base_score():
    score, vector = cvss_score_from_osv({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
    })
    assert score == 7.5
    assert vector.startswith("CVSS:3.1/")


def test_osv_fixed_versions_and_affected_ranges():
    vuln = {"affected": [{
        "package": {"name": "body-parser", "ecosystem": "npm"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "2.0.0"}, {"fixed": "2.4.0"}
        ]}]
    }]}
    fixed, ranges = _affected_metadata(vuln, {"name": "body-parser", "ecosystem": "npm", "version": "2.3.0"})
    assert fixed == ["2.4.0"]
    assert ranges == ["introduced 2.0.0 → fixed 2.4.0"]


def test_cyclonedx_sbom_includes_vulnerability_affects_component():
    dependencies = [{"name": "body-parser", "version": "2.3.0", "ecosystem": "npm"}]
    findings = [{
        "type": "DEPENDENCY_VULNERABILITY", "advisoryId": "GHSA-test", "cve": "CVE-2026-0001",
        "packageName": "body-parser", "installedVersion": "2.3.0", "ecosystem": "npm",
        "severity": "HIGH", "summary": "Example vulnerability", "cvssScore": 7.5,
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "references": ["https://osv.dev/vulnerability/GHSA-test"],
        "recommendation": "Upgrade to 2.4.0", "cwes": ["CWE-248"]
    }]
    bom = make_cyclonedx("owner/repo", dependencies, findings)
    assert bom["specVersion"] == "1.5"
    assert bom["vulnerabilities"][0]["id"] == "GHSA-test"
    assert bom["vulnerabilities"][0]["affects"][0]["ref"] == bom["components"][0]["bom-ref"]
    assert bom["vulnerabilities"][0]["ratings"][0]["score"] == 7.5
    assert bom["vulnerabilities"][0]["ratings"][0]["method"] == "CVSSv3"


def test_unknown_findings_still_add_review_priority():
    assert _finding_points("UNKNOWN") > 0
    assert _risk_level(0) == "NONE"
    assert _risk_level(40) == "HIGH"
    assert _risk_level(75) == "CRITICAL"


@pytest.mark.parametrize("order", [
    {"package.json": '{"dependencies":{"left-pad":"^1.0.0"}}',
     "package-lock.json": '{"packages":{"":{"name":"sample"},"node_modules/left-pad":{"version":"1.3.0"}}}'},
    {"package-lock.json": '{"packages":{"":{"name":"sample"},"node_modules/left-pad":{"version":"1.3.0"}}}',
     "package.json": '{"dependencies":{"left-pad":"^1.0.0"}}'},
])
def test_lockfile_versions_win_regardless_of_archive_order(order):
    files = {name: content.encode() for name, content in order.items()}
    dependencies, _ = extract_dependencies(files)
    left_pad = next(item for item in dependencies if item["name"] == "left-pad")
    assert left_pad["version"] == "1.3.0"
    assert "_priority" not in left_pad


def test_secret_detector_additional_token_pattern_and_redaction():
    findings = scan_secrets({"config.txt": b'SLACK_TOKEN="xoxb-123456789012345678901234"'})
    assert findings
    assert findings[0]["severity"] == "HIGH"
    assert "recommendation" in findings[0]
    assert "123456789012" not in findings[0]["evidence"]


def test_docker_remote_shell_execution_rule():
    findings = scan_dockerfiles({"Dockerfile": b"FROM python:3.12\nRUN curl https://example.invalid/install.sh | bash\n"})
    assert any("remotely downloaded script" in finding["title"] for finding in findings)
    assert all("recommendation" in finding for finding in findings)


def test_osv_detail_hydration_fills_missing_severity_and_details():
    class FakeResponse:
        def raise_for_status(self):
            return None
        def json(self):
            return {
                "id": "GHSA-example",
                "summary": "Example advisory",
                "details": "Full advisory detail",
                "database_specific": {"severity": "HIGH"},
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
            }
    class FakeClient:
        async def get(self, url, **kwargs):
            assert kwargs.get("timeout") == 12.0
            assert url.endswith("GHSA-example")
            return FakeResponse()
    original = {"id": "GHSA-example"}
    hydrated, warning = asyncio.run(_hydrate_osv_vulnerability(FakeClient(), original))
    assert warning is None
    assert severity_from_osv(hydrated) == "HIGH"
    assert hydrated["details"] == "Full advisory detail"



def test_query_osv_hydrates_abbreviated_querybatch_record(monkeypatch):
    from app import scanner

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload
        def raise_for_status(self):
            return None
        def json(self):
            return self.payload

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, json):
            assert url.endswith("/v1/querybatch")
            assert json["queries"][0]["package"]["name"] == "body-parser"
            return FakeResponse({"results": [{"vulns": [{"id": "GHSA-27r3-jxmh-p828"}]}]})
        async def get(self, url, **kwargs):
            assert kwargs.get("timeout") == 12.0
            assert url.endswith("GHSA-27r3-jxmh-p828")
            return FakeResponse({
                "id": "GHSA-27r3-jxmh-p828",
                "summary": "body-parser denial of service",
                "details": "Detailed advisory text",
                "published": "2026-10-23T20:53:11Z",
                "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-248"]},
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                "affected": [{
                    "package": {"name": "body-parser", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.4.0"}]}]
                }],
                "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-27r3-jxmh-p828"}],
            })

    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeAsyncClient)
    findings, warnings = asyncio.run(scanner.query_osv([
        {"name": "body-parser", "version": "2.3.0", "ecosystem": "npm"}
    ]))
    assert not warnings
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["cvssScore"] == 7.5
    assert findings[0]["fixedVersions"] == ["2.4.0"]
    assert findings[0]["advisoryId"] == "GHSA-27r3-jxmh-p828"
    assert findings[0]["recommendation"].startswith("Upgrade body-parser")



def test_scan_repository_returns_severity_risk_and_recommendations(monkeypatch):
    from app import scanner
    archive = make_zip({
        "package.json": json.dumps({"dependencies": {"body-parser": "2.3.0"}}),
        "Dockerfile": "FROM python:3.12\nUSER root\n",
    })

    class FakeStreamResponse:
        headers = {"content-length": str(len(archive))}
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        def raise_for_status(self):
            return None
        async def aiter_bytes(self):
            yield archive[:20]
            yield archive[20:]

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        def stream(self, method, url):
            assert method == "GET"
            assert url.endswith("/repos/owner/repo/zipball")
            return FakeStreamResponse()

    async def fake_query_osv(dependencies):
        assert dependencies[0]["name"] == "body-parser"
        return ([{
            "type": "DEPENDENCY_VULNERABILITY", "title": "Test advisory", "severity": "HIGH",
            "packageName": "body-parser", "installedVersion": "2.3.0", "ecosystem": "npm",
            "recommendation": "Upgrade to a fixed version.", "references": [],
        }], [])

    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(scanner, "query_osv", fake_query_osv)
    result = asyncio.run(scan_github_repository("https://github.com/owner/repo"))
    assert result["scanStatus"] == "COMPLETED"
    assert result["dependencyCount"] == 1
    assert result["severityCounts"]["HIGH"] == 2  # OSV finding + root-user Dockerfile finding
    assert result["riskScore"] == 44
    assert result["riskLevel"] == "HIGH"
    assert result["topRecommendations"]


def test_archive_stream_stops_when_download_exceeds_limit(monkeypatch):
    from app import scanner
    class FakeStreamResponse:
        headers = {}
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def raise_for_status(self): return None
        async def aiter_bytes(self):
            yield b"x" * (scanner.MAX_ARCHIVE_BYTES + 1)
    class FakeClient:
        def stream(self, method, url): return FakeStreamResponse()
    with pytest.raises(ValueError, match="20 MB"):
        asyncio.run(_download_github_archive(FakeClient(), "https://api.github.com/repos/o/r/zipball"))


def test_safe_archive_rejects_excessive_total_uncompressed_content():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for index in range(53):
            zipped.writestr(f"owner-repo-main/file-{index}.txt", b"0" * 1_000_000)
    archive = buffer.getvalue()
    assert len(archive) < 20 * 1024 * 1024
    with pytest.raises(ValueError, match="50 MB inspection limit"):
        safe_read_archive(archive)

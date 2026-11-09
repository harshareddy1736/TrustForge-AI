from fastapi.testclient import TestClient

from app import main


def _fake_scan(repository_url: str):
    async def fake(repository_url_arg: str):
        return {
            "repository": "owner/repo",
            "scanStatus": "COMPLETED",
            "receivedRepositoryUrl": repository_url_arg,
            "dependencyCount": 0,
            "findings": [],
            "riskScore": 0,
        }
    return fake


def test_scan_accepts_standard_json_body(monkeypatch):
    monkeypatch.setattr(main, "scan_github_repository", _fake_scan("unused"))
    client = TestClient(main.app)

    response = client.post(
        "/api/v1/scan",
        json={"repository_url": "https://github.com/expressjs/express"},
    )

    assert response.status_code == 200
    assert response.json()["receivedRepositoryUrl"] == "https://github.com/expressjs/express"


def test_scan_accepts_java_repository_header_without_body(monkeypatch):
    monkeypatch.setattr(main, "scan_github_repository", _fake_scan("unused"))
    client = TestClient(main.app)

    response = client.post(
        "/api/v1/scan",
        headers={"X-Repository-Url": "https://github.com/expressjs/express"},
    )

    assert response.status_code == 200
    assert response.json()["receivedRepositoryUrl"] == "https://github.com/expressjs/express"


def test_scan_rejects_request_without_body_or_header():
    client = TestClient(main.app)

    response = client.post("/api/v1/scan")

    assert response.status_code == 422
    assert "X-Repository-Url" in response.text


def test_sbom_endpoint_includes_vulnerability_metadata(monkeypatch):
    async def fake_scan(repository_url: str):
        return {
            "repository": "owner/repo",
            "dependencies": [{"name": "body-parser", "version": "2.3.0", "ecosystem": "npm"}],
            "findings": [{
                "type": "DEPENDENCY_VULNERABILITY", "advisoryId": "GHSA-example",
                "packageName": "body-parser", "installedVersion": "2.3.0", "ecosystem": "npm",
                "severity": "HIGH", "cvssScore": 7.5,
                "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "references": ["https://osv.dev/vulnerability/GHSA-example"],
                "summary": "Sample advisory", "recommendation": "Upgrade to a fixed release.",
            }],
        }
    monkeypatch.setattr(main, "scan_github_repository", fake_scan)
    client = TestClient(main.app)
    response = client.post("/api/v1/sbom", json={"repository_url": "https://github.com/owner/repo"})
    assert response.status_code == 200
    bom = response.json()
    assert bom["specVersion"] == "1.5"
    assert bom["vulnerabilities"][0]["id"] == "GHSA-example"
    assert bom["vulnerabilities"][0]["ratings"][0]["score"] == 7.5

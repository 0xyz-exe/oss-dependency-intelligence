"""Integration tests for FastAPI endpoints."""
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import init_db

client = TestClient(app)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"

def setup_module():
    init_db()

def test_api_health():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_project_crud_and_scan():
    # 1. Create project
    npm_path = str(FIXTURES_DIR / "sample-npm")
    res = client.post("/api/v1/projects", json={
        "name": "Integration Test Project",
        "description": "Testing project creation",
        "ecosystem": "npm",
        "target_path": npm_path
    })
    assert res.status_code == 200
    proj_data = res.json()
    proj_id = proj_data["id"]

    # 2. Trigger scan
    scan_res = client.post(f"/api/v1/projects/{proj_id}/scans")
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] == "completed"
    assert scan_data["total_dependencies"] >= 4
    assert scan_data["vulnerabilities_count"] >= 1

    # 3. Get dependencies
    dep_res = client.get(f"/api/v1/scans/{scan_id}/dependencies")
    assert dep_res.status_code == 200
    deps = dep_res.json()
    assert len(deps) >= 4

    # 4. Get vulnerabilities
    vuln_res = client.get(f"/api/v1/scans/{scan_id}/vulnerabilities")
    assert vuln_res.status_code == 200
    vulns = vuln_res.json()
    assert len(vulns) >= 1

    # 5. Get licenses
    lic_res = client.get(f"/api/v1/scans/{scan_id}/licenses")
    assert lic_res.status_code == 200
    lics = lic_res.json()
    assert "summary" in lics

    # 6. Export CycloneDX SBOM
    sbom_res = client.get(f"/api/v1/scans/{scan_id}/sbom?format=cyclonedx-json")
    assert sbom_res.status_code == 200
    assert sbom_res.json()["bomFormat"] == "CycloneDX"

    # 7. Export SPDX SBOM
    spdx_res = client.get(f"/api/v1/scans/{scan_id}/sbom?format=spdx-json")
    assert spdx_res.status_code == 200
    assert spdx_res.json()["spdxVersion"] == "SPDX-2.3"

    # 8. Export CSV report
    csv_res = client.get(f"/api/v1/scans/{scan_id}/report?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers.get("content-type", "")

    # 9. Policy evaluation
    policy_res = client.get(f"/api/v1/scans/{scan_id}/policy-evaluation")
    assert policy_res.status_code == 200
    pol_eval = policy_res.json()
    assert pol_eval["result"] in ("PASS", "WARN", "FAIL")

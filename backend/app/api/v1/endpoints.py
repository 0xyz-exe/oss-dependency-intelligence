"""FastAPI REST API v1 endpoints for OSS Dependency Intelligence."""
import io
import csv
import json
import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Form, Response
from backend.app.core.database import get_db
from backend.app.schemas.models import (
    ProjectCreate, ProjectOut, ScanOut, PolicyCreate, PolicyOut,
    PolicyEvaluationResult, ScanCompareRequest, ScanCompareResult,
    DependencyItem, VulnerabilityItem
)
from backend.app.services.ingestion.scanner import ingestion_scanner
from backend.app.services.sbom.generator import sbom_generator
from backend.app.services.policies.engine import policy_engine
from backend.app.services.compare.engine import scan_comparator

router = APIRouter()

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "OSS Dependency Intelligence",
        "version": "1.0.0"
    }

# ----------------- Projects -----------------

@router.get("/projects", response_model=List[ProjectOut])
def list_projects():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM projects ORDER BY created_at DESC;")
        rows = cur.fetchall()
        projects = []
        for r in rows:
            # fetch latest scan
            s_cur = conn.execute(
                "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC LIMIT 1;",
                (r["id"],)
            )
            s_row = s_cur.fetchone()
            latest = dict(s_row) if s_row else None
            projects.append(ProjectOut(
                id=r["id"],
                name=r["name"],
                description=r["description"] or "",
                ecosystem=r["ecosystem"] or "",
                repository_url=r["repository_url"] or "",
                target_path=r["target_path"] or "",
                created_at=r["created_at"],
                updated_at=r["updated_at"],
                latest_scan=latest
            ))
        return projects

@router.post("/projects", response_model=ProjectOut)
def create_project(data: ProjectCreate):
    p_id = f"proj-{uuid.uuid4().hex[:8]}"
    with get_db() as conn:
        conn.execute(
            "INSERT INTO projects (id, name, description, ecosystem, repository_url, target_path) VALUES (?, ?, ?, ?, ?, ?);",
            (p_id, data.name, data.description, data.ecosystem, data.repository_url, data.target_path)
        )
    return ProjectOut(
        id=p_id,
        name=data.name,
        description=data.description or "",
        ecosystem=data.ecosystem or "",
        repository_url=data.repository_url or "",
        target_path=data.target_path or "",
        created_at="just now",
        updated_at="just now"
    )

@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: str):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM projects WHERE id = ?;", (project_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        s_cur = conn.execute(
            "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC LIMIT 1;",
            (project_id,)
        )
        s_row = s_cur.fetchone()
        return ProjectOut(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            ecosystem=row["ecosystem"] or "",
            repository_url=row["repository_url"] or "",
            target_path=row["target_path"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            latest_scan=dict(s_row) if s_row else None
        )

@router.delete("/projects/{project_id}")
def delete_project(project_id: str):
    with get_db() as conn:
        conn.execute("DELETE FROM projects WHERE id = ?;", (project_id,))
    return {"success": True, "deleted": project_id}

# ----------------- Scans -----------------

@router.post("/projects/{project_id}/scans", response_model=ScanOut)
def trigger_scan(
    project_id: str,
    target_path: Optional[str] = Query(None)
):
    with get_db() as conn:
        p_row = conn.execute("SELECT * FROM projects WHERE id = ?;", (project_id,)).fetchone()
        if not p_row:
            raise HTTPException(status_code=404, detail="Project not found")
        scan_target = target_path or p_row["target_path"]
        if not scan_target:
            raise HTTPException(status_code=400, detail="No scan target specified.")
        
    try:
        return ingestion_scanner.scan_path(scan_target, project_id=project_id, project_name=p_row["name"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scans/upload", response_model=ScanOut)
async def upload_and_scan(
    project_name: str = Form("Uploaded Scan"),
    file: UploadFile = File(...)
):
    import tempfile
    filename = file.filename or "upload.bin"
    suffix = ".zip" if filename.endswith(".zip") else f"-{filename}"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        scan_result = ingestion_scanner.scan_path(tmp_path, project_name=project_name)
        return scan_result
    finally:
        try:
            import os
            os.remove(tmp_path)
        except Exception:
            pass

@router.get("/projects/{project_id}/scans", response_model=List[ScanOut])
def list_project_scans(project_id: str):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC;", (project_id,))
        return [ScanOut(**dict(r)) for r in cur.fetchall()]

@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        return ScanOut(**dict(row))

@router.get("/scans/{scan_id}/dependencies")
def get_scan_dependencies(
    scan_id: str,
    query: Optional[str] = None,
    ecosystem: Optional[str] = None,
    is_direct: Optional[bool] = None,
    license_status: Optional[str] = None
):
    with get_db() as conn:
        sql = "SELECT * FROM dependencies WHERE scan_id = ?"
        params: List[Any] = [scan_id]
        if query:
            sql += " AND name LIKE ?"
            params.append(f"%{query}%")
        if ecosystem:
            sql += " AND ecosystem = ?"
            params.append(ecosystem)
        if is_direct is not None:
            sql += " AND is_direct = ?"
            params.append(1 if is_direct else 0)
        if license_status:
            sql += " AND license_status = ?"
            params.append(license_status)
        sql += " ORDER BY risk_score DESC, name ASC;"
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

@router.get("/scans/{scan_id}/vulnerabilities")
def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    with get_db() as conn:
        sql = "SELECT * FROM vulnerabilities WHERE scan_id = ?"
        params: List[Any] = [scan_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity.upper())
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, dependency_name ASC;"
        cur = conn.execute(sql, params)
        results = []
        for r in cur.fetchall():
            d = dict(r)
            if d.get("references_json"):
                d["references"] = json.loads(d["references_json"])
            results.append(d)
        return results

@router.patch("/scans/{scan_id}/vulnerabilities/{vuln_id}")
def update_vulnerability_status(
    scan_id: str,
    vuln_id: str,
    status: str = Query(...)
):
    allowed_statuses = {"open", "in_progress", "fixed", "accepted_risk", "false_positive"}
    if status not in allowed_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {allowed_statuses}")
    with get_db() as conn:
        conn.execute("UPDATE vulnerabilities SET status = ? WHERE id = ? AND scan_id = ?;", (status, vuln_id, scan_id))
    return {"success": True, "vuln_id": vuln_id, "new_status": status}

@router.get("/scans/{scan_id}/licenses")
def get_scan_licenses(scan_id: str):
    with get_db() as conn:
        cur = conn.execute("""
        SELECT detected_license, license_category, license_status, COUNT(*) as count
        FROM dependencies
        WHERE scan_id = ?
        GROUP BY detected_license, license_category, license_status
        ORDER BY count DESC;
        """, (scan_id,))
        summary = [dict(r) for r in cur.fetchall()]
        return {"summary": summary}

# ----------------- SBOM & Reports -----------------

@router.get("/scans/{scan_id}/sbom")
def export_sbom(
    scan_id: str,
    format: str = Query("cyclonedx-json", pattern="^(cyclonedx-json|spdx-json)$")
):
    with get_db() as conn:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,)).fetchone()
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")
        proj_row = conn.execute("SELECT name FROM projects WHERE id = ?;", (scan_row["project_id"],)).fetchone()
        project_name = proj_row["name"] if proj_row else "Application"

        dep_rows = conn.execute("SELECT * FROM dependencies WHERE scan_id = ?;", (scan_id,)).fetchall()
        vuln_rows = conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?;", (scan_id,)).fetchall()

    deps = [DependencyItem(**dict(r)) for r in dep_rows]
    vulns = []
    for r in vuln_rows:
        d = dict(r)
        d["references"] = json.loads(d.get("references_json") or "[]")
        vulns.append(VulnerabilityItem(**d))

    if format == "cyclonedx-json":
        return sbom_generator.generate_cyclonedx_json(project_name, deps, vulns)
    else:
        return sbom_generator.generate_spdx_json(project_name, deps, vulns)

@router.get("/scans/{scan_id}/report")
def export_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|csv)$")
):
    with get_db() as conn:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,)).fetchone()
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")
        dep_rows = [dict(r) for r in conn.execute("SELECT * FROM dependencies WHERE scan_id = ?;", (scan_id,)).fetchall()]
        vuln_rows = [dict(r) for r in conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?;", (scan_id,)).fetchall()]

    if format == "json":
        return {
            "scan": dict(scan_row),
            "dependencies_count": len(dep_rows),
            "vulnerabilities_count": len(vuln_rows),
            "dependencies": dep_rows,
            "vulnerabilities": vuln_rows
        }
    else:
        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Name", "Version", "Ecosystem", "PURL", "Direct", "License", "License_Status", "Vulnerabilities", "Max_Severity", "Risk_Score"])
        for d in dep_rows:
            writer.writerow([
                d["name"], d["version"], d["ecosystem"], d["purl"],
                "Yes" if d["is_direct"] else "No",
                d["detected_license"], d["license_status"],
                d["vulnerability_count"], d["max_severity"], d["risk_score"]
            ])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=ossdi-report-{scan_id}.csv"}
        )

# ----------------- Compare -----------------

@router.post("/scans/compare", response_model=ScanCompareResult)
def compare_scans(body: ScanCompareRequest):
    with get_db() as conn:
        b_scan = conn.execute("SELECT * FROM scans WHERE id = ?;", (body.baseline_scan_id,)).fetchone()
        c_scan = conn.execute("SELECT * FROM scans WHERE id = ?;", (body.current_scan_id,)).fetchone()
        if not b_scan or not c_scan:
            raise HTTPException(status_code=404, detail="One or both scans not found")

        b_deps = [DependencyItem(**dict(r)) for r in conn.execute("SELECT * FROM dependencies WHERE scan_id = ?;", (body.baseline_scan_id,)).fetchall()]
        c_deps = [DependencyItem(**dict(r)) for r in conn.execute("SELECT * FROM dependencies WHERE scan_id = ?;", (body.current_scan_id,)).fetchall()]

        b_vulns = []
        for r in conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?;", (body.baseline_scan_id,)).fetchall():
            d = dict(r)
            d["references"] = json.loads(d.get("references_json") or "[]")
            b_vulns.append(VulnerabilityItem(**d))

        c_vulns = []
        for r in conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?;", (body.current_scan_id,)).fetchall():
            d = dict(r)
            d["references"] = json.loads(d.get("references_json") or "[]")
            c_vulns.append(VulnerabilityItem(**d))

    return scan_comparator.compare_scans(
        body.baseline_scan_id,
        body.current_scan_id,
        b_deps,
        c_deps,
        b_vulns,
        c_vulns,
        b_scan["risk_score"],
        c_scan["risk_score"]
    )

# ----------------- Policies -----------------

@router.get("/policies", response_model=List[PolicyOut])
def list_policies():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM policies ORDER BY created_at ASC;").fetchall()
        policies = []
        for r in rows:
            policies.append(PolicyOut(
                id=r["id"],
                name=r["name"],
                description=r["description"] or "",
                is_default=bool(r["is_default"]),
                fail_on_severity=r["fail_on_severity"],
                max_high_count=r["max_high_count"],
                block_copyleft=bool(r["block_copyleft"]),
                block_unknown_license=bool(r["block_unknown_license"]),
                require_fix_available=bool(r["require_fix_available"]),
                allowed_licenses=json.loads(r["allowed_licenses_json"] or "[]"),
                denied_licenses=json.loads(r["denied_licenses_json"] or "[]"),
                created_at=r["created_at"]
            ))
        return policies

@router.post("/policies", response_model=PolicyOut)
def create_policy(data: PolicyCreate):
    pol_id = f"pol-{uuid.uuid4().hex[:8]}"
    with get_db() as conn:
        conn.execute("""
        INSERT INTO policies (
            id, name, description, is_default, fail_on_severity, max_high_count,
            block_copyleft, block_unknown_license, require_fix_available,
            allowed_licenses_json, denied_licenses_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            pol_id, data.name, data.description, 1 if data.is_default else 0,
            data.fail_on_severity, data.max_high_count, 1 if data.block_copyleft else 0,
            1 if data.block_unknown_license else 0, 1 if data.require_fix_available else 0,
            json.dumps(data.allowed_licenses), json.dumps(data.denied_licenses)
        ))
    return PolicyOut(
        id=pol_id,
        name=data.name,
        description=data.description or "",
        is_default=data.is_default,
        fail_on_severity=data.fail_on_severity,
        max_high_count=data.max_high_count,
        block_copyleft=data.block_copyleft,
        block_unknown_license=data.block_unknown_license,
        require_fix_available=data.require_fix_available,
        allowed_licenses=data.allowed_licenses,
        denied_licenses=data.denied_licenses,
        created_at="just now"
    )

@router.get("/scans/{scan_id}/policy-evaluation", response_model=PolicyEvaluationResult)
def evaluate_scan_policy(scan_id: str, policy_id: Optional[str] = None):
    with get_db() as conn:
        if policy_id:
            p_row = conn.execute("SELECT * FROM policies WHERE id = ?;", (policy_id,)).fetchone()
        else:
            p_row = conn.execute("SELECT * FROM policies WHERE is_default = 1 LIMIT 1;").fetchone()

        if not p_row:
            p_row = conn.execute("SELECT * FROM policies LIMIT 1;").fetchone()

        if not p_row:
            raise HTTPException(status_code=404, detail="No policy found")

        policy_obj = PolicyOut(
            id=p_row["id"],
            name=p_row["name"],
            description=p_row["description"] or "",
            is_default=bool(p_row["is_default"]),
            fail_on_severity=p_row["fail_on_severity"],
            max_high_count=p_row["max_high_count"],
            block_copyleft=bool(p_row["block_copyleft"]),
            block_unknown_license=bool(p_row["block_unknown_license"]),
            require_fix_available=bool(p_row["require_fix_available"]),
            allowed_licenses=json.loads(p_row["allowed_licenses_json"] or "[]"),
            denied_licenses=json.loads(p_row["denied_licenses_json"] or "[]"),
            created_at=p_row["created_at"]
        )

        dep_rows = conn.execute("SELECT * FROM dependencies WHERE scan_id = ?;", (scan_id,)).fetchall()
        vuln_rows = conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?;", (scan_id,)).fetchall()

    deps = [DependencyItem(**dict(r)) for r in dep_rows]
    vulns = []
    for r in vuln_rows:
        d = dict(r)
        d["references"] = json.loads(d.get("references_json") or "[]")
        vulns.append(VulnerabilityItem(**d))

    return policy_engine.evaluate(policy_obj, scan_id, deps, vulns)

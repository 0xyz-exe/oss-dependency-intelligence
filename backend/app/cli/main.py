"""Command Line Interface (CLI) for OSS Dependency Intelligence (ossdi)."""
import argparse
import sys
import json
from pathlib import Path
from backend.app.core.database import init_db
from backend.app.services.ingestion.scanner import ingestion_scanner
from backend.app.services.sbom.generator import sbom_generator
from backend.app.services.policies.engine import policy_engine
from backend.app.services.compare.engine import scan_comparator
from backend.app.schemas.models import PolicyOut, DependencyItem, VulnerabilityItem

def print_banner():
    print("""
===========================================================
  OSS Dependency Intelligence (ossdi) v1.0.0
  Understand Your Dependencies. Detect Risks. Ship with Confidence.
===========================================================
""")

def cmd_scan(args):
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: Target path does not exist: {target}", file=sys.stderr)
        return 2

    init_db()
    scan = ingestion_scanner.scan_path(str(target), project_name=target.name)

    # Check fail-on threshold
    fail_on = (args.fail_on or "HIGH").upper()
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    threshold = sev_rank.get(fail_on, 3)

    critical_count = scan.critical_count
    high_count = scan.high_count
    med_count = scan.medium_count
    low_count = scan.low_count

    if args.format == "json":
        print(json.dumps(scan.model_dump(), indent=2))
    else:
        print_banner()
        print(f"Target:               {scan.scan_target}")
        print(f"Total Dependencies:   {scan.total_dependencies} ({scan.direct_dependencies} direct, {scan.transitive_dependencies} transitive)")
        print(f"Vulnerabilities:      {scan.vulnerabilities_count}")
        print(f"  - Critical:         {critical_count}")
        print(f"  - High:             {high_count}")
        print(f"  - Medium:           {med_count}")
        print(f"  - Low:              {low_count}")
        print(f"License Violations:   {scan.license_violations_count}")
        print(f"Unknown Licenses:     {scan.unknown_license_count}")
        print(f"Composite Risk Score: {scan.risk_score} / 100")
        print(f"Duration:             {scan.duration_ms} ms")
        print("-----------------------------------------------------------")

    if threshold <= 4 and critical_count > 0:
        print(f"[FAIL] Quality gate violated: {critical_count} CRITICAL vulnerabilities found.", file=sys.stderr)
        return 1
    if threshold <= 3 and high_count > 0:
        print(f"[FAIL] Quality gate violated: {high_count} HIGH vulnerabilities found.", file=sys.stderr)
        return 1
    if threshold <= 2 and med_count > 0:
        print(f"[FAIL] Quality gate violated: {med_count} MEDIUM vulnerabilities found.", file=sys.stderr)
        return 1

    print("[PASS] Scan completed within quality gate thresholds.")
    return 0

def cmd_sbom(args):
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: Target path does not exist: {target}", file=sys.stderr)
        return 2

    init_db()
    scan = ingestion_scanner.scan_path(str(target), project_name=target.name)

    from backend.app.core.database import get_db
    with get_db() as conn:
        dep_rows = conn.execute("SELECT * FROM dependencies WHERE scan_id = ?;", (scan.id,)).fetchall()
        vuln_rows = conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?;", (scan.id,)).fetchall()

    deps = [DependencyItem(**dict(r)) for r in dep_rows]
    vulns = []
    for r in vuln_rows:
        d = dict(r)
        d["references"] = json.loads(d.get("references_json") or "[]")
        vulns.append(VulnerabilityItem(**d))

    fmt = args.format or "cyclonedx-json"
    if fmt == "cyclonedx-json":
        doc = sbom_generator.generate_cyclonedx_json(target.name, deps, vulns)
    else:
        doc = sbom_generator.generate_spdx_json(target.name, deps, vulns)

    doc_str = json.dumps(doc, indent=2)
    if args.output:
        Path(args.output).write_text(doc_str, encoding="utf-8")
        print(f"SBOM written to {args.output}")
    else:
        print(doc_str)
    return 0

def cmd_licenses(args):
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: Target path does not exist: {target}", file=sys.stderr)
        return 2

    init_db()
    scan = ingestion_scanner.scan_path(str(target), project_name=target.name)

    from backend.app.core.database import get_db
    with get_db() as conn:
        dep_rows = conn.execute("SELECT * FROM dependencies WHERE scan_id = ? ORDER BY license_category, name;", (scan.id,)).fetchall()

    print_banner()
    print(f"License inventory for: {target.name}\n")
    print(f"{'Package':<30} {'Version':<12} {'License':<20} {'Category':<18} {'Status'}")
    print("-" * 90)
    for r in dep_rows:
        print(f"{r['name']:<30} {r['version']:<12} {r['detected_license']:<20} {r['license_category']:<18} {r['license_status']}")
    print("-" * 90)
    return 0

def cmd_policy(args):
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: Target path does not exist: {target}", file=sys.stderr)
        return 2

    init_db()
    scan = ingestion_scanner.scan_path(str(target), project_name=target.name)

    from backend.app.core.database import get_db
    with get_db() as conn:
        p_row = conn.execute("SELECT * FROM policies WHERE is_default = 1 LIMIT 1;").fetchone()
        dep_rows = conn.execute("SELECT * FROM dependencies WHERE scan_id = ?;", (scan.id,)).fetchall()
        vuln_rows = conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?;", (scan.id,)).fetchall()

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
        allowed_licenses=[],
        denied_licenses=[],
        created_at=p_row["created_at"]
    )

    deps = [DependencyItem(**dict(r)) for r in dep_rows]
    vulns = []
    for r in vuln_rows:
        d = dict(r)
        d["references"] = json.loads(d.get("references_json") or "[]")
        vulns.append(VulnerabilityItem(**d))

    eval_result = policy_engine.evaluate(policy_obj, scan.id, deps, vulns)

    print_banner()
    print(f"Policy Evaluation: {policy_obj.name}")
    print(f"Result:            {eval_result.result}")
    print(f"Summary:           {eval_result.summary}\n")
    if eval_result.violations:
        print("Violations:")
        for v in eval_result.violations:
            print(f"  [X] {v}")
    if eval_result.warnings:
        print("\nWarnings:")
        for w in eval_result.warnings:
            print(f"  [!] {w}")

    return 1 if eval_result.result == "FAIL" else 0

def cmd_compare(args):
    baseline_path = Path(args.baseline).resolve()
    current_path = Path(args.current).resolve()

    if not baseline_path.exists() or not current_path.exists():
        print("Error: baseline or current report file not found.", file=sys.stderr)
        return 2

    b_data = json.loads(baseline_path.read_text(encoding="utf-8"))
    c_data = json.loads(current_path.read_text(encoding="utf-8"))

    b_deps = [DependencyItem(**d) for d in b_data.get("dependencies", [])]
    c_deps = [DependencyItem(**d) for d in c_data.get("dependencies", [])]

    b_vulns = [VulnerabilityItem(**v) for v in b_data.get("vulnerabilities", [])]
    c_vulns = [VulnerabilityItem(**v) for v in c_data.get("vulnerabilities", [])]

    b_risk = b_data.get("scan", {}).get("risk_score", 0.0)
    c_risk = c_data.get("scan", {}).get("risk_score", 0.0)

    diff = scan_comparator.compare_scans(
        "baseline", "current", b_deps, c_deps, b_vulns, c_vulns, b_risk, c_risk
    )

    print_banner()
    print(f"Scan Comparison Report")
    print(f"Risk Score Delta:           {diff.risk_score_delta:+.1f}")
    print(f"Added Dependencies:         {len(diff.added_dependencies)}")
    print(f"Removed Dependencies:       {len(diff.removed_dependencies)}")
    print(f"Version Changes:            {len(diff.version_changes)}")
    print(f"New Vulnerabilities:        {len(diff.new_vulnerabilities)}")
    print(f"Resolved Vulnerabilities:   {len(diff.resolved_vulnerabilities)}")
    print(f"License Changes:            {len(diff.license_changes)}")
    print("-----------------------------------------------------------")
    return 0

def main():
    parser = argparse.ArgumentParser(prog="ossdi", description="OSS Dependency Intelligence CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan a directory or manifest for dependencies and risks")
    scan_p.add_argument("path", help="Path to project directory or manifest file")
    scan_p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default="high", help="Severity failure threshold")

    # sbom
    sbom_p = subparsers.add_parser("sbom", help="Generate SBOM")
    sbom_sub = sbom_p.add_subparsers(dest="sbom_command", required=True)
    gen_p = sbom_sub.add_parser("generate", help="Generate CycloneDX or SPDX SBOM")
    gen_p.add_argument("path", help="Path to target directory")
    gen_p.add_argument("--format", choices=["cyclonedx-json", "spdx-json"], default="cyclonedx-json", help="SBOM specification")
    gen_p.add_argument("--output", help="Write to output file")

    # licenses
    lic_p = subparsers.add_parser("licenses", help="Inspect and audit licenses")
    lic_p.add_argument("path", help="Path to project directory")

    # policy
    pol_p = subparsers.add_parser("policy", help="Check security and license policy compliance")
    pol_sub = pol_p.add_subparsers(dest="policy_command", required=True)
    check_p = pol_sub.add_parser("check", help="Evaluate policy against dependencies")
    check_p.add_argument("path", help="Path to project directory")

    # compare
    cmp_p = subparsers.add_parser("compare", help="Compare two scan result reports")
    cmp_p.add_argument("--baseline", required=True, help="Baseline scan report JSON")
    cmp_p.add_argument("--current", required=True, help="Current scan report JSON")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "sbom" and args.sbom_command == "generate":
        sys.exit(cmd_sbom(args))
    elif args.command == "licenses":
        sys.exit(cmd_licenses(args))
    elif args.command == "policy" and args.policy_command == "check":
        sys.exit(cmd_policy(args))
    elif args.command == "compare":
        sys.exit(cmd_compare(args))

if __name__ == "__main__":
    main()

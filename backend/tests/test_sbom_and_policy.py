"""Tests for SBOM generators and Policy evaluation engine."""
from backend.app.schemas.models import DependencyItem, VulnerabilityItem, PolicyOut
from backend.app.services.sbom.generator import sbom_generator
from backend.app.services.policies.engine import policy_engine

def test_cyclonedx_generation():
    deps = [
        DependencyItem(name="lodash", version="4.17.15", ecosystem="npm", purl="pkg:npm/lodash@4.17.15", is_direct=True, detected_license="MIT")
    ]
    vulns = [
        VulnerabilityItem(
            dependency_name="lodash", installed_version="4.17.15", ecosystem="npm",
            purl="pkg:npm/lodash@4.17.15", advisory_id="GHSA-p6mc-m468-83gw",
            severity="HIGH", cvss_score=7.5, fixed_version="4.17.19"
        )
    ]
    doc = sbom_generator.generate_cyclonedx_json("MyTestApp", deps, vulns)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert len(doc["components"]) == 1
    assert doc["components"][0]["name"] == "lodash"
    assert len(doc["vulnerabilities"]) == 1

def test_spdx_generation():
    deps = [
        DependencyItem(name="requests", version="2.25.1", ecosystem="PyPI", purl="pkg:pypi/requests@2.25.1", is_direct=True, detected_license="Apache-2.0")
    ]
    doc = sbom_generator.generate_spdx_json("PythonTestApp", deps, [])
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert len(doc["packages"]) == 2  # Root + 1 dependency
    assert len(doc["relationships"]) == 2

def test_policy_evaluation():
    deps = [
        DependencyItem(name="gpl-pkg", version="1.0.0", ecosystem="npm", purl="pkg:npm/gpl-pkg@1.0.0", is_direct=True, detected_license="GPL-3.0", license_category="Strong Copyleft")
    ]
    vulns = [
        VulnerabilityItem(
            dependency_name="bad-pkg", installed_version="1.0.0", ecosystem="npm",
            purl="pkg:npm/bad-pkg@1.0.0", advisory_id="CVE-2024-9999", severity="CRITICAL"
        )
    ]
    policy = PolicyOut(
        id="strict-pol",
        name="Strict Policy",
        is_default=True,
        fail_on_severity="HIGH",
        max_high_count=0,
        block_copyleft=True,
        block_unknown_license=True,
        require_fix_available=True,
        created_at="now"
    )
    result = policy_engine.evaluate(policy, "scan-123", deps, vulns)
    assert result.result == "FAIL"
    assert len(result.violations) >= 2

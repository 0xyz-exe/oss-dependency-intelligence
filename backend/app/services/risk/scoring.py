"""Explainable supply chain risk scoring engine."""
from typing import List, Dict, Any, Tuple
from backend.app.schemas.models import DependencyItem, VulnerabilityItem

class RiskScorer:
    @staticmethod
    def calculate_dependency_risk(dep: DependencyItem, vulns: List[VulnerabilityItem]) -> Tuple[float, List[str]]:
        """
        Calculate 0-100 risk score for a single dependency with breakdown factors.
        """
        score = 0.0
        factors = []

        # 1. Vulnerability severity impact
        has_critical = any(v.severity == "CRITICAL" for v in vulns)
        has_high = any(v.severity == "HIGH" for v in vulns)
        has_medium = any(v.severity == "MEDIUM" for v in vulns)
        has_low = any(v.severity == "LOW" for v in vulns)

        if has_critical:
            score += 45.0
            factors.append("Contains Critical vulnerability (+45)")
        elif has_high:
            score += 30.0
            factors.append("Contains High vulnerability (+30)")
        elif has_medium:
            score += 15.0
            factors.append("Contains Medium vulnerability (+15)")
        elif has_low:
            score += 5.0
            factors.append("Contains Low vulnerability (+5)")

        # Additional vulnerability accumulation
        extra_vulns = len(vulns) - 1
        if extra_vulns > 0:
            extra_pts = min(extra_vulns * 5.0, 15.0)
            score += extra_pts
            factors.append(f"{extra_vulns} additional vulnerabilities (+{extra_pts})")

        # 2. Exposure factor: Direct vs Transitive
        if dep.is_direct:
            score += 15.0
            factors.append("Direct top-level dependency (+15)")
        else:
            score += 5.0
            factors.append("Transitive indirect dependency (+5)")

        # 3. Fix availability
        if vulns and all(not v.fixed_version for v in vulns):
            score += 10.0
            factors.append("No official upstream fix available (+10)")

        # 4. License compliance risk
        if dep.license_status == "restricted":
            score += 20.0
            factors.append(f"Restricted license policy conflict: {dep.detected_license} (+20)")
        elif dep.license_status == "unknown" or dep.license_category == "Unknown":
            score += 10.0
            factors.append("Unconfirmed / Unknown license metadata (+10)")
        elif dep.license_category in ("Strong Copyleft", "Network Copyleft"):
            score += 10.0
            factors.append(f"Copyleft distribution risk: {dep.detected_license} (+10)")

        normalized_score = min(round(score, 1), 100.0)
        return normalized_score, factors

    @staticmethod
    def calculate_project_risk(
        dependencies: List[DependencyItem],
        vulnerabilities: List[VulnerabilityItem]
    ) -> float:
        """
        Calculate composite 0-100 project risk score.
        Weighted combination of highest severity vulns and overall security posture.
        """
        if not dependencies:
            return 0.0

        crit_count = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.severity == "HIGH")
        med_count = sum(1 for v in vulnerabilities if v.severity == "MEDIUM")
        restricted_licenses = sum(1 for d in dependencies if d.license_status == "restricted")
        unknown_licenses = sum(1 for d in dependencies if d.license_status == "unknown")

        base_score = 0.0
        base_score += min(crit_count * 30.0, 60.0)
        base_score += min(high_count * 15.0, 40.0)
        base_score += min(med_count * 5.0, 15.0)
        base_score += min(restricted_licenses * 10.0, 20.0)
        base_score += min(unknown_licenses * 2.0, 10.0)

        # Average dependency risk component
        avg_dep_risk = sum(d.risk_score for d in dependencies) / len(dependencies) if dependencies else 0.0
        composite = (base_score * 0.7) + (avg_dep_risk * 0.3)

        return min(round(composite, 1), 100.0)

risk_scorer = RiskScorer()

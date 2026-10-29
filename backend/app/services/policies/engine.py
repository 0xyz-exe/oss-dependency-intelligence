"""Policy evaluation engine for security and license governance."""
from typing import List, Dict, Any
from backend.app.schemas.models import DependencyItem, VulnerabilityItem, PolicyEvaluationResult, PolicyOut

class PolicyEngine:
    @staticmethod
    def evaluate(
        policy: PolicyOut,
        scan_id: str,
        dependencies: List[DependencyItem],
        vulnerabilities: List[VulnerabilityItem]
    ) -> PolicyEvaluationResult:
        """
        Evaluate scan results against a security and compliance policy.
        Returns PolicyEvaluationResult with PASS, WARN, or FAIL.
        """
        violations: List[str] = []
        warnings: List[str] = []

        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
        threshold_rank = sev_rank.get(policy.fail_on_severity.upper(), 3)

        # 1. Vulnerability severity threshold check
        high_vuln_count = 0
        for v in vulnerabilities:
            current_rank = sev_rank.get(v.severity.upper(), 1)
            if v.severity.upper() == "HIGH":
                high_vuln_count += 1

            if current_rank >= threshold_rank:
                violations.append(
                    f"Policy violation: {v.severity} vulnerability '{v.advisory_id}' in package '{v.dependency_name}@{v.installed_version}' exceeds allowed threshold '{policy.fail_on_severity}'."
                )
            elif current_rank == (threshold_rank - 1):
                warnings.append(
                    f"Warning: {v.severity} vulnerability '{v.advisory_id}' detected in '{v.dependency_name}'."
                )

        if high_vuln_count > policy.max_high_count:
            violations.append(
                f"Policy violation: High-severity vulnerability count ({high_vuln_count}) exceeds tolerated maximum ({policy.max_high_count})."
            )

        # 2. License compliance checks
        for dep in dependencies:
            if policy.denied_licenses and dep.detected_license in policy.denied_licenses:
                violations.append(
                    f"Policy violation: Package '{dep.name}' uses prohibited license '{dep.detected_license}'."
                )

            if policy.allowed_licenses and dep.detected_license not in policy.allowed_licenses:
                violations.append(
                    f"Policy violation: Package '{dep.name}' license '{dep.detected_license}' not in allowed policy whitelist."
                )

            if policy.block_copyleft and dep.license_category in ("Strong Copyleft", "Network Copyleft"):
                violations.append(
                    f"Policy violation: Copyleft license '{dep.detected_license}' in '{dep.name}' blocked by commercial distribution policy."
                )

            if policy.block_unknown_license and (dep.license_category == "Unknown" or dep.license_status == "unknown"):
                violations.append(
                    f"Policy violation: Unconfirmed license in package '{dep.name}'."
                )
            elif dep.license_category == "Unknown":
                warnings.append(
                    f"Warning: Package '{dep.name}' has unconfirmed/unknown license metadata."
                )

        # 3. Fix availability check
        if policy.require_fix_available:
            for v in vulnerabilities:
                if not v.fixed_version:
                    warnings.append(
                        f"Advisory '{v.advisory_id}' in '{v.dependency_name}' has no available patch."
                    )

        result_status = "FAIL" if violations else ("WARN" if warnings else "PASS")
        summary = (
            f"Policy {result_status}: {len(violations)} violations, {len(warnings)} warnings across {len(dependencies)} packages."
        )

        return PolicyEvaluationResult(
            scan_id=scan_id,
            policy_id=policy.id,
            result=result_status,
            violations=violations,
            warnings=warnings,
            summary=summary
        )

policy_engine = PolicyEngine()

"""SPDX License intelligence, classification, expression parsing, and policy evaluation."""
import re
from typing import Dict, List, Optional, Tuple

# Comprehensive mapping of common licenses to categories and default risks
LICENSE_CATALOG: Dict[str, Dict[str, str]] = {
    # Permissive
    "MIT": {"category": "Permissive", "risk": "LOW"},
    "Apache-2.0": {"category": "Permissive", "risk": "LOW"},
    "BSD-2-Clause": {"category": "Permissive", "risk": "LOW"},
    "BSD-3-Clause": {"category": "Permissive", "risk": "LOW"},
    "ISC": {"category": "Permissive", "risk": "LOW"},
    "Unlicense": {"category": "Permissive", "risk": "LOW"},
    "CC0-1.0": {"category": "Permissive", "risk": "LOW"},
    "0BSD": {"category": "Permissive", "risk": "LOW"},
    "Zlib": {"category": "Permissive", "risk": "LOW"},
    
    # Weak Copyleft
    "MPL-2.0": {"category": "Weak Copyleft", "risk": "MEDIUM"},
    "LGPL-2.0": {"category": "Weak Copyleft", "risk": "MEDIUM"},
    "LGPL-2.1": {"category": "Weak Copyleft", "risk": "MEDIUM"},
    "LGPL-3.0": {"category": "Weak Copyleft", "risk": "MEDIUM"},
    "EPL-1.0": {"category": "Weak Copyleft", "risk": "MEDIUM"},
    "EPL-2.0": {"category": "Weak Copyleft", "risk": "MEDIUM"},

    # Strong Copyleft
    "GPL-2.0": {"category": "Strong Copyleft", "risk": "HIGH"},
    "GPL-3.0": {"category": "Strong Copyleft", "risk": "HIGH"},
    "GPL-2.0-only": {"category": "Strong Copyleft", "risk": "HIGH"},
    "GPL-3.0-only": {"category": "Strong Copyleft", "risk": "HIGH"},
    "GPL-2.0-or-later": {"category": "Strong Copyleft", "risk": "HIGH"},
    "GPL-3.0-or-later": {"category": "Strong Copyleft", "risk": "HIGH"},

    # Network / AGPL Copyleft
    "AGPL-3.0": {"category": "Network Copyleft", "risk": "CRITICAL"},
    "AGPL-3.0-only": {"category": "Network Copyleft", "risk": "CRITICAL"},
    "AGPL-3.0-or-later": {"category": "Network Copyleft", "risk": "CRITICAL"},
    "SSPL-1.0": {"category": "Source Available / Non-Commercial", "risk": "HIGH"},

    # Proprietary / Commercial
    "Proprietary": {"category": "Proprietary", "risk": "HIGH"},
}

# Known heuristics for inferring licenses from package names or common text
PACKAGE_LICENSE_HEURISTICS: Dict[str, str] = {
    "react": "MIT",
    "react-dom": "MIT",
    "vue": "MIT",
    "express": "MIT",
    "fastapi": "MIT",
    "uvicorn": "BSD-3-Clause",
    "pydantic": "MIT",
    "requests": "Apache-2.0",
    "pytest": "MIT",
    "click": "BSD-3-Clause",
    "lodash": "MIT",
    "axios": "MIT",
    "chalk": "MIT",
    "debug": "MIT",
    "tokio": "MIT",
    "serde": "MIT OR Apache-2.0",
    "symfony": "MIT",
    "laravel": "MIT",
    "gin-gonic/gin": "MIT",
    "golang.org/x/sync": "BSD-3-Clause",
}

class LicenseAnalyzer:
    @staticmethod
    def normalize_license(raw_license: Optional[str], package_name: str = "") -> Tuple[str, str, str]:
        """
        Normalize license string into: (normalized_spdx, category, status).
        Returns e.g. ("MIT", "Permissive", "allowed")
        """
        if not raw_license or raw_license.strip().upper() in ("UNKNOWN", "NONE", "UNLICENSED", "UNDEFINED"):
            # Check heuristic fallback
            lower_name = package_name.lower().split("/")[-1]
            if lower_name in PACKAGE_LICENSE_HEURISTICS:
                raw_license = PACKAGE_LICENSE_HEURISTICS[lower_name]
            else:
                return "Unknown", "Unknown", "unknown"

        cleaned = raw_license.strip()
        # Clean parentheses or common variances
        cleaned = re.sub(r"^\(|\)$", "", cleaned)
        
        # Check direct lookup
        for spdx_id, meta in LICENSE_CATALOG.items():
            if spdx_id.lower() == cleaned.lower():
                status = "restricted" if meta["category"] in ("Strong Copyleft", "Network Copyleft") else "allowed"
                return spdx_id, meta["category"], status

        # Handle expression like (MIT OR Apache-2.0)
        if " OR " in cleaned:
            parts = [p.strip(" ()") for p in cleaned.split(" OR ")]
            # If any option is Permissive, user can choose Permissive
            categories = [LICENSE_CATALOG.get(p, {}).get("category", "Unknown") for p in parts]
            if "Permissive" in categories:
                return cleaned, "Permissive", "allowed"
            return cleaned, "Multiple Options", "review_required"

        if " AND " in cleaned:
            return cleaned, "Dual Obligation", "review_required"

        # Check partial matching
        if "MIT" in cleaned.upper():
            return "MIT", "Permissive", "allowed"
        elif "APACHE" in cleaned.upper():
            return "Apache-2.0", "Permissive", "allowed"
        elif "BSD" in cleaned.upper():
            return "BSD-3-Clause", "Permissive", "allowed"
        elif "GPL" in cleaned.upper():
            return "GPL-3.0", "Strong Copyleft", "restricted"

        return cleaned, "Custom / Review Required", "review_required"

    @staticmethod
    def evaluate_policy(
        license_category: str,
        detected_license: str,
        block_copyleft: bool = False,
        block_unknown: bool = False,
        allowed_licenses: Optional[List[str]] = None,
        denied_licenses: Optional[List[str]] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Evaluate license against project policy rules.
        Returns: (status ['allowed', 'review_required', 'restricted', 'unknown'], violation_reason)
        """
        if denied_licenses and detected_license in denied_licenses:
            return "restricted", f"License '{detected_license}' explicitly prohibited by policy."

        if allowed_licenses and detected_license not in allowed_licenses:
            return "restricted", f"License '{detected_license}' not in allowed policy whitelist."

        if block_copyleft and license_category in ("Strong Copyleft", "Network Copyleft"):
            return "restricted", f"Copyleft license '{detected_license}' ({license_category}) blocked by policy."

        if block_unknown and license_category == "Unknown":
            return "restricted", "Unknown license blocked by policy."

        if license_category in ("Strong Copyleft", "Network Copyleft"):
            return "review_required", f"Copyleft obligations require distribution review ({detected_license})."

        if license_category == "Unknown":
            return "unknown", "License metadata is unconfirmed or unknown."

        return "allowed", None

license_analyzer = LicenseAnalyzer()

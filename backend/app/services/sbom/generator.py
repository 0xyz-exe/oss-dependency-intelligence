"""Standard Software Bill of Materials (SBOM) generator for CycloneDX 1.5 and SPDX 2.3."""
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.app.schemas.models import DependencyItem, VulnerabilityItem

class SbomGenerator:
    @staticmethod
    def generate_cyclonedx_json(
        project_name: str,
        dependencies: List[DependencyItem],
        vulnerabilities: List[VulnerabilityItem]
    ) -> Dict[str, Any]:
        """Generate CycloneDX v1.5 compliant JSON SBOM."""
        serial_number = f"urn:uuid:{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        components = []
        for dep in dependencies:
            comp: Dict[str, Any] = {
                "bom-ref": dep.purl,
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": dep.purl,
                "scope": "required" if dep.is_direct else "optional",
            }
            if dep.detected_license and dep.detected_license != "Unknown":
                comp["licenses"] = [{"license": {"id": dep.detected_license}}]
            components.append(comp)

        # Attach vulnerability elements
        cyclone_vulns = []
        for v in vulnerabilities:
            vuln_obj: Dict[str, Any] = {
                "id": v.advisory_id,
                "source": {"name": v.source, "url": "https://osv.dev"},
                "ratings": [{
                    "severity": v.severity.lower(),
                    "score": v.cvss_score or 5.0,
                    "method": "CVSSv31"
                }],
                "description": v.summary,
                "detail": v.details,
                "recommendation": v.remediation_advice,
                "affects": [{"ref": v.purl}]
            }
            cyclone_vulns.append(vuln_obj)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": [
                    {
                        "vendor": "OSS Dependency Intelligence",
                        "name": "ossdi",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": "1.0.0"
                }
            },
            "components": components,
            "vulnerabilities": cyclone_vulns
        }

    @staticmethod
    def generate_spdx_json(
        project_name: str,
        dependencies: List[DependencyItem],
        vulnerabilities: List[VulnerabilityItem]
    ) -> Dict[str, Any]:
        """Generate SPDX v2.3 compliant JSON SBOM."""
        doc_uuid = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        spdx_doc_id = "SPDXRef-DOCUMENT"
        packages = []
        relationships = []

        # Root project package
        root_pkg_id = f"SPDXRef-Package-Root-{project_name.replace(' ', '-').lower()}"
        packages.append({
            "SPDXID": root_pkg_id,
            "name": project_name,
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "packageLicenseConcluded": "NOASSERTION",
            "packageLicenseDeclared": "NOASSERTION"
        })
        relationships.append({
            "spdxElementId": spdx_doc_id,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_pkg_id
        })

        for i, dep in enumerate(dependencies):
            clean_name = dep.name.replace("/", "-").replace("@", "").lower()
            pkg_id = f"SPDXRef-Package-{clean_name}-{i}"
            license_str = dep.detected_license if (dep.detected_license and dep.detected_license != "Unknown") else "NOASSERTION"

            packages.append({
                "SPDXID": pkg_id,
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "packageLicenseConcluded": license_str,
                "packageLicenseDeclared": license_str,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": dep.purl
                    }
                ]
            })

            relationships.append({
                "spdxElementId": root_pkg_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": pkg_id
            })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": spdx_doc_id,
            "name": f"{project_name} SBOM",
            "documentNamespace": f"https://spdx.org/spdxdocs/{project_name}-{doc_uuid}",
            "creationInfo": {
                "created": now_iso,
                "creators": [
                    "Tool: OSS-Dependency-Intelligence-1.0.0",
                    "Organization: OSSDI"
                ]
            },
            "packages": packages,
            "relationships": relationships
        }

sbom_generator = SbomGenerator()

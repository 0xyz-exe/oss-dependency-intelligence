"""Parser for Node.js / npm ecosystem: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml."""
import json
import re
from pathlib import Path
from typing import List, Dict, Set
from backend.app.schemas.models import DependencyItem
from backend.app.services.parsers.base import BaseParser, normalize_purl

class NpmParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name in ("package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml")

    def parse(self, file_path: Path, content: str) -> List[DependencyItem]:
        name = file_path.name.lower()
        if name == "package-lock.json":
            return self._parse_package_lock(file_path, content)
        elif name == "package.json":
            return self._parse_package_json(file_path, content)
        elif name == "yarn.lock":
            return self._parse_yarn_lock(file_path, content)
        elif name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(file_path, content)
        return []

    def _parse_package_lock(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        try:
            data = json.loads(content)
        except Exception:
            return []

        # Lockfile v2 / v3 has "packages"
        if "packages" in data and isinstance(data["packages"], dict):
            # First find root direct dependencies
            root_direct: Set[str] = set()
            root_pkg = data["packages"].get("", {})
            for section in ("dependencies", "devDependencies"):
                if section in root_pkg and isinstance(root_pkg[section], dict):
                    root_direct.update(root_pkg[section].keys())

            for pkg_path, meta in data["packages"].items():
                if not pkg_path or not isinstance(meta, dict):
                    continue
                # Path looks like "node_modules/@scope/pkg" or "node_modules/pkg"
                parts = pkg_path.split("node_modules/")
                pkg_name = parts[-1]
                version = meta.get("version", "unknown")
                if not pkg_name or version == "unknown":
                    continue

                is_direct = (pkg_name in root_direct)
                license_val = meta.get("license")

                items.append(DependencyItem(
                    name=pkg_name,
                    version=version,
                    ecosystem="npm",
                    purl=normalize_purl("npm", pkg_name, version),
                    is_direct=is_direct,
                    declared_license=str(license_val) if license_val else None,
                    detected_license=str(license_val) if license_val else None,
                    source_file=file_path.name,
                    depth=1 if is_direct else 2
                ))
            if items:
                return items

        # Fallback to Lockfile v1 dependencies format
        if "dependencies" in data and isinstance(data["dependencies"], dict):
            for pkg_name, meta in data["dependencies"].items():
                if not isinstance(meta, dict):
                    continue
                version = meta.get("version", "unknown")
                is_direct = not meta.get("dev", False)
                items.append(DependencyItem(
                    name=pkg_name,
                    version=version,
                    ecosystem="npm",
                    purl=normalize_purl("npm", pkg_name, version),
                    is_direct=is_direct,
                    source_file=file_path.name,
                    depth=1 if is_direct else 2
                ))
        return items

    def _parse_package_json(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        try:
            data = json.loads(content)
        except Exception:
            return []

        for dep_type, is_direct in (("dependencies", True), ("devDependencies", False)):
            deps = data.get(dep_type, {})
            if isinstance(deps, dict):
                for pkg_name, constraint in deps.items():
                    clean_ver = re.sub(r"^[~^><= ]+", "", str(constraint)).strip() or "0.0.0"
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=clean_ver,
                        ecosystem="npm",
                        purl=normalize_purl("npm", pkg_name, clean_ver),
                        is_direct=is_direct,
                        declared_constraint=str(constraint),
                        source_file=file_path.name,
                        depth=1
                    ))
        return items

    def _parse_yarn_lock(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        lines = content.splitlines()
        current_pkg = None
        current_version = None

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if not line.startswith(" ") and not line.startswith("\t"):
                # Header line like "express@^4.18.2, express@~4.18.0:"
                match = re.match(r"^\"?(@?[^@\s,:]+)@", line_str)
                if match:
                    current_pkg = match.group(1).strip('"')
            elif line_str.startswith("version ") and current_pkg:
                ver_match = re.search(r'version\s+"?([^"\s]+)"?', line_str)
                if ver_match:
                    current_version = ver_match.group(1)
                    items.append(DependencyItem(
                        name=current_pkg,
                        version=current_version,
                        ecosystem="npm",
                        purl=normalize_purl("npm", current_pkg, current_version),
                        is_direct=True,
                        source_file=file_path.name,
                        depth=1
                    ))
                    current_pkg = None
                    current_version = None
        return items

    def _parse_pnpm_lock(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        # Parse YAML packages block safely
        in_packages = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("packages:", "snapshots:"):
                in_packages = True
                continue
            if in_packages:
                if line and not line.startswith("  ") and not line.startswith("\t"):
                    in_packages = False
                    continue
                # Line format: "  /@babel/core@7.24.0:" or "  /lodash@4.17.21:"
                match = re.match(r"^\s*['\"]?/?(@?[^@\s]+)@([^:('\"\s]+)", stripped)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2)
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=version,
                        ecosystem="npm",
                        purl=normalize_purl("npm", pkg_name, version),
                        is_direct=True,
                        source_file=file_path.name,
                        depth=1
                    ))
        return items

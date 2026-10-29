"""Parser for PHP / Composer ecosystem: composer.json, composer.lock."""
import json
import re
from pathlib import Path
from typing import List
from backend.app.schemas.models import DependencyItem
from backend.app.services.parsers.base import BaseParser, normalize_purl

class ComposerParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name in ("composer.lock", "composer.json")

    def parse(self, file_path: Path, content: str) -> List[DependencyItem]:
        name = file_path.name.lower()
        if name == "composer.lock":
            return self._parse_composer_lock(file_path, content)
        elif name == "composer.json":
            return self._parse_composer_json(file_path, content)
        return []

    def _parse_composer_lock(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        try:
            data = json.loads(content)
        except Exception:
            return []

        for section, is_direct in (("packages", True), ("packages-dev", False)):
            packages = data.get(section, [])
            if isinstance(packages, list):
                for pkg in packages:
                    if not isinstance(pkg, dict):
                        continue
                    pkg_name = pkg.get("name")
                    version = pkg.get("version", "").lstrip("v")
                    if not pkg_name or not version:
                        continue
                    licenses = pkg.get("license", [])
                    declared_lic = licenses[0] if isinstance(licenses, list) and licenses else None
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=version,
                        ecosystem="Composer",
                        purl=normalize_purl("composer", pkg_name, version),
                        is_direct=is_direct,
                        declared_license=declared_lic,
                        detected_license=declared_lic,
                        source_file=file_path.name,
                        depth=1 if is_direct else 2
                    ))
        return items

    def _parse_composer_json(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        try:
            data = json.loads(content)
        except Exception:
            return []

        for section, is_direct in (("require", True), ("require-dev", False)):
            reqs = data.get(section, {})
            if isinstance(reqs, dict):
                for pkg_name, constraint in reqs.items():
                    if pkg_name.lower() in ("php", "ext-json", "ext-mbstring", "ext-pdo"):
                        continue
                    clean_ver = re.sub(r"^[~^><= ]+", "", str(constraint)).strip() or "0.0.0"
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=clean_ver,
                        ecosystem="Composer",
                        purl=normalize_purl("composer", pkg_name, clean_ver),
                        is_direct=is_direct,
                        declared_constraint=str(constraint),
                        source_file=file_path.name,
                        depth=1
                    ))
        return items

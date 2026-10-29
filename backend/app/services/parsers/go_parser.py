"""Parser for Go ecosystem: go.mod, go.sum."""
import re
from pathlib import Path
from typing import List
from backend.app.schemas.models import DependencyItem
from backend.app.services.parsers.base import BaseParser, normalize_purl

class GoParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name in ("go.mod", "go.sum")

    def parse(self, file_path: Path, content: str) -> List[DependencyItem]:
        name = file_path.name.lower()
        if name == "go.mod":
            return self._parse_go_mod(file_path, content)
        elif name == "go.sum":
            return self._parse_go_sum(file_path, content)
        return []

    def _parse_go_mod(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        in_require = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require:
                if stripped == ")":
                    in_require = False
                    continue
                match = re.match(r"^([^\s]+)\s+([^\s]+)(?:\s+//\s+(indirect))?", stripped)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2).lstrip("v")
                    is_indirect = bool(match.group(3))
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=version,
                        ecosystem="Go",
                        purl=normalize_purl("golang", pkg_name, version),
                        is_direct=not is_indirect,
                        source_file=file_path.name,
                        depth=2 if is_indirect else 1
                    ))
            elif stripped.startswith("require "):
                match = re.match(r"^require\s+([^\s]+)\s+([^\s]+)(?:\s+//\s+(indirect))?", stripped)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2).lstrip("v")
                    is_indirect = bool(match.group(3))
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=version,
                        ecosystem="Go",
                        purl=normalize_purl("golang", pkg_name, version),
                        is_direct=not is_indirect,
                        source_file=file_path.name,
                        depth=2 if is_indirect else 1
                    ))
        return items

    def _parse_go_sum(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        seen = set()
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                pkg_name = parts[0]
                version_raw = parts[1].split("/")[0].lstrip("v")
                key = (pkg_name, version_raw)
                if key not in seen:
                    seen.add(key)
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=version_raw,
                        ecosystem="Go",
                        purl=normalize_purl("golang", pkg_name, version_raw),
                        is_direct=True,
                        source_file=file_path.name,
                        depth=1
                    ))
        return items

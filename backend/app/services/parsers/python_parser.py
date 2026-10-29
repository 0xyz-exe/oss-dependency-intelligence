"""Parser for Python ecosystem: requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock."""
import json
import re
from pathlib import Path
from typing import List
from backend.app.schemas.models import DependencyItem
from backend.app.services.parsers.base import BaseParser, normalize_purl

class PythonParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name in ("requirements.txt", "pyproject.toml", "pipfile.lock", "poetry.lock") or name.endswith("-requirements.txt")

    def parse(self, file_path: Path, content: str) -> List[DependencyItem]:
        name = file_path.name.lower()
        if "requirements" in name:
            return self._parse_requirements(file_path, content)
        elif name == "pyproject.toml":
            return self._parse_pyproject(file_path, content)
        elif name == "pipfile.lock":
            return self._parse_pipfile_lock(file_path, content)
        elif name == "poetry.lock":
            return self._parse_poetry_lock(file_path, content)
        return []

    def _parse_requirements(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r") or line.startswith("--"):
                continue
            # Strip comments
            line = line.split("#")[0].strip()
            # Match package==1.2.3 or >=, ~=, etc.
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]+)\s*([a-zA-Z0-9_\-\.\*]+)", line)
            if match:
                pkg_name = match.group(1).lower()
                constraint = match.group(2)
                version = match.group(3)
                items.append(DependencyItem(
                    name=pkg_name,
                    version=version if constraint == "==" else version.replace("*", "0"),
                    ecosystem="PyPI",
                    purl=normalize_purl("pypi", pkg_name, version if constraint == "==" else "0.0.0"),
                    is_direct=True,
                    declared_constraint=f"{constraint}{version}",
                    source_file=file_path.name,
                    depth=1
                ))
            else:
                # Bare package name without version constraint
                bare_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
                if bare_match:
                    pkg_name = bare_match.group(1).lower()
                    items.append(DependencyItem(
                        name=pkg_name,
                        version="0.0.0",
                        ecosystem="PyPI",
                        purl=normalize_purl("pypi", pkg_name, "0.0.0"),
                        is_direct=True,
                        source_file=file_path.name,
                        depth=1
                    ))
        return items

    def _parse_pyproject(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("dependencies = [", "[project.dependencies]", "[tool.poetry.dependencies]"):
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("]") or stripped.startswith("["):
                    in_deps = False
                    continue
                # Line like "requests>=2.28.0", or requests = "^2.28.0"
                clean_line = stripped.strip('",\'')
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:[=:]\s*\"?([=><~^!]*)([0-9a-zA-Z_\-\.]+)\"?|([=><~^!]+)\s*([a-zA-Z0-9_\-\.]+))", clean_line)
                if match:
                    pkg_name = match.group(1).lower()
                    version = match.group(3) or match.group(5) or "0.0.0"
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=version,
                        ecosystem="PyPI",
                        purl=normalize_purl("pypi", pkg_name, version),
                        is_direct=True,
                        source_file=file_path.name,
                        depth=1
                    ))
        return items

    def _parse_pipfile_lock(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        try:
            data = json.loads(content)
        except Exception:
            return []
        
        for section, is_direct in (("default", True), ("develop", False)):
            pkgs = data.get(section, {})
            if isinstance(pkgs, dict):
                for pkg_name, meta in pkgs.items():
                    raw_ver = meta.get("version", "==0.0.0")
                    clean_ver = raw_ver.replace("==", "").strip() or "0.0.0"
                    items.append(DependencyItem(
                        name=pkg_name.lower(),
                        version=clean_ver,
                        ecosystem="PyPI",
                        purl=normalize_purl("pypi", pkg_name, clean_ver),
                        is_direct=is_direct,
                        source_file=file_path.name,
                        depth=1 if is_direct else 2
                    ))
        return items

    def _parse_poetry_lock(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        current_name = None
        current_version = None
        
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[[package]]":
                if current_name and current_version:
                    items.append(DependencyItem(
                        name=current_name.lower(),
                        version=current_version,
                        ecosystem="PyPI",
                        purl=normalize_purl("pypi", current_name, current_version),
                        is_direct=True,
                        source_file=file_path.name,
                        depth=1
                    ))
                current_name = None
                current_version = None
            elif stripped.startswith("name = "):
                current_name = stripped.split("=")[1].strip(' "')
            elif stripped.startswith("version = "):
                current_version = stripped.split("=")[1].strip(' "')

        if current_name and current_version:
            items.append(DependencyItem(
                name=current_name.lower(),
                version=current_version,
                ecosystem="PyPI",
                purl=normalize_purl("pypi", current_name, current_version),
                is_direct=True,
                source_file=file_path.name,
                depth=1
            ))
        return items

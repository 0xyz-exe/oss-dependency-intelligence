"""Parser for Rust / Cargo ecosystem: Cargo.toml, Cargo.lock."""
import re
from pathlib import Path
from typing import List
from backend.app.schemas.models import DependencyItem
from backend.app.services.parsers.base import BaseParser, normalize_purl

class CargoParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name in ("cargo.lock", "cargo.toml")

    def parse(self, file_path: Path, content: str) -> List[DependencyItem]:
        name = file_path.name.lower()
        if name == "cargo.lock":
            return self._parse_cargo_lock(file_path, content)
        elif name == "cargo.toml":
            return self._parse_cargo_toml(file_path, content)
        return []

    def _parse_cargo_lock(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        current_name = None
        current_version = None

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[[package]]":
                if current_name and current_version:
                    items.append(DependencyItem(
                        name=current_name,
                        version=current_version,
                        ecosystem="crates.io",
                        purl=normalize_purl("cargo", current_name, current_version),
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
                name=current_name,
                version=current_version,
                ecosystem="crates.io",
                purl=normalize_purl("cargo", current_name, current_version),
                is_direct=True,
                source_file=file_path.name,
                depth=1
            ))
        return items

    def _parse_cargo_toml(self, file_path: Path, content: str) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("["):
                    in_deps = False
                    continue
                if not stripped or stripped.startswith("#"):
                    continue
                # Line like: serde = "1.0.197" or tokio = { version = "1.36.0", features = ["full"] }
                match = re.match(r"^([a-zA-Z0-9_\-]+)\s*=\s*(?:\"([^\"]+)\"|\{[^}]*version\s*=\s*\"([^\"]+)\"[^}]*\})", stripped)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2) or match.group(3) or "0.0.0"
                    items.append(DependencyItem(
                        name=pkg_name,
                        version=version,
                        ecosystem="crates.io",
                        purl=normalize_purl("cargo", pkg_name, version),
                        is_direct=True,
                        declared_constraint=version,
                        source_file=file_path.name,
                        depth=1
                    ))
        return items

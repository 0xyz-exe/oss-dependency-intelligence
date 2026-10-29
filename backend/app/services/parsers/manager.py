"""Registry and coordinator for all ecosystem manifest parsers."""
from pathlib import Path
from typing import List, Dict
from backend.app.schemas.models import DependencyItem
from backend.app.services.parsers.base import BaseParser
from backend.app.services.parsers.npm_parser import NpmParser
from backend.app.services.parsers.python_parser import PythonParser
from backend.app.services.parsers.composer_parser import ComposerParser
from backend.app.services.parsers.cargo_parser import CargoParser
from backend.app.services.parsers.go_parser import GoParser

class ParserRegistry:
    def __init__(self):
        self.parsers: List[BaseParser] = [
            NpmParser(),
            PythonParser(),
            ComposerParser(),
            CargoParser(),
            GoParser(),
        ]

    def parse_file(self, file_path: Path, content: str) -> List[DependencyItem]:
        """Find matching parser and parse content."""
        for parser in self.parsers:
            if parser.can_parse(file_path):
                return parser.parse(file_path, content)
        return []

    def deduplicate_dependencies(self, items: List[DependencyItem]) -> List[DependencyItem]:
        """Deduplicate dependencies by PURL, prioritizing lockfile/direct items."""
        deduped: Dict[str, DependencyItem] = {}
        for item in items:
            if item.purl not in deduped:
                deduped[item.purl] = item
            else:
                existing = deduped[item.purl]
                # If current item is direct and existing was not, update
                if item.is_direct and not existing.is_direct:
                    existing.is_direct = True
                    existing.depth = 1
                if item.declared_license and not existing.declared_license:
                    existing.declared_license = item.declared_license
                    existing.detected_license = item.detected_license
        return list(deduped.values())

parser_registry = ParserRegistry()

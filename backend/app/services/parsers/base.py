"""Base parser interfaces and normalization utilities."""
from abc import ABC, abstractmethod
from typing import List
from pathlib import Path
from backend.app.schemas.models import DependencyItem

def normalize_purl(ecosystem: str, name: str, version: str) -> str:
    """Format Package URL (purl) per standard spec: pkg:<type>/[namespace/]<name>@<version>."""
    clean_name = name.strip()
    clean_ver = version.strip()
    eco = ecosystem.lower().strip()
    
    if eco in ("npm", "javascript"):
        if clean_name.startswith("@") and "/" in clean_name:
            parts = clean_name.split("/", 1)
            return f"pkg:npm/{parts[0]}/{parts[1]}@{clean_ver}"
        return f"pkg:npm/{clean_name}@{clean_ver}"
    elif eco in ("pypi", "python"):
        normalized = clean_name.replace("_", "-").lower()
        return f"pkg:pypi/{normalized}@{clean_ver}"
    elif eco in ("composer", "php"):
        return f"pkg:composer/{clean_name}@{clean_ver}"
    elif eco in ("cargo", "rust", "crates.io"):
        return f"pkg:cargo/{clean_name}@{clean_ver}"
    elif eco in ("golang", "go"):
        return f"pkg:golang/{clean_name}@{clean_ver}"
    elif eco in ("maven", "java"):
        return f"pkg:maven/{clean_name}@{clean_ver}"
    elif eco in ("gem", "ruby", "rubygems"):
        return f"pkg:gem/{clean_name}@{clean_ver}"
    return f"pkg:generic/{clean_name}@{clean_ver}"

class BaseParser(ABC):
    """Abstract base parser for manifest and lockfile formats."""
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Check if parser handles this file."""
        pass

    @abstractmethod
    def parse(self, file_path: Path, content: str) -> List[DependencyItem]:
        """Parse file content and return normalized dependency items."""
        pass

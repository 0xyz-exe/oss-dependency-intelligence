"""Tests for all ecosystem manifest and lockfile parsers."""
from pathlib import Path
from backend.app.services.parsers.npm_parser import NpmParser
from backend.app.services.parsers.python_parser import PythonParser
from backend.app.services.parsers.composer_parser import ComposerParser
from backend.app.services.parsers.cargo_parser import CargoParser
from backend.app.services.parsers.go_parser import GoParser
from backend.app.services.parsers.manager import parser_registry

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"

def test_npm_package_lock_parser():
    parser = NpmParser()
    lock_file = FIXTURES_DIR / "sample-npm" / "package-lock.json"
    content = lock_file.read_text(encoding="utf-8")
    deps = parser.parse(lock_file, content)
    
    names = {d.name: d for d in deps}
    assert "lodash" in names
    assert names["lodash"].version == "4.17.15"
    assert names["lodash"].ecosystem == "npm"
    assert names["lodash"].is_direct is True
    assert "axios" in names
    assert names["axios"].version == "0.21.1"

def test_python_requirements_parser():
    parser = PythonParser()
    req_file = FIXTURES_DIR / "sample-python" / "requirements.txt"
    content = req_file.read_text(encoding="utf-8")
    deps = parser.parse(req_file, content)
    
    names = {d.name: d for d in deps}
    assert "requests" in names
    assert names["requests"].version == "2.25.1"
    assert names["requests"].ecosystem == "PyPI"
    assert "fastapi" in names

def test_composer_parser():
    parser = ComposerParser()
    comp_file = FIXTURES_DIR / "sample-composer" / "composer.json"
    content = comp_file.read_text(encoding="utf-8")
    deps = parser.parse(comp_file, content)
    
    names = {d.name: d for d in deps}
    assert "guzzlehttp/guzzle" in names
    assert names["guzzlehttp/guzzle"].version == "6.5.4"
    assert names["guzzlehttp/guzzle"].ecosystem == "Composer"

def test_cargo_parser():
    parser = CargoParser()
    cargo_file = FIXTURES_DIR / "sample-cargo" / "Cargo.toml"
    content = cargo_file.read_text(encoding="utf-8")
    deps = parser.parse(cargo_file, content)
    
    names = {d.name: d for d in deps}
    assert "serde" in names
    assert names["serde"].version == "1.0.197"
    assert "tokio" in names
    assert names["tokio"].version == "1.36.0"

def test_go_parser():
    parser = GoParser()
    go_file = FIXTURES_DIR / "sample-go" / "go.mod"
    content = go_file.read_text(encoding="utf-8")
    deps = parser.parse(go_file, content)
    
    names = {d.name: d for d in deps}
    assert "github.com/gin-gonic/gin" in names
    assert names["github.com/gin-gonic/gin"].is_direct is True
    assert "golang.org/x/sync" in names
    assert names["golang.org/x/sync"].is_direct is False

def test_parser_registry_deduplication():
    npm_file = FIXTURES_DIR / "sample-npm" / "package-lock.json"
    content = npm_file.read_text(encoding="utf-8")
    parsed = parser_registry.parse_file(npm_file, content)
    deduped = parser_registry.deduplicate_dependencies(parsed + parsed)
    assert len(deduped) == len(parsed)

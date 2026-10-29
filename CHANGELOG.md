# Changelog

All notable changes to **OSS Dependency Intelligence** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-29

### Added
- **Multi-Ecosystem Manifest Parsers:** Support for npm (`package-lock.json`, `package.json`, `yarn.lock`, `pnpm-lock.yaml`), PyPI (`requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`), Composer (`composer.json`, `composer.lock`), Cargo (`Cargo.toml`, `Cargo.lock`), and Go Modules (`go.mod`, `go.sum`).
- **Canonical PURL Normalization:** Standardized package URL representation for cross-language consistency.
- **OSV Intelligence Engine:** Batch vulnerability intelligence retrieval with persistent caching and offline fixture fallback.
- **SPDX License Compliance:** License detection, family classification (Permissive, Weak Copyleft, Strong Copyleft, Network Copyleft), and policy gating.
- **Explainable Risk Scoring:** Multi-factor supply chain risk scoring model.
- **Dual SBOM Generator:** CycloneDX 1.5 JSON and SPDX 2.3 JSON compliant export.
- **Single-page Web Dashboard:** High-contrast developer-first UI built with React 19, Tailwind CSS v4, and Lucide icons.
- **CLI & CI/CD Tool (`ossdi`):** Headless vulnerability scanning and quality gate exit code evaluation.

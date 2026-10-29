"""Database layer for OSS Dependency Intelligence using SQLite WAL mode."""
import sqlite3
from typing import Generator
from contextlib import contextmanager
from backend.app.core.config import settings

def init_db():
    """Initialize database tables and WAL mode."""
    conn = get_db_connection()
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        
        # Projects table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            ecosystem TEXT,
            repository_url TEXT,
            target_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Scans table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL, -- pending, running, completed, failed
            scan_target TEXT NOT NULL,
            branch TEXT,
            commit_hash TEXT,
            total_dependencies INTEGER DEFAULT 0,
            direct_dependencies INTEGER DEFAULT 0,
            transitive_dependencies INTEGER DEFAULT 0,
            vulnerabilities_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            license_violations_count INTEGER DEFAULT 0,
            unknown_license_count INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            duration_ms INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        """)

        # Dependencies table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS dependencies (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            purl TEXT NOT NULL,
            is_direct BOOLEAN DEFAULT 1,
            declared_constraint TEXT,
            depth INTEGER DEFAULT 1,
            parent_name TEXT,
            source_file TEXT,
            declared_license TEXT,
            detected_license TEXT,
            license_category TEXT,
            license_status TEXT DEFAULT 'allowed', -- allowed, review_required, restricted, unknown
            vulnerability_count INTEGER DEFAULT 0,
            max_severity TEXT DEFAULT 'NONE',
            risk_score REAL DEFAULT 0.0,
            confidence REAL DEFAULT 1.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            UNIQUE (scan_id, purl)
        );
        """)

        # Vulnerabilities table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            dependency_name TEXT NOT NULL,
            installed_version TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            purl TEXT NOT NULL,
            advisory_id TEXT NOT NULL,
            cve_id TEXT,
            ghsa_id TEXT,
            osv_id TEXT,
            summary TEXT,
            details TEXT,
            severity TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
            cvss_score REAL,
            vulnerable_range TEXT,
            fixed_version TEXT,
            references_json TEXT,
            source TEXT DEFAULT 'OSV',
            status TEXT DEFAULT 'open', -- open, in_progress, fixed, accepted_risk, false_positive
            remediation_advice TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        """)

        # Policies table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            is_default BOOLEAN DEFAULT 0,
            fail_on_severity TEXT DEFAULT 'HIGH', -- CRITICAL, HIGH, MEDIUM, LOW
            max_high_count INTEGER DEFAULT 0,
            block_copyleft BOOLEAN DEFAULT 0,
            block_unknown_license BOOLEAN DEFAULT 0,
            require_fix_available BOOLEAN DEFAULT 0,
            allowed_licenses_json TEXT,
            denied_licenses_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Policy Evaluations table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS policy_evaluations (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            result TEXT NOT NULL, -- PASS, WARN, FAIL, INCOMPLETE
            details_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
        );
        """)

        # Provider Cache table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS provider_cache (
            cache_key TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            data_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Insert default policy if none exists
        cursor = conn.execute("SELECT COUNT(*) FROM policies;")
        if cursor.fetchone()[0] == 0:
            conn.execute("""
            INSERT INTO policies (id, name, description, is_default, fail_on_severity, max_high_count, block_copyleft, block_unknown_license, require_fix_available)
            VALUES ('default-policy', 'Standard Security Baseline', 'Fails on Critical or High vulnerabilities and alerts on restrictive copyleft.', 1, 'HIGH', 0, 0, 0, 1);
            """)

        conn.commit()
    finally:
        conn.close()

def get_db_connection() -> sqlite3.Connection:
    """Return a raw sqlite connection with row factory enabled."""
    conn = sqlite3.connect(settings.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database connections."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

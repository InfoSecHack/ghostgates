"""
ghostgates/storage/sqlite_store.py

Local SQLite storage for GateModels and ScanResults.

Design decisions:
  - GateModel and ScanResult are stored as JSON blobs (avoids complex ORM).
  - Indexed columns for common queries (org, repo, collected_at).
  - Parameterized queries ONLY (no f-strings in SQL).
  - DB file created with 0o600 permissions.
  - Thread-safe via sqlite3's built-in serialized mode.

Security:
  - No tokens or credentials are ever stored.
  - All SQL uses ? placeholders.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ghostgates.models.gates import GateModel
from ghostgates.models.findings import ScanResult

logger = logging.getLogger("ghostgates.storage")

_SCHEMA_VERSION = 1

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gate_models (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org         TEXT NOT NULL,
    repo        TEXT NOT NULL,
    full_name   TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    data        TEXT NOT NULL,
    UNIQUE(org, repo)
);

CREATE INDEX IF NOT EXISTS idx_gate_models_org ON gate_models(org);
CREATE INDEX IF NOT EXISTS idx_gate_models_full_name ON gate_models(full_name);

CREATE TABLE IF NOT EXISTS scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org             TEXT NOT NULL,
    attacker_level  TEXT NOT NULL,
    scan_time       TEXT NOT NULL,
    repos_scanned   INTEGER NOT NULL,
    finding_count   INTEGER NOT NULL,
    data            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_results_org ON scan_results(org);
CREATE INDEX IF NOT EXISTS idx_scan_results_time ON scan_results(scan_time);
"""


class SQLiteStore:
    """Local SQLite storage for GhostGates data.

    Usage::

        store = SQLiteStore("ghostgates.db")
        store.upsert_gate_model(gate_model)
        models = store.get_gate_models("my-org")
        store.close()
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Create the database file and tables if needed."""
        is_new = not self._db_path.exists()

        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        if is_new:
            # Set restrictive file permissions
            try:
                os.chmod(self._db_path, 0o600)
            except OSError as exc:
                logger.warning("Could not set DB permissions: %s", exc)

        # Create tables
        self._conn.executescript(_CREATE_TABLES)

        # Check/set schema version
        cursor = self._conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cursor.fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (_SCHEMA_VERSION,),
            )
            self._conn.commit()
        else:
            stored_version = row["version"]
            if stored_version != _SCHEMA_VERSION:
                logger.warning(
                    "Schema version mismatch: stored=%d, expected=%d",
                    stored_version, _SCHEMA_VERSION,
                )

    @property
    def db_path(self) -> Path:
        return self._db_path

    # ------------------------------------------------------------------
    # GateModel CRUD
    # ------------------------------------------------------------------

    def upsert_gate_model(self, model: GateModel) -> None:
        """Insert or replace a GateModel for org/repo.

        Uses SQLite's INSERT OR REPLACE with UNIQUE(org, repo) constraint.
        """
        collected_at = ""
        if model.collected_at:
            collected_at = model.collected_at.isoformat()
        else:
            collected_at = datetime.now(timezone.utc).isoformat()

        data = model.model_dump_json()

        self._conn.execute(
            """
            INSERT OR REPLACE INTO gate_models (org, repo, full_name, collected_at, data)
            VALUES (?, ?, ?, ?, ?)
            """,
            (model.org, model.repo, model.full_name, collected_at, data),
        )
        self._conn.commit()

    def upsert_gate_models(self, models: list[GateModel]) -> int:
        """Batch upsert multiple GateModels. Returns count inserted."""
        count = 0
        for model in models:
            self.upsert_gate_model(model)
            count += 1
        return count

    def get_gate_model(self, org: str, repo: str) -> GateModel | None:
        """Retrieve a single GateModel by org/repo. None if not found."""
        cursor = self._conn.execute(
            "SELECT data FROM gate_models WHERE org = ? AND repo = ?",
            (org, repo),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return GateModel.model_validate_json(row["data"])

    def get_gate_models(self, org: str) -> list[GateModel]:
        """Retrieve all GateModels for an org."""
        cursor = self._conn.execute(
            "SELECT data FROM gate_models WHERE org = ? ORDER BY repo",
            (org,),
        )
        return [GateModel.model_validate_json(row["data"]) for row in cursor.fetchall()]

    def delete_gate_model(self, org: str, repo: str) -> bool:
        """Delete a GateModel. Returns True if it existed."""
        cursor = self._conn.execute(
            "DELETE FROM gate_models WHERE org = ? AND repo = ?",
            (org, repo),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def count_gate_models(self, org: str | None = None) -> int:
        """Count stored GateModels, optionally filtered by org."""
        if org:
            cursor = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM gate_models WHERE org = ?",
                (org,),
            )
        else:
            cursor = self._conn.execute("SELECT COUNT(*) as cnt FROM gate_models")
        return cursor.fetchone()["cnt"]

    # ------------------------------------------------------------------
    # ScanResult CRUD
    # ------------------------------------------------------------------

    def save_scan_result(self, result: ScanResult) -> int:
        """Save a scan result. Returns the row ID."""
        scan_time = result.collected_at or datetime.now(timezone.utc).isoformat()
        data = result.model_dump_json()

        cursor = self._conn.execute(
            """
            INSERT INTO scan_results (org, attacker_level, scan_time, repos_scanned, finding_count, data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result.org,
                str(result.attacker_level),
                scan_time,
                result.repos_scanned,
                len(result.findings),
                data,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid

    def get_scan_result(self, scan_id: int) -> ScanResult | None:
        """Retrieve a scan result by ID."""
        cursor = self._conn.execute(
            "SELECT data FROM scan_results WHERE id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return ScanResult.model_validate_json(row["data"])

    def get_latest_scan(self, org: str) -> ScanResult | None:
        """Get the most recent scan result for an org."""
        cursor = self._conn.execute(
            "SELECT data FROM scan_results WHERE org = ? ORDER BY scan_time DESC LIMIT 1",
            (org,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return ScanResult.model_validate_json(row["data"])

    def list_scans(self, org: str, limit: int = 20) -> list[dict]:
        """List scan result summaries (without full data) for an org.

        Returns dicts with: id, org, attacker_level, scan_time, repos_scanned, finding_count.
        """
        cursor = self._conn.execute(
            """
            SELECT id, org, attacker_level, scan_time, repos_scanned, finding_count
            FROM scan_results
            WHERE org = ?
            ORDER BY scan_time DESC
            LIMIT ?
            """,
            (org, limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

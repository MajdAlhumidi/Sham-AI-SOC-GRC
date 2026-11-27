"""SQLite persistence for the GRC module; no additional package is required."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "grc.sqlite3"
CHAIN_SOURCES = {
    "audit_logs": (
        "SELECT * FROM audit_logs WHERE id=?",
        "SELECT id FROM audit_logs ORDER BY rowid",
    ),
    "evidence": (
        "SELECT * FROM evidence WHERE id=?",
        "SELECT id FROM evidence ORDER BY rowid",
    ),
}
GENESIS = "0" * 64


def database_path() -> Path:
    configured = os.getenv("GRC_DB_PATH")
    path = Path(configured).expanduser() if configured else DEFAULT_DB_PATH
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_connection() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


@contextmanager
def db_session():
    connection = get_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    with db_session() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS risks (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'Cybersecurity',
                asset TEXT NOT NULL DEFAULT '',
                owner TEXT NOT NULL DEFAULT '',
                likelihood INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
                impact INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
                inherent_score INTEGER NOT NULL,
                inherent_level TEXT NOT NULL,
                residual_likelihood INTEGER,
                residual_impact INTEGER,
                residual_score INTEGER,
                residual_level TEXT,
                treatment TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS controls (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT 'Protect',
                framework TEXT NOT NULL DEFAULT 'SHAM Internal Baseline',
                framework_ref TEXT,
                implementation_status TEXT NOT NULL DEFAULT 'not_assessed',
                owner TEXT NOT NULL DEFAULT '',
                review_frequency TEXT NOT NULL DEFAULT 'quarterly',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS risk_controls (
                risk_id TEXT NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
                control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                PRIMARY KEY (risk_id, control_id)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                risk_id TEXT REFERENCES risks(id) ON DELETE SET NULL,
                control_id TEXT REFERENCES controls(id) ON DELETE SET NULL,
                source TEXT NOT NULL,
                reference_id TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                sha256 TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                collected_by TEXT NOT NULL DEFAULT 'unspecified',
                collected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                reference_type TEXT NOT NULL,
                reference_id TEXT NOT NULL,
                requested_action TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                decided_by TEXT,
                decision_note TEXT,
                created_at TEXT NOT NULL,
                decided_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                before_json TEXT,
                after_json TEXT,
                reason TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS thehive_deliveries (
                incident_id TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL REFERENCES approvals(id),
                result_json TEXT,
                started_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS grc_integrity_chain (
                stream TEXT NOT NULL CHECK (stream IN ('audit_logs','evidence')),
                seq INTEGER NOT NULL CHECK (seq > 0),
                entry_id TEXT NOT NULL,
                prev_sha256 TEXT NOT NULL,
                entry_sha256 TEXT NOT NULL,
                PRIMARY KEY (stream, seq),
                UNIQUE (stream, entry_id)
            );

            CREATE TABLE IF NOT EXISTS grc_migrations (
                name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS integrity_chain_no_update
            BEFORE UPDATE ON grc_integrity_chain
            BEGIN SELECT RAISE(ABORT, 'grc_integrity_chain is append-only'); END;

            CREATE TRIGGER IF NOT EXISTS integrity_chain_no_delete
            BEFORE DELETE ON grc_integrity_chain
            BEGIN SELECT RAISE(ABORT, 'grc_integrity_chain is append-only'); END;

            CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
            CREATE INDEX IF NOT EXISTS idx_risks_level ON risks(inherent_level);
            CREATE INDEX IF NOT EXISTS idx_controls_status ON controls(implementation_status);
            CREATE INDEX IF NOT EXISTS idx_evidence_risk ON evidence(risk_id);
            CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence(control_id);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

            CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs is append-only');
            END;
            """
        )
        connection.execute("BEGIN IMMEDIATE")
        ensure_columns(connection, "approvals", {
            "requested_actor_id": "TEXT",
            "decided_actor_id": "TEXT",
        })
        if not connection.execute("SELECT 1 FROM grc_migrations WHERE name='integrity_chain_v1'").fetchone():
            for stream, (_, list_sql) in CHAIN_SOURCES.items():
                for source in connection.execute(list_sql):
                    append_chain_entry(connection, stream, source["id"])
            connection.execute("INSERT INTO grc_migrations VALUES ('integrity_chain_v1',?)", (utc_now(),))
        seed_default_controls(connection)


def ensure_columns(connection, table, columns):
    existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    for name, sql_type in columns.items():
        if name not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")


def _entry_digest(stream, sequence, previous, record):
    payload = {"stream": stream, "seq": sequence, "prev_sha256": previous, "record": dict(record)}
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(data).hexdigest()


def append_chain_entry(connection, stream, entry_id):
    """Append within the same write transaction as the original record."""
    row = connection.execute(CHAIN_SOURCES[stream][0], (entry_id,)).fetchone()
    if row is None:
        raise ValueError("An integrity entry must reference a stored GRC record.")
    head = connection.execute(
        "SELECT seq, entry_sha256 FROM grc_integrity_chain WHERE stream=? ORDER BY seq DESC LIMIT 1", (stream,),
    ).fetchone()
    sequence, previous = (head["seq"] + 1, head["entry_sha256"]) if head else (1, GENESIS)
    connection.execute(
        "INSERT INTO grc_integrity_chain VALUES (?,?,?,?,?)",
        (stream, sequence, entry_id, previous, _entry_digest(stream, sequence, previous, row)),
    )


def verify_integrity_chains():
    """Verify sequence, links, digests, and coverage against one read snapshot."""
    results = {}
    with db_session() as connection:
        connection.execute("BEGIN")
        for stream, (select_sql, list_sql) in CHAIN_SOURCES.items():
            previous = GENESIS
            seen = set()
            invalid = None
            entries = connection.execute(
                "SELECT * FROM grc_integrity_chain WHERE stream=? ORDER BY seq", (stream,),
            )
            for sequence, entry in enumerate(entries, 1):
                row = connection.execute(select_sql, (entry["entry_id"],)).fetchone()
                if (entry["seq"] != sequence or entry["prev_sha256"] != previous or row is None
                        or entry["entry_sha256"] != _entry_digest(stream, sequence, previous, row)):
                    invalid = sequence
                    break
                seen.add(entry["entry_id"])
                previous = entry["entry_sha256"]
            expected = {row["id"] for row in connection.execute(list_sql)}
            results[stream] = {
                "valid": invalid is None and seen == expected,
                "verified_records": len(seen),
                "stored_records": len(expected),
                "first_invalid_seq": invalid,
            }
    return results


def seed_default_controls(connection: sqlite3.Connection) -> None:
    seed_path = Path(__file__).with_name("seed_controls.json")
    try:
        controls = json.loads(seed_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        controls = []

    now = utc_now()
    for control in controls:
        connection.execute(
            """
            INSERT OR IGNORE INTO controls (
                id, title, description, domain, framework, framework_ref,
                implementation_status, owner, review_frequency, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'not_assessed', '', ?, ?, ?)
            """,
            (
                control["id"],
                control["title"],
                control.get("description", ""),
                control.get("domain", "Protect"),
                control.get("framework", "SHAM Internal Baseline"),
                control.get("framework_ref"),
                control.get("review_frequency", "quarterly"),
                now,
                now,
            ),
        )

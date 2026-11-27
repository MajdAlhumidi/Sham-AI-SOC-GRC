import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from scripts.casework import store
from scripts.grc.audit import record_audit
from scripts.grc.db import db_session, initialize_database, verify_integrity_chains
from scripts.grc.evidence import insert_evidence


class StorageIntegrityTests(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = directory / "grc.db"
        self.enterContext(patch.dict(os.environ, {
            "GRC_DB_PATH": str(self.path),
            "SOC_CASE_DB_PATH": str(directory / "cases.db"),
        }))

    def test_legacy_row_is_chained_without_rewriting_it(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.executescript("""
                CREATE TABLE audit_logs (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
                    entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, before_json TEXT,
                    after_json TEXT, reason TEXT, created_at TEXT NOT NULL
                );
                INSERT INTO audit_logs VALUES
                    ('legacy','operator','fixture.created','risk','R-1',NULL,'{"a": 1}',NULL,'fixture-time');
            """)
        initialize_database()
        initialize_database()
        with db_session() as connection:
            original = connection.execute("SELECT after_json FROM audit_logs WHERE id='legacy'").fetchone()
            self.assertEqual(original[0], '{"a": 1}')
            record_audit(connection, "fixture", "fixture.reviewed", "risk", "R-1")
            evidence_id = insert_evidence(
                connection, risk_id=None, control_id="SHAM-LOG-001", source="fixture", reference_id="R-1",
                description="Test evidence", sha256=None, metadata={}, collected_by="fixture",
            )
        chains = verify_integrity_chains()
        self.assertTrue(chains["audit_logs"]["valid"])
        self.assertEqual(chains["audit_logs"]["verified_records"], 3)
        self.assertTrue(chains["evidence"]["valid"])
        with db_session() as connection:
            connection.execute("UPDATE evidence SET description='fixture changed' WHERE id=?", (evidence_id,))
        self.assertFalse(verify_integrity_chains()["evidence"]["valid"])

    def test_concurrent_duplicate_capture_preserves_evidence(self):
        alert = {
            "id": "local-fixture", "agent": {"id": "001", "name": "fixture-host"},
            "data": {"srcip": "192.0.2.5"}, "rule": {"id": "1", "level": 5},
            "timestamp": "2026-11-20T12:00:00Z",
        }
        record = {"incident_id": "INC-FIXTURE", "source_alert_id": "local-fixture", "classification": "suspicious"}
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(store.capture, record, alert) for _ in range(4)]
        self.assertEqual(len({fixture.result() for fixture in futures}), 1)
        with store.db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 1)
        evidence = store.get_evidence("INC-FIXTURE", "A1")
        self.assertTrue(evidence["integrity_ok"])

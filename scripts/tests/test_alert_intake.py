from contextlib import closing
import gzip
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from alert_intake import BATCH_SIZE, open_alert_intake


def event(identifier, level=7):
    return (json.dumps({"id": identifier, "rule": {"level": level}, "full_log": "تجربة"},
                       ensure_ascii=False) + "\n").encode()


class AlertIntakeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "alerts.json"
        self.db_path = self.root / "state" / "alerts.sqlite3"
        self.source.write_bytes(event("old"))
        self.env = patch.dict(os.environ, {"SOC_ALERT_RESUME_FILE": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.prepare = Mock(side_effect=lambda alert, incident: {"id": incident, "alert_id": alert["id"]})
        self.published = []
        self.publish = Mock(side_effect=lambda alert, report: self.published.append(report["alert_id"]))

    def open(self):
        return open_alert_intake(self.source, self.db_path, 7)

    def append(self, *records, path=None):
        with (path or self.source).open("ab") as output:
            for record in records:
                output.write(record)

    def bootstrap(self):
        with self.open() as intake:
            self.assertFalse(intake.capture())

    def drain(self, intake):
        while intake.deliver(self.prepare, self.publish):
            pass

    def test_restart_replays_unprocessed_alerts_and_continues_at_exact_byte_offset(self):
        self.bootstrap()
        self.append(event("queued"))
        with self.open() as intake:
            self.assertTrue(intake.capture())
        partial = event("after-restart")
        self.append(event("queued"), partial[:-2])
        with self.open() as intake:
            intake.capture()
            self.drain(intake)
            self.assertEqual(self.published, ["queued"])
        self.append(partial[-2:], event("low-severity", 5))
        with self.open() as intake:
            intake.capture()
            self.drain(intake)
        self.assertEqual(self.published, ["queued", "after-restart"])

    def test_first_install_keeps_partial_line_until_it_is_complete(self):
        partial = event("in-progress")
        self.append(partial[:20])
        self.bootstrap()
        self.append(partial[20:])
        with self.open() as intake:
            self.assertTrue(intake.capture())
            self.drain(intake)
        self.assertEqual(self.published, ["in-progress"])

    def test_wazuh_archive_recovery_over_two_rotations_while_stopped(self):
        self.bootstrap()
        self.append(event("seen"))
        with self.open() as intake:
            intake.capture()
            self.drain(intake)
        self.append(event("old-unread"))
        archive_dir = self.root / "2026" / "Nov"
        archive_dir.mkdir(parents=True)
        original = archive_dir / "ossec-alerts-27.json.gz"
        middle = archive_dir / "ossec-alerts-27-001.json.gz"
        original.write_bytes(gzip.compress(self.source.read_bytes()))
        middle.write_bytes(gzip.compress(event("next-archive") + event("seen")))
        stamp = max(original.stat().st_mtime_ns, middle.stat().st_mtime_ns)
        for path in (original, middle):
            os.utime(path, ns=(stamp, stamp))
        self.source.unlink()
        self.source.write_bytes(event("current"))
        with self.open() as intake:
            intake.capture()
            self.drain(intake)
        self.assertEqual(self.published, ["seen", "old-unread", "next-archive", "current"])

    def test_hard_link_rotation_ignores_current_archive_alias_and_recovers_many_records(self):
        self.bootstrap()
        native_dir = self.root / "2026" / "Nov"
        native_dir.mkdir(parents=True)
        old = native_dir / "ossec-alerts-27.json"
        old.hardlink_to(self.source)
        identifiers = [f"event-{i}" for i in range(BATCH_SIZE + 3)]
        self.append(*(event(identifier) for identifier in identifiers))
        with self.open() as intake:
            self.source.unlink()
            self.assertFalse(intake.capture())
            current = native_dir / "ossec-alerts-27-001.json"
            current.write_bytes(event("current"))
            self.source.hardlink_to(current)
            intake.capture()
            self.drain(intake)
        self.assertEqual(self.published, [*identifiers, "current"])

    def test_copytruncate_detected_even_after_new_log_grows_past_saved_offset(self):
        self.bootstrap()
        self.append(event("old-unread"))
        (self.root / "alerts.json.1").write_bytes(self.source.read_bytes())
        old_inode = self.source.stat().st_ino
        self.source.write_bytes(event("new-first") + event("new-second"))
        self.assertEqual(self.source.stat().st_ino, old_inode)
        with self.open() as intake:
            intake.capture()
            self.drain(intake)
        self.assertEqual(self.published, ["old-unread", "new-first", "new-second"])

    def test_missing_rotation_reports_gap_and_collects_the_current_log(self):
        self.bootstrap()
        self.source.unlink()
        self.source.write_bytes(event("current"))
        with self.open() as intake:
            with self.assertLogs("alert_intake", level="WARNING") as logs:
                self.assertTrue(intake.capture())
            self.drain(intake)
        self.assertIn("unavailable at its checkpoint", logs.output[0])
        self.assertEqual(self.published, ["current"])

    def test_prepared_report_and_incident_id_survive_interruption_during_delivery(self):
        self.bootstrap()
        self.append(event("retry"))
        interrupted = Mock(side_effect=KeyboardInterrupt)
        with self.open() as intake:
            intake.capture()
            with self.assertRaises(KeyboardInterrupt):
                intake.deliver(self.prepare, interrupted)
        with self.open() as intake:
            self.drain(intake)
        self.prepare.assert_called_once()
        self.assertEqual(self.publish.call_args, interrupted.call_args)
        self.assertEqual(self.published, ["retry"])

    def test_storage_failure_keeps_alert_queued_and_allows_next_event(self):
        self.bootstrap()
        self.append(event("failed"), event("independent"))
        with self.open() as intake, patch("alert_intake.time.time", return_value=10):
            intake.capture()
            with self.assertLogs("alert_intake", level="ERROR"):
                intake.deliver(self.prepare, Mock(side_effect=OSError("private detail")))
            self.drain(intake)
        self.assertEqual(self.published, ["independent"])
        with self.open() as intake, patch("alert_intake.time.time", return_value=20):
            self.drain(intake)
        self.assertEqual(self.published, ["independent", "failed"])
        self.assertEqual(self.prepare.call_count, 2)

    def test_initial_legacy_cursor_is_consumed_once(self):
        stat = self.source.stat()
        cursor = self.root / "legacy.json"
        cursor.write_text(json.dumps({
            "path": str(self.source), "inode": stat.st_ino, "device": stat.st_dev, "offset": stat.st_size,
            "already_processed_ids": ["already-processed"],
        }), encoding="utf-8")
        self.append(event("already-processed"), event("cutover"))
        with patch.dict(os.environ, {"SOC_ALERT_RESUME_FILE": str(cursor)}), self.open() as intake:
            intake.capture()
            self.drain(intake)
        cursor.unlink()
        self.append(event("after"))
        with patch.dict(os.environ, {"SOC_ALERT_RESUME_FILE": str(cursor)}), self.open() as intake:
            intake.capture()
            self.drain(intake)
        self.assertEqual(self.published, ["cutover", "after"])

    def test_single_consumer_and_dedicated_database(self):
        with self.open():
            with self.assertRaises(OSError), self.open():
                self.fail("A second process acquired the intake lock")
        unrelated = self.root / "unrelated.sqlite3"
        with closing(sqlite3.connect(unrelated)) as conn, conn:
            conn.execute("CREATE TABLE unrelated (id INT)")
        with self.assertRaisesRegex(ValueError, "own SQLite database"), open_alert_intake(self.source, unrelated, 7):
            self.fail("Intake opened an unrelated database")

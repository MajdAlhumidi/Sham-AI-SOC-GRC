import json
import os
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts.casework import export, store


class CaseExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SOC_CASE_DB_PATH": str(Path(self.temp.name) / "case.db")})
        self.env.start()
        # These tests describe export semantics independently of an async worker.
        module = types.SimpleNamespace(list_turns=lambda case_id, limit=50: [], get_turn=lambda case_id, turn_id: None)
        self.modules = patch.dict("sys.modules", {"scripts.casework.followup": module})
        self.modules.start()

    def tearDown(self):
        self.modules.stop()
        self.env.stop()
        self.temp.cleanup()

    def capture(self, incident_id="INC-EXPORT-1", **extra):
        alert = {"id": "SOURCE-" + incident_id, "timestamp": "2026-11-20T12:00:00Z", "agent": {"id": "001", "name": "Lab host"},
                 "rule": {"id": "5710", "level": 8}, "data": {"srcip": "192.0.2.10", "dstuser": "operator"},
                 "full_log": "Recorded failed login <script>alert(1)</script>", **extra.pop("alert", {})}
        record = {"incident_id": incident_id, "analyst_notes": "Investigate recorded login <script>alert(2)</script> [A1].", **extra.pop("record", {})}
        context = extra.pop("context", {"tool_results": [{"tool_name": "query_logs", "status": "error", "result": "Timeout; no conclusion", "truncated": False}],
                                       "validated_assessment": {"findings": [{"observation": "Login recorded", "evidence": ["A1"]}], "limitations": ["Endpoint context missing"]}})
        return store.capture(record, alert, context)

    def bundle(self, case_id):
        content, filename = export.build_bundle(case_id)
        archive = ZipFile(BytesIO(content))
        entries = {name: archive.read(name) for name in archive.namelist()}
        return entries, filename

    def test_manifest_hashes_exact_exported_bytes_and_preserves_source_hash_separately(self):
        case_id = self.capture(alert={"data": {"password": "private-fixture-password", "srcip": "192.0.2.10"}})
        original = store.get_evidence("INC-EXPORT-1", "A1")
        entries, filename = self.bundle(case_id)
        manifest = json.loads(entries["manifest.json"])
        self.assertEqual(set(entries) - {"manifest.json"}, {item["path"] for item in manifest["files"]})
        for item in manifest["files"]:
            self.assertEqual(item["sha256"], sha256(entries[item["path"]]).hexdigest())
            self.assertEqual(item["size_bytes"], len(entries[item["path"]]))
        first = json.loads(entries["evidence/record-0001.json"])
        self.assertTrue(first["source_integrity"]["matches_stored_fingerprint"])
        self.assertEqual(first["source_integrity"]["expected_stored_sha256"], original["sha256"])
        self.assertEqual(first["record"]["value"]["data"]["password"], export.REDACTED)
        self.assertNotEqual(sha256(entries["evidence/record-0001.json"]).hexdigest(), original["sha256"])
        self.assertEqual(filename, case_id + "-evidence.zip")
        self.assertIn("does not verify truth", first["source_integrity"]["meaning"])

    def test_modified_and_invalid_evidence_is_flagged_not_relabelled_verified(self):
        case_id = self.capture()
        with store.db() as conn:
            conn.execute("UPDATE evidence SET payload='not JSON password=do-not-export' WHERE ref='A1'")
        entries, _ = self.bundle(case_id)
        first = json.loads(entries["evidence/record-0001.json"])
        self.assertFalse(first["source_integrity"]["matches_stored_fingerprint"])
        self.assertTrue(first["record"]["raw_data_omitted"])
        self.assertIn("MISMATCH", entries["report.html"].decode())
        self.assertNotIn(b"do-not-export", b"\n".join(entries.values()))

    def test_all_human_report_text_is_escaped_and_paths_are_fixed(self):
        case_id = self.capture(incident_id="../../<script>bad</script>")
        entries, filename = self.bundle(case_id)
        html = entries["report.html"].decode()
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertTrue(all(".." not in path and not path.startswith("/") for path in entries))
        self.assertNotIn("/", filename)
        self.assertNotIn("\\", filename)

    def test_credentials_redacted_in_nested_evidence_profiles_audit_and_free_text(self):
        secrets = ["nestedPassword774", "envSecret775", "bearerSecret776", "inlineSecret777", "authSecret778", "urlPassword779", "private-material-780", "auditSecret781"]
        log = ('SOC_GRC_API_TOKEN="envSecret775"\nBearer bearerSecret776\npassword=inlineSecret777\n'
               'Authorization: Basic authSecret778\nhttps://user:urlPassword779@example.test/path\n'
               '-----BEGIN PRIVATE KEY-----\nprivate-material-780\n-----END PRIVATE KEY-----')
        case_id = self.capture(alert={"data": {"password": secrets[0], "nested": {"refresh_token": "fixture-refresh-secret"}}, "full_log": log},
                               record={"analyst_notes": "A copied secret was nestedPassword774"})
        detail = store.case_detail(case_id)
        asset_id = detail["asset"]["id"]
        with store.db() as conn:
            profile = {**detail["asset"], "owner": "API_KEY=profileSecret782", "credentials": {"private_key": "profileSecret783"}}
            conn.execute("UPDATE assets SET payload=? WHERE id=?", (store.encode(profile), asset_id))
            store.log(conn, "asset_updated", asset_id, None, {"notes": "password='auditSecret781'", "Authorization": "Bearer auditHeaderSecret784"})
        entries, _ = self.bundle(case_id)
        plain = b"\n".join(entries.values()).decode()
        for secret in secrets + ["fixture-refresh-secret", "profileSecret782", "profileSecret783", "auditHeaderSecret784"]:
            self.assertNotIn(secret, plain)
        self.assertIn(export.REDACTED, plain)

    def test_missing_source_references_and_failed_tools_explicit(self):
        case_id = self.capture(context={"validated_assessment": {"findings": [{"observation": "Unsupported citation", "evidence": ["A1", "T99"]}]}})
        with store.db() as conn:
            conn.execute("DELETE FROM evidence WHERE ref='A1'")
        entries, _ = self.bundle(case_id)
        limitations = json.loads(entries["case.json"])["limitations"]
        self.assertTrue(any("Missing source evidence" in note and "A1" in note for note in limitations))
        self.assertTrue(any("T99" in note for note in limitations))
        self.assertFalse(any(name.startswith("evidence/") for name in entries))
        self.assertIn("does not certify", entries["report.html"].decode())

    def test_escaped_inline_credentials_do_not_leave_value_tails(self):
        case_id = self.capture(alert={"full_log": '\\"api_key\\":\\"escapedSecret885\\"\npassword="quoted\\"tailSecret886"\nAuthorization: Bearer bearerSecret887'})
        entries, _ = self.bundle(case_id)
        plain = b"\n".join(entries.values()).decode()
        for secret in ["escapedSecret885", "tailSecret886", "bearerSecret887"]:
            self.assertNotIn(secret, plain)

    def test_legacy_metadata_is_never_presented_as_original_alert(self):
        case_id = store.capture({"incident_id": "OLD-1", "analyst_notes": "Archived citation [A1]", "timestamp": "2026-11-20T12:00:00"})
        entries, _ = self.bundle(case_id)
        evidence = json.loads(entries["evidence/record-0001.json"])
        self.assertEqual(evidence["ref"], "M1")
        self.assertEqual(evidence["record"]["status"], "archive_only")
        self.assertTrue(json.loads(entries["case.json"])["events"][0]["legacy"])

    def test_full_followup_evidence_preserved_and_queued_state_is_not_answer(self):
        case_id = self.capture()
        turns = {"turn-done": {"id": "turn-done", "case_id": case_id, "question": "Check failed tool", "status": "completed", "answer": "Tool failed; no conclusion.",
                               "provider": "ollama", "model": "fixture", "elapsed_seconds": 2.5, "limitations": ["Query unavailable"],
                               "findings": [{"observation": "No result", "evidence_refs": ["F1"]}], "tool_trace": [{"status": "error"}],
                               "evidence": {"F1": {"status": "error", "result": "token=followupSecret", "tool": "query_logs"}}},
                 "turn-queued": {"id": "turn-queued", "case_id": case_id, "question": "Next check", "status": "queued", "answer": None}}
        module = types.SimpleNamespace(list_turns=lambda c, limit=50: [{"id": key, "status": value["status"]} for key, value in turns.items()][:limit],
                                       get_turn=lambda c, key: turns[key])
        with patch.dict("sys.modules", {"scripts.casework.followup": module}):
            entries, _ = self.bundle(case_id)
        self.assertIn("followups/turn-0001-evidence-0001.json", entries)
        done = json.loads(entries["followups/turn-0001.json"])
        queued = json.loads(entries["followups/turn-0002.json"])
        self.assertEqual(done["provider"], "ollama")
        self.assertEqual(done["exported_evidence"][0]["ref"], "F1")
        self.assertEqual(queued["status"], "queued")
        self.assertIsNone(queued["answer"])
        self.assertNotIn(b"followupSecret", b"\n".join(entries.values()))

    def test_case_and_source_limits_fail_explicitly_without_partial_output(self):
        with self.assertRaises(KeyError):
            export.build_bundle("missing")
        case_id = self.capture()
        self.assertEqual(self.capture("INC-EXPORT-2"), case_id)
        for name, cap in [("MAX_EVENTS", 1), ("MAX_SOURCE_BYTES", 20), ("MAX_RECORD_BYTES", 20), ("MAX_OUTPUT_BYTES", 50), ("MAX_FILES", 1), ("MAX_AUDIT", 0)]:
            with self.subTest(name=name), patch.object(export, name, cap):
                with self.assertRaisesRegex(export.ExportLimitError, "Export limit"):
                    export.build_bundle(case_id)

    def test_followup_limit_is_explicit(self):
        case_id = self.capture()
        module = types.SimpleNamespace(list_turns=lambda c, limit=50: [{"id": str(i)} for i in range(limit)], get_turn=lambda c, key: {})
        with patch.dict("sys.modules", {"scripts.casework.followup": module}), patch.object(export, "MAX_FOLLOWUPS", 2):
            with self.assertRaises(export.ExportLimitError):
                export.build_bundle(case_id)

    def test_followup_snapshot_source_hash_is_not_claimed_to_hash_excerpt(self):
        case_id = self.capture()
        original = {"full": "source larger than snapshot"}
        fresh = {"status": "returned", "result": "password=freshSecret889"}
        turn = {"id": "turn-hashes", "status": "completed", "evidence": {
            "S1": {"sha256": sha256(store.encode(original).encode()).hexdigest(), "integrity_ok": True,
                   "snapshot_truncated": True, "record": {"excerpt": "bounded source"}},
            "F1": {"sha256": sha256(store.encode(fresh).encode()).hexdigest(), "integrity_ok": True, "record": fresh}}}
        module = types.SimpleNamespace(list_turns=lambda c, limit=50: [{"id": turn["id"]}], get_turn=lambda c, key: turn)
        with patch.dict("sys.modules", {"scripts.casework.followup": module}):
            entries, _ = self.bundle(case_id)
        saved = json.loads(entries["followups/turn-0001-evidence-0001.json"])
        new = json.loads(entries["followups/turn-0001-evidence-0002.json"])
        self.assertEqual(saved["source_integrity"]["comparison"], "not_comparable_bounded_snapshot")
        self.assertIsNone(saved["source_integrity"]["matches_recorded_fingerprint"])
        self.assertTrue(saved["source_integrity"]["recorded_capture_integrity_ok"])
        self.assertTrue(new["source_integrity"]["matches_recorded_fingerprint"])
        self.assertNotIn(b"freshSecret889", b"\n".join(entries.values()))
        self.assertIn("not the hash of that excerpt", entries["report.html"].decode())

    def test_exact_followup_count_rejects_silently_truncated_listing(self):
        case_id = self.capture()
        with store.db() as conn:
            conn.execute("CREATE TABLE case_followup_turns(id TEXT,case_id TEXT,question TEXT,snapshot_json TEXT,result_json TEXT)")
            conn.execute("INSERT INTO case_followup_turns VALUES(?,?,?,?,?)", ("retained", case_id, "A question", "{}", "{}"))
        # Fake list_turns returns zero despite one retained row: fail, not partial.
        with self.assertRaisesRegex(ValueError, "count changed or was truncated"):
            self.bundle(case_id)


if __name__ == "__main__":
    unittest.main()

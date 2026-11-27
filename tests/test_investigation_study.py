import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.casework import investigation_study as study
from scripts.ollama_reporting import evidence_packet


class InvestigationStudyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "study.sqlite3"
        self.digest, self.cases = study.load_dataset(study.DATASET)
        self.case = self.cases["I01"]
        self.decision = {"classification": "suspicious", "escalate": True, "rationale": "Failed logins.",
                         "evidence_refs": ["A1"]}

    def test_plan_balances_the_two_arms_and_does_not_reveal_labels(self):
        plan = study.assignments(self.cases, ["reviewer-a", "reviewer-b"])
        self.assertEqual(len(plan), 4)
        self.assertEqual(sum(entry["manual"] == "reviewer-a" for entry in plan), 2)
        self.assertTrue(all(entry["manual"] != entry["assisted"] for entry in plan))
        self.assertNotIn("labels", json.dumps(plan))

    def test_assisted_loop_and_manual_session_use_same_isolated_evidence(self):
        assisted = study.EvidenceSession(self.case, "assisted-fixture")
        manual = study.EvidenceSession(self.case, "manual-fixture")
        name = "search_related_agent_logs"
        with (patch.object(study.agent, "_dispatch_tool") as live_dispatch,
              patch.object(study.agent, "_write_audit_event") as local_audit,
              patch.object(study.agent, "_ollama_chat", side_effect=[
                  {"tool_calls": [{"function": {"name": name, "arguments": {
                      "agent_id": "000", "query": "Related authentication", "time_range_minutes": 30}}}]},
                  {"content": "DONE"},
              ]) as model,
              patch.object(study.agent, "_synthesize_ollama_report", return_value="Validated study report"),
              patch.dict("os.environ", {"SOC_OLLAMA_URL": "http://127.0.0.1:11434/api/chat"})):
            manual.lookup(name)
            report, outcome = assisted.assist()
        self.assertEqual(report, "Validated study report")
        self.assertEqual(outcome["status"], "completed")
        self.assertEqual(outcome["tool_calls"], 1)
        self.assertEqual(evidence_packet(manual.alert, manual.context), evidence_packet(assisted.alert, assisted.context))
        self.assertEqual([item["status"] for item in assisted.audit], ["returned"])
        self.assertEqual(model.call_count, 2)
        live_dispatch.assert_not_called()
        local_audit.assert_not_called()

    def test_remote_model_url_is_rejected_before_a_request(self):
        session = study.EvidenceSession(self.case, "private-fixture")
        with (patch.dict("os.environ", {"SOC_OLLAMA_URL": "https://model.example.invalid/api/chat"}),
              patch.object(study.agent, "_ollama_chat") as model):
            with self.assertRaisesRegex(ValueError, "loopback"):
                session.assist()
        model.assert_not_called()

    def test_interruption_and_repeated_viewing_do_not_create_completed_trials(self):
        with study.study_db(self.db) as conn:
            study.begin_trial(conn, self.digest, "I01", "reviewer-a", "manual")
            with self.assertRaisesRegex(ValueError, "already started"):
                study.begin_trial(conn, self.digest, "I01", "REVIEWER-A", "assisted")
            self.assertEqual(study.blind_submissions(conn, self.digest), [])
            stats = study.score(conn, self.digest, {"dataset_sha256": self.digest, "labels": {}})
        self.assertEqual(stats["arms"]["manual"]["incomplete"], 1)
        self.assertIsNone(stats["paired_median_elapsed_difference_seconds"])

    def test_blind_export_and_paired_metrics_across_two_human_decisions(self):
        references = {"dataset_sha256": self.digest, "labels": {
            "I01": {"classification": "suspicious", "escalate": True}}}
        evidence = evidence_packet(self.case["alert"], {})
        with study.study_db(self.db) as conn:
            manual = study.begin_trial(conn, self.digest, "I01", "reviewer-a", "manual")
            assisted = study.begin_trial(conn, self.digest, "I01", "reviewer-b", "assisted")
            failed = study.begin_trial(conn, self.digest, "I02", "reviewer-a", "assisted")
            study.finish_trial(conn, manual, self.decision, evidence, 40, {"status": "not_requested"}, [])
            study.finish_trial(conn, assisted, {**self.decision, "escalate": False}, evidence,
                               25, {"status": "completed", "model": "test-model"}, [])
            study.finish_trial(conn, failed, self.decision, evidence, 66, {"status": "failed"}, [])
            with self.assertRaisesRegex(ValueError, "already been submitted"):
                study.finish_trial(conn, manual, self.decision, evidence, 10, {"status": "not_requested"}, [])
            blind = study.blind_submissions(conn, self.digest)
            stats = study.score(conn, self.digest, {**references, "unsupported_claims": {manual: 1}})
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                study.score(conn, "wrong-dataset", references)
        self.assertTrue(all(set(item) == {"trial_id", "case_id", "decision", "evidence"} for item in blind))
        self.assertEqual(stats["completed_pairs"], 1)
        self.assertEqual(stats["paired_median_elapsed_difference_seconds"], 15)
        self.assertEqual(stats["arms"]["manual"]["unsupported_claims"], 1)
        self.assertEqual(stats["arms"]["assisted"]["correct_escalations"], 0)
        self.assertEqual(stats["arms"]["assisted"]["assistance_failures"], 1)

    def test_manual_cli_records_tool_evidence_and_submission(self):
        answers = ["search_related_agent_logs", "", "suspicious", "Repeated failed authentication.", "A1 T1", "yes"]
        with patch("builtins.input", side_effect=answers), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(study.main(["--state", str(self.db), "run", "--case", "I01",
                                         "--analyst", "reviewer-a", "--arm", "manual"]), 0)
        self.assertIn('"recorded": true', output.getvalue())
        with study.study_db(self.db) as conn:
            trial = study.blind_submissions(conn, self.digest)[0]
        self.assertEqual(trial["decision"]["evidence_refs"], ["A1", "T1"])
        self.assertEqual(trial["evidence"]["T1"]["status"], "returned")

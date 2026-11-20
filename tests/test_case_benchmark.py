import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from scripts.casework import benchmark


class CaseBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        folder = Path(self.temp.name)
        self.env = patch.dict(os.environ, {
            "SOC_BENCHMARK_DB_PATH": str(folder / "comparison.sqlite3"),
            "SOC_CASE_DB_PATH": str(folder / "production-cases.sqlite3"),
            "GRC_DB_PATH": str(folder / "production-grc.sqlite3"),
            "SOC_OLLAMA_MODEL": "test-model-only",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    @staticmethod
    def decision(label="suspicious", refs=None):
        return {"classification": label, "rationale": "This synthetic packet needs review based on its recorded observations.",
                "evidence_refs": ["A1"] if refs is None else refs, "limitations": ["Synthetic fixed evidence only."]}

    def model_message(self, label="suspicious", refs=None):
        return {"content": json.dumps(self.decision(label, refs))}

    def test_catalogue_is_balanced_and_does_not_expose_answer_key(self):
        fixture = benchmark._fixture()
        self.assertEqual(len(fixture["cases"]), 16)
        for label in benchmark.LABELS:
            self.assertEqual(sum(c["expected_label"] == label for c in fixture["cases"]), 4)
        public = json.dumps(benchmark.dataset())
        self.assertNotIn("expected_label", public)
        self.assertNotIn("rubric", public)
        self.assertNotIn("account_owner_statement", public)
        self.assertTrue(any(not c["evidence"] for c in fixture["cases"]))
        self.assertTrue(any(any(e["status"] == "error" for e in c["evidence"].values()) for c in fixture["cases"]))

    def test_manual_is_blinded_and_model_cannot_precede_submission(self):
        trial = benchmark.create_trial({"scenario_id": "S05", "analyst": "QA operator"})
        self.assertFalse(trial["analyst_identity_verified"])
        self.assertNotIn("answer_key", trial)
        self.assertNotIn("expected_label", json.dumps(trial))
        with patch.object(benchmark, "_call_model") as model:
            with self.assertRaisesRegex(ValueError, "Submit the manual"):
                benchmark.run_ai_trial(trial["id"])
            model.assert_not_called()
        completed = benchmark.finish_manual(trial["id"], self.decision())
        self.assertNotIn("answer_key", completed)
        self.assertEqual(completed["manual"]["status"], "completed")
        with self.assertRaises(ValueError):
            benchmark.finish_manual(trial["id"], self.decision())

    def test_identical_immutable_packet_and_no_production_writes(self):
        trial = benchmark.create_trial({"scenario_id": "S05"})
        benchmark.finish_manual(trial["id"], self.decision())
        seen = []
        def run(evidence, context):
            seen.append(copy.deepcopy(evidence))
            context["llm_requests"] = [{"phase": "synthetic_comparison", "prompt_tokens": 200}]
            return self.model_message()
        with patch.object(benchmark, "_call_model", side_effect=run):
            result = benchmark.run_ai_trial(trial["id"])
        self.assertEqual(seen, [trial["evidence"]])
        self.assertNotIn("expected_label", json.dumps(seen))
        self.assertEqual(result["answer_key"]["classification"], "suspicious")
        self.assertFalse(result["ai"]["fallback_used"])
        self.assertEqual(result["ai"]["model"], "test-model-only")
        self.assertFalse(Path(os.environ["SOC_CASE_DB_PATH"]).exists())
        self.assertFalse(Path(os.environ["GRC_DB_PATH"]).exists())
        with self.assertRaises(ValueError):
            benchmark.run_ai_trial(trial["id"])

    def test_ai_only_never_creates_fabricated_manual_results(self):
        trial = benchmark.start_ai_only("S13")
        with patch.object(benchmark, "_call_model", return_value=self.model_message("insufficient", [])):
            result = benchmark.run_ai_trial(trial["id"])
        self.assertEqual(result["manual"], {"status": "not_recorded"})
        stats = benchmark.summary()
        self.assertEqual(stats["manual"]["n"], 0)
        self.assertEqual(stats["manual"]["correct"], 0)
        self.assertIsNone(stats["manual"]["label_agreement_rate"])
        self.assertIsNone(stats["paired_wall_delta_seconds_mean"])
        self.assertEqual(stats["paired_completed"], 0)
        self.assertEqual(stats["ai"]["correct"], 1)
        self.assertEqual(stats["ai"]["reference_error_trials"], 0)

    def test_provider_failure_is_counted_without_fallback_or_exception_secret(self):
        trial = benchmark.start_ai_only("S01")
        with patch.object(benchmark, "_call_model", side_effect=RuntimeError("https://secret.example?token=private")):
            result = benchmark.run_ai_trial(trial["id"])
        self.assertEqual(result["ai"]["failure_kind"], "provider_error")
        self.assertFalse(result["ai"]["fallback_used"])
        self.assertNotIn("private", json.dumps(result))
        stats = benchmark.summary()["ai"]
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["completed"], 0)
        self.assertEqual(stats["failure_rate"], 1)
        self.assertIsNone(stats["label_agreement_rate"])

    def test_incomplete_model_output_is_not_scored_as_correct(self):
        trial = benchmark.start_ai_only("S05")
        with patch.object(benchmark, "_call_model", return_value={"content": '{"classification":"suspicious"}'}):
            result = benchmark.run_ai_trial(trial["id"])
        self.assertEqual(result["ai"]["failure_kind"], "invalid_response")
        self.assertEqual(benchmark.summary()["ai"]["correct"], 0)

    def test_reference_integrity_is_separate_from_label_agreement(self):
        trial = benchmark.start_ai_only("S08")
        with patch.object(benchmark, "_call_model", return_value=self.model_message("suspicious", ["T1", "T99"])):
            result = benchmark.run_ai_trial(trial["id"])
        errors = result["ai"]["decision"]["reference_errors"]
        self.assertIn("unknown_reference:T99", errors)
        self.assertIn("no_available_supporting_reference", errors)
        stats = benchmark.summary()["ai"]
        self.assertEqual(stats["correct"], 1)
        self.assertEqual(stats["reference_error_trials"], 1)
        self.assertEqual(stats["reference_error_rate"], 1)

    def test_elapsed_active_and_paired_metrics_do_not_imply_savings(self):
        trial = benchmark.create_trial({"scenario_id": "S05"})
        with self.assertRaises(ValueError):
            benchmark.finish_manual(trial["id"], {**self.decision(), "active_seconds": 100000})
        with self.assertRaises(ValueError):
            benchmark.finish_manual(trial["id"], {**self.decision(), "active_seconds": float("nan")})
        benchmark.finish_manual(trial["id"], {**self.decision(), "active_seconds": 0})
        with patch.object(benchmark, "_call_model", return_value=self.model_message("benign")):
            benchmark.run_ai_trial(trial["id"])
        stats = benchmark.summary()
        self.assertEqual(stats["paired_completed"], 1)
        self.assertEqual(stats["manual"]["correct"], 1)
        self.assertEqual(stats["ai"]["incorrect"], 1)
        self.assertEqual(stats["manual"]["active_time_n"], 1)
        self.assertEqual(stats["manual"]["active_seconds_total_self_reported"], 0)
        self.assertIn("not analyst active-time savings", stats["paired_wall_delta_definition"])
        self.assertNotIn("savings_percent", stats)

    def test_snapshot_survives_fixture_changes(self):
        trial = benchmark.start_ai_only("S05")
        fixture = benchmark._fixture()
        fixture["cases"][4]["expected_label"] = "benign"
        fixture["cases"][4]["evidence"] = {}
        with patch.object(benchmark, "_fixture", return_value=fixture), patch.object(benchmark, "_call_model", return_value=self.model_message()):
            result = benchmark.run_ai_trial(trial["id"])
        self.assertEqual(result["answer_key"]["classification"], "suspicious")
        self.assertEqual(result["evidence"], trial["evidence"])

    def test_storage_refuses_production_db_alias(self):
        with patch.dict(os.environ, {"SOC_BENCHMARK_DB_PATH": os.environ["SOC_CASE_DB_PATH"]}):
            with self.assertRaisesRegex(ValueError, "separate"):
                benchmark.start_ai_only("S01")
        self.assertFalse(Path(os.environ["SOC_CASE_DB_PATH"]).exists())

    def test_concurrent_model_admission_is_bounded_and_retryable(self):
        first = benchmark.start_ai_only("S05")
        second = benchmark.start_ai_only("S06")
        entered, release = threading.Event(), threading.Event()
        exceptions = []
        def call(evidence, context):
            entered.set()
            release.wait(4)
            return self.model_message()
        def run():
            try:
                benchmark.run_ai_trial(first["id"])
            except Exception as exc:
                exceptions.append(exc)
        with patch.object(benchmark, "_call_model", side_effect=call):
            thread = threading.Thread(target=run)
            thread.start()
            try:
                self.assertTrue(entered.wait(3))
                with self.assertRaisesRegex(ValueError, "Another comparison"):
                    benchmark.run_ai_trial(second["id"])
                self.assertEqual(benchmark.get_trial(second["id"])["ai"]["status"], "pending")
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(exceptions, [])

    def test_invalid_ids_and_inputs(self):
        with self.assertRaises(KeyError):
            benchmark.get_trial("missing")
        with self.assertRaises(ValueError):
            benchmark.create_trial({"scenario_id": "missing"})
        with self.assertRaises(ValueError):
            benchmark.create_trial({"scenario_id": "S01", "classification": "malicious"})
        with self.assertRaises(ValueError):
            benchmark.list_trials(10000)

    def test_polling_recovers_interrupted_model_runs_without_new_trial(self):
        for read in (benchmark.get_trial, lambda _: benchmark.list_trials(), lambda _: benchmark.summary()):
            trial = benchmark.start_ai_only("S05")
            with benchmark._db() as conn:
                saved = benchmark._load(conn, trial["id"])
                saved["ai"].update(status="running", started_at="2000-01-01T00:00:00+00:00", run_id="expired")
                benchmark._save(conn, saved)
            read(trial["id"])
            result = benchmark.get_trial(trial["id"])
            self.assertEqual(result["ai"]["status"], "failed")
            self.assertEqual(result["ai"]["failure_kind"], "interrupted")
        self.assertEqual(benchmark.summary()["ai"]["failed"], 3)

    def test_late_worker_cannot_overwrite_recovered_run(self):
        trial = benchmark.start_ai_only("S05")
        def late_model(evidence, context):
            with benchmark._db() as conn:
                saved = benchmark._load(conn, trial["id"])
                saved["ai"].update(status="failed", failure_kind="interrupted", run_id="recovered-owner")
                benchmark._save(conn, saved)
            return self.model_message()
        with patch.object(benchmark, "_call_model", side_effect=late_model):
            result = benchmark.run_ai_trial(trial["id"])
        self.assertEqual(result["ai"]["status"], "failed")
        self.assertEqual(result["ai"]["failure_kind"], "interrupted")
        self.assertNotIn("decision", result["ai"])


if __name__ == "__main__":
    unittest.main()

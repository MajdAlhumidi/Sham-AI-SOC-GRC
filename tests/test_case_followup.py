import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scripts.casework import followup, store


class FollowupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            "SOC_CASE_DB_PATH": str(Path(self.temp.name)/"cases.db"),
            "SOC_AUDIT_LOG_PATH": str(Path(self.temp.name)/"tools.jsonl"),
            "SOC_FOLLOWUP_MAX_TOOL_STEPS": "3", "SOC_FOLLOWUP_MAX_PENDING": "4",
            "SOC_OLLAMA_MODEL": "fixture-model",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def capture(self, incident="INC-1", *, legacy=False):
        record = dict(incident_id=incident, source_alert_id="wazuh-"+incident,
                      target_host="QA host", timestamp="2026-11-13T12:00:00Z",
                      analyst_notes="A saved preliminary report, not verified ground truth.")
        if legacy:
            return store.capture(record)
        alert = dict(id=record["source_alert_id"], timestamp=record["timestamp"],
                     agent={"id": "001", "name": "QA host"},
                     rule={"id": "5710", "description": "SSH authentication failure", "level": 7},
                     data={"srcip": "8.8.8.8", "dstuser": "admin"})
        return store.capture(record, alert)

    @staticmethod
    def final(refs=None, text="The saved evidence records a failed login; it does not establish compromise."):
        refs = refs or ["S1"]
        return {"content": json.dumps(dict(answer=text, answer_evidence=refs,
            findings=[dict(observation="A failed authentication event was recorded.", evidence=refs)],
            limitations=["A failed login alone does not establish its cause or later success."],
            recommended_next_steps=["Review related authentication activity with the analyst."]))}

    @staticmethod
    def call(name="search_related_agent_logs", **arguments):
        return {"tool_calls": [{"function": {"name": name, "arguments": arguments}}]}

    def run_answers(self, case, responses, question="Did a login succeed after this failure?", request_id="request-1"):
        turn = followup.enqueue(case, question, request_id)
        with patch.object(followup.investigator, "_ollama_chat", side_effect=responses) as model:
            followup.run_turn(turn["id"])
        return followup.get_turn(case, turn["id"]), model

    def test_enqueue_idempotency_conflict_busy_and_bounds(self):
        case = self.capture()
        first = followup.enqueue(case, "What happened to this login?", "retry-1")
        self.assertEqual(first["id"], followup.enqueue(case, "What happened to this login?", "retry-1")["id"])
        with self.assertRaises(followup.FollowupConflict):
            followup.enqueue(case, "A different question?", "retry-1")
        with self.assertRaises(followup.FollowupBusy):
            followup.enqueue(case, "A different question?", "new-2")
        for question, request in [("x", "ok"), ("x"*1201, "ok"), ("Valid question", "../bad"), (None, "ok")]:
            with self.assertRaises(ValueError):
                followup.enqueue(case, question, request)
        with self.assertRaises(KeyError):
            followup.enqueue("missing", "What happened here?", "missing")
        self.assertIsNone(followup.get_turn(case, "missing"))
        self.assertEqual(len(followup.list_turns(case)), 1)

    def test_overall_queue_bound_does_not_insert_extra_job(self):
        with patch.dict(os.environ, {"SOC_FOLLOWUP_MAX_PENDING": "1"}):
            first, second = self.capture(), self.capture("INC-OTHER")
            # Distinct timestamps alone are not needed: missing source => these
            # alerts do not auto-correlate, so use archived independent case.
            second = self.capture("INC-ARCHIVE", legacy=True)
            followup.enqueue(first, "What happened here?", "a")
            with self.assertRaises(followup.FollowupQueueFull):
                followup.enqueue(second, "What happened here?", "b")
            self.assertEqual(followup.list_turns(second), [])

    def test_question_focus_native_tools_fresh_evidence_and_idempotent_worker(self):
        case = self.capture()
        original = copy.deepcopy(store.get_evidence("INC-1", "A1"))
        question = "Did an authentication succeed, or is only a failure recorded?"
        responses = [self.call(agent_id="001", query="successful authentication", time_range_minutes=30),
                     {"content": "DONE"}, self.final(["S1", "F1"])]
        with patch.object(followup.investigator, "_dispatch_tool", return_value='{"status":"success","records":[{"action":"login failed"}]}') as dispatch:
            result, model = self.run_answers(case, responses, question)
        self.assertEqual(result["status"], "completed")
        dispatch.assert_called_once_with("search_related_agent_logs", {"agent_id": "001", "query": "successful authentication", "time_range_minutes": 30})
        self.assertEqual(result["model"], "fixture-model")
        self.assertEqual(result["containment_status"], "NOT_EXECUTED")
        self.assertIn("F1", result["evidence"])
        self.assertEqual(result["evidence"]["F1"]["provenance"], "fresh_followup_tool_result")
        self.assertEqual(result["evidence"]["F1"]["time_basis"], "recent_query_at_followup_not_original_event")
        self.assertEqual(result["tool_trace"][0]["status"], "success")
        self.assertEqual(original, store.get_evidence("INC-1", "A1"))
        for call in model.call_args_list:
            self.assertIn(question, call.args[0][-1]["content"])
        self.assertIn("SSH authentication failure", model.call_args_list[0].args[0][1]["content"])
        self.assertIn("login failed", model.call_args_list[-1].args[0][1]["content"])
        with patch.object(followup.investigator, "_ollama_chat") as again:
            followup.run_turn(result["id"])
            again.assert_not_called()
        summary = followup.list_turns(case)[0]
        self.assertNotIn("evidence", summary)
        self.assertNotIn("snapshot_json", result)
        self.assertIn("F1", summary["evidence_refs"])
        self.assertNotIn("result", summary["tool_trace"][0])
        actions = [x["action"] for x in store.audit_page()["items"]]
        self.assertIn("followup_queued", actions)
        self.assertIn("followup_started", actions)
        self.assertIn("followup_finished", actions)

    def test_cross_agent_unobserved_indicator_and_containment_never_dispatch(self):
        case = self.capture()
        calls = {"tool_calls": [
            self.call(agent_id="999", query="all users")["tool_calls"][0],
            self.call("check_ip_reputation", ip="1.1.1.1")["tool_calls"][0],
            self.call("trigger_containment_action", agent_id="001", command="isolate")["tool_calls"][0]]}
        with patch.object(followup.investigator, "_dispatch_tool") as dispatch:
            result, _ = self.run_answers(case, [calls, self.final()])
        dispatch.assert_not_called()
        self.assertEqual(result["status"], "limited")
        self.assertEqual([x["status"] for x in result["tool_trace"]], ["blocked"]*3)
        self.assertIn("Cross-agent", result["tool_trace"][0]["result"])
        self.assertEqual(result["containment_status"], "NOT_EXECUTED")

    def test_remote_syslog_collector_is_not_an_endpoint_query_target(self):
        alert = dict(id="router-alert", timestamp="2026-11-13T12:00:00Z",
            agent={"id": "000", "name": "collector"}, location="10.0.0.2",
            rule={"id": "100111", "description": "Router login failure", "level": 7},
            decoder={"name": "mikrotik"}, data={"srcip": "8.8.8.8"})
        case = store.capture({"incident_id": "ROUTER-1"}, alert)
        with patch.object(followup.investigator, "_dispatch_tool") as dispatch:
            result, model = self.run_answers(case, [self.call(agent_id="000", query="login"), {"content": "DONE"}, self.final()])
        dispatch.assert_not_called()
        tools = model.call_args_list[0].kwargs["tools"]
        self.assertFalse(any(t["function"]["name"] in followup.investigator.EVIDENCE_TOOL_NAMES for t in tools))
        self.assertEqual(result["scope"]["original_agent_id"], "000")
        self.assertFalse(result["scope"]["endpoint_queries_allowed"])
        self.assertEqual(result["tool_trace"][0]["status"], "blocked")
        self.assertEqual(result["status"], "limited")
        self.assertTrue(any("manager/collector" in x for x in result["limitations"]))

    def test_no_remaining_tools_goes_directly_to_answer_after_local_history(self):
        alert = dict(id="private-router-alert", timestamp="2026-11-13T12:00:00Z",
            agent={"id": "000", "name": "collector"}, location="10.0.0.2",
            rule={"id": "100111", "description": "Router login failure", "level": 7},
            decoder={"name": "mikrotik"}, data={"srcip": "192.168.10.10"})
        case = store.capture({"incident_id": "PRIVATE-ROUTER"}, alert)
        with patch.object(followup.investigator, "_dispatch_tool", return_value='{"status":"empty","historical_cases":[]}'):
            result, model = self.run_answers(case, [self.call("search_historical_incidents", query="authentication"), self.final()])
        self.assertEqual(model.call_count, 2)
        self.assertEqual([call.args[2] for call in model.call_args_list], ["case_followup_tools", "case_followup_answer"])
        self.assertEqual(result["status"], "limited")
        self.assertEqual(len(result["tool_trace"]), 1)

    def test_failed_tool_cannot_be_positive_support(self):
        case = self.capture()
        with patch.object(followup.investigator, "_dispatch_tool", return_value='{"status":"error","message":"not available"}'):
            result, _ = self.run_answers(case, [self.call(agent_id="001", query="login"),
                {"content": "DONE"}, self.final(["F1"]), self.final(["F1"])])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "invalid_model_output")
        self.assertEqual(result["answer"], "")
        self.assertEqual(result["tool_trace"][0]["status"], "error")

    def test_unsupported_references_repair_once_then_fail_without_answer(self):
        case = self.capture()
        result, model = self.run_answers(case, [{"content": "DONE"}, self.final(["MADE-UP"]), self.final(["MADE-UP"])])
        self.assertEqual(model.call_count, 3)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["answer"])
        self.assertFalse(result["findings"])
        self.assertEqual(result["reference_validation"], "not_completed")

    def test_archived_case_has_saved_context_only_and_never_advertises_tools(self):
        case = self.capture(legacy=True)
        with patch.object(followup.investigator, "_dispatch_tool") as dispatch:
            result, model = self.run_answers(case, [self.final(text="The saved report contains a preliminary claim; the original alert is unavailable.")])
        self.assertEqual(model.call_count, 1)
        self.assertEqual(model.call_args.args[2], "case_followup_answer")
        self.assertIsNone(model.call_args.kwargs["tools"])
        dispatch.assert_not_called()
        self.assertEqual(result["status"], "limited")
        self.assertEqual(result["source_status"], "archive_only")
        self.assertIn("Saved-context answer only", result["answer"])
        self.assertTrue(any("No fresh original-agent" in x for x in result["limitations"]))

    def test_bad_original_hash_cannot_supply_scope(self):
        case = self.capture()
        with store.db() as conn:
            conn.execute("UPDATE evidence SET payload=? WHERE incident_id=?", ('{"kind":"incoming_alert","value":{"agent":{"id":"999"}}}', "INC-1"))
        with patch.object(followup.investigator, "_ollama_chat") as model, patch.object(followup.investigator, "_dispatch_tool") as dispatch:
            turn = followup.enqueue(case, "Can you inspect the original agent?", "bad-hash")
            followup.run_turn(turn["id"])
        result = followup.get_turn(case, turn["id"])
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["source_status"], "original_unavailable")
        model.assert_not_called()
        dispatch.assert_not_called()
        self.assertTrue(any("integrity" in x for x in result["limitations"]))

    def test_later_turn_has_untrusted_history_not_new_target_authority(self):
        case = self.capture()
        first, _ = self.run_answers(case, [{"content": "DONE"}, self.final(text="The operator mentioned 1.1.1.1, but that address is not observed in this alert.")])
        with patch.object(followup.investigator, "_dispatch_tool") as dispatch:
            second, model = self.run_answers(case, [self.call("check_ip_reputation", ip="1.1.1.1"), {"content": "DONE"}, self.final()],
                question="Check the address discussed in the previous answer.", request_id="second")
        self.assertEqual(second["status"], "limited")
        self.assertIn("prior_turns_untrusted", model.call_args_list[0].args[0][1]["content"])
        self.assertIn(first["answer"], model.call_args_list[0].args[0][1]["content"])
        dispatch.assert_not_called()
        self.assertIn("not observed", second["tool_trace"][0]["result"])

    def test_model_outage_is_visible_and_malformed_prose_never_executes(self):
        case = self.capture()
        turn = followup.enqueue(case, "Did a login succeed?", "offline")
        with patch.object(followup.investigator, "_ollama_chat", side_effect=OSError("private connection detail")):
            followup.run_turn(turn["id"])
        result = followup.get_turn(case, turn["id"])
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["answer"])
        self.assertNotIn("private connection detail", json.dumps(result))
        malformed = {"content": '{"function":"inspect_process_tree","arguments":{"agent_id":"001"}}'}
        with patch.object(followup.investigator, "_dispatch_tool") as dispatch:
            result, model = self.run_answers(case, [malformed, malformed, self.final()], request_id="text-tool")
        self.assertEqual(model.call_count, 3)
        self.assertEqual(result["status"], "limited")
        self.assertTrue(result["answer"])
        self.assertFalse(result["tool_trace"])
        self.assertTrue(any("not executed" in x for x in result["limitations"]))
        dispatch.assert_not_called()

    def test_malformed_selection_retry_can_recover_native_tool_use(self):
        case = self.capture()
        malformed = {"content": '{"name":"search_related_agent_logs","arguments":{"agent_id":"001"}}'}
        with patch.object(followup.investigator, "_dispatch_tool", return_value='{"status":"empty","records":[]}') as dispatch:
            result, model = self.run_answers(case, [malformed, self.call(agent_id="001", query="login"), {"content": "DONE"}, self.final()])
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(result["status"], "limited")
        self.assertEqual(len(result["tool_trace"]), 1)
        self.assertIn("was not a valid native call", model.call_args_list[1].args[0][0]["content"])

    def test_expired_running_jobs_visible_and_new_turn_can_proceed(self):
        case = self.capture()
        turn = followup.enqueue(case, "What happened here?", "expired")
        with store.db() as conn:
            conn.execute("UPDATE case_followup_turns SET status='running',expires_at=0 WHERE id=?", (turn["id"],))
        expired = followup.list_turns(case)[0]
        self.assertEqual(expired["status"], "failed")
        self.assertEqual(expired["error"], "interrupted_or_expired")
        self.assertFalse(expired["answer"])
        new = followup.enqueue(case, "What should be reviewed next?", "new-job")
        self.assertEqual(new["status"], "queued")

    def test_wait_budget_keeps_lingering_calls_bounded_and_discards_late_data(self):
        release, returned = threading.Event(), threading.Event()
        def slow():
            release.wait(timeout=1)
            returned.set()
            return "late unaccepted result"
        with patch.object(followup, "_calls", threading.BoundedSemaphore(1)):
            try:
                with self.assertRaises(followup._BudgetError):
                    followup._wait_call(slow, 0.01)
                with self.assertRaises(followup._Unavailable):
                    followup._wait_call(lambda: "must not start", 0.01)
            finally:
                release.set()
                self.assertTrue(returned.wait(timeout=1))

    def test_duplicate_scheduled_worker_does_not_wait_or_run_a_second_job(self):
        case = self.capture()
        turn = followup.enqueue(case, "Did an authentication succeed?", "queued-retry")
        worker_slots = threading.Semaphore(0)
        with patch.object(followup, "_workers", worker_slots), patch.object(followup.investigator, "_ollama_chat", side_effect=[{"content": "DONE"}, self.final()]) as model:
            first = threading.Thread(target=followup.run_turn, args=(turn["id"],))
            first.start()
            try:
                for _ in range(100):
                    with store.db() as conn:
                        reserved = conn.execute("SELECT worker_id FROM case_followup_turns WHERE id=?", (turn["id"],)).fetchone()[0]
                    if reserved:
                        break
                    time.sleep(0.005)
                self.assertTrue(reserved)
                duplicate = threading.Thread(target=followup.run_turn, args=(turn["id"],))
                duplicate.start()
                duplicate.join(timeout=0.5)
                self.assertFalse(duplicate.is_alive(), "Duplicate task must return before a worker slot is free")
                model.assert_not_called()
            finally:
                worker_slots.release()
                first.join(timeout=2)
            self.assertFalse(first.is_alive())
            self.assertEqual(model.call_count, 2)
        self.assertEqual(followup.get_turn(case, turn["id"])["status"], "completed")

    def test_scoped_package_mode_dispatch_does_not_require_vector_store(self):
        from scripts import agent_tools
        with patch.object(agent_tools, "query_related_alerts", return_value='{"status":"success"}') as query:
            result = followup.investigator._dispatch_tool("search_related_agent_logs", {"agent_id": "001", "query": "login", "time_range_minutes": 5})
        self.assertEqual(json.loads(result)["status"], "success")
        self.assertEqual(query.call_args.kwargs["agent_id"], "001")

    def test_false_execution_claims_in_any_output_and_arabic_are_rejected(self):
        packet = {"S1": {"status": "observed"}}
        for text in ["We isolated the host successfully.", "The device was quarantined by the agent.",
                     "عزلت الجهاز بعد فحص التنبيه.", "تم حظر العنوان بنجاح."]:
            for field in ["answer", "findings", "recommended_next_steps"]:
                payload = json.loads(self.final()["content"])
                if field == "findings":
                    payload[field][0]["observation"] = text
                elif field == "recommended_next_steps":
                    payload[field] = [text]
                else:
                    payload[field] = text
                with self.assertRaises(ValueError, msg=(field, text)):
                    followup._validate_answer(json.dumps(payload), packet)
        payload = json.loads(self.final()["content"])
        payload["recommended_next_steps"] = ["Recommend isolating the host only after separate approval.", "ينبغي حظر العنوان بعد موافقة المسؤول."]
        self.assertTrue(followup._validate_answer(json.dumps(payload), packet))


if __name__ == "__main__":
    unittest.main()

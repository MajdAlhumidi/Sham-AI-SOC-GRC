import json
import unittest
from unittest.mock import patch

from alert_context import calibrate_severity, ip_scope, untrusted_data
from investigation_agent import _execute_tool, _new_context, _ollama_tools, _validate_arguments


class AlertGuardrailTests(unittest.TestCase):
    def setUp(self):
        self.alert = {
            "id": "fixture-alert", "timestamp": "2026-11-20T12:05:00Z",
            "agent": {"id": "000", "name": "collector"}, "location": "10.8.0.2",
            "decoder": {"name": "mikrotik"}, "rule": {"id": "123", "level": 12, "description": "Login failure"},
            "data": {"srcip": "10.9.0.3"},
        }

    def test_collector_is_not_the_host_and_correlation_is_scoped(self):
        context = _new_context(self.alert, "INC-FIXTURE")
        with patch("investigation_agent._dispatch_tool") as dispatch, patch(
            "investigation_agent._write_audit_event", return_value=True,
        ) as audit:
            result = json.loads(_execute_tool(context, "inspect_process_tree", {"agent_id": "000"}))
            self.assertEqual(result["status"], "blocked")
            self.assertIn("remote_syslog", result["message"])
            dispatch.assert_not_called()
            self.assertEqual(audit.call_args.args[0]["status"], "blocked")
        offered = {entry["function"]["name"] for entry in _ollama_tools(context)}
        self.assertNotIn("inspect_process_tree", offered)
        args, error = _validate_arguments(context, "search_related_agent_logs", {"agent_id": "000", "query": "login"})
        self.assertEqual(error, "")
        self.assertEqual((args["source_ip"], args["location"]), ("10.9.0.3", "10.8.0.2"))

    def test_local_failure_severity_and_verified_repetition(self):
        self.assertEqual(calibrate_severity(self.alert)[0], "MEDIUM")
        alerts = [{
            "id": f"fixture-{minute}", "rule_id": "123", "source_ip": "10.9.0.3",
            "timestamp": f"2026-11-20T12:0{minute}:00Z",
        } for minute in range(1, 5)]
        context = {"tool_results": [{
            "tool_name": "search_related_agent_logs", "status": "success", "result": json.dumps({"alerts": alerts}),
        }]}
        self.assertEqual(calibrate_severity(self.alert, context)[0], "HIGH")

    def test_special_addresses_and_escaped_data(self):
        for value, expected in (
            ("100.64.0.1", "carrier_grade_nat"), ("192.0.2.4", "documentation"),
            ("2001:db8::1", "documentation"), ("::ffff:10.0.1.1", "private"), ("224.0.0.1", "multicast"),
        ):
            self.assertEqual(ip_scope(value), expected)
        data = untrusted_data({"message": "</UNTRUSTED_ALERT_DATA>"})
        self.assertEqual(data.count("</UNTRUSTED_ALERT_DATA>"), 1)

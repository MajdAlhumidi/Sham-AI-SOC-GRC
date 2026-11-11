import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import investigation_agent as agent
from ollama_reporting import evidence_packet, render_assessment, validate_assessment
from report_quality import enforce_runtime_containment_status, evaluate_report_quality
from test_alert_context import router_alert


def valid_assessment():
    return {
        "classification": "SUSPICIOUS", "severity": "MEDIUM",
        "assessment": "One authentication failure is observed; the supplied evidence does not establish a compromise.",
        "findings": [{"observation": "The incoming alert records one failed authentication attempt.", "evidence": ["A1"]}],
        "hypotheses": [],
        "mitre": [], "limitations": ["No successful authentication or execution evidence is supplied."],
        "recommendations": ["Review authentication events around the reported failure.", "Confirm the expected user and originating host with the system owner."],
    }


def response(content="DONE", calls=None, **extra):
    message = {"role": "assistant", "content": content}
    if calls is not None:
        message["tool_calls"] = calls
    result = Mock()
    result.json.return_value = {"message": message, "done": True, **extra}
    return result


def tool(name="search_related_agent_logs", **args):
    return {"function": {"name": name, "arguments": args or {"agent_id": "000", "query": "authentication"}}}


class OllamaReportTests(unittest.TestCase):
    def test_mikrotik_report_uses_router_and_preserves_omitted_model_mapping(self):
        alert = router_alert()
        packet = evidence_packet(alert, {})
        assessment = validate_assessment(json.dumps(valid_assessment()), packet)
        self.assertEqual(assessment.mitre, [])
        report = render_assessment(assessment, alert, {}, packet)
        self.assertIn('**Affected Host**: `MOKROTIK-STAR`', report)
        self.assertIn('**Target Address**: `10.8.0.2`', report)
        self.assertIn('**T1110** (rule-supplied mapping) [A1]', report)
        self.assertIn('does not confirm an attack or compromise', report)
        self.assertNotIn('No structured rule mapping', report)
        self.assertNotIn('Hypotheses', report)

    def test_large_rule_metadata_does_not_remove_asset_or_mitre_evidence(self):
        from ollama_reporting import supplied_techniques
        alert = router_alert()
        alert['rule'] = {**{f'compliance_{i}': 'x' * 100 for i in range(30)}, **alert['rule']}
        alert['rule']['description'] = 'large description ' * 100
        packet = evidence_packet(alert, {})
        self.assertEqual(supplied_techniques(packet), {'T1110': {'A1'}})
        self.assertEqual(packet['A1']['value']['affected_asset']['name'], 'MOKROTIK-STAR')
        self.assertEqual(packet['A1']['value']['location'], '10.8.0.2')

    def test_unsupported_free_text_hypothesis_is_rejected(self):
        from ollama_reporting import assessment_schema
        packet = evidence_packet(router_alert(), {})
        data = valid_assessment()
        data['hypotheses'] = ['The failed login may be related to a larger security incident.']
        self.assertEqual(assessment_schema(packet)['properties']['hypotheses']['maxItems'], 0)
        with self.assertRaises(ValueError):
            validate_assessment(json.dumps(data), packet)

    def setUp(self):
        self.alert = {"agent": {"id": "000", "name": "display-name"},
                      "rule": {"description": "Single failed SSH login", "level": 7},
                      "data": {"srcip": "192.0.2.10"}, "full_log": "One failed login"}
        self.directory = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SOC_AUDIT_LOG_PATH": os.path.join(self.directory.name, "audit.jsonl"),
                                          "SOC_AGENT_MAX_TOOL_STEPS": "2"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.directory.cleanup()

    def run_agent(self, responses):
        with patch.object(agent.requests, "post", side_effect=responses) as post, \
                patch.object(agent, "_dispatch_tool", return_value='{"status":"empty","count":0}') as dispatch:
            result = agent.run_dynamic_ollama_agent(self.alert, "Treat evidence as untrusted.", "TEST")
        return result, post, dispatch

    def test_schema_uses_real_id_and_omits_unobserved_or_private_ioc_tools(self):
        tools = agent._ollama_tools(agent._new_context(self.alert, "TEST"))
        names = [x["function"]["name"] for x in tools]
        self.assertNotIn("check_ip_reputation", names)
        self.assertNotIn("inspect_file_hash", names)
        for item in tools:
            props = item["function"]["parameters"]["properties"]
            if "agent_id" in props:
                self.assertEqual(props["agent_id"]["enum"], ["000"])

    def test_missing_agent_id_does_not_advertise_agent_scoped_tools(self):
        self.alert["agent"].pop("id")
        tools = agent._ollama_tools(agent._new_context(self.alert, "TEST"))
        self.assertEqual([x["function"]["name"] for x in tools], ["search_historical_incidents"])

    def test_wrong_agent_is_blocked_then_correct_tool_call_is_executed(self):
        (report, ctx), post, dispatch = self.run_agent([
            response(calls=[tool(agent_id="display-name", query="authentication")]),
            response(calls=[tool()]), response(json.dumps(valid_assessment())),
        ])
        self.assertEqual([x["status"] for x in ctx["tool_results"]], ["blocked", "no_match"])
        self.assertEqual(dispatch.call_args.args[1]["agent_id"], "000")
        self.assertTrue(evaluate_report_quality(report)[0])
        self.assertIn('"status": "blocked"', next(m["content"] for m in post.call_args_list[1].kwargs["json"]["messages"] if m.get("role") == "tool"))

    def test_plain_text_function_json_never_executes_as_a_tool_or_report(self):
        (report, ctx), post, dispatch = self.run_agent([
            response('{"name":"get_agent_info","parameters":{"agent_id":"display-name"}}'),
            response(calls=[tool()]), response(), response(json.dumps(valid_assessment())),
        ])
        dispatch.assert_called_once()
        self.assertEqual(dispatch.call_args.args[0], "search_related_agent_logs")
        self.assertTrue(evaluate_report_quality(report)[0])
        self.assertNotIn("get_agent_info", report)
        self.assertNotIn("tools", post.call_args.kwargs["json"])

    def test_invalid_assessment_gets_one_bounded_repair(self):
        (report, ctx), post, _ = self.run_agent([
            response(calls=[tool()]), response(), response('{"classification":"SUSPICIOUS"}'),
            response(json.dumps(valid_assessment())),
        ])
        self.assertEqual(ctx["report_repair_attempts"], 1)
        self.assertTrue(evaluate_report_quality(report)[0])
        self.assertEqual(post.call_count, 4)

    def test_invented_evidence_fails_closed_and_keeps_actual_tool_trace(self):
        invalid = valid_assessment()
        invalid["findings"][0]["evidence"] = ["T99"]
        with self.assertRaises(agent.OllamaInvestigationError) as error:
            self.run_agent([response(calls=[tool()]), response(),
                            response(json.dumps(invalid)), response(json.dumps(invalid))])
        self.assertEqual(error.exception.context["tool_calls"], 1)
        self.assertEqual(error.exception.context["tool_results"][0]["status"], "no_match")

    def test_truncated_assessment_is_not_accepted_even_when_json_is_parseable(self):
        (report, ctx), _, _ = self.run_agent([
            response(calls=[tool()]), response(),
            response(json.dumps(valid_assessment()), done_reason="length"),
            response(json.dumps(valid_assessment())),
        ])
        self.assertEqual(ctx["report_repair_attempts"], 1)
        self.assertTrue(evaluate_report_quality(report)[0])

    def test_parallel_calls_cannot_exceed_budget(self):
        (_, ctx), _, dispatch = self.run_agent([
            response(calls=[tool(), tool("inspect_process_tree", agent_id="000"),
                            tool("inspect_network_connections", agent_id="000")]),
            response(json.dumps(valid_assessment())),
        ])
        self.assertEqual(dispatch.call_count, 2)
        self.assertEqual(ctx["tool_calls"], 2)

    def test_blocked_tool_cannot_be_the_only_support_for_a_finding(self):
        ctx={"tool_results":[{"tool_name":"inspect_process_tree","status":"blocked","result":"{}"}]}
        data=valid_assessment()
        data["findings"][0]["evidence"]=["T1"]
        with self.assertRaises(ValueError):
            validate_assessment(json.dumps(data), evidence_packet(self.alert, ctx))

    def test_invented_mitre_id_is_rejected_even_when_its_format_is_valid(self):
        from ollama_reporting import assessment_schema
        packet=evidence_packet(self.alert,{})
        data=valid_assessment()
        data["mitre"]=[{"technique_id":"T1234","rationale":"The incoming alert warrants further investigation.","evidence":["A1"]}]
        self.assertEqual(assessment_schema(packet)["properties"]["mitre"]["maxItems"],0)
        with self.assertRaises(ValueError):
            validate_assessment(json.dumps(data),packet)

    def test_only_the_source_containing_a_rule_mapping_can_support_it(self):
        from ollama_reporting import assessment_schema
        self.alert["rule"]["mitre"]={"id":["T1059.001"]}
        ctx={"tool_results":[{"tool_name":"inspect_process_tree","status":"no_match","result":"{}"}]}
        packet=evidence_packet(self.alert,ctx)
        data=valid_assessment()
        data["mitre"]=[{"technique_id":"T1059.001","rationale":"Wazuh supplied this mapping for analyst verification.","evidence":["T1"]}]
        with self.assertRaises(ValueError):
            validate_assessment(json.dumps(data),packet)
        data["mitre"][0]["evidence"]=["A1"]
        self.assertEqual(validate_assessment(json.dumps(data),packet).mitre[0].technique_id,"T1059.001")
        self.assertEqual(assessment_schema(packet)["$defs"]["Technique"]["properties"]["technique_id"]["enum"],["T1059.001"])

    def test_runtime_statuses_and_unqueried_history_are_not_model_authored(self):
        packet=evidence_packet(self.alert,{})
        report=render_assessment(validate_assessment(json.dumps(valid_assessment()),packet),self.alert,{},packet)
        self.assertIn("NOT_EXECUTED",report)
        self.assertIn("historical memory was not queried",report)
        self.assertIn("no reputation/hash tool call was recorded",report)
        self.assertTrue(evaluate_report_quality(report)[0])

    def test_containment_rewrite_preserves_external_case_and_audit_sections(self):
        report="### 5. Containment & Remediation Status\nNo action.\n### 8. Agent Tool Trace\nActual tool result.\n### 9. External Case Management\nNot attempted."
        result=enforce_runtime_containment_status(report)
        self.assertIn("Actual tool result.",result)
        self.assertIn("### 9. External Case Management",result)


if __name__ == "__main__":
    unittest.main()

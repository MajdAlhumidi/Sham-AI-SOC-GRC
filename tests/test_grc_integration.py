"""Exercise the merged API and SOC bridge with real temporary SQLite storage."""

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from scripts.api_server import app
from scripts.grc.db import db_session
from scripts.grc.integration import sync_incident
from scripts.schema import IncidentRecord


REPORT = """# Incident Investigation Report
### 1. Incident Classification & Severity Level
* **Classification**: **SUSPICIOUS**
* **Severity Level**: **HIGH**
### 2. Analysis & Technical Findings
One failed login observed; insufficient evidence of compromise.
### 3. MITRE ATT&CK Mapping
No technique confirmed.
### 4. Historical Memory Context (Vector DB)
No reviewed historical match.
### 5. Containment & Remediation Status
NOT_EXECUTED
### 6. Recommended Next Steps for Human Analysts
Review the authentication history.
### 7. Diagnostic & Audit Notes
External reputation not checked.
"""


class GRCIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.review_log = Path(self.directory.name) / "reviews.jsonl"
        self.environment = patch.dict(os.environ, {
            "GRC_DB_PATH": str(Path(self.directory.name) / "grc.sqlite3"),
            "SOC_GRC_ENABLED": "true", "SOC_GRC_API_TOKEN": "test-grc-token",
            "SOC_REVIEW_API_TOKEN": "test-review-token",
            "SOC_HUMAN_REVIEW_LOG_PATH": str(self.review_log),
            "SOC_LLM_PROVIDER": "ollama", "SOC_OLLAMA_MODEL": "test-local-model",
            "SOC_AUDIT_LOG_PATH": str(Path(self.directory.name) / 'tool-audit.jsonl'),
        })
        self.environment.start()
        self.client = TestClient(app)
        self.client.__enter__()
        self.headers = {"X-GRC-Token": "test-grc-token"}
        self.alert = {
            "id": "alert-123", "timestamp": "2026-11-10T12:00:00Z",
            "rule": {"id": "100100", "level": 7, "description": "Single failed login"},
            "agent": {"id": "001", "name": "test-router"},
            "full_log": "TEST ONLY: single failed login",
        }

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.environment.stop()
        self.directory.cleanup()

    def record(self):
        return IncidentRecord(
            incident_id="INC-TEST-001", rule_name="Single failed login",
            classification="suspicious", analyst_notes=REPORT,
            alert_summary="Investigate one failed login", source_ip="192.0.2.1",
            destination_ip="192.0.2.2", user_account="test-user", raw_logs="PRIVATE RAW LOG",
            rule_level=7, llm_provider="ollama", llm_model="test-local-model",
        )

    def evidence(self):
        response = self.client.get("/api/grc/evidence", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["items"]

    def test_grc_routes_fail_closed_without_valid_token(self):
        self.assertEqual(self.client.get("/api/grc/health").status_code, 401)
        self.assertEqual(self.client.get("/api/grc/evidence", headers={"X-GRC-Token": "bad"}).status_code, 401)
        with patch.dict(os.environ, {"SOC_GRC_API_TOKEN": ""}):
            self.assertEqual(self.client.get("/api/grc/health", headers=self.headers).status_code, 503)
        self.assertEqual(self.client.get("/api/grc/health", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.post("/api/grc/approvals", json={
            "reference_type": "incident", "reference_id": "INC-TEST",
            "requested_action": "Review incident",
        }).status_code, 401)

    def test_bridge_is_opt_in_and_replays_do_not_duplicate_evidence(self):
        with patch.dict(os.environ, {"SOC_GRC_ENABLED": "false"}):
            self.assertEqual(sync_incident(self.record(), self.alert)["status"], "disabled")
        self.assertEqual(self.evidence(), [])
        first = sync_incident(self.record(), self.alert)
        second = sync_incident(self.record(), self.alert)
        self.assertEqual(first["status"], "recorded")
        self.assertEqual(first["evidence_ids"], second["evidence_ids"])
        items = self.evidence()
        self.assertEqual(len(items), 2)
        self.assertNotIn("PRIVATE RAW LOG", json.dumps(items))
        self.assertNotIn(REPORT, json.dumps(items))
        assessment = next(item for item in items if item["source"] == "sham_ai")
        self.assertEqual(assessment["metadata"]["containment_status"], "NOT_EXECUTED")
        self.assertEqual(assessment["metadata"]["human_review_status"], "pending")
        self.assertEqual(assessment["metadata"]["llm_provider"], "ollama")

    def test_real_soc_hook_and_human_review_preserve_separate_decisions(self):
        from scripts import investigation_agent, report_quality, schema, alert_context, historical_memory

        vector = types.ModuleType("vector_store")
        vector.store_incidents = Mock()
        agent_tools = types.ModuleType("agent_tools")
        for name in ("check_ip_reputation", "inspect_file_hash", "search_historical_incidents", "create_thehive_incident_case"):
            setattr(agent_tools, name, Mock())
        # Only the external SOC services are replaced. The GRC bridge and API are real.
        import scripts.grc
        import scripts.grc.integration
        aliases = {
            "schema": schema, "vector_store": vector, "agent_tools": agent_tools,
            "investigation_agent": investigation_agent, "report_quality": report_quality,
            "alert_context": alert_context,
            "historical_memory": historical_memory,
            "grc": scripts.grc, "grc.integration": scripts.grc.integration,
        }
        spec = importlib.util.spec_from_file_location(
            "merged_soc_test", Path(__file__).resolve().parents[1] / "scripts" / "soc_agent.py"
        )
        soc = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, aliases):
            spec.loader.exec_module(soc)
        self.alert.update({
            'agent': {'id': '000', 'name': 'wazuh-collector'}, 'location': '10.8.0.2',
            'decoder': {'name': 'sham-mikrotik-native-auth'},
            'data': {'srcip': '192.0.2.10', 'dstuser': 'admin', 'protocol': 'winbox'},
            'full_log': 'system,error,critical MOKROTIK-STAR: login failure for user admin from 192.0.2.10 via winbox',
        })
        self.alert['rule']['mitre'] = {'id': ['T1110']}
        fallback = soc.generate_fallback_report(self.alert, 'test unavailable model')
        self.assertIn('**Affected Host**: `MOKROTIK-STAR`', fallback)
        self.assertIn('**T1110** (rule-supplied mapping)', fallback)
        with patch.object(soc.requests, 'post') as notify_post:
            soc.notify_stream('INVESTIGATION_REPORT', self.alert, REPORT, case_id='TEST')
        payload = notify_post.call_args.kwargs['json']
        self.assertEqual(payload['target_host'], 'MOKROTIK-STAR')
        self.assertEqual(payload['user'], 'admin')
        with patch('scripts.api_server.get_real_incidents_from_chroma', return_value=[]), self.client.websocket_connect('/ws') as ws:
            ws.receive_json()
            self.assertEqual(self.client.post('/api/broadcast', json=payload).status_code, 200)
            live = ws.receive_json()['incident']
            self.assertEqual(live['host_agent'], 'MOKROTIK-STAR')
            self.assertEqual(live['user'], 'admin')
        history = json.dumps({'status': 'success', 'match_basis': 'same_rule_vector_search', 'historical_cases': [
            {'incident_id': 'INC-TEST-OLD', 'rule_name': 'Single failed login', 'classification': 'suspicious', 'similarity_distance': .2}
        ]})
        with patch.object(investigation_agent, '_dispatch_tool', return_value=history), \
             patch.object(soc, "generate_ollama_report", return_value=REPORT), \
             patch.object(soc, "_maybe_create_thehive_case", return_value={"status": "not_configured"}), \
             patch.object(soc, "notify_stream") as broadcast, patch("builtins.print"), \
             patch.object(soc, "uuid", types.SimpleNamespace(uuid4=Mock(side_effect=[
                 types.SimpleNamespace(hex="abcd" + "1" * 28),
                 types.SimpleNamespace(hex="abcd" + "2" * 28),
             ]))):
            soc.investigate_alert(self.alert)
            soc.investigate_alert({**self.alert, "id": "alert-456"})
        self.assertEqual(vector.store_incidents.call_count, 2)
        self.assertEqual(broadcast.call_count, 2)
        saved = vector.store_incidents.call_args_list[0].args[0][0]
        second = vector.store_incidents.call_args_list[1].args[0][0]
        self.assertNotEqual(saved.incident_id, second.incident_id)
        self.assertEqual(saved.to_metadata()["source_alert_id"], self.alert["id"])
        self.assertEqual(second.to_metadata()["source_alert_id"], "alert-456")
        self.assertEqual(saved.containment_status, "NOT_EXECUTED")
        self.assertEqual(saved.target_host, 'MOKROTIK-STAR')
        self.assertEqual(saved.to_metadata()['target_host'], 'MOKROTIK-STAR')
        self.assertEqual(saved.destination_ip, '10.8.0.2')
        self.assertEqual(len(self.evidence()), 4)
        wazuh_evidence = next(item for item in self.evidence() if item['source'] == 'wazuh')
        self.assertEqual(wazuh_evidence['metadata']['target_host'], 'MOKROTIK-STAR')
        self.assertEqual(wazuh_evidence['metadata']['agent_name'], 'wazuh-collector')
        # The same real SOC bridge must retain retrieved IDs when the model is offline.
        with patch.object(investigation_agent, '_dispatch_tool', return_value=history), \
             patch.object(soc, 'generate_ollama_report', side_effect=RuntimeError('model offline')), \
             patch.object(soc, '_maybe_create_thehive_case', return_value={'status': 'not_configured'}), \
             patch.object(soc, 'notify_stream'), patch('builtins.print'):
            soc.investigate_alert({**self.alert, 'id': 'offline-test'})
        offline = vector.store_incidents.call_args.args[0][0]
        self.assertTrue(offline.fallback_used)
        self.assertIn('INC-TEST-OLD', offline.analyst_notes)
        self.assertNotIn('Fallback Heuristic Record', offline.analyst_notes)
        self.assertIn('search_historical_incidents — status: success', offline.analyst_notes)
        self.assertTrue(report_quality.evaluate_report_quality(offline.analyst_notes)[0])
        response = self.client.post("/api/reviews", headers={"X-Review-Token": "test-review-token"}, json={
            "incident_id": saved.incident_id, "agent_classification": "suspicious",
            "decision": "corrected", "final_classification": "false_positive",
            "reviewer": "test-analyst", "notes": "Authorized test confirmed.",
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["grc_sync"]["status"], "recorded")
        items = self.evidence()
        original = next(item for item in items if item["source"] == "sham_ai")
        review = next(item for item in items if item["source"] == "human_review")
        self.assertEqual(original["metadata"]["classification"], "suspicious")
        self.assertEqual(review["metadata"]["final_classification"], "false_positive")
        self.assertEqual(review["metadata"]["incident_id"], saved.incident_id)
        self.assertEqual(len(self.review_log.read_text(encoding="utf-8").splitlines()), 1)
        self.assertEqual(self.client.get("/api/grc/approvals", headers=self.headers).json()["count"], 0)

    def test_grc_failure_keeps_original_human_review(self):
        with patch("scripts.grc.integration._persist", side_effect=sqlite3.OperationalError("locked")):
            response = self.client.post("/api/reviews", headers={"X-Review-Token": "test-review-token"}, json={
                "incident_id": "INC-TEST-FAILURE", "agent_classification": "suspicious",
                "decision": "escalated", "reviewer": "test-analyst",
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["grc_sync"]["status"], "error")
        review = json.loads(self.review_log.read_text(encoding="utf-8"))
        self.assertEqual(review["human_decision"], "escalated")
        self.assertIsNone(review["final_classification"])

    def test_incident_sync_failure_is_reported_without_raising(self):
        with patch("scripts.grc.integration._persist", side_effect=sqlite3.OperationalError("locked")):
            result = sync_incident(self.record(), self.alert)
        self.assertEqual(result["status"], "error")

    def test_risk_controls_approval_and_append_only_audit(self):
        response = self.client.post("/api/grc/risks", headers=self.headers, json={
            "title": "Unauthorized management access", "likelihood": 4, "impact": 5,
        })
        self.assertEqual(response.status_code, 201, response.text)
        risk = response.json()
        self.assertEqual(risk["inherent_score"], 20)
        self.assertEqual(self.client.post(
            "/api/grc/risks/" + risk["id"] + "/controls/SHAM-IAM-001", headers=self.headers,
        ).status_code, 201)
        approval = self.client.post("/api/grc/approvals", headers=self.headers, json={
            "reference_type": "risk", "reference_id": risk["id"],
            "requested_action": "Review access controls", "requested_by": "analyst",
        }).json()
        decision_url = "/api/grc/approvals/" + approval["id"] + "/decision"
        decision = {"status": "approved", "decided_by": "reviewer"}
        self.assertEqual(self.client.patch(decision_url, headers=self.headers, json=decision).status_code, 200)
        self.assertEqual(self.client.patch(decision_url, headers=self.headers, json=decision).status_code, 409)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            with db_session() as connection:
                connection.execute("DELETE FROM audit_logs")
        audit = self.client.get("/api/grc/audit-logs", headers=self.headers).json()
        self.assertGreaterEqual(audit["count"], 4)

    def test_external_evidence_routes_remain_compatible(self):
        response = self.client.post("/api/grc/integrations/wazuh/evidence", headers=self.headers, json={
            "alert_id": "external-alert", "summary": "Authentication failure observed",
            "control_ids": ["SHAM-LOG-001"],
        })
        self.assertEqual(response.status_code, 201, response.text)
        response = self.client.post("/api/grc/integrations/sham-ai/assessment", headers=self.headers, json={
            "incident_id": "external-incident", "classification": "SUSPICIOUS", "severity": "HIGH",
            "summary": "More evidence required", "control_ids": ["SHAM-AI-002"],
        })
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(len(self.evidence()), 2)


if __name__ == "__main__":
    unittest.main()

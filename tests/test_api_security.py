import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from scripts import api_server
from scripts.security import SESSION_COOKIE


class APISecurityTests(unittest.TestCase):
    origin = "https://demo.example.test"

    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {
            "SOC_API_AUTH_MODE": "token",
            "SOC_API_HOST": "127.0.0.1",
            "SOC_ALLOWED_ORIGINS": self.origin,
            "SOC_WEBSOCKET_ALLOWED_ORIGINS": self.origin,
            "SOC_API_SERVICE_TOKEN": "fixture-service",
            "SOC_UI_TOKEN": "fixture-ui",
            "SOC_REVIEW_API_TOKEN": "fixture-review",
            "SOC_API_BEARER_TOKEN": "fixture-admin",
            "SOC_API_TOKENS_JSON": json.dumps({
                "fixture-requester": {"subject": "Request owner", "actor_id": "user:owner", "roles": ["GRC_EDITOR"]},
                "fixture-owner-decision": {"subject": "Owner's other token", "actor_id": "user:owner", "roles": ["CASE_APPROVER"]},
                "fixture-approver": {"subject": "Approver", "actor_id": "user:approver", "roles": ["CASE_APPROVER"]},
                "fixture-auditor": {"subject": "Auditor", "actor_id": "user:auditor", "roles": ["GRC_AUDITOR"]},
            }),
            "GRC_DB_PATH": str(Path(directory) / "grc.db"),
            "SOC_CASE_DB_PATH": str(Path(directory) / "cases.db"),
            "SOC_HUMAN_REVIEW_LOG_PATH": str(Path(directory) / "reviews.jsonl"),
        }))
        self.app = api_server.create_app()
        self.client = self.enterContext(TestClient(self.app, base_url=self.origin))

    @staticmethod
    def bearer(token):
        return {"Authorization": "Bearer " + token}

    def test_login_shell_and_authenticated_websocket(self):
        incident = {
            "case_id": "INC-FIXTURE-ONLY", "verdict": "Suspicious / Review", "level": 7,
            "time": "12:00:00", "host_agent": "fixture", "rule_name": "Fixture alert",
            "containment": "Not executed", "source_ip": "192.0.2.10", "user": "fixture", "details": "Test evidence",
        }
        with patch.object(api_server, "get_real_incidents_from_chroma", return_value=[incident]) as read:
            self.assertIn("Sign in to SHAM", self.client.get("/").text)
            self.assertEqual(self.client.get("/api/incidents").status_code, 401)
            read.assert_not_called()
            with self.assertRaises(WebSocketDisconnect):
                with self.client.websocket_connect("wss://demo.example.test/ws", headers={"Origin": self.origin}):
                    self.fail("An unauthenticated WebSocket must not connect")
            sign_in = self.client.post("/api/auth/session", headers={"Origin": self.origin}, json={"token": "fixture-ui"})
            self.assertEqual(sign_in.status_code, 204)
            cookie = sign_in.headers["set-cookie"]
            self.assertIn(SESSION_COOKIE, cookie)
            self.assertIn("HttpOnly", cookie)
            self.assertIn("Secure", cookie)
            self.assertNotIn("fixture-ui", cookie)
            self.assertIn("INC-FIXTURE-ONLY", self.client.get("/").text)
            with self.client.websocket_connect("wss://demo.example.test/ws", headers={"Origin": self.origin}) as stream:
                self.assertEqual(stream.receive_json()["incidents"], [incident])
                event = self.client.post("/api/broadcast", headers=self.bearer("fixture-service"), json={
                    "case_id": "INC-SERVICE-FIXTURE", "containment_status": "EXECUTED_AND_VERIFIED",
                })
                self.assertEqual(event.status_code, 200)
                data = stream.receive_json()["incident"]
                self.assertEqual(data["case_id"], "INC-SERVICE-FIXTURE")
                self.assertEqual(data["containment"], "Not executed")
                saved = self.client.cookies.get(SESSION_COOKIE)
                self.assertEqual(self.client.post("/api/auth/logout", headers={"Origin": self.origin}).status_code, 204)
                stream.send_text("refresh")
                with self.assertRaises(WebSocketDisconnect):
                    stream.receive_json()
                self.assertIsNone(self.app.state.security.principal_for_session(saved))
            self.assertEqual(self.client.get("/api/incidents").status_code, 401)

    def test_role_checks_cover_audit_list_and_detail(self):
        reader = self.bearer("fixture-ui")
        auditor = self.bearer("fixture-auditor")
        for path in ("/api/grc/audit-logs", "/api/grc/workspace/audit"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path, headers=reader).status_code, 403)
                self.assertEqual(self.client.get(path, headers=auditor).status_code, 200)
        self.assertEqual(self.client.get("/api/grc/workspace/audit/missing", headers=reader).status_code, 403)
        self.assertEqual(self.client.post("/api/broadcast", headers=reader, json={}).status_code, 403)
        self.assertEqual(self.client.get("/api/incidents", headers=self.bearer("fixture-service")).status_code, 403)

    def test_separation_and_authenticated_audit_actor(self):
        created = self.client.post("/api/grc/approvals", headers=self.bearer("fixture-requester"), json={
            "reference_type": "incident", "reference_id": "INC-FIXTURE",
            "requested_action": "thehive.create_case", "requested_by": "Display name",
        })
        self.assertEqual(created.status_code, 201)
        approval = created.json()
        self.assertEqual(approval["requested_actor_id"], "user:owner")
        url = f"/api/grc/approvals/{approval['id']}/decision"
        payload = {"status": "approved", "decided_by": "Alternate display name"}
        self.assertEqual(self.client.patch(url, headers=self.bearer("fixture-owner-decision"), json=payload).status_code, 403)
        result = self.client.patch(url, headers=self.bearer("fixture-approver"), json=payload)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["decided_actor_id"], "user:approver")
        audit = self.client.get("/api/grc/audit-logs", headers=self.bearer("fixture-auditor")).json()
        self.assertEqual({item["actor"] for item in audit["items"]}, {"user:owner", "user:approver"})

    def test_cookie_mutations_require_an_allowed_origin(self):
        self.assertEqual(self.client.post("/api/auth/session", json={"token": "fixture-ui"}).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/session", headers={"Origin": self.origin}, json={"token": "fixture-ui"}).status_code, 204)
        self.assertEqual(self.client.post("/api/auth/logout", headers={"Origin": "https://unrelated.example.test"}).status_code, 403)
        self.assertEqual(self.client.post("/api/reviews", json={}).status_code, 403)

    def test_review_identity_is_recorded_from_credential(self):
        review = self.client.post("/api/reviews", headers={
            "X-Review-Token": "fixture-review", "X-Actor": "Unverified actor",
        }, json={
            "incident_id": "INC-FIXTURE", "agent_classification": "suspicious",
            "decision": "accepted", "reviewer": "Display reviewer",
        })
        self.assertEqual(review.status_code, 200)
        record = json.loads(Path(os.environ["SOC_HUMAN_REVIEW_LOG_PATH"]).read_text(encoding="utf-8"))
        self.assertEqual(record["reviewer"], "configured:review")
        self.assertEqual(record["reviewer_display"], "Display reviewer")

    def test_disabled_authentication_is_local(self):
        with patch.dict(os.environ, {"SOC_API_AUTH_MODE": "disabled"}):
            with TestClient(api_server.create_app(), base_url=self.origin) as remote:
                self.assertEqual(remote.get("/").status_code, 403)
            with TestClient(api_server.create_app(), base_url="http://127.0.0.1:8000",
                            client=("127.0.0.1", 50000)) as local:
                self.assertEqual(local.get("/api/incidents").status_code, 200)
                self.assertNotIn("Sign in to SHAM", local.get("/").text)
            with patch.dict(os.environ, {"SOC_API_HOST": "0.0.0.0"}):
                with self.assertRaisesRegex(ValueError, "loopback"):
                    api_server.create_app()

    def test_export_rate_limit_is_per_principal(self):
        self.app.state.security.export_limit = 1
        path = "/api/investigations/cases/fixture-missing/export"
        self.assertEqual(self.client.get(path, headers=self.bearer("fixture-ui")).status_code, 404)
        self.assertEqual(self.client.get(path, headers=self.bearer("fixture-ui")).status_code, 429)
        self.assertEqual(self.client.get(path, headers=self.bearer("fixture-auditor")).status_code, 404)

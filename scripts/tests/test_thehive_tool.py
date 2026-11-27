import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import thehive_tool
from grc.db import db_session, initialize_database


class TheHiveAdapterTests(unittest.TestCase):
    def test_missing_api_key_does_not_claim_a_case_was_created(self):
        with patch.object(thehive_tool, "THEHIVE_API_KEY", ""):
            result = json.loads(
                thehive_tool.create_thehive_incident_case(
                    title="Test incident",
                    severity="high",
                    description="Test description",
                )
            )
        self.assertEqual(result["status"], "not_configured")
        self.assertNotIn("case_id", result)

    @patch("thehive_tool.requests.post")
    def test_v5_paths_and_partial_followup_results_are_reported(self, post):
        created_case = Mock(status_code=201, text="")
        created_case.json.return_value = {"_id": "~case-123"}
        failed_observable = Mock(status_code=400, text="observable rejected")
        created_task = Mock(status_code=201, text="")
        post.side_effect = [created_case, failed_observable, created_task]
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {"GRC_DB_PATH": str(Path(directory) / "fixture.db")}))
        initialize_database()
        with db_session() as connection:
            connection.execute("""
                INSERT INTO approvals (id, reference_type, reference_id, requested_action, requested_by,
                                       status, requested_actor_id, decided_actor_id, created_at)
                VALUES ('APR-FIXTURE', 'incident', 'INC-FIXTURE', 'thehive.create_case',
                        'Requester', 'approved', 'user:requester', 'user:approver', 'fixture-time')
            """)

        with (
            patch.object(thehive_tool, "THEHIVE_API_KEY", "test-key"),
            patch.object(thehive_tool, "THEHIVE_URL", "https://thehive.example"),
            patch.object(thehive_tool, "THEHIVE_API_VERSION", "v5"),
            patch.object(thehive_tool, "THEHIVE_VERIFY_TLS", True),
        ):
            denied = thehive_tool.create_thehive_incident_case(
                title="Wrong incident", severity="low", description="Fixture",
                incident_id="INC-OTHER", approval_id="APR-FIXTURE",
            )
            self.assertEqual(json.loads(denied)["status"], "not_attempted")
            post.assert_not_called()
            result = json.loads(
                thehive_tool.create_thehive_incident_case(
                    title="Test incident",
                    severity="high",
                    description="Test investigation evidence",
                    observables=[{"type": "ip", "value": "203.0.113.5"}],
                    tasks=["Review related telemetry"],
                    incident_id="INC-FIXTURE", approval_id="APR-FIXTURE",
                )
            )
            replay = thehive_tool.create_thehive_incident_case(
                title="Same incident", severity="low", description="Fixture",
                incident_id="INC-FIXTURE", approval_id="APR-FIXTURE",
            )
            self.assertEqual(json.loads(replay), result)
            self.assertEqual(post.call_count, 3)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["case_id"], "~case-123")
        self.assertEqual(result["observables_created"], 0)
        self.assertEqual(result["tasks_created"], 1)
        self.assertEqual(
            post.call_args_list[0].args[0],
            "https://thehive.example/api/v1/case",
        )
        self.assertEqual(
            post.call_args_list[1].args[0],
            "https://thehive.example/api/v1/case/~case-123/observable",
        )
        self.assertEqual(
            post.call_args_list[2].args[0],
            "https://thehive.example/api/v1/case/~case-123/task",
        )
        self.assertTrue(all(call.kwargs["verify"] is True for call in post.call_args_list))


if __name__ == "__main__":
    unittest.main()

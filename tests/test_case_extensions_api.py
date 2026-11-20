"""Exercise HTTP integration without calling external models or security tools."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile
from fastapi.testclient import TestClient
from scripts.api_server import app
from scripts.casework import store, followup, benchmark


class CaseExtensionsAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            "SOC_CASE_DB_PATH": str(Path(self.temp.name)/"cases.sqlite"),
            "GRC_DB_PATH": str(Path(self.temp.name)/"grc.sqlite"),
            "SOC_BENCHMARK_DB_PATH": str(Path(self.temp.name)/"comparison.sqlite"),
        })
        self.env.start()
        self.client = TestClient(app)
        self.client.__enter__()
        alert = {"id":"wazuh-extension","timestamp":"2026-11-20T12:00:00Z", "agent":{"id":"001","name":"LAB"},
                 "rule":{"id":"5710","description":"Authentication failure","level":5},
                 "data":{"srcip":"192.0.2.1"},"full_log":"Login failure password=test-secret"}
        self.case = store.capture({"incident_id":"INC-EXT","rule_name":"Authentication failure"}, alert)
        self.base = "/api/investigations/"

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()
        self.temp.cleanup()

    def test_followup_accepted_persisted_and_scoped_http_contract(self):
        payload={"question":"What evidence is missing?", "request_id":"extension-request-1"}
        with patch.object(followup, "run_turn") as worker:
            response=self.client.post(self.base+"cases/"+self.case+"/followups",json=payload)
        self.assertEqual(response.status_code,202,response.text)
        self.assertEqual(response.headers["cache-control"],"no-store")
        worker.assert_called_once_with(response.json()["id"])
        path="cases/"+self.case+"/followups"
        items=self.client.get(self.base+path).json()["items"]
        self.assertEqual(len(items),1)
        self.assertEqual(self.client.get(self.base+path+"/"+items[0]["id"]).status_code,200)
        self.assertEqual(self.client.get(self.base+"cases/missing/followups/"+items[0]["id"]).status_code,404)
        bad=self.client.post(self.base+path,json={**payload,"command":"block IP"})
        self.assertEqual(bad.status_code,422)
        self.assertEqual(self.client.post(self.base+"cases/missing/followups",json=payload).status_code,404)

    def test_bundle_is_a_download_with_redacted_actual_content(self):
        response=self.client.get(self.base+"cases/"+self.case+"/export")
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.headers["content-type"],"application/zip")
        self.assertIn("attachment",response.headers["content-disposition"])
        with ZipFile(io.BytesIO(response.content)) as bundle:
            self.assertIn("manifest.json",bundle.namelist())
            self.assertIn("report.html",bundle.namelist())
            self.assertNotIn(b"test-secret",b"\n".join(bundle.read(p) for p in bundle.namelist()))
        self.assertEqual(self.client.get(self.base+"cases/missing/export").status_code,404)

    def test_blind_paired_review_schedules_ai_only_after_submission(self):
        catalogue=self.client.get(self.base+"comparison/dataset").json()
        self.assertNotIn("expected_label",json.dumps(catalogue))
        start=self.client.post(self.base+"comparison/trials",json={"scenario_id":catalogue["items"][0]["id"],"analyst":"UI reviewer"})
        self.assertEqual(start.status_code,201,start.text)
        trial=start.json();self.assertNotIn("answer_key",trial)
        self.assertEqual(self.client.post(self.base+"comparison/trials/"+trial["id"]+"/run-ai").status_code,409)
        with patch.object(benchmark,"run_ai_trial") as worker:
            result=self.client.post(self.base+"comparison/trials/"+trial["id"]+"/complete",json={
                "classification":"insufficient","rationale":"Lab reviewer has insufficient evidence.","evidence_refs":["A1"]})
        self.assertEqual(result.status_code,202,result.text)
        worker.assert_called_once_with(trial["id"])
        self.assertEqual(result.json()["manual"]["status"],"completed")

    def test_ai_only_cannot_fabricate_human_baseline(self):
        scenario=benchmark.dataset()["items"][0]["id"]
        with patch.object(benchmark,"run_ai_trial") as worker:
            response=self.client.post(self.base+"comparison/ai-trials",json={"scenario_id":scenario})
        self.assertEqual(response.status_code,202,response.text)
        worker.assert_called_once_with(response.json()["id"])
        self.assertEqual(response.json()["manual"]["status"],"not_recorded")
        summary=self.client.get(self.base+"comparison/summary").json()
        self.assertEqual(summary["manual"]["completed"],0)
        self.assertIsNone(summary["paired_wall_delta_seconds_mean"])
        for path in ["comparison/dataset","comparison/trials","comparison/summary"]:
            self.assertEqual(self.client.get(self.base+path).headers["cache-control"],"no-store")
        self.assertEqual(self.client.get(self.base+"comparison/trials/missing").status_code,404)
        self.assertEqual(self.client.post(self.base+"comparison/trials/missing/run-ai").status_code,404)


if __name__ == "__main__":
    unittest.main()

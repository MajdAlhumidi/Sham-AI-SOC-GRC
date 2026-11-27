"""Generate an isolated, synthetic dashboard fixture for browser checks."""
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient
from scripts.api_server import create_app
from scripts.dashboard import render_dashboard
from scripts.casework import store, benchmark


def generate(destination):
    destination=Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        os.environ.update({"SOC_CASE_DB_PATH":directory+"/cases.sqlite","GRC_DB_PATH":directory+"/grc.sqlite","SOC_BENCHMARK_DB_PATH":directory+"/comparison.sqlite"})
        with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
            incident="INC-UI-TEST"
            alert={"id":"ui-alert","timestamp":"2026-11-20T12:00:00Z","agent":{"id":"001","name":"LAB-ROUTER"},"rule":{"id":"5710","level":7,"description":"Authentication failures on branch router"},"data":{"srcip":"192.0.2.10","dstuser":"admin"},"full_log":"UI TEST DATA: login failure"}
            case=store.capture({"incident_id":incident,"rule_name":alert["rule"]["description"],"analyst_notes":"Observed login failure [A1]."},alert)
            refs=["cases","cases/"+case,"incidents/"+incident,"evidence/"+incident+"/A1","context","audit","cases/"+case+"/followups","comparison/dataset","comparison/summary","comparison/trials"]
            paths=["/api/investigations/"+r for r in refs]
            fixtures={p:client.get(p).json() for p in paths}
            trial=benchmark.create_trial({"scenario_id":benchmark.dataset()["items"][0]["id"],"analyst":"UI fixture only"})
            (destination/"fixture.json").write_text(json.dumps({"case":case,"incident":incident,"trial":trial,"responses":fixtures}),encoding="utf-8")
            (destination/"dashboard.html").write_bytes(render_dashboard([]).body)


if __name__ == "__main__":
    generate(sys.argv[1])

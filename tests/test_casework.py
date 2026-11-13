import copy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from scripts.api_server import app
from scripts.casework import store


class CaseworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SOC_CASE_DB_PATH": str(Path(self.temp.name)/"cases.db"), "GRC_DB_PATH": str(Path(self.temp.name)/"grc.db"), "SOC_GRC_API_TOKEN": "fixture-token"})
        self.env.start()
        self.client = TestClient(app)
        self.client.__enter__()
        self.headers = {"X-GRC-Token":"fixture-token"}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()
        self.temp.cleanup()

    def capture(self, id="INC-QA-1", minute=0, source="192.0.2.10", account="admin", target="10.0.0.2", rule="100111", level=7, stamp=None, context=None):
        alert = {"id":"wazuh-"+id,"timestamp": stamp or f"2026-11-13T12:{minute:02}:00Z", "agent":{"id":"000","name":"collector"},"location":target,"decoder":{"name":"mikrotik"}, "rule":{"id":rule,"description":"Router authentication failure","level":level},"data":{"srcip":source,"dstuser":account},"full_log":"system,error,critical BRANCH-ROUTER: login failure"}
        record = {"incident_id":id,"source_alert_id":alert["id"],"rule_name":alert["rule"]["description"],"rule_level":level,"source_ip":source,"user_account":account,"analyst_notes":"Observed failed login [A1]."}
        return store.capture(record,alert,context)

    def get(self,path):
        return self.client.get('/api/investigations/'+path,headers=self.headers)

    def test_correlation_keeps_originals_and_excludes_same_ip_other_entities(self):
        case = self.capture()
        self.assertEqual(self.capture("INC-QA-2",minute=4),case)
        self.assertNotEqual(self.capture("INC-QA-3",minute=5,target="10.0.0.3"),case)
        self.assertNotEqual(self.capture("INC-QA-4",minute=6,account="another-user"),case)
        self.assertNotEqual(self.capture("INC-QA-5",minute=7,rule="5710"),case)
        self.assertEqual(len(store.case_detail(case)["events"]),2)
        self.assertEqual(store.list_cases()["summary"]["events"],5)
        self.assertEqual(store.case_detail(case)["asset"]["name"],"BRANCH-ROUTER")

    def test_bounded_span_timezone_and_no_chain_extension(self):
        first=self.capture()
        self.assertEqual(self.capture("INC-QA-2",stamp="2026-11-13T15:20:00+03:00"),first)
        self.assertNotEqual(self.capture("INC-QA-3",minute=40),first)
        self.assertNotEqual(self.capture("INC-QA-4",stamp="2026-11-13T12:25:00"),first)
        self.assertEqual(self.capture("INC-QA-5",minute=5),first)

    def test_ambiguous_bridge_stays_separate(self):
        first=self.capture(minute=0)
        second=self.capture("INC-QA-2",minute=40)
        bridge=self.capture("INC-QA-3",minute=20)
        self.assertNotIn(bridge,[first,second])
        self.assertIn("ambiguous",store.case_detail(bridge)["events"][0]["join_reason"])

    def test_missing_source_and_unknown_asset_do_not_join(self):
        self.assertNotEqual(self.capture(source="N/A"),self.capture("INC-QA-2",source="N/A"))
        a={"timestamp":"2026-11-13T12:00:00Z","rule":{"id":"1"}}
        r={"incident_id":"unknown1","source_ip":"192.0.2.1"}
        first=store.capture(r,a)
        self.assertNotEqual(first,store.capture({**r,"incident_id":"unknown2"},a))
        self.assertFalse(any(x['id'].startswith('unresolved:') for x in store.profiles()['assets']))

    def test_idempotent_capture_does_not_replace_original_evidence(self):
        case=self.capture()
        self.assertEqual(self.capture(source="203.0.113.99"),case)
        raw=store.get_evidence("INC-QA-1","A1")
        self.assertTrue(raw["integrity_ok"])
        self.assertEqual(raw["record"]["value"]["data"]["srcip"],"192.0.2.10")
        self.assertEqual(store.list_cases()["summary"]["events"],1)

    def test_tool_evidence_claim_refs_and_missing_or_failed_results(self):
        context={"tool_results":[{"tool_name":"query_logs","status":"error","result":"timeout","timestamp":"2026-11-13T12:00:01Z","truncated":False}],"validated_assessment":{"findings":[{"observation":"Tool was unavailable","evidence":["T1"]},{"observation":"Imagined result","evidence":["T9"]},{"observation":"Alert recorded","evidence":["A1"]}],"limitations":["Logs unavailable"]},"report_evidence_packet":{"A1":{"value":"bounded model view"}}}
        case=self.capture(context=context)
        findings=store.case_detail(case)["events"][0]["findings"]
        self.assertEqual([f["citation_status"] for f in findings],["missing_or_failed_evidence","missing_or_failed_evidence","available_for_review"])
        self.assertEqual(store.get_evidence("INC-QA-1","T1")["record"]["result"],"timeout")
        self.assertEqual(store.get_evidence("INC-QA-1","A1")["record"]["model_view"],context["report_evidence_packet"]["A1"])
        self.assertEqual(self.get("evidence/INC-QA-1/T9").status_code,404)

    def test_legacy_reports_not_relabelled_as_source_events(self):
        old={"incident_id":"INC-OLD-1","target_host":"Router","source_ip":"192.0.2.10","timestamp":"2026-11-13T12:00:00","analyst_notes":"claim [A1]"}
        first=store.capture(old)
        second=store.capture({**old,"incident_id":"INC-OLD-2"})
        self.assertNotEqual(first,second)
        self.assertIsNone(store.get_evidence("INC-OLD-1","A1"))
        self.assertTrue(store.case_detail(first)["legacy"])
        self.assertEqual(store.case_detail(first)["events"][0]["time_basis"],"report_created_utc")

    def test_hash_detects_modified_payload(self):
        self.capture()
        with store.db() as conn:
            conn.execute("UPDATE evidence SET payload=? WHERE ref='A1'",(json.dumps({"changed":True}),))
        self.assertFalse(store.get_evidence("INC-QA-1","A1")["integrity_ok"])

    def test_all_routes_fail_closed_and_shell_does_not_embed_secret(self):
        for route in ["cases","cases/missing","context","audit","incidents/x","evidence/x/A1"]:
            self.assertEqual(self.client.get('/api/investigations/'+route).status_code,401)
        for route in ["assets/x","changes/x"]:
            self.assertEqual(self.client.put('/api/investigations/'+route,json={}).status_code,401)
        with patch.dict(os.environ,{"SOC_GRC_API_TOKEN":""}):
            self.assertEqual(self.get("cases").status_code,503)
        with patch('scripts.api_server.get_real_incidents_from_chroma',return_value=[]):
            page=self.client.get('/').text
        self.assertNotIn("fixture-token",page)
        self.assertIn('id="mode-investigations"',page)
        self.assertNotIn('__CASE_',page)
        self.assertEqual(self.get('cases').headers['cache-control'],'no-store')

    def change(self,asset):
        return dict(id="CHG-QA-1",revision=0,asset_id=asset,ticket="TEST-1",description="Authorized login validation",rule_id="100111",source_ip="192.0.2.10",account="admin",start="2026-11-13T11:55:00Z",end="2026-11-13T12:30:00Z",approved_at="2026-11-13T11:00:00Z",approved_by="QA approver",status="approved")

    def test_context_updates_priority_optimistic_lock_and_audits(self):
        case=self.capture()
        before=store.case_detail(case)
        asset=before['asset']['id']
        payload=dict(revision=0,owner="Network team",service="Branch connectivity",criticality="critical",sensitivity="restricted")
        response=self.client.put('/api/investigations/assets/'+asset,headers=self.headers,json=payload)
        self.assertEqual(response.status_code,200)
        after=store.case_detail(case)
        self.assertEqual(after['priority']['score'],before['priority']['score']+30)
        self.assertEqual(self.client.put('/api/investigations/assets/'+asset,headers=self.headers,json=payload).status_code,409)
        audit=store.audit_page()['items'][0]
        self.assertEqual(audit['action'],'asset_updated')
        self.assertEqual(json.loads(audit['before_json'])['criticality'],'unassessed')
        with store.db() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute('DELETE FROM audit')

    def test_approved_change_exact_scope_never_downgrades_priority(self):
        case=self.capture(level=14)
        d=store.case_detail(case);change=self.change(d['asset']['id'])
        response=self.client.put('/api/investigations/changes/CHG-QA-1',headers=self.headers,json=change)
        self.assertEqual(response.status_code,200,response.text)
        p=store.case_detail(case)['priority']
        self.assertEqual(p['score'],d['priority']['score'])
        self.assertEqual(len(p['change_matches']),1)
        for key,value in [('source_ip','203.0.113.8'),('account','other'),('rule_id','5710'),('status','revoked'),('start','2026-11-13T12:10:00Z')]:
            altered={**change,key:value}
            self.assertFalse(store.priority(store.case_detail(case)['events'],d['asset'],[altered])['change_matches'])

    def test_bad_change_windows_wildcards_and_unrecognised_fields_rejected(self):
        case=self.capture();change=self.change(store.case_detail(case)['asset']['id'])
        for overrides in [{'end':'2026-11-13T10:00:00Z'},{'start':'2026-11-13T12:00:00'},{'source_ip':'*'},{'approved_at':'2026-11-13T12:00:01Z'},{'end':'2026-12-13T12:00:00Z'},{'run_command':'drop'}]:
            response=self.client.put('/api/investigations/changes/CHG-QA-1',headers=self.headers,json={**change,**overrides})
            self.assertEqual(response.status_code,422,response.text)

    def test_search_pagination_and_deep_link_keep_full_ids(self):
        case=self.capture()
        for i in range(2,34):
            store.capture({'incident_id':f'ARCHIVE-{i}','timestamp':'2026-11-13T12:00:00'})
        page=self.get('cases?offset=30&limit=10').json()
        self.assertEqual(len(page['items']),3)
        self.assertEqual(self.get('cases?q=INC-QA-1').json()['items'][0]['id'],case)
        self.assertEqual(self.get('incidents/INC-QA-1').json()['case_id'],case)
        self.assertEqual(self.get('cases?q=%27%20OR%201=1').json()['total'],0)
        self.assertEqual(self.get('cases?offset=-1').status_code,422)
        self.assertEqual(self.get('cases/missing').status_code,404)

    def test_migration_matches_original_ids_only_and_never_restores_deleted_ids(self):
        from scripts.casework.backfill import run
        source=Path(self.temp.name)/'source.jsonl'
        alert={'id':'source-1','timestamp':'2026-11-13T12:00:00Z','agent':{'id':'001','name':'QA-host'},'rule':{'id':'5710','level':7},'data':{'srcip':'192.0.2.10','dstuser':'admin'}}
        source.write_text(json.dumps(alert)+'\n'+json.dumps({**alert,'id':'deleted-source'})+'\n',encoding='utf-8')
        metadata={'ids':['retained-1','retained-2'],'metadatas':[{'source_alert_id':'source-1'},{'source_alert_id':'not-in-file'}]}
        collection=types.SimpleNamespace(get=lambda **kwargs:metadata)
        client=types.SimpleNamespace(get_collection=lambda name:collection)
        fake=types.SimpleNamespace(PersistentClient=lambda **kwargs:client)
        with patch.dict('sys.modules',{'chromadb':fake}): result=run('fixture',str(source))
        self.assertEqual(result['matching_source_alerts_available'],1)
        self.assertEqual(store.list_cases()['summary']['events'],2)
        self.assertEqual(store.get_evidence('retained-1','A1')['record']['value']['id'],'source-1')
        self.assertIsNone(store.get_evidence('retained-1','T1'))
        self.assertIsNone(store.get_evidence('retained-2','A1'))
        self.assertIsNone(store.get_evidence('deleted-source','A1'))


if __name__=='__main__':
    unittest.main()

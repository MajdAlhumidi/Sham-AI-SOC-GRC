import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from scripts.api_server import app
from scripts.grc.db import db_session
from scripts.dashboard import render_dashboard


class GRCWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'GRC_DB_PATH': str(Path(self.directory.name)/'grc.sqlite3'), 'SOC_GRC_API_TOKEN': 'private-workspace-test-token'})
        self.env.start()
        self.client = TestClient(app)
        self.client.__enter__()
        self.headers = {'X-GRC-Token': 'private-workspace-test-token'}
        self.base = '/api/grc/workspace'

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()
        self.directory.cleanup()

    def get(self, path='', **params):
        response = self.client.get(self.base+path, headers=self.headers, params=params)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        return response.json()

    def test_all_workspace_routes_are_protected_and_shell_contains_no_token(self):
        for path in ['/summary', '/risks', '/controls', '/evidence', '/approvals', '/audit', '/controls/SHAM-LOG-001']:
            self.assertEqual(self.client.get(self.base+path).status_code, 401)
            self.assertEqual(self.client.get(self.base+path,headers={'X-GRC-Token':'wrong'}).status_code, 401)
        with patch.dict(os.environ, {'SOC_GRC_API_TOKEN':''}):
            self.assertEqual(self.client.get(self.base+'/summary',headers=self.headers).status_code,503)
        html = render_dashboard([]).body.decode()
        self.assertIn('id="mode-grc"', html)
        self.assertIn('id="grc-token"', html)
        self.assertNotIn('private-workspace-test-token', html)
        self.assertNotIn('localStorage', html)
        self.assertNotIn('sessionStorage', html)

    def test_pagination_and_search_reach_records_beyond_old_500_limit(self):
        with db_session() as db:
            db.executemany('INSERT INTO evidence (id,source,reference_id,description,metadata_json,collected_at) VALUES (?,?,?,?,?,?)',[
                (f'EVD-{i:04}', 'wazuh' if i%2 else 'sham_ai', f'INC-TEST-{i:04}', 'Rare needle' if i==509 else 'Evidence', '{}', '2026-11-11T12:00:00Z') for i in range(510)])
        first = self.get('/evidence', limit=40)
        tail = self.get('/evidence', offset=500, limit=40)
        self.assertEqual(first['total'],510)
        self.assertEqual(len(tail['items']),10)
        self.assertEqual(tail['items'][-1]['id'],'EVD-0509')
        self.assertEqual(self.get('/evidence',q='Rare needle')['items'][0]['id'],'EVD-0509')
        self.assertEqual(self.get('/evidence',status='wazuh')['total'],255)
        self.assertEqual(self.get('/evidence',q="%' OR 1=1 --")['total'],0)
        self.assertEqual(self.get('/summary')['counts']['evidence'],510)
        self.assertEqual(self.client.get(self.base+'/evidence',params={'offset':-1},headers=self.headers).status_code,422)
        self.assertEqual(self.client.get(self.base+'/evidence',params={'limit':1000},headers=self.headers).status_code,422)

    def test_linked_incidents_resolve_through_evidence_controls_approvals_and_audit(self):
        risk = self.client.post('/api/grc/risks',headers=self.headers,json={'title':'Router access','likelihood':3,'impact':4}).json()
        self.client.post('/api/grc/risks/'+risk['id']+'/controls/SHAM-LOG-001',headers=self.headers)
        evidence = self.client.post('/api/grc/evidence',headers=self.headers,json={
            'control_id':'SHAM-LOG-001','source':'test','reference_id':'review-1',
            'description':'<img src=x onerror=alert(1)>','metadata':{'incident_id':'INC-TEST-001'}}).json()
        approval = self.client.post('/api/grc/approvals',headers=self.headers,json={
            'reference_type':'risk','reference_id':risk['id'],'requested_action':'Review router access','requested_by':'tester'}).json()
        for section, record_id in [('risks',risk['id']),('controls','SHAM-LOG-001'),('evidence',evidence['id']),('approvals',approval['id'])]:
            self.assertEqual(self.get('/'+section+'/'+record_id)['related_incidents']['ids'],['INC-TEST-001'])
        audit = next(x for x in self.get('/audit')['items'] if x['entity_id']==evidence['id'])
        self.assertEqual(self.get('/audit/'+audit['id'])['related_incidents']['ids'],['INC-TEST-001'])
        approval_audit = next(x for x in self.get('/audit')['items'] if x['entity_id']==approval['id'])
        self.assertEqual(self.get('/audit/'+approval_audit['id'])['related_incidents']['ids'],['INC-TEST-001'])
        self.assertEqual(self.get('/evidence/'+evidence['id'])['record']['description'],'<img src=x onerror=alert(1)>')
        summary = self.get('/summary')
        self.assertEqual(summary['open_risks'],1)
        self.assertEqual(summary['pending_approvals'],1)
        self.assertEqual(summary['implemented_controls'],0)
        before=summary['counts']['audit']
        self.get('/risks');self.get('/approvals');self.get('/controls');self.get('/audit')
        self.assertEqual(self.get('/summary')['counts']['audit'],before)
        change = self.client.post('/api/grc/approvals',headers=self.headers,json={
            'reference_type':'control_change','reference_id':'SHAM-LOG-001',
            'requested_action':'Review logging control','requested_by':'tester'}).json()
        self.assertEqual(self.get('/approvals/'+change['id'])['related_incidents']['ids'],['INC-TEST-001'])

    def test_link_pagination_empty_states_and_unknown_records(self):
        with db_session() as db:
            db.executemany('INSERT INTO evidence (id,control_id,source,reference_id,metadata_json,collected_at) VALUES (?,?,?,?,?,?)',[
                (f'EVD-{i:03}','SHAM-LOG-001','test',f'INC-OLD-{i:03}',json.dumps({'incident_id':f'INC-OLD-{i:03}'}),'2026-11-11') for i in range(25)])
        first=self.get('/controls/SHAM-LOG-001')['related_incidents']
        second=self.get('/controls/SHAM-LOG-001',incident_offset=12)['related_incidents']
        self.assertEqual(first['total'],25)
        self.assertEqual(len(first['ids']),12)
        self.assertFalse(set(first['ids']) & set(second['ids']))
        self.assertEqual(self.get('/risks')['total'],0)
        self.assertEqual(self.client.get(self.base+'/evidence/missing',headers=self.headers).status_code,404)
        self.assertEqual(self.client.get(self.base+'/unknown',headers=self.headers).status_code,404)


if __name__=='__main__':
    unittest.main()

import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

from historical_memory import render_historical_memory, replace_historical_section
from investigation_agent import prepare_investigation_context, _ollama_tools
from ollama_reporting import evidence_packet


def result_payload():
    return {'status': 'success', 'match_basis': 'same_rule_vector_search', 'historical_cases': [
        {'incident_id': 'INC-OLD-A', 'rule_name': 'Router authentication failure',
         'classification': 'suspicious', 'human_review_status': 'unknown',
         'similarity_distance': .18, 'analyst_notes': 'Long old report ' * 2000},
        {'incident_id': 'INC-OLD-B', 'rule_name': 'Router authentication failure',
         'classification': 'false_positive', 'human_review_status': 'unknown',
         'similarity_distance': .19},
    ]}


def context_for(payload, status='success'):
    return {'tool_results': [{'tool_name': 'search_historical_incidents', 'status': status, 'result': json.dumps(payload)}]}


class HistoricalMemoryTests(unittest.TestCase):
    def test_actual_ids_survive_large_reports_and_replace_model_claims(self):
        context = context_for(result_payload())
        report = '### 4. Historical Memory Context (Vector DB)\nMatch: INC-INVENTED\n### 5. Containment & Remediation Status\nNOT_EXECUTED'
        rendered = replace_historical_section(report, context)
        self.assertIn('INC-OLD-A', rendered)
        self.assertIn('INC-OLD-B', rendered)
        self.assertNotIn('INC-INVENTED', rendered)
        self.assertIn('review status: unknown', rendered)
        self.assertIn('do not establish unauthorized access', rendered)
        self.assertIn('### 5. Containment & Remediation Status\nNOT_EXECUTED', rendered)
        packet = evidence_packet({'rule': {'description': 'Router authentication failure'}}, context)
        self.assertEqual([x['incident_id'] for x in packet['T1']['value']['historical_cases']], ['INC-OLD-A', 'INC-OLD-B'])
        self.assertNotIn('truncated', packet['T1']['value'])

    def test_absent_empty_and_failed_searches_are_not_matches(self):
        self.assertIn('Not checked', render_historical_memory({}))
        self.assertIn('No eligible historical incidents', render_historical_memory(context_for({'status': 'empty'}, 'no_match')))
        self.assertIn('Unavailable or failed', render_historical_memory(context_for(result_payload(), 'error')))
        self.assertNotIn('INC-OLD', render_historical_memory(context_for(result_payload(), 'error')))

    @patch('investigation_agent._write_audit_event', return_value=True)
    @patch('investigation_agent._dispatch_tool', return_value=json.dumps(result_payload()))
    def test_runtime_prefetch_is_bounded_and_audited_before_model(self, dispatch, audit):
        alert = {'id': 'current-alert', 'rule': {'description': 'Router authentication failure'}}
        context = prepare_investigation_context(alert, 'CURRENT-CASE')
        dispatch.assert_called_once_with('search_historical_incidents', {
            'query': 'Router authentication failure', 'n_results': 2,
            'rule_name': 'Router authentication failure', 'exclude_source_alert_id': 'current-alert'})
        self.assertEqual(context['tool_calls'], 1)
        self.assertEqual(audit.call_args.args[0]['incident_id'], 'CURRENT-CASE')
        self.assertNotIn('search_historical_incidents', [x['function']['name'] for x in _ollama_tools(context)])

    def test_retrieval_excludes_same_alert_and_uses_database_ids(self):
        vector = types.ModuleType('vector_store')
        vector.search_incidents = Mock(return_value={
            'ids': [['CURRENT-STORED', 'WRONG-RULE', 'INC-OLD-A', 'INC-OLD-B']],
            'documents': [['self', 'unrelated', 'old a', 'old b']],
            'metadatas': [[
                {'source_alert_id': 'current-alert', 'rule_name': 'Router authentication failure'},
                {'rule_name': 'Unrelated rule'},
                {'incident_id': 'INC-STALE-METADATA', 'rule_name': 'Router authentication failure'},
                {'rule_name': 'Router authentication failure'},
            ]], 'distances': [[.01, .02, .18, .19]],
        })
        spec = importlib.util.spec_from_file_location('history_tools_test', Path(__file__).resolve().parents[1] / 'agent_tools.py')
        module = importlib.util.module_from_spec(spec)
        intel = types.ModuleType('threat_intel')
        intel.check_ip_reputation = Mock()
        intel.check_file_hash = Mock()
        with patch.dict(sys.modules, {'vector_store': vector, 'threat_intel': intel}):
            spec.loader.exec_module(module)
        result = json.loads(module.search_historical_incidents('router', 2, 'Router authentication failure', 'current-alert'))
        self.assertEqual([x['incident_id'] for x in result['historical_cases']], ['INC-OLD-A', 'INC-OLD-B'])
        self.assertEqual(result['match_basis'], 'same_rule_vector_search')
        self.assertEqual(vector.search_incidents.call_args.kwargs['rule_name'], 'Router authentication failure')
        intel.check_ip_reputation.assert_not_called()
        intel.check_file_hash.assert_not_called()
        vector.search_incidents.side_effect = RuntimeError('database unavailable')
        self.assertEqual(json.loads(module.search_historical_incidents('router'))['status'], 'error')

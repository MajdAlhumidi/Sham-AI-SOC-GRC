import unittest

from alert_context import incident_target_host, resolve_alert_asset


def router_alert():
    return {
        'id': 'wazuh-test-alert', 'timestamp': '2026-11-11T11:27:31Z',
        'agent': {'id': '000', 'name': 'wazuh-collector'},
        'location': '10.8.0.2',
        'decoder': {'name': 'sham-mikrotik-native-auth'},
        'rule': {'id': '100111', 'level': 7, 'description': 'MikroTik router login failure',
                 'groups': ['mikrotik', 'authentication_failed'], 'mitre': {'id': ['T1110']}},
        'data': {'dstuser': 'admin', 'srcip': '192.0.2.10', 'protocol': 'winbox'},
        'full_log': 'system,error,critical MOKROTIK-STAR: login failure for user admin from 192.0.2.10 via winbox',
    }


class AssetContextTests(unittest.TestCase):
    def test_router_identity_is_not_its_collector_or_login_source(self):
        alert = router_alert()
        asset = resolve_alert_asset(alert)
        self.assertEqual(asset['name'], 'MOKROTIK-STAR')
        self.assertEqual(asset['ip'], '10.8.0.2')
        self.assertNotEqual(asset['ip'], alert['data']['srcip'])
        self.assertEqual(alert['agent'], {'id': '000', 'name': 'wazuh-collector'})

    def test_remote_syslog_without_identity_uses_sender_ip(self):
        alert = router_alert()
        alert['full_log'] = 'Unrecognized message without a device identity'
        self.assertEqual(resolve_alert_asset(alert)['name'], '10.8.0.2')

    def test_endpoint_agent_keeps_its_own_identity(self):
        alert = router_alert()
        alert['agent'] = {'id': '001', 'name': 'workstation', 'ip': '10.0.0.10'}
        asset = resolve_alert_asset(alert)
        self.assertEqual(asset['name'], 'workstation')
        self.assertEqual(asset['ip'], '10.0.0.10')

    def test_manager_local_log_does_not_turn_into_a_router(self):
        alert = router_alert()
        alert['location'] = 'journald'
        self.assertEqual(resolve_alert_asset(alert)['name'], 'wazuh-collector')

    def test_dashboard_prefers_persisted_name_and_supports_old_records(self):
        self.assertEqual(incident_target_host({'target_host': 'MOKROTIK-STAR', 'destination_ip': '10.8.0.2'}), 'MOKROTIK-STAR')
        self.assertEqual(incident_target_host({'destination_ip': '10.8.0.2'}), '10.8.0.2')
        self.assertEqual(incident_target_host({'destination_ip': 'N/A'}), 'local-agent')

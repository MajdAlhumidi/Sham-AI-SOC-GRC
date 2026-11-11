"""Deployment compatibility for existing dashboards and private Wazuh CAs."""
import os
import ssl
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from scripts import api_server, indexer_tool


class RuntimeCompatibilityTests(unittest.TestCase):
    def test_sync_endpoint_keeps_existing_incident_shape(self):
        records = [{"case_id": "legacy-incident", "verdict": "Suspicious / Review"}]
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "GRC_DB_PATH": os.path.join(directory, "grc.sqlite3"),
        }), patch.object(api_server, "get_real_incidents_from_chroma", return_value=records):
            with TestClient(api_server.app) as client:
                response = client.get("/api/incidents")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"incidents": records})

    def test_custom_ca_keeps_certificate_verification_enabled(self):
        with patch.dict(os.environ, {"WAZUH_INDEXER_CA_CERTS": "/private/root-ca.pem"}), \
                patch.object(indexer_tool, "INDEXER_VERIFY_TLS", True), \
                patch.object(indexer_tool, "OpenSearch") as factory:
            indexer_tool.get_opensearch_client()
        self.assertEqual(factory.call_args.kwargs["ca_certs"], "/private/root-ca.pem")
        self.assertTrue(factory.call_args.kwargs["verify_certs"])

    def test_no_custom_ca_uses_default_trust_store(self):
        with patch.dict(os.environ, {"WAZUH_INDEXER_CA_CERTS": ""}), \
                patch.object(indexer_tool, "INDEXER_VERIFY_TLS", True), \
                patch.object(indexer_tool, "OpenSearch") as factory:
            indexer_tool.get_opensearch_client()
        self.assertNotIn("ca_certs", factory.call_args.kwargs)
        self.assertTrue(factory.call_args.kwargs["verify_certs"])

    def test_legacy_ca_mode_preserves_peer_verification(self):
        context = ssl.create_default_context()
        with patch.dict(os.environ, {"WAZUH_INDEXER_CA_CERTS": "/private/root-ca.pem", "WAZUH_INDEXER_TLS_STRICT": "false"}), \
                patch.object(indexer_tool, "INDEXER_VERIFY_TLS", True), \
                patch.object(indexer_tool.ssl, "create_default_context", return_value=context), \
                patch.object(indexer_tool, "OpenSearch") as factory:
            indexer_tool.get_opensearch_client()
        supplied = factory.call_args.kwargs["ssl_context"]
        self.assertEqual(supplied.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(supplied.check_hostname)
        self.assertFalse(supplied.verify_flags & ssl.VERIFY_X509_STRICT)

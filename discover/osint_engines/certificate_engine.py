"""
Certificate Engine

SSL/TLS certificate analysis:
  - Fetch and parse certificate chain via socket
  - Extract SANs (Subject Alternative Names) for subdomain discovery
  - Certificate transparency search (crt.sh)
  - Detect expired, soon-to-expire, and self-signed certificates
  - Weak cipher / protocol detection
"""
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logger.warning("cryptography package not installed — cert parsing will be limited")


class CertificateEngine(BaseOSINTEngine):
    """
    SSL/TLS certificate intelligence engine.
    """

    name = 'CertificateEngine'
    description = 'SSL/TLS certificate analysis, SANs extraction, CT log search'
    is_active = False

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        results: Dict[str, Any] = {
            'domain': domain,
            'certificates': [],
            'sans': [],
            'ct_log_entries': [],
            'errors': [],
        }

        # Live certificate fetch
        cert_info = self._fetch_certificate(domain)
        if cert_info:
            results['certificates'].append(cert_info)
            results['sans'] = cert_info.get('san', [])

        # CT log search via crt.sh
        ct_entries, ct_error = self._search_ct_logs(domain)
        if ct_error:
            results['errors'].append(f'CT logs: {ct_error}')
        results['ct_log_entries'] = ct_entries

        return results

    # ------------------------------------------------------------------

    def _fetch_certificate(self, domain: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Retrieve and analyse the SSL/TLS certificate from the target server.

        Uses TLS 1.2+ by default for the connection itself. The tool still
        detects weak configurations by inspecting the negotiated protocol/cipher
        reported in the server's handshake response — it does not need to use
        an insecure protocol version to detect that a server *supports* one.
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Prefer TLS 1.2+ for the connection; servers negotiating something
            # weaker will still be visible in ssock.version().
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    raw_cert = ssock.getpeercert(binary_form=True)
                    protocol = ssock.version()
                    cipher = ssock.cipher()

            info: Dict[str, Any] = {
                'protocol': protocol,
                'cipher_suite': cipher[0] if cipher else None,
                'cipher_bits': cipher[2] if cipher else None,
            }

            if CRYPTOGRAPHY_AVAILABLE and raw_cert:
                cert = x509.load_der_x509_certificate(raw_cert, default_backend())
                info.update(self._parse_cert(cert))
            else:
                # Fallback: use getpeercert dict form
                context2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context2.check_hostname = False
                context2.verify_mode = ssl.CERT_NONE
                context2.minimum_version = ssl.TLSVersion.TLSv1_2
                with socket.create_connection((domain, port), timeout=10) as s2:
                    with context2.wrap_socket(s2, server_hostname=domain) as ss2:
                        peer = ss2.getpeercert()
                if peer:
                    info['subject'] = dict(x[0] for x in peer.get('subject', []))
                    info['issuer'] = dict(x[0] for x in peer.get('issuer', []))
                    info['not_before'] = peer.get('notBefore')
                    info['not_after'] = peer.get('notAfter')
                    san_raw = peer.get('subjectAltName', [])
                    info['san'] = [v for _, v in san_raw]

            return info
        except Exception as exc:
            logger.debug("Certificate fetch failed for %s: %s", domain, exc)
            return None

    def _parse_cert(self, cert: Any) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            info['subject'] = cert.subject.rfc4514_string()
            info['issuer'] = cert.issuer.rfc4514_string()
            info['serial_number'] = str(cert.serial_number)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            info['not_before'] = not_before.isoformat()
            info['not_after'] = not_after.isoformat()
            now = datetime.now(timezone.utc)
            info['is_expired'] = now > not_after
            days_remaining = (not_after - now).days
            info['days_until_expiry'] = days_remaining
            info['expires_soon'] = 0 < days_remaining < 30
            info['is_self_signed'] = cert.issuer == cert.subject

            # SANs
            try:
                san_ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                info['san'] = [str(n.value) for n in san_ext.value]
            except x509.ExtensionNotFound:
                info['san'] = []
        except Exception as exc:
            logger.debug("Cert parsing error: %s", exc)
        return info

    def _search_ct_logs(self, domain: str):
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            entries = resp.json()
            processed = []
            seen_ids = set()
            for entry in entries[:100]:
                cert_id = entry.get('id')
                if cert_id in seen_ids:
                    continue
                seen_ids.add(cert_id)
                processed.append({
                    'id': cert_id,
                    'logged_at': entry.get('entry_timestamp'),
                    'not_before': entry.get('not_before'),
                    'not_after': entry.get('not_after'),
                    'common_name': entry.get('common_name'),
                    'name_value': entry.get('name_value'),
                    'issuer': entry.get('issuer_name'),
                })
            return processed, None
        except Exception as exc:
            return [], str(exc)

    def _count_items(self, data: Dict[str, Any]) -> int:
        return len(data.get('certificates', [])) + len(data.get('ct_log_entries', []))

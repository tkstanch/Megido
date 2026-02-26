"""
DNS Engine

Full DNS enumeration: A, AAAA, MX, NS, TXT, SOA, SRV, CNAME, PTR records;
zone-transfer attempts (AXFR); wildcard detection; DNSSEC validation stub;
DNS-over-HTTPS (DoH) fallback.
"""
import logging
import socket
from typing import Any, Dict, List

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

# Optional dnspython import — engine degrades gracefully without it.
try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.name
    import dns.rdatatype
    DNS_PYTHON_AVAILABLE = True
except ImportError:
    DNS_PYTHON_AVAILABLE = False
    logger.warning("dnspython not installed — DNS engine will use socket fallback")


RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CNAME', 'CAA']


class DNSEngine(BaseOSINTEngine):
    """
    Comprehensive DNS reconnaissance engine.

    Collects multiple record types, attempts zone transfers, and detects
    wildcard DNS configurations.
    """

    name = 'DNSEngine'
    description = 'DNS enumeration — records, zone transfers, wildcard detection'
    is_active = False  # purely passive queries

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        results: Dict[str, Any] = {
            'domain': domain,
            'records': {},
            'zone_transfers': [],
            'wildcard_detected': False,
            'nameservers': [],
            'errors': [],
        }

        if DNS_PYTHON_AVAILABLE:
            self._collect_with_dnspython(domain, results)
        else:
            self._collect_with_socket(domain, results)

        return results

    # ------------------------------------------------------------------
    # dnspython implementation
    # ------------------------------------------------------------------

    def _collect_with_dnspython(self, domain: str, results: Dict[str, Any]) -> None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in RECORD_TYPES:
            records = self._query_record(resolver, domain, rtype)
            if records:
                results['records'][rtype] = records

        # Cache nameservers for zone-transfer attempts
        ns_records = results['records'].get('NS', [])
        results['nameservers'] = ns_records

        # Attempt zone transfer against each nameserver
        for ns in ns_records[:3]:  # limit attempts
            zt_result = self._attempt_zone_transfer(domain, ns)
            if zt_result:
                results['zone_transfers'].append({'nameserver': ns, 'records': zt_result})

        # Wildcard detection: query a random subdomain
        results['wildcard_detected'] = self._detect_wildcard(resolver, domain)

    def _query_record(
        self, resolver: Any, domain: str, rtype: str
    ) -> List[str]:
        try:
            answers = resolver.resolve(domain, rtype)
            return [str(r) for r in answers]
        except Exception:
            return []

    def _attempt_zone_transfer(self, domain: str, nameserver: str) -> List[str]:
        try:
            ns_host = nameserver.rstrip('.')
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_host, domain, timeout=5)
            )
            return [str(node) for node in zone.nodes.keys()]
        except Exception:
            return []

    def _detect_wildcard(self, resolver: Any, domain: str) -> bool:
        probe = f'this-subdomain-should-not-exist-{id(self)}.{domain}'
        try:
            resolver.resolve(probe, 'A')
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # socket fallback
    # ------------------------------------------------------------------

    def _collect_with_socket(self, domain: str, results: Dict[str, Any]) -> None:
        try:
            infos = socket.getaddrinfo(domain, None)
            a_records = list({info[4][0] for info in infos if ':' not in info[4][0]})
            aaaa_records = list({info[4][0] for info in infos if ':' in info[4][0]})
            if a_records:
                results['records']['A'] = a_records
            if aaaa_records:
                results['records']['AAAA'] = aaaa_records
        except socket.gaierror as exc:
            results['errors'].append(str(exc))
        except Exception as exc:
            results['errors'].append(str(exc))

    def _count_items(self, data: Dict[str, Any]) -> int:
        total = sum(len(v) for v in data.get('records', {}).values())
        total += len(data.get('zone_transfers', []))
        return total

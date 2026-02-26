"""
Threat Intelligence Engine

Correlates target with threat intelligence feeds:
  - VirusTotal domain/IP report
  - AbuseIPDB IP checks
  - OTX AlienVault indicators
  - Shodan InternetDB (no API key required)
  - URLhaus malware feed check
"""
import logging
import socket
from typing import Any, Dict, List, Optional

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)


class ThreatIntelEngine(BaseOSINTEngine):
    """
    Threat intelligence correlation engine.
    """

    name = 'ThreatIntelEngine'
    description = 'VirusTotal, AbuseIPDB, OTX, Shodan InternetDB, URLhaus threat correlation'
    is_active = False

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        results: Dict[str, Any] = {
            'domain': domain,
            'virustotal': {},
            'shodan_internetdb': [],
            'otx': {},
            'urlhaus': {},
            'abuseipdb': [],
            'threat_score': 0,
            'errors': [],
        }

        vt_key = self._get_config('virustotal_api_key')
        abuseipdb_key = self._get_config('abuseipdb_api_key')

        # Shodan InternetDB (no API key)
        ips = self._resolve_ips(domain)
        for ip in ips[:3]:
            sdb = self._shodan_internetdb(ip)
            if sdb:
                results['shodan_internetdb'].append(sdb)

        # VirusTotal
        if vt_key:
            vt_data, vt_error = self._virustotal_domain(domain, vt_key)
            if vt_error:
                results['errors'].append(f'VirusTotal: {vt_error}')
            else:
                results['virustotal'] = vt_data
        else:
            results['errors'].append('VirusTotal API key not configured')

        # OTX AlienVault (no API key for basic queries)
        otx_data, otx_error = self._otx_domain(domain)
        if otx_error:
            results['errors'].append(f'OTX: {otx_error}')
        else:
            results['otx'] = otx_data

        # URLhaus
        urlhaus_data, urlhaus_error = self._urlhaus_lookup(domain)
        if urlhaus_error:
            results['errors'].append(f'URLhaus: {urlhaus_error}')
        else:
            results['urlhaus'] = urlhaus_data

        # AbuseIPDB
        if abuseipdb_key:
            for ip in ips[:3]:
                abuse_data, abuse_error = self._abuseipdb(ip, abuseipdb_key)
                if not abuse_error and abuse_data:
                    results['abuseipdb'].append(abuse_data)

        # Calculate basic threat score (0-100)
        results['threat_score'] = self._calculate_threat_score(results)

        return results

    # ------------------------------------------------------------------

    def _resolve_ips(self, domain: str) -> List[str]:
        try:
            infos = socket.getaddrinfo(domain, None)
            return list({info[4][0] for info in infos if ':' not in info[4][0]})[:5]
        except Exception:
            return []

    def _shodan_internetdb(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f'https://internetdb.shodan.io/{ip}'
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'ip': ip,
                    'ports': data.get('ports', []),
                    'cpes': data.get('cpes', []),
                    'hostnames': data.get('hostnames', []),
                    'tags': data.get('tags', []),
                    'vulns': data.get('vulns', []),
                }
        except Exception as exc:
            logger.debug("Shodan InternetDB error for %s: %s", ip, exc)
        return None

    def _virustotal_domain(self, domain: str, api_key: str):
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'reputation': attrs.get('reputation', 0),
                'categories': attrs.get('categories', {}),
                'total_votes': attrs.get('total_votes', {}),
            }, None
        except Exception as exc:
            return {}, str(exc)

    def _otx_domain(self, domain: str):
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'reputation': data.get('reputation', 0),
                    'indicator': data.get('indicator'),
                }, None
        except Exception as exc:
            return {}, str(exc)
        return {}, None

    def _urlhaus_lookup(self, domain: str):
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        try:
            resp = requests.post(url, data={'host': domain}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'query_status': data.get('query_status'),
                    'url_count': data.get('urls_count', 0),
                    'blacklists': data.get('blacklists', {}),
                }, None
        except Exception as exc:
            return {}, str(exc)
        return {}, None

    def _abuseipdb(self, ip: str, api_key: str):
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json().get('data', {})
            return {
                'ip': ip,
                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country_code': data.get('countryCode'),
                'isp': data.get('isp'),
            }, None
        except Exception as exc:
            return None, str(exc)

    def _calculate_threat_score(self, results: Dict[str, Any]) -> int:
        score = 0
        vt = results.get('virustotal', {})
        score += min(vt.get('malicious', 0) * 10, 40)
        score += min(vt.get('suspicious', 0) * 5, 20)

        for sdb in results.get('shodan_internetdb', []):
            score += min(len(sdb.get('vulns', [])) * 5, 20)

        otx = results.get('otx', {})
        score += min(otx.get('pulse_count', 0) * 2, 20)

        urlhaus = results.get('urlhaus', {})
        if urlhaus.get('url_count', 0) > 0:
            score += 20

        return min(score, 100)

    def _count_items(self, data: Dict[str, Any]) -> int:
        total = len(data.get('shodan_internetdb', []))
        if data.get('virustotal'):
            total += 1
        if data.get('otx'):
            total += 1
        return total

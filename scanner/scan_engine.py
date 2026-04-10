import os
import logging
from concurrent.futures import as_completed
from threading import Lock
from typing import List, Optional, Dict, Any
import threading
import django
from scanner.scan_plugins.scan_plugin_registry import get_scan_registry
from scanner.models import Vulnerability

try:
    from scanner.stealth_engine import StealthEngine
    _HAS_STEALTH = True
except ImportError:
    StealthEngine = None
    _HAS_STEALTH = False

logger = logging.getLogger(__name__)

class ScanEngine:
    SCAN_PROFILES = {
        'stealth': {
            'enable_stealth': True,
            'stealth_timing': 'normal',
            'max_workers': 3,
            'max_retries': 2,
            'description': 'Slow, paranoid timing, maximum evasion'
        },
        'balanced': {
            'enable_stealth': True,
            'stealth_timing': 'normal',
            'max_workers': 3,
            'max_retries': 2,
            'description': 'Moderate timing, standard payloads'
        },
        'aggressive': {
            'enable_stealth': False,
            'stealth_timing': 'normal',
            'max_workers': 3,
            'max_retries': 2,
            'description': 'No delays, maximum payloads'
        },
        'quick': {
            'enable_stealth': False,
            'stealth_timing': 'normal',
            'max_workers': 3,
            'max_retries': 2,
            'description': 'Fast, only high-severity checks'
        }
    }

    def __init__(self):
        self.registry = get_scan_registry()
        self.enable_stealth = False
        self.stealth_timing = 'normal'
        self._stealth_engine = None
        self.MAX_THREADS = 5

    def _inject_env_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        if 'max_retries' not in config:
            config['max_retries'] = 2
        if 'enable_stealth' not in config:
            config['enable_stealth'] = self.enable_stealth and _HAS_STEALTH
        if 'stealth_timing' not in config:
            config['stealth_timing'] = self.stealth_timing
        return config

    def _get_plugin(self, plugin_id: str) -> Optional[Any]:
        return self.registry.get_plugin(plugin_id)

    def _apply_plugin_config(self, plugin: Any, config: Dict[str, Any]) -> None:
        plugin.config = config

    def _run_plugin(self, plugin: Any, url: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        if plugin:
            findings = plugin.run_scan(url, config)
            logger.debug(f"Plugin {plugin.name} found {len(findings)} issue(s)")
        return findings

    def _post_scan_process(self, findings: List[Dict[str, Any]], config: Dict[str, Any]) -> None:
        # Placeholder for any post-scan processing
        pass

    def _save_findings_to_db(self, scan: 'Scan', findings: List[Dict[str, Any]]) -> List['Vulnerability']:
        if not django.apps.apps.is_installed('scanner'):
            logger.warning("Django models not available, skipping database save")
            return []
        vulnerabilities = []
        for finding in findings:
            http_traffic = finding.get('http_traffic', {})
            vuln = Vulnerability.objects.create(
                scan=scan,
                vulnerability_type=finding.get('vulnerability_type'),
                severity=finding.get('severity'),
                url=finding.get('url'),
                parameter=finding.get('parameter'),
                description=finding.get('description'),
                evidence=finding.get('evidence'),
                remediation=finding.get('remediation'),
                confidence_score=finding.get('confidence_score'),
                verified=finding.get('verified'),
                successful_payloads=finding.get('successful_payloads', []),
                repeater_data=finding.get('repeater_requests', []),
                http_traffic=http_traffic,
            )
            vulnerabilities.append(vuln)
        logger.info(f"Saved {len(vulnerabilities)} vulnerability(ies) to database for scan {scan.id}")
        return vulnerabilities

    def _pre_scan_recon(self, url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        # Placeholder for pre-scan recon logic
        return config

    def _list_available_plugins(self) -> List[Dict[str, Any]]:
        return self.registry.list_plugins()

    def _get_stealth_headers(self) -> Dict[str, str]:
        if not self._stealth_engine:
            self._stealth_engine = StealthEngine()
        return self._stealth_engine.get_random_user_agent()

    def _apply_stealth_session(self, config: Dict[str, Any]) -> None:
        if self.enable_stealth:
            config['stealth_headers'] = self._get_stealth_headers()
            config['enable_stealth'] = True

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        config = self._inject_env_config(config or {})
        self._apply_stealth_session(config)
        return self._run_plugin(None, url, config)

    def scan_with_plugins(self, url: str, plugin_ids: List[str], config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        config = self._inject_env_config(config or {})
        self._apply_stealth_session(config)
        all_findings = []
        for plugin_id in plugin_ids:
            plugin = self._get_plugin(plugin_id)
            if plugin:
                findings = self._run_plugin(plugin, url, config)
                all_findings.extend(findings)
            else:
                logger.warning(f"Plugin not found: {plugin_id}")
        return all_findings

    def scan_concurrent(self, url: str, config: Optional[Dict[str, Any]] = None, max_workers: int = 3) -> List[Dict[str, Any]]:
        import concurrent.futures
        import threading
        config = self._inject_env_config(config or {})
        self._apply_stealth_session(config)
        all_findings = []
        lock = threading.Lock()

        def _run_plugin(plugin: Any) -> None:
            thread_config = dict(config)
            self._apply_stealth_session(thread_config)
            findings = self._run_plugin(plugin, url, thread_config)
            with lock:
                all_findings.extend(findings)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_run_plugin, plugin): plugin for plugin in self.registry.get_all_plugins()}
            for future in concurrent.futures.as_completed(futures):
                plugin = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Concurrent plugin %s raised: %s", plugin.name, exc)

        return all_findings

    def scan_with_profile(self, url: str, profile_name: str, extra_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if profile_name not in self.SCAN_PROFILES:
            raise ValueError(
                f"Unknown scan profile '{profile_name}'. "
                f"Valid profiles: {list(self.SCAN_PROFILES)}"
            )
        profile = self.SCAN_PROFILES[profile_name]
        config = extra_config.copy() if extra_config else {}
        max_workers = profile.pop('max_workers', 3)
        max_retries = profile.pop('max_retries', 2)
        self.enable_stealth = profile.pop('enable_stealth', False) and _HAS_STEALTH
        self.stealth_timing = profile.pop('stealth_timing', 'normal')
        if self.enable_stealth and self._stealth_engine is None:
            self._stealth_engine = StealthEngine()
        config.update(profile)
        config['max_retries'] = max_retries
        config = self._inject_env_config(config)
        self._apply_stealth_session(config)
        return self.scan_concurrent(url, config=config, max_workers=max_workers)

    def save_findings_to_db(self, scan: 'Scan', findings: List[Dict[str, Any]]) -> List['Vulnerability']:
        if not django.apps.apps.is_installed('scanner'):
            logger.warning("Django models not available, skipping database save")
            return []
        return self._save_findings_to_db(scan, findings)

    def list_available_plugins(self) -> List[Dict[str, Any]]:
        return self.registry.list_plugins()

def get_scan_engine() -> ScanEngine:
    return ScanEngine()

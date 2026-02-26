"""
Automated Injection Engine.
Multi-threaded engine that tests payloads against discovered injection points.
"""
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError
except ImportError:
    requests = None
    Timeout = Exception
    RequestsConnectionError = Exception

from .response_analyzer import ResponseAnalyzer, TIME_BASED_DELAY_THRESHOLD_MS
from .poc_generator import PoCGenerator

logger = logging.getLogger(__name__)


class AutoInjector:
    """
    Automated multi-threaded injection engine.
    Tests payload variants against discovered injection points.
    """

    def __init__(self, concurrency: int = 10, timeout: int = 15,
                 custom_headers: Optional[Dict] = None,
                 auth_cookies: Optional[Dict] = None,
                 follow_redirects: bool = True,
                 on_result_callback: Optional[Callable] = None):
        self.concurrency = min(concurrency, 20)
        self.timeout = timeout
        self.custom_headers = custom_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.follow_redirects = follow_redirects
        self.on_result_callback = on_result_callback

        self.analyzer = ResponseAnalyzer()
        self.poc_gen = PoCGenerator()

        self._stop_flag = False
        self._results: List[Dict] = []
        self._request_count = 0

    def stop(self):
        """Signal the injector to stop."""
        self._stop_flag = True

    def _build_headers(self, extra: Optional[Dict] = None) -> Dict:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; Megido Security Scanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        headers.update(self.custom_headers)
        if extra:
            headers.update(extra)
        return headers

    def _get_baseline(self, injection_point: Dict) -> Optional[Dict]:
        """Get baseline response for an injection point."""
        if requests is None:
            return None
        try:
            url = injection_point['form_action'] or injection_point['url']
            method = injection_point.get('form_method', 'GET').upper()
            param_type = injection_point['parameter_type']
            param_name = injection_point['parameter_name']
            original_value = injection_point.get('original_value', 'test')

            start = time.time()
            if param_type == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [original_value]
                new_query = urlencode({k: v[0] for k, v in params.items()})
                new_url = parsed._replace(query=new_query).geturl()
                resp = requests.get(new_url, headers=self._build_headers(),
                                    cookies=self.auth_cookies, timeout=self.timeout,
                                    allow_redirects=self.follow_redirects)
            elif param_type == 'POST':
                resp = requests.post(url, data={param_name: original_value},
                                     headers=self._build_headers(),
                                     cookies=self.auth_cookies, timeout=self.timeout,
                                     allow_redirects=self.follow_redirects)
            else:
                resp = requests.get(url, headers=self._build_headers(),
                                    cookies=self.auth_cookies, timeout=self.timeout,
                                    allow_redirects=self.follow_redirects)

            elapsed_ms = int((time.time() - start) * 1000)
            return {
                'status': resp.status_code,
                'body': resp.text[:5000],
                'time_ms': elapsed_ms,
            }
        except Exception as e:
            logger.debug(f"Baseline failed: {e}")
            return None

    def _inject_payload(self, injection_point: Dict, payload: str,
                        baseline: Optional[Dict] = None) -> Dict:
        """
        Inject a single payload into an injection point and analyze the response.
        Returns result dict.
        """
        if requests is None:
            return {'error': 'requests not available', 'is_successful': False,
                    'blocked': False, 'rate_limited': False}

        url = injection_point.get('form_action') or injection_point['url']
        method = injection_point.get('form_method', 'GET').upper()
        param_type = injection_point['parameter_type']
        param_name = injection_point['parameter_name']

        request_headers = self._build_headers()
        request_body = ''
        request_url = url

        try:
            start = time.time()

            if param_type == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [payload]
                new_query = urlencode({k: v[0] for k, v in params.items()})
                request_url = parsed._replace(query=new_query).geturl()
                resp = requests.get(request_url, headers=request_headers,
                                    cookies=self.auth_cookies, timeout=self.timeout,
                                    allow_redirects=self.follow_redirects)

            elif param_type == 'POST':
                request_body = urlencode({param_name: payload})
                resp = requests.post(url, data={param_name: payload},
                                     headers=request_headers,
                                     cookies=self.auth_cookies, timeout=self.timeout,
                                     allow_redirects=self.follow_redirects)

            elif param_type == 'header':
                request_headers[param_name] = payload
                resp = requests.get(url, headers=request_headers,
                                    cookies=self.auth_cookies, timeout=self.timeout,
                                    allow_redirects=self.follow_redirects)

            elif param_type == 'cookie':
                cookies = dict(self.auth_cookies)
                cookies[param_name] = payload
                resp = requests.get(url, headers=request_headers,
                                    cookies=cookies, timeout=self.timeout,
                                    allow_redirects=self.follow_redirects)

            elif param_type == 'json':
                request_headers['Content-Type'] = 'application/json'
                body_data = json.dumps({param_name: payload})
                request_body = body_data
                resp = requests.post(url, data=body_data, headers=request_headers,
                                     cookies=self.auth_cookies, timeout=self.timeout,
                                     allow_redirects=self.follow_redirects)

            else:
                resp = requests.get(f"{url}?{param_name}={payload}",
                                    headers=request_headers,
                                    cookies=self.auth_cookies, timeout=self.timeout,
                                    allow_redirects=self.follow_redirects)

            elapsed_ms = int((time.time() - start) * 1000)
            self._request_count += 1

            response_body = resp.text[:10000]

            if self.analyzer.check_waf_block(resp.status_code, response_body):
                return {
                    'blocked': True,
                    'response_status': resp.status_code,
                    'response_time_ms': elapsed_ms,
                    'is_successful': False,
                }

            if self.analyzer.check_rate_limit(resp.status_code, response_body):
                return {
                    'rate_limited': True,
                    'response_status': resp.status_code,
                    'response_time_ms': elapsed_ms,
                    'is_successful': False,
                }

            baseline_time = baseline['time_ms'] if baseline else 0
            baseline_body = baseline['body'] if baseline else ''

            analysis = self.analyzer.analyze(
                payload=payload,
                response_body=response_body,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_time_ms=elapsed_ms,
                baseline_time_ms=baseline_time,
                baseline_body=baseline_body,
            )

            result = {
                'payload_text': payload,
                'request_method': method,
                'request_url': request_url,
                'request_headers': request_headers,
                'request_body': request_body,
                'response_status': resp.status_code,
                'response_headers': dict(resp.headers),
                'response_body': response_body[:5000],
                'response_time_ms': elapsed_ms,
                'is_successful': analysis['is_successful'],
                'vulnerability_type': analysis['vulnerability_type'],
                'detection_method': analysis['detection_method'],
                'confidence': analysis['confidence'],
                'evidence': analysis['evidence'],
                'severity': analysis['severity'],
                'blocked': False,
                'rate_limited': False,
            }

            if analysis['is_successful']:
                poc = self.poc_gen.generate(
                    injection_point=injection_point,
                    payload=payload,
                    result=result,
                )
                result.update(poc)

            return result

        except Timeout:
            elapsed_ms = int(self.timeout * 1000)
            if baseline and elapsed_ms - baseline.get('time_ms', 0) >= TIME_BASED_DELAY_THRESHOLD_MS:
                return {
                    'payload_text': payload,
                    'request_method': method,
                    'request_url': request_url,
                    'request_headers': request_headers,
                    'request_body': request_body,
                    'response_status': 0,
                    'response_headers': {},
                    'response_body': '',
                    'response_time_ms': elapsed_ms,
                    'is_successful': True,
                    'vulnerability_type': 'SQLi (Time-based Blind)',
                    'detection_method': 'time-based',
                    'confidence': 0.7,
                    'evidence': f'Request timed out after {elapsed_ms}ms',
                    'severity': 'critical',
                    'blocked': False,
                    'rate_limited': False,
                }
            return {
                'error': 'timeout',
                'response_time_ms': elapsed_ms,
                'is_successful': False,
                'blocked': False,
                'rate_limited': False,
            }

        except Exception as e:
            logger.debug(f"Injection failed: {e}")
            return {
                'error': str(e),
                'is_successful': False,
                'blocked': False,
                'rate_limited': False,
            }

    def test_injection_point(self, injection_point: Dict,
                             payloads: List[str]) -> List[Dict]:
        """
        Test all payloads against a single injection point.
        Returns list of result dicts for successful exploits.
        """
        results = []
        baseline = self._get_baseline(injection_point)

        rate_limited = False
        consecutive_blocks = 0

        for payload in payloads:
            if self._stop_flag:
                break
            if rate_limited:
                time.sleep(2)
                rate_limited = False

            result = self._inject_payload(injection_point, payload, baseline)

            if result.get('rate_limited'):
                rate_limited = True
                time.sleep(3)
                continue

            if result.get('blocked'):
                consecutive_blocks += 1
                if consecutive_blocks >= 5:
                    break
                continue

            consecutive_blocks = 0

            if result.get('is_successful'):
                result['injection_point'] = injection_point
                results.append(result)

                if self.on_result_callback:
                    try:
                        self.on_result_callback(result)
                    except Exception:
                        pass

        return results

    def run_campaign(self, injection_points: List[Dict],
                     payloads: List[str]) -> Dict:
        """
        Run an injection campaign against all injection points with all payloads.
        Returns summary dict with results.
        """
        self._stop_flag = False
        self._results = []
        self._request_count = 0

        all_results = []

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self.test_injection_point, ip, payloads): ip
                for ip in injection_points
            }

            for future in as_completed(futures):
                if self._stop_flag:
                    executor.shutdown(wait=False)
                    break
                try:
                    results = future.result(timeout=300)
                    all_results.extend(results)
                except Exception as e:
                    logger.debug(f"Injection point test failed: {e}")

        return {
            'total_results': len(all_results),
            'successful_exploits': len([r for r in all_results if r.get('is_successful')]),
            'total_requests': self._request_count,
            'results': all_results,
        }

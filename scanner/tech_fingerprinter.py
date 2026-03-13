import re
import requests
from requests.exceptions import RequestException
from collections import defaultdict

class TechFingerprinter:
    def __init__(self, timeout=10, verify_ssl=True, session=None, probe_paths=True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.probe_paths = probe_paths
        self.session = session or requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (compatible; MegidoScanner/5.0; +https://github.com/tkstanch/Megido)'

        # Define technology categories and their detection patterns
        self.tech_categories = {
            'web_server': {
                'patterns': [re.compile(r'Apache', re.IGNORECASE)],
                'default': 'Unknown'
            },
            'programming_language': {
                'patterns': [re.compile(r'Python', re.IGNORECASE)],
                'default': 'Unknown'
            },
            'frameworks': {
                'patterns': [re.compile(r'Django', re.IGNORECASE)],
                'default': 'Unknown'
            },
            'content_management_systems': {
                'patterns': [re.compile(r'Django CMS', re.IGNORECASE)],
                'default': 'Unknown'
            },
            'content_delivery_network': {
                'patterns': [re.compile(r'Cloudflare', re.IGNORECASE)],
                'default': 'Unknown'
            },
            'javascript_frameworks': {
                'patterns': [re.compile(r'Angular', re.IGNORECASE)],
                'default': 'Unknown'
            }
        }

    def fingerprint(self, url):
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()
        except RequestException as e:
            print(f"Request failed: {e}")
            return TechStack()

        return self.fingerprint_from_response(response)

    def fingerprint_from_response(self, response):
        headers = response.headers
        cookies = response.cookies.get_dict()
        html = response.text

        stack = TechStack()
        stack.merge(self._from_headers(headers))
        stack.merge(self._from_cookies(cookies))
        stack.merge(self._from_html(html))
        stack.merge(self._from_path_probes(response.url))

        return stack

    def _from_headers(self, headers):
        stack = TechStack()
        for category, tech_info in self.tech_categories.items():
            for pattern in tech_info['patterns']:
                match = pattern.search(headers.get('Server', ''))
                if match:
                    stack.add(category, match.group(0))
        return stack

    def _from_cookies(self, cookies):
        stack = TechStack()
        for category, tech_info in self.tech_categories.items():
            for pattern in tech_info['patterns']:
                for key, value in cookies.items():
                    if pattern.search(key) or pattern.search(value):
                        stack.add(category, value)
        return stack

    def _from_html(self, html):
        stack = TechStack()
        for category, tech_info in self.tech_categories.items():
            for pattern in tech_info['patterns']:
                if pattern.search(html):
                    stack.add(category, pattern.search(html).group(0))
        return stack

    def _from_path_probes(self, url):
        stack = TechStack()
        if self.probe_paths:
            for category, tech_info in self.tech_categories.items():
                if tech_info.get('probes'):
                    for probe in tech_info['probes']:
                        probe_url = f"{url}{probe}"
                        try:
                            response = self.session.get(probe_url, timeout=self.timeout, verify=self.verify_ssl)
                            if response.status_code == 200:
                                stack.add(category, response.url)
                        except RequestException:
                            pass
        return stack

    def _build_stack(self, raw_stack):
        stack = TechStack()
        for tech in raw_stack:
            category, value = tech
            if not stack.get(category):
                stack.add(category, value)
        return stack

    def _pick(self, entries):
        if not entries:
            return None
        return max(entries, key=lambda entry: entry['confidence'])

class TechStack:
    def __init__(self):
        self.entries = []

    def add(self, category, value, confidence=0):
        self.entries.append({'category': category, 'value': value, 'confidence': confidence})

    def merge(self, other_stack):
        for entry in other_stack.entries:
            if not self.get(entry['category']):
                self.add(entry['category'], entry['value'], entry['confidence'])

    def get(self, category):
        for entry in self.entries:
            if entry['category'] == category:
                return entry['value']
        return None

    def __str__(self):
        return ', '.join(f"{tech['category']}={tech['value']}" for tech in self.entries)

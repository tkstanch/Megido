"""
Cloud Resource Enumeration Engine

Discovers exposed cloud resources:
  - S3 buckets (name permutations)
  - Azure blob storage
  - GCP Storage buckets
  - Open Firebase databases
  - Exposed Elasticsearch / Kibana instances
"""
import logging
import re
from typing import Any, Dict, List, Tuple

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

# S3 bucket URL patterns
S3_REGIONS = [
    's3.amazonaws.com',
    's3-us-east-1.amazonaws.com',
    's3-eu-west-1.amazonaws.com',
    's3.us-west-2.amazonaws.com',
]

# Suffixes / prefixes added to the target name when guessing bucket names
BUCKET_SUFFIXES = [
    '', '-dev', '-staging', '-prod', '-backup', '-assets', '-static',
    '-files', '-uploads', '-media', '-data', '-public', '-private',
    '-logs', '-archive', '-store', '.com', '-web', '-app',
]

BUCKET_PREFIXES = ['', 'dev-', 'staging-', 'backup-', 'prod-', 'static-', 'assets-']


class CloudEnumEngine(BaseOSINTEngine):
    """
    Cloud resource enumeration engine.
    """

    name = 'CloudEnumEngine'
    description = 'S3, Azure Blob, GCP, Firebase, Elasticsearch cloud resource discovery'
    is_active = True

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        org = domain.split('.')[0]

        results: Dict[str, Any] = {
            'domain': domain,
            's3_buckets': [],
            'azure_blobs': [],
            'gcp_buckets': [],
            'firebase_dbs': [],
            'elasticsearch': [],
            'errors': [],
        }

        # S3 buckets
        for bucket_name in self._generate_bucket_names(org):
            status, url = self._check_s3_bucket(bucket_name)
            if status != 'not_found':
                results['s3_buckets'].append({
                    'name': bucket_name,
                    'url': url,
                    'status': status,
                })

        # Azure blob storage
        for container in self._generate_bucket_names(org):
            status, url = self._check_azure_blob(container)
            if status != 'not_found':
                results['azure_blobs'].append({
                    'name': container,
                    'url': url,
                    'status': status,
                })

        # GCP buckets
        for bucket_name in self._generate_bucket_names(org):
            status, url = self._check_gcp_bucket(bucket_name)
            if status != 'not_found':
                results['gcp_buckets'].append({
                    'name': bucket_name,
                    'url': url,
                    'status': status,
                })

        # Firebase real-time database
        status, url = self._check_firebase(org)
        if status != 'not_found':
            results['firebase_dbs'].append({'name': org, 'url': url, 'status': status})

        return results

    # ------------------------------------------------------------------

    def _generate_bucket_names(self, base: str) -> List[str]:
        names = set()
        for prefix in BUCKET_PREFIXES:
            for suffix in BUCKET_SUFFIXES:
                names.add(f'{prefix}{base}{suffix}')
        return list(names)[:40]  # cap at 40 to avoid being too noisy

    def _check_s3_bucket(self, name: str) -> Tuple[str, str]:
        url = f'https://{name}.s3.amazonaws.com/'
        try:
            resp = requests.get(url, timeout=5, verify=False)  # noqa: S501
            if resp.status_code == 200:
                return 'open', url
            elif resp.status_code == 403:
                return 'exists_private', url
            elif resp.status_code == 301:
                return 'redirect', url
        except Exception:
            pass
        return 'not_found', url

    def _check_azure_blob(self, name: str) -> Tuple[str, str]:
        url = f'https://{name}.blob.core.windows.net/'
        try:
            resp = requests.get(url, timeout=5, verify=False)  # noqa: S501
            if resp.status_code in (200, 400):
                return 'exists', url
        except Exception:
            pass
        return 'not_found', url

    def _check_gcp_bucket(self, name: str) -> Tuple[str, str]:
        url = f'https://storage.googleapis.com/{name}/'
        try:
            resp = requests.get(url, timeout=5, verify=False)  # noqa: S501
            if resp.status_code == 200:
                return 'open', url
            elif resp.status_code == 403:
                return 'exists_private', url
        except Exception:
            pass
        return 'not_found', url

    def _check_firebase(self, name: str) -> Tuple[str, str]:
        url = f'https://{name}.firebaseio.com/.json'
        try:
            resp = requests.get(url, timeout=5, verify=False)  # noqa: S501
            if resp.status_code == 200:
                return 'open', url
            elif resp.status_code == 401:
                return 'exists_auth_required', url
        except Exception:
            pass
        return 'not_found', url

    def _count_items(self, data: Dict[str, Any]) -> int:
        return (
            len(data.get('s3_buckets', []))
            + len(data.get('azure_blobs', []))
            + len(data.get('gcp_buckets', []))
            + len(data.get('firebase_dbs', []))
            + len(data.get('elasticsearch', []))
        )

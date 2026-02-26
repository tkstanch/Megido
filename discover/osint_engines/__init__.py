"""
OSINT Engines Package

Modular OSINT data source collectors for the Discover app.
Each engine is an independent, pluggable module that targets a specific
data source or reconnaissance technique.
"""

from .base_engine import BaseOSINTEngine, EngineResult
from .dns_engine import DNSEngine
from .subdomain_engine import SubdomainEngine
from .whois_engine import WHOISEngine
from .certificate_engine import CertificateEngine
from .technology_engine import TechnologyEngine
from .web_crawler_engine import WebCrawlerEngine
from .email_engine import EmailEngine
from .social_media_engine import SocialMediaEngine
from .cloud_enum_engine import CloudEnumEngine
from .threat_intel_engine import ThreatIntelEngine

__all__ = [
    'BaseOSINTEngine',
    'EngineResult',
    'DNSEngine',
    'SubdomainEngine',
    'WHOISEngine',
    'CertificateEngine',
    'TechnologyEngine',
    'WebCrawlerEngine',
    'EmailEngine',
    'SocialMediaEngine',
    'CloudEnumEngine',
    'ThreatIntelEngine',
]

# Registry of all available engines, keyed by engine name
ENGINE_REGISTRY = {
    'dns': DNSEngine,
    'subdomains': SubdomainEngine,
    'whois': WHOISEngine,
    'certificates': CertificateEngine,
    'technology': TechnologyEngine,
    'web_crawler': WebCrawlerEngine,
    'email': EmailEngine,
    'social_media': SocialMediaEngine,
    'cloud_enum': CloudEnumEngine,
    'threat_intel': ThreatIntelEngine,
}


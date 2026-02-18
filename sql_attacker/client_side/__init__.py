"""
Client-Side Attack Module

This module provides client-side SQL injection and security testing capabilities,
including browser automation, static JavaScript analysis, HTTP Parameter Pollution,
and privacy/storage risk analysis.
"""

from .browser_automation import BrowserAutomationWorker
from .static_scanner import JavaScriptStaticScanner
from .hpp_detector import HTTPParameterPollutionDetector
from .privacy_analyzer import PrivacyStorageAnalyzer
from .orchestrator import ClientSideScanOrchestrator, ScanConfiguration, ScanType

__all__ = [
    'BrowserAutomationWorker',
    'JavaScriptStaticScanner',
    'HTTPParameterPollutionDetector',
    'PrivacyStorageAnalyzer',
    'ClientSideScanOrchestrator',
    'ScanConfiguration',
    'ScanType',
]

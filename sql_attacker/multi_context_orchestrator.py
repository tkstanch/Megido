"""
Multi-Context Injection Attack Orchestrator

Coordinates injection attacks across multiple contexts (SQL, LDAP, XPath, etc.)
and manages parallel testing, result aggregation, and proof generation.
"""

import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from .injection_contexts import (
    InjectionContext,
    InjectionResult,
    InjectionContextType,
)
from .injection_contexts.sql_context import SQLInjectionContext
from .injection_contexts.ldap_context import LDAPInjectionContext
from .injection_contexts.xpath_context import XPathInjectionContext
from .injection_contexts.message_queue_context import MessageQueueInjectionContext
from .injection_contexts.custom_query_context import CustomQueryInjectionContext


logger = logging.getLogger(__name__)


class MultiContextAttackOrchestrator:
    """
    Orchestrates injection attacks across multiple query contexts.
    
    Supports parallel testing of different injection types and aggregates
    results with visual proof and detailed evidence.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the orchestrator.
        
        Args:
            config: Configuration dictionary with options:
                - enabled_contexts: List of context types to test (default: all)
                - parallel_execution: Enable parallel context testing (default: True)
                - max_workers: Maximum parallel workers (default: 5)
                - timeout: Request timeout in seconds (default: 10)
        """
        self.config = config or {}
        self.enabled_contexts = self.config.get('enabled_contexts', [
            InjectionContextType.SQL,
            InjectionContextType.LDAP,
            InjectionContextType.XPATH,
            InjectionContextType.MESSAGE_QUEUE,
            InjectionContextType.CUSTOM_QUERY,
        ])
        
        # Initialize context handlers
        self.contexts: Dict[InjectionContextType, InjectionContext] = {}
        self._initialize_contexts()
        
        self.parallel_execution = self.config.get('parallel_execution', True)
        self.max_workers = self.config.get('max_workers', 5)
    
    def _initialize_contexts(self):
        """Initialize all enabled injection contexts."""
        context_classes = {
            InjectionContextType.SQL: SQLInjectionContext,
            InjectionContextType.LDAP: LDAPInjectionContext,
            InjectionContextType.XPATH: XPathInjectionContext,
            InjectionContextType.MESSAGE_QUEUE: MessageQueueInjectionContext,
            InjectionContextType.CUSTOM_QUERY: CustomQueryInjectionContext,
        }
        
        for context_type in self.enabled_contexts:
            if context_type in context_classes:
                try:
                    self.contexts[context_type] = context_classes[context_type](self.config)
                    logger.info(f"Initialized {context_type.value} injection context")
                except Exception as e:
                    logger.error(f"Failed to initialize {context_type.value} context: {e}")
    
    def test_all_contexts(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str = "",
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> List[InjectionResult]:
        """
        Test all enabled contexts against a target parameter.
        
        Args:
            target_url: Target URL to test
            parameter_name: Parameter name to inject into
            parameter_type: Parameter type (GET, POST, etc.)
            parameter_value: Original parameter value
            http_method: HTTP method to use
            headers: Additional HTTP headers
            cookies: Cookies to send
        
        Returns:
            List of successful injection results
        """
        all_results = []
        
        logger.info(f"Starting multi-context attack on {target_url} parameter '{parameter_name}'")
        
        if self.parallel_execution:
            all_results = self._test_contexts_parallel(
                target_url, parameter_name, parameter_type, parameter_value,
                http_method, headers, cookies
            )
        else:
            all_results = self._test_contexts_sequential(
                target_url, parameter_name, parameter_type, parameter_value,
                http_method, headers, cookies
            )
        
        # Filter successful results
        successful_results = [r for r in all_results if r.success]
        
        logger.info(f"Multi-context attack completed. Found {len(successful_results)} vulnerabilities")
        
        return successful_results
    
    def _test_contexts_parallel(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        http_method: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> List[InjectionResult]:
        """Test contexts in parallel using thread pool."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks for each context
            future_to_context = {}
            
            for context_type, context in self.contexts.items():
                future = executor.submit(
                    self._test_single_context,
                    context,
                    target_url,
                    parameter_name,
                    parameter_type,
                    parameter_value,
                    http_method,
                    headers,
                    cookies
                )
                future_to_context[future] = context_type
            
            # Collect results as they complete
            for future in as_completed(future_to_context):
                context_type = future_to_context[future]
                try:
                    context_results = future.result()
                    results.extend(context_results)
                except Exception as e:
                    logger.error(f"Error testing {context_type.value} context: {e}")
        
        return results
    
    def _test_contexts_sequential(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        http_method: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> List[InjectionResult]:
        """Test contexts sequentially."""
        results = []
        
        for context_type, context in self.contexts.items():
            try:
                context_results = self._test_single_context(
                    context,
                    target_url,
                    parameter_name,
                    parameter_type,
                    parameter_value,
                    http_method,
                    headers,
                    cookies
                )
                results.extend(context_results)
            except Exception as e:
                logger.error(f"Error testing {context_type.value} context: {e}")
        
        return results
    
    def _test_single_context(
        self,
        context: InjectionContext,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        http_method: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> List[InjectionResult]:
        """
        Test all payloads for a single context.
        
        Returns list of successful injection results.
        """
        results = []
        context_type = context.get_context_type()
        
        logger.info(f"Testing {context_type.value} injection with {context.get_payload_count()} payloads")
        
        # Test each payload
        for payload in context.payloads:
            try:
                result = context.test_injection(
                    target_url=target_url,
                    parameter_name=parameter_name,
                    parameter_type=parameter_type,
                    parameter_value=parameter_value,
                    payload=payload,
                    http_method=http_method,
                    headers=headers,
                    cookies=cookies
                )
                
                if result.success:
                    logger.info(
                        f"✓ {context_type.value.upper()} injection successful! "
                        f"Payload: {payload[:50]}... Confidence: {result.confidence_score:.2f}"
                    )
                    results.append(result)
                    
                    # Attempt exploitation if successful
                    if self.config.get('enable_exploitation', True):
                        exploitation_data = context.attempt_exploitation(
                            target_url=target_url,
                            vulnerable_parameter=parameter_name,
                            parameter_type=parameter_type,
                            successful_payload=payload
                        )
                        
                        if exploitation_data:
                            result.exploited = True
                            result.extracted_data = exploitation_data
                            logger.info(f"✓ {context_type.value.upper()} exploitation successful!")
                
            except Exception as e:
                logger.debug(f"Payload test failed for {context_type.value}: {e}")
                continue
        
        logger.info(f"Completed {context_type.value} testing. Found {len(results)} vulnerabilities")
        
        return results
    
    def get_context_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about available contexts and payloads.
        
        Returns:
            Dictionary with context statistics
        """
        stats = {
            'enabled_contexts': len(self.contexts),
            'total_payloads': sum(ctx.get_payload_count() for ctx in self.contexts.values()),
            'contexts': {}
        }
        
        for context_type, context in self.contexts.items():
            stats['contexts'][context_type.value] = {
                'description': context.get_description(),
                'payload_count': context.get_payload_count(),
            }
        
        return stats
    
    def generate_attack_report(
        self,
        results: List[InjectionResult],
        target_url: str,
        parameter_name: str
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive attack report.
        
        Args:
            results: List of successful injection results
            target_url: Target URL that was tested
            parameter_name: Parameter that was tested
        
        Returns:
            Dictionary with attack report data
        """
        report = {
            'target_url': target_url,
            'parameter_name': parameter_name,
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(results),
            'contexts_affected': len(set(r.context_type for r in results)),
            'vulnerabilities_by_context': {},
            'high_confidence_findings': [],
            'exploited_vulnerabilities': [],
        }
        
        # Group results by context
        for result in results:
            context_name = result.context_type.value
            
            if context_name not in report['vulnerabilities_by_context']:
                report['vulnerabilities_by_context'][context_name] = []
            
            vuln_data = {
                'payload': result.attack_vector.payload,
                'confidence': result.confidence_score,
                'evidence': result.evidence,
                'exploited': result.exploited,
                'response_time': result.response_time,
            }
            
            report['vulnerabilities_by_context'][context_name].append(vuln_data)
            
            # Track high confidence findings
            if result.confidence_score >= 0.85:
                report['high_confidence_findings'].append({
                    'context': context_name,
                    'payload': result.attack_vector.payload,
                    'confidence': result.confidence_score,
                })
            
            # Track exploited vulnerabilities
            if result.exploited:
                report['exploited_vulnerabilities'].append({
                    'context': context_name,
                    'payload': result.attack_vector.payload,
                    'extracted_data': result.extracted_data,
                })
        
        return report

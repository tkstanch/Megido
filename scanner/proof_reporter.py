"""
Unified Proof Reporter for Exploit Plugins

This module provides a pluggable proof reporting system that standardizes
evidence collection across all exploit plugins. It captures:
- HTTP request/response traffic
- Exploitation logs and output
- Visual proofs (screenshots, GIFs)
- Callback/OOB evidence
- All proof data is stored in multiple formats (JSON, HTML, file, DB)

The ProofReporter is designed to be:
- Extensible: Easy to add new proof types
- Configurable: Visual proof can be enabled/disabled
- Pluggable: Works with any exploit plugin
- Database-integrated: Stores all evidence with vulnerability findings
"""

import json
import logging
import hashlib
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ProofData:
    """
    Container for all proof/evidence data collected during exploitation.
    """
    
    def __init__(self, vulnerability_type: str, vulnerability_id: Optional[int] = None):
        """
        Initialize proof data container.
        
        Args:
            vulnerability_type: Type of vulnerability (xss, rce, sqli, etc.)
            vulnerability_id: Optional database ID of the vulnerability
        """
        self.vulnerability_type = vulnerability_type
        self.vulnerability_id = vulnerability_id
        self.timestamp = datetime.now().isoformat()
        
        # HTTP traffic evidence
        self.http_requests: List[Dict[str, Any]] = []
        self.http_responses: List[Dict[str, Any]] = []
        
        # Exploitation output/logs
        self.logs: List[str] = []
        self.command_output: Optional[str] = None
        self.extracted_data: Optional[Union[str, Dict, List]] = None
        
        # Visual proof
        self.screenshots: List[Dict[str, Any]] = []
        self.visual_proof_path: Optional[str] = None
        self.visual_proof_type: Optional[str] = None
        
        # Callback/OOB evidence
        self.callback_evidence: List[Dict[str, Any]] = []
        self.oob_interactions: List[Dict[str, Any]] = []
        
        # Success indicators
        self.success = False
        self.verified = False
        self.confidence_score = 0.0
        
        # Additional metadata
        self.metadata: Dict[str, Any] = {}
    
    def add_http_request(self, method: str, url: str, headers: Optional[Dict] = None,
                        body: Optional[str] = None, timestamp: Optional[str] = None):
        """Add HTTP request to evidence."""
        self.http_requests.append({
            'method': method,
            'url': url,
            'headers': headers or {},
            'body': body or '',
            'timestamp': timestamp or datetime.now().isoformat()
        })
    
    def add_http_response(self, status_code: int, headers: Optional[Dict] = None,
                         body: Optional[str] = None, timestamp: Optional[str] = None):
        """Add HTTP response to evidence."""
        self.http_responses.append({
            'status_code': status_code,
            'headers': headers or {},
            'body': body or '',
            'timestamp': timestamp or datetime.now().isoformat()
        })
    
    def add_log(self, message: str, level: str = 'info'):
        """Add log message to evidence."""
        log_entry = f"[{datetime.now().isoformat()}] [{level.upper()}] {message}"
        self.logs.append(log_entry)
    
    def set_command_output(self, output: str):
        """Set command execution output (for RCE)."""
        self.command_output = output
    
    def set_extracted_data(self, data: Union[str, Dict, List]):
        """Set extracted/exfiltrated data."""
        self.extracted_data = data
    
    def add_screenshot(self, path: str, screenshot_type: str = 'screenshot',
                       size: Optional[int] = None, url: Optional[str] = None):
        """Add screenshot evidence."""
        self.screenshots.append({
            'path': path,
            'type': screenshot_type,
            'size': size,
            'url': url,
            'timestamp': datetime.now().isoformat()
        })
    
    def set_visual_proof(self, path: str, proof_type: str = 'screenshot'):
        """Set primary visual proof."""
        self.visual_proof_path = path
        self.visual_proof_type = proof_type
    
    def add_callback_evidence(self, callback_data: Dict[str, Any]):
        """Add callback/OOB evidence."""
        self.callback_evidence.append({
            **callback_data,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_oob_interaction(self, interaction: Dict[str, Any]):
        """Add out-of-band interaction evidence."""
        self.oob_interactions.append(interaction)
    
    def set_success(self, success: bool, verified: bool = False, confidence: float = 0.0):
        """Set success status and verification."""
        self.success = success
        self.verified = verified
        self.confidence_score = confidence
    
    def add_metadata(self, key: str, value: Any):
        """Add custom metadata."""
        self.metadata[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert proof data to dictionary."""
        return {
            'vulnerability_type': self.vulnerability_type,
            'vulnerability_id': self.vulnerability_id,
            'timestamp': self.timestamp,
            'http_requests': self.http_requests,
            'http_responses': self.http_responses,
            'logs': self.logs,
            'command_output': self.command_output,
            'extracted_data': self.extracted_data,
            'screenshots': self.screenshots,
            'visual_proof_path': self.visual_proof_path,
            'visual_proof_type': self.visual_proof_type,
            'callback_evidence': self.callback_evidence,
            'oob_interactions': self.oob_interactions,
            'success': self.success,
            'verified': self.verified,
            'confidence_score': self.confidence_score,
            'metadata': self.metadata
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert proof data to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


class ProofReporter:
    """
    Unified proof reporter for all exploit plugins.
    
    This class provides a standardized interface for collecting and storing
    exploitation evidence across all vulnerability types.
    """
    
    def __init__(self, output_dir: str = 'media/exploit_proofs',
                 enable_visual_proof: bool = True,
                 enable_http_capture: bool = True,
                 enable_callback_verification: bool = True):
        """
        Initialize the proof reporter.
        
        Args:
            output_dir: Directory for storing proof files
            enable_visual_proof: Enable visual proof capture (screenshots/GIFs)
            enable_http_capture: Enable HTTP traffic capture
            enable_callback_verification: Enable callback/OOB verification
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.enable_visual_proof = enable_visual_proof
        self.enable_http_capture = enable_http_capture
        self.enable_callback_verification = enable_callback_verification
        
        # Optional integrations
        self.visual_proof_capture = None
        self.oob_framework = None
        
        # Initialize integrations if enabled
        if enable_visual_proof:
            self._init_visual_proof_capture()
    
    def _init_visual_proof_capture(self):
        """Initialize visual proof capture module."""
        try:
            from scanner.visual_proof_capture import get_visual_proof_capture
            self.visual_proof_capture = get_visual_proof_capture(str(self.output_dir))
            if self.visual_proof_capture:
                logger.info("Visual proof capture enabled")
        except Exception as e:
            logger.warning(f"Could not initialize visual proof capture: {e}")
            self.enable_visual_proof = False
    
    def create_proof_data(self, vulnerability_type: str,
                         vulnerability_id: Optional[int] = None) -> ProofData:
        """
        Create a new proof data container.
        
        Args:
            vulnerability_type: Type of vulnerability
            vulnerability_id: Optional vulnerability database ID
            
        Returns:
            ProofData instance
        """
        return ProofData(vulnerability_type, vulnerability_id)
    
    def capture_visual_proof(self, proof_data: ProofData, url: str,
                            capture_type: str = 'screenshot',
                            duration: float = 3.0) -> bool:
        """
        Capture visual proof (screenshot or GIF).
        
        Args:
            proof_data: ProofData instance to update
            url: URL to capture
            capture_type: 'screenshot' or 'gif'
            duration: Capture duration for GIFs (seconds)
            
        Returns:
            True if capture was successful
        """
        if not self.enable_visual_proof or not self.visual_proof_capture:
            logger.debug("Visual proof capture disabled or unavailable")
            return False
        
        try:
            vuln_id = proof_data.vulnerability_id or 0
            result = self.visual_proof_capture.capture_exploit_proof(
                proof_data.vulnerability_type,
                vuln_id,
                url,
                capture_type=capture_type,
                duration=duration
            )
            
            if result:
                proof_data.add_screenshot(
                    path=result['path'],
                    screenshot_type=result['type'],
                    size=result.get('size'),
                    url=result.get('url')
                )
                proof_data.set_visual_proof(result['path'], result['type'])
                logger.info(f"Visual proof captured: {result['path']}")
                return True
            else:
                logger.warning("Visual proof capture returned no result")
                return False
                
        except Exception as e:
            logger.error(f"Failed to capture visual proof: {e}")
            return False
    
    def save_proof_json(self, proof_data: ProofData, filename: Optional[str] = None) -> Optional[str]:
        """
        Save proof data to JSON file.
        
        Args:
            proof_data: ProofData instance
            filename: Optional custom filename
            
        Returns:
            Path to saved file or None on failure
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                vuln_id = proof_data.vulnerability_id or 'unknown'
                filename = f"{proof_data.vulnerability_type}_{vuln_id}_{timestamp}_proof.json"
            
            file_path = self.output_dir / filename
            file_path.write_text(proof_data.to_json())
            
            logger.info(f"Proof data saved to JSON: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Failed to save proof JSON: {e}")
            return None
    
    def save_proof_html(self, proof_data: ProofData, filename: Optional[str] = None) -> Optional[str]:
        """
        Save proof data to HTML report.
        
        Args:
            proof_data: ProofData instance
            filename: Optional custom filename
            
        Returns:
            Path to saved file or None on failure
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                vuln_id = proof_data.vulnerability_id or 'unknown'
                filename = f"{proof_data.vulnerability_type}_{vuln_id}_{timestamp}_proof.html"
            
            html_content = self._generate_html_report(proof_data)
            file_path = self.output_dir / filename
            file_path.write_text(html_content)
            
            logger.info(f"Proof data saved to HTML: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Failed to save proof HTML: {e}")
            return None
    
    def _generate_html_report(self, proof_data: ProofData) -> str:
        """Generate HTML report from proof data."""
        data = proof_data.to_dict()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Exploitation Proof - {proof_data.vulnerability_type.upper()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; }}
        h2 {{ color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }}
        .success {{ color: #388e3c; font-weight: bold; }}
        .failed {{ color: #d32f2f; font-weight: bold; }}
        .verified {{ background: #4caf50; color: white; padding: 5px 10px; border-radius: 3px; }}
        .section {{ margin: 20px 0; }}
        pre {{ background: #f5f5f5; padding: 10px; border-left: 3px solid #1976d2; overflow-x: auto; }}
        .http-request {{ background: #e3f2fd; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .http-response {{ background: #fff3e0; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .screenshot {{ max-width: 100%; border: 1px solid #ddd; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #1976d2; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Exploitation Proof Report</h1>
        <div class="section">
            <h2>Summary</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Vulnerability Type</td><td>{proof_data.vulnerability_type.upper()}</td></tr>
                <tr><td>Vulnerability ID</td><td>{proof_data.vulnerability_id or 'N/A'}</td></tr>
                <tr><td>Timestamp</td><td>{proof_data.timestamp}</td></tr>
                <tr><td>Status</td><td><span class="{'success' if proof_data.success else 'failed'}">
                    {'SUCCESS' if proof_data.success else 'FAILED'}</span></td></tr>
                <tr><td>Verified</td><td>{'<span class="verified">VERIFIED</span>' if proof_data.verified else 'No'}</td></tr>
                <tr><td>Confidence Score</td><td>{proof_data.confidence_score:.2%}</td></tr>
            </table>
        </div>
"""
        
        # HTTP Traffic
        if data['http_requests'] or data['http_responses']:
            html += """
        <div class="section">
            <h2>HTTP Traffic</h2>
"""
            for i, req in enumerate(data['http_requests'], 1):
                html += f"""
            <div class="http-request">
                <strong>Request #{i}</strong><br>
                <strong>Method:</strong> {req.get('method', 'N/A')}<br>
                <strong>URL:</strong> {req.get('url', 'N/A')}<br>
                <strong>Headers:</strong><pre>{json.dumps(req.get('headers', {}), indent=2)}</pre>
                {'<strong>Body:</strong><pre>' + str(req.get('body', ''))[:500] + '</pre>' if req.get('body') else ''}
            </div>
"""
            
            for i, resp in enumerate(data['http_responses'], 1):
                html += f"""
            <div class="http-response">
                <strong>Response #{i}</strong><br>
                <strong>Status:</strong> {resp.get('status_code', 'N/A')}<br>
                <strong>Headers:</strong><pre>{json.dumps(resp.get('headers', {}), indent=2)}</pre>
                {'<strong>Body:</strong><pre>' + str(resp.get('body', ''))[:500] + '</pre>' if resp.get('body') else ''}
            </div>
"""
            html += "        </div>\n"
        
        # Exploitation Output
        if data['command_output'] or data['extracted_data']:
            html += """
        <div class="section">
            <h2>Exploitation Output</h2>
"""
            if data['command_output']:
                html += f"""
            <h3>Command Output</h3>
            <pre>{data['command_output']}</pre>
"""
            if data['extracted_data']:
                html += f"""
            <h3>Extracted Data</h3>
            <pre>{json.dumps(data['extracted_data'], indent=2) if isinstance(data['extracted_data'], (dict, list)) else data['extracted_data']}</pre>
"""
            html += "        </div>\n"
        
        # Visual Proof
        if data['screenshots']:
            html += """
        <div class="section">
            <h2>Visual Proof</h2>
"""
            for screenshot in data['screenshots']:
                html += f"""
            <div>
                <strong>Type:</strong> {screenshot['type']}<br>
                <strong>Path:</strong> {screenshot['path']}<br>
                {'<strong>URL:</strong> ' + screenshot['url'] + '<br>' if screenshot.get('url') else ''}
                <img src="../{screenshot['path']}" class="screenshot" alt="Screenshot">
            </div>
"""
            html += "        </div>\n"
        
        # Callback Evidence
        if data['callback_evidence'] or data['oob_interactions']:
            html += """
        <div class="section">
            <h2>Callback Evidence</h2>
"""
            for evidence in data['callback_evidence']:
                html += f"""
            <div style="margin: 10px 0;">
                <pre>{json.dumps(evidence, indent=2)}</pre>
            </div>
"""
            for interaction in data['oob_interactions']:
                html += f"""
            <div style="margin: 10px 0;">
                <strong>OOB Interaction:</strong>
                <pre>{json.dumps(interaction, indent=2)}</pre>
            </div>
"""
            html += "        </div>\n"
        
        # Logs
        if data['logs']:
            html += """
        <div class="section">
            <h2>Logs</h2>
            <pre>
"""
            for log in data['logs']:
                html += f"{log}\n"
            html += """            </pre>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def store_in_database(self, proof_data: ProofData,
                         vulnerability_model=None) -> bool:
        """
        Store proof data in database (attached to Vulnerability model).
        
        Args:
            proof_data: ProofData instance
            vulnerability_model: Optional Vulnerability model instance
            
        Returns:
            True if stored successfully
        """
        if not proof_data.vulnerability_id and not vulnerability_model:
            logger.warning("No vulnerability ID or model provided for database storage")
            return False
        
        try:
            # Import here to avoid circular dependency
            from scanner.models import Vulnerability
            
            # Get vulnerability instance
            if vulnerability_model:
                vuln = vulnerability_model
            else:
                vuln = Vulnerability.objects.get(id=proof_data.vulnerability_id)
            
            # Update vulnerability with proof data
            vuln.verified = proof_data.verified
            vuln.confidence_score = proof_data.confidence_score
            
            # Store proof data as JSON
            vuln.proof_of_impact = proof_data.to_json()
            
            # Store HTTP traffic
            if proof_data.http_requests or proof_data.http_responses:
                http_traffic = {
                    'requests': proof_data.http_requests,
                    'responses': proof_data.http_responses
                }
                # Store in evidence field or create new JSONField
                if hasattr(vuln, 'http_traffic'):
                    vuln.http_traffic = http_traffic
                else:
                    # Fallback to evidence field
                    vuln.evidence = json.dumps(http_traffic, indent=2)
            
            # Store visual proof path
            if proof_data.visual_proof_path:
                vuln.visual_proof_path = proof_data.visual_proof_path
                vuln.visual_proof_type = proof_data.visual_proof_type
            
            vuln.save()
            logger.info(f"Proof data stored in database for vulnerability {vuln.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store proof data in database: {e}")
            return False
    
    def report_proof(self, proof_data: ProofData,
                    save_json: bool = True,
                    save_html: bool = True,
                    store_db: bool = True,
                    vulnerability_model=None) -> Dict[str, Any]:
        """
        Complete proof reporting - save to all configured outputs.
        
        Args:
            proof_data: ProofData instance
            save_json: Save to JSON file
            save_html: Save to HTML report
            store_db: Store in database
            vulnerability_model: Optional Vulnerability model instance
            
        Returns:
            Dictionary with paths/status of saved outputs
        """
        results = {
            'success': True,
            'json_path': None,
            'html_path': None,
            'db_stored': False
        }
        
        try:
            # Save JSON
            if save_json:
                results['json_path'] = self.save_proof_json(proof_data)
            
            # Save HTML
            if save_html:
                results['html_path'] = self.save_proof_html(proof_data)
            
            # Store in database
            if store_db:
                results['db_stored'] = self.store_in_database(proof_data, vulnerability_model)
            
            logger.info(f"Proof reporting complete for {proof_data.vulnerability_type}")
            return results
            
        except Exception as e:
            logger.error(f"Proof reporting failed: {e}")
            results['success'] = False
            return results


# Global singleton instance
_global_reporter = None


def get_proof_reporter(output_dir: str = 'media/exploit_proofs',
                      enable_visual_proof: bool = True,
                      enable_http_capture: bool = True,
                      enable_callback_verification: bool = True) -> ProofReporter:
    """
    Get or create global ProofReporter instance.
    
    Args:
        output_dir: Output directory for proof files
        enable_visual_proof: Enable visual proof capture
        enable_http_capture: Enable HTTP traffic capture
        enable_callback_verification: Enable callback verification
        
    Returns:
        ProofReporter instance
    """
    global _global_reporter
    
    if _global_reporter is None:
        _global_reporter = ProofReporter(
            output_dir=output_dir,
            enable_visual_proof=enable_visual_proof,
            enable_http_capture=enable_http_capture,
            enable_callback_verification=enable_callback_verification
        )
    
    return _global_reporter

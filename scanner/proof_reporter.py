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
        self.visual_proof_status: str = 'not_attempted'
        self.visual_proof_warnings: List[Dict[str, Any]] = []
        
        # Callback/OOB evidence
        # callback_evidence: High-level callback verification results (e.g., XSS callback verified)
        # oob_interactions: Low-level out-of-band interaction details (e.g., HTTP request received, DNS query)
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
    
    def set_visual_proof(self, path: str, proof_type: str = 'screenshot', status: str = 'captured'):
        """
        Set the primary visual proof for this exploitation.
        
        Args:
            path: Path to visual proof file
            proof_type: Type of proof ('screenshot', 'gif', 'video')
            status: Status of visual proof capture
        """
        self.visual_proof_path = path
        self.visual_proof_type = proof_type
        self.visual_proof_status = status
    
    def set_visual_proof_status(self, status: str, warning: Optional[Dict[str, Any]] = None):
        """
        Set visual proof capture status with optional warning.
        
        Args:
            status: Status code ('captured', 'disabled', 'failed', 'not_supported', 'missing_dependencies', 'not_attempted')
            warning: Optional warning dictionary with details
        """
        self.visual_proof_status = status
        if warning:
            self.visual_proof_warnings.append(warning)
    
    def add_visual_proof_warning(self, message: str, severity: str = 'medium', 
                                 component: str = 'Visual Proof', recommendation: str = ''):
        """
        Add a warning about visual proof capture.
        
        Args:
            message: Warning message
            severity: Severity level ('low', 'medium', 'high')
            component: Component that generated the warning
            recommendation: Recommended action to resolve the issue
        """
        self.visual_proof_warnings.append({
            'category': 'visual_proof',
            'severity': severity,
            'component': component,
            'message': message,
            'recommendation': recommendation
        })
    
    def add_callback_evidence(self, callback_data: Dict[str, Any]):
        """
        Add high-level callback evidence (e.g., XSS callback verified, SSRF callback received).
        
        Use this for application-level callback verification results.
        """
        self.callback_evidence.append({
            **callback_data,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_oob_interaction(self, interaction: Dict[str, Any]):
        """
        Add low-level out-of-band interaction details (e.g., HTTP request, DNS query).
        
        Use this for protocol-level OOB interaction logs.
        Note: Timestamps should be included in the interaction dict by the caller.
        """
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
            'visual_proof_status': self.visual_proof_status,
            'visual_proof_warnings': self.visual_proof_warnings,
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
        self.visual_proof_warnings: List[Dict[str, Any]] = []
        
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
            else:
                # Dependencies are missing - collect warnings
                self._collect_visual_proof_warnings()
                self.enable_visual_proof = False
        except ImportError as e:
            logger.warning(
                f"Visual proof capture is enabled but required dependencies are missing: {e}\n"
                "Install dependencies with: pip install playwright selenium Pillow\n"
                "For Playwright, also run: playwright install chromium"
            )
            self._collect_visual_proof_warnings()
            self.enable_visual_proof = False
        except Exception as e:
            logger.warning(f"Could not initialize visual proof capture: {e}")
            self._collect_visual_proof_warnings()
            self.enable_visual_proof = False
    
    def _collect_visual_proof_warnings(self):
        """Collect warnings about visual proof setup issues."""
        try:
            from scanner.visual_proof_diagnostics import get_visual_proof_warnings
            warnings = get_visual_proof_warnings(str(self.output_dir))
            self.visual_proof_warnings = warnings
            if warnings:
                logger.warning(f"Visual proof diagnostics found {len(warnings)} issue(s)")
                for warning in warnings:
                    logger.warning(f"  - {warning.get('component')}: {warning.get('message')}")
        except Exception as e:
            logger.error(f"Failed to collect visual proof warnings: {e}")
            self.visual_proof_warnings = [{
                'category': 'visual_proof',
                'severity': 'high',
                'component': 'Visual Proof System',
                'message': 'Visual proof system initialization failed',
                'recommendation': 'Check logs for details and verify dependencies are installed'
            }]
    
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
        # Check if visual proof was explicitly disabled in config
        if not self.enable_visual_proof:
            # Determine if it was disabled due to missing dependencies or config
            if self.visual_proof_warnings:
                # Disabled because dependencies are missing
                proof_data.set_visual_proof_status('missing_dependencies')
                # Add warnings from diagnostics
                for warning in self.visual_proof_warnings:
                    proof_data.add_visual_proof_warning(
                        message=warning.get('message', 'Visual proof unavailable'),
                        severity=warning.get('severity', 'high'),
                        component=warning.get('component', 'Visual Proof'),
                        recommendation=warning.get('recommendation', '')
                    )
                logger.debug("Visual proof capture unavailable (missing dependencies)")
            else:
                # Explicitly disabled by configuration (no warnings)
                proof_data.set_visual_proof_status('disabled')
                logger.debug("Visual proof capture disabled by configuration")
            return False
        
        # Check if visual proof capture is unavailable due to missing dependencies
        if not self.visual_proof_capture:
            proof_data.set_visual_proof_status('missing_dependencies')
            # Add warnings from diagnostics
            for warning in self.visual_proof_warnings:
                proof_data.add_visual_proof_warning(
                    message=warning.get('message', 'Visual proof unavailable'),
                    severity=warning.get('severity', 'high'),
                    component=warning.get('component', 'Visual Proof'),
                    recommendation=warning.get('recommendation', '')
                )
            logger.debug("Visual proof capture unavailable (missing dependencies)")
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
                proof_data.set_visual_proof(result['path'], result['type'], status='captured')
                logger.info(f"Visual proof captured: {result['path']}")
                return True
            else:
                proof_data.set_visual_proof_status('failed')
                proof_data.add_visual_proof_warning(
                    message='Visual proof capture returned no result',
                    severity='medium',
                    component='Visual Proof Capture',
                    recommendation='Check browser automation logs for details'
                )
                logger.warning("Visual proof capture returned no result")
                return False
                
        except Exception as e:
            proof_data.set_visual_proof_status('failed')
            proof_data.add_visual_proof_warning(
                message=f'Visual proof capture failed: {str(e)}',
                severity='medium',
                component='Visual Proof Capture',
                recommendation='Check logs and verify browser automation is working'
            )
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
                # Sanitize vulnerability type to prevent path traversal
                vuln_type_safe = str(proof_data.vulnerability_type).replace('../', '').replace('..\\', '').replace('/', '_').replace('\\', '_')
                filename = f"{vuln_type_safe}_{vuln_id}_{timestamp}_proof.json"
            
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
                # Sanitize vulnerability type to prevent path traversal
                vuln_type_safe = str(proof_data.vulnerability_type).replace('../', '').replace('..\\', '').replace('/', '_').replace('\\', '_')
                filename = f"{vuln_type_safe}_{vuln_id}_{timestamp}_proof.html"
            
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
        import html
        
        data = proof_data.to_dict()
        
        # Escape all user-controlled values
        vuln_type_escaped = html.escape(str(proof_data.vulnerability_type).upper())
        timestamp_escaped = html.escape(str(proof_data.timestamp))
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Exploitation Proof - {vuln_type_escaped}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; }}
        h2 {{ color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }}
        .success {{ color: #388e3c; font-weight: bold; }}
        .failed {{ color: #d32f2f; font-weight: bold; }}
        .verified {{ background: #4caf50; color: white; padding: 5px 10px; border-radius: 3px; }}
        .section {{ margin: 20px 0; }}
        pre {{ background: #f5f5f5; padding: 10px; border-left: 3px solid #1976d2; overflow-x: auto; word-wrap: break-word; white-space: pre-wrap; }}
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
                <tr><td>Vulnerability Type</td><td>{vuln_type_escaped}</td></tr>
                <tr><td>Vulnerability ID</td><td>{html.escape(str(proof_data.vulnerability_id or 'N/A'))}</td></tr>
                <tr><td>Timestamp</td><td>{timestamp_escaped}</td></tr>
                <tr><td>Status</td><td><span class="{'success' if proof_data.success else 'failed'}">
                    {'SUCCESS' if proof_data.success else 'FAILED'}</span></td></tr>
                <tr><td>Verified</td><td>{'<span class="verified">VERIFIED</span>' if proof_data.verified else 'No'}</td></tr>
                <tr><td>Confidence Score</td><td>{proof_data.confidence_score:.2%}</td></tr>
            </table>
        </div>
"""
        
        # HTTP Traffic
        if data['http_requests'] or data['http_responses']:
            html_content += """
        <div class="section">
            <h2>HTTP Traffic</h2>
"""
            for i, req in enumerate(data['http_requests'], 1):
                html_content += f"""
            <div class="http-request">
                <strong>Request #{i}</strong><br>
                <strong>Method:</strong> {html.escape(str(req.get('method', 'N/A')))}<br>
                <strong>URL:</strong> {html.escape(str(req.get('url', 'N/A')))}<br>
                <strong>Headers:</strong><pre>{html.escape(json.dumps(req.get('headers', {}), indent=2))}</pre>
                {'<strong>Body:</strong><pre>' + html.escape(str(req.get('body', ''))[:500]) + '</pre>' if req.get('body') else ''}
            </div>
"""
            
            for i, resp in enumerate(data['http_responses'], 1):
                html_content += f"""
            <div class="http-response">
                <strong>Response #{i}</strong><br>
                <strong>Status:</strong> {html.escape(str(resp.get('status_code', 'N/A')))}<br>
                <strong>Headers:</strong><pre>{html.escape(json.dumps(resp.get('headers', {}), indent=2))}</pre>
                {'<strong>Body:</strong><pre>' + html.escape(str(resp.get('body', ''))[:500]) + '</pre>' if resp.get('body') else ''}
            </div>
"""
            html_content += "        </div>\n"
        
        # Exploitation Output
        if data['command_output'] or data['extracted_data']:
            html_content += """
        <div class="section">
            <h2>Exploitation Output</h2>
"""
            if data['command_output']:
                html_content += f"""
            <h3>Command Output</h3>
            <pre>{html.escape(str(data['command_output']))}</pre>
"""
            if data['extracted_data']:
                extracted_str = json.dumps(data['extracted_data'], indent=2) if isinstance(data['extracted_data'], (dict, list)) else str(data['extracted_data'])
                html_content += f"""
            <h3>Extracted Data</h3>
            <pre>{html.escape(extracted_str)}</pre>
"""
            html_content += "        </div>\n"
        
        # Visual Proof
        if data['screenshots']:
            html_content += """
        <div class="section">
            <h2>Visual Proof</h2>
"""
            for screenshot in data['screenshots']:
                # Validate and sanitize screenshot path
                screenshot_path = str(screenshot['path'])
                # Remove any path traversal attempts
                screenshot_path = screenshot_path.replace('../', '').replace('..\\', '')
                screenshot_path_escaped = html.escape(screenshot_path)
                
                html_content += f"""
            <div>
                <strong>Type:</strong> {html.escape(str(screenshot['type']))}<br>
                <strong>Path:</strong> {screenshot_path_escaped}<br>
                {'<strong>URL:</strong> ' + html.escape(str(screenshot['url'])) + '<br>' if screenshot.get('url') else ''}
                <img src="../{screenshot_path_escaped}" class="screenshot" alt="Screenshot">
            </div>
"""
            html_content += "        </div>\n"
        
        # Callback Evidence
        if data['callback_evidence'] or data['oob_interactions']:
            html_content += """
        <div class="section">
            <h2>Callback Evidence</h2>
"""
            for evidence in data['callback_evidence']:
                html_content += f"""
            <div style="margin: 10px 0;">
                <pre>{html.escape(json.dumps(evidence, indent=2))}</pre>
            </div>
"""
            for interaction in data['oob_interactions']:
                html_content += f"""
            <div style="margin: 10px 0;">
                <strong>OOB Interaction:</strong>
                <pre>{html.escape(json.dumps(interaction, indent=2))}</pre>
            </div>
"""
            html_content += "        </div>\n"
        
        # Logs
        if data['logs']:
            html_content += """
        <div class="section">
            <h2>Logs</h2>
            <pre>
"""
            for log in data['logs']:
                html_content += html.escape(str(log)) + "\n"
            html_content += """            </pre>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        return html_content

    def generate_poc_walkthrough_html(self, poc_steps: list,
                                      vuln_type: str = '',
                                      poc_summary: str = '',
                                      remediation: str = '') -> str:
        """
        Generate a rich, self-contained HTML PoC walkthrough report.

        Args:
            poc_steps: List of step dicts with keys: step_number, title,
                       description, request, response_snippet,
                       screenshot_path, gif_path, verified, html_evidence
            vuln_type: Vulnerability type label (e.g. 'XSS')
            poc_summary: Short summary of the exploitation result
            remediation: Remediation advice text

        Returns:
            Self-contained HTML string for the full step-by-step PoC report
        """
        import html as _html
        import json as _json
        from datetime import datetime

        vuln_escaped = _html.escape(str(vuln_type).upper())
        summary_escaped = _html.escape(str(poc_summary))
        remediation_escaped = _html.escape(str(remediation)).replace('\n', '<br>')
        ts = _html.escape(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
        step_count = len(poc_steps)

        poc_badge = 'Full PoC Available' if step_count >= 3 else ('Partial PoC' if step_count >= 1 else 'No PoC')
        badge_color = '#388e3c' if step_count >= 3 else ('#f57c00' if step_count >= 1 else '#9e9e9e')

        steps_html = ''
        for step in poc_steps:
            sn = _html.escape(str(step.get('step_number', '')))
            title = _html.escape(str(step.get('title', '')))
            desc = _html.escape(str(step.get('description', '')))
            req = _html.escape(str(step.get('request', '')))
            resp = _html.escape(str(step.get('response_snippet', '')))
            screenshot = _html.escape(str(step.get('screenshot_path', '')))
            gif = _html.escape(str(step.get('gif_path', '')))
            html_ev = str(step.get('html_evidence', ''))
            verified_badge = '<span class="verified-badge">✓ Verified</span>' if step.get('verified') else ''

            screenshot_tag = (
                f'<div class="media-box"><img src="{screenshot}" alt="Step {sn} screenshot" '
                f'class="step-img"></div>' if screenshot else ''
            )
            gif_tag = (
                f'<div class="media-box"><img src="{gif}" alt="Step {sn} animation" '
                f'class="step-img"></div>' if gif else ''
            )
            req_block = (
                f'<details><summary>HTTP Request</summary>'
                f'<pre class="code-block">{req}</pre></details>' if req else ''
            )
            resp_block = (
                f'<details><summary>Response Snippet</summary>'
                f'<pre class="code-block">{resp}</pre></details>' if resp else ''
            )
            html_ev_block = (
                f'<details><summary>HTML Evidence</summary>'
                f'<div class="html-ev">{html_ev}</div></details>' if html_ev else ''
            )

            steps_html += f"""
        <div class="step-card">
            <div class="step-header">
                <span class="step-number">Step {sn}</span>
                <span class="step-title">{title}</span>
                {verified_badge}
            </div>
            <p class="step-desc">{desc}</p>
            {screenshot_tag}
            {gif_tag}
            {req_block}
            {resp_block}
            {html_ev_block}
        </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PoC Report - {vuln_escaped}</title>
    <style>
        body{{font-family:Arial,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}}
        .container{{max-width:960px;margin:0 auto;padding:24px}}
        h1{{color:#f0883e;border-bottom:2px solid #f0883e;padding-bottom:8px}}
        h2{{color:#58a6ff;margin-top:32px}}
        .badge{{display:inline-block;background:{badge_color};color:#fff;
                padding:4px 12px;border-radius:12px;font-size:0.85rem;margin-bottom:16px}}
        .meta-table{{width:100%;border-collapse:collapse;margin:16px 0}}
        .meta-table th,.meta-table td{{border:1px solid #30363d;padding:8px 12px;text-align:left}}
        .meta-table th{{background:#161b22;color:#58a6ff}}
        .step-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:16px;margin:16px 0}}
        .step-header{{display:flex;align-items:center;gap:12px;margin-bottom:8px}}
        .step-number{{background:#388e3c;color:#fff;border-radius:50%;
                      width:28px;height:28px;display:flex;align-items:center;
                      justify-content:center;font-weight:bold;font-size:0.9rem;flex-shrink:0}}
        .step-title{{font-weight:bold;font-size:1.05rem;color:#f0f6fc}}
        .verified-badge{{background:#388e3c;color:#fff;padding:2px 8px;
                          border-radius:8px;font-size:0.78rem}}
        .step-desc{{color:#8b949e;margin:4px 0 12px 0}}
        .media-box{{margin:12px 0}}
        .step-img{{max-width:100%;border:1px solid #30363d;border-radius:4px}}
        details{{margin:8px 0}}
        summary{{cursor:pointer;color:#58a6ff;font-weight:bold;padding:4px 0}}
        .code-block{{background:#0d1117;border:1px solid #30363d;border-radius:4px;
                     padding:12px;overflow-x:auto;white-space:pre-wrap;font-size:0.85rem;
                     color:#e6edf3}}
        .html-ev{{background:#0d1117;border:1px solid #30363d;border-radius:4px;
                  padding:12px;overflow-x:auto;font-size:0.85rem}}
        .remediation{{background:#161b22;border-left:4px solid #f0883e;
                      padding:12px 16px;border-radius:0 4px 4px 0;margin:16px 0}}
        .summary-box{{background:#161b22;border:1px solid #388e3c;border-radius:8px;
                      padding:12px 16px;margin:16px 0;color:#c9d1d9}}
    </style>
</head>
<body>
<div class="container">
    <h1>🔒 Proof of Concept Report: {vuln_escaped}</h1>
    <span class="badge">{_html.escape(poc_badge)}</span>
    <table class="meta-table">
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Vulnerability Type</td><td>{vuln_escaped}</td></tr>
        <tr><td>Generated</td><td>{ts}</td></tr>
        <tr><td>Total Steps</td><td>{step_count}</td></tr>
        <tr><td>PoC Status</td><td>{_html.escape(poc_badge)}</td></tr>
    </table>
    {"<div class='summary-box'><strong>Summary:</strong> " + summary_escaped + "</div>" if poc_summary else ""}
    <h2>Exploitation Steps</h2>
    {steps_html if steps_html else "<p>No steps recorded.</p>"}
    {"<h2>Remediation</h2><div class='remediation'>" + remediation_escaped + "</div>" if remediation else ""}
</div>
</body>
</html>
"""

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
                vuln.visual_proof_status = proof_data.visual_proof_status
            else:
                # Set status even if no visual proof was captured
                vuln.visual_proof_status = proof_data.visual_proof_status
            
            vuln.save()
            logger.info(f"Proof data stored in database for vulnerability {vuln.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store proof data in database: {e}")
            return False
    
    def generate_report_template(self, vulnerability_type: str = '', affected_url: str = '') -> str:
        """
        Generate a structured Markdown report template for researchers to fill in.

        Args:
            vulnerability_type: Type of vulnerability (e.g., 'xss', 'sqli')
            affected_url: Affected URL for the report header

        Returns:
            Markdown string containing the structured report template
        """
        vuln_type_display = vulnerability_type.upper() if vulnerability_type else '[VULNERABILITY TYPE]'
        url_display = affected_url if affected_url else '[AFFECTED URL]'
        discovery_date = datetime.now().strftime('%Y-%m-%d')

        return f"""# Security Vulnerability Report — {vuln_type_display}

---

## 1. Vulnerability Summary

| Field | Value |
|---|---|
| **Type** | {vuln_type_display} |
| **Severity** | [TODO: Fill in — Critical / High / Medium / Low] |
| **CVSS v3.1 Score** | [TODO: Fill in — e.g., 8.1 (High)] |
| **CVSS Vector** | [TODO: Fill in — e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N] |
| **Affected URL** | {url_display} |
| **Discovery Date** | {discovery_date} |
| **Reported Date** | {discovery_date} |
| **Status** | Open |

---

## 2. Description

[TODO: Fill in — Provide a clear, concise description of the vulnerability. Explain what
the issue is, why it exists, and what makes it exploitable. Avoid jargon where possible.]

---

## 3. Steps to Reproduce

> ⚠️ Only perform these steps on systems you are **explicitly authorized** to test.

1. [TODO: Fill in — Step 1 (e.g., Navigate to the affected URL)]
2. [TODO: Fill in — Step 2 (e.g., Insert the payload into the vulnerable parameter)]
3. [TODO: Fill in — Step 3 (e.g., Observe the response / trigger condition)]
4. [TODO: Fill in — Add more steps as needed]

---

## 4. Impact Analysis

[TODO: Fill in — Describe the business and technical impact. Consider:
- What data or functionality can an attacker access or modify?
- Are there privilege escalation opportunities?
- What is the blast radius (number of users affected, data categories at risk)?
- Is this exploitable without authentication?]

---

## 5. Evidence

### 5.1 HTTP Request

```http
[TODO: Fill in — Paste the raw HTTP request here]
```

### 5.2 HTTP Response

```http
[TODO: Fill in — Paste the relevant HTTP response here (truncate large bodies)]
```

### 5.3 Screenshots / Proof of Concept

[TODO: Fill in — Attach screenshots or a screen recording demonstrating exploitation.
Use filenames such as `poc_step1.png`, `poc_step2.png`, etc.]

### 5.4 Proof of Concept Code

```python
# [TODO: Fill in — Optional PoC script (Python, bash, etc.) if applicable]
```

---

## 6. Remediation Recommendations

[TODO: Fill in — Provide actionable recommendations. Examples:
- Implement input validation / output encoding
- Apply parameterized queries
- Add CSRF tokens to state-changing forms
- Set security-relevant HTTP headers (CSP, X-Frame-Options, etc.)
- Reference OWASP cheat sheets where relevant]

---

## 7. References

- [TODO: CWE Link — e.g., https://cwe.mitre.org/data/definitions/79.html]
- [TODO: OWASP Link — e.g., https://owasp.org/www-community/attacks/xss/]
- [TODO: Add any additional references (CVEs, advisories, writeups)]

---

## 8. Timeline

| Event | Date |
|---|---|
| Discovery | {discovery_date} |
| Report Drafted | {discovery_date} |
| Vendor Notified | [TODO: Fill in] |
| Vendor Response | [TODO: Fill in] |
| Fix Deployed | [TODO: Fill in] |
| Disclosure | [TODO: Fill in] |

---

*This report was generated by Megido Security Scanner. All testing was performed
on authorized systems only. Ensure responsible disclosure practices are followed.*
"""

    def generate_filled_template(self, proof_data: 'ProofData') -> str:
        """
        Generate a Markdown report template pre-populated with actual scan data.

        Auto-fills fields available in *proof_data* and leaves ``[TODO: Fill in]``
        markers for sections that require manual researcher input.

        Args:
            proof_data: ProofData instance containing scan evidence

        Returns:
            Markdown string with auto-filled and TODO-marked sections
        """
        vuln_type = str(proof_data.vulnerability_type).upper() if proof_data.vulnerability_type else '[VULNERABILITY TYPE]'
        target_url = proof_data.metadata.get('target_url', '[AFFECTED URL]')
        timestamp = proof_data.timestamp or datetime.now().isoformat()
        try:
            discovery_date = datetime.fromisoformat(timestamp).strftime('%Y-%m-%d')
        except (ValueError, TypeError):
            discovery_date = datetime.now().strftime('%Y-%m-%d')
        confidence_pct = f"{proof_data.confidence_score * 100:.0f}%" if proof_data.confidence_score else 'N/A'
        verified_label = 'Yes (exploitation confirmed)' if proof_data.verified else 'No (detection only)'

        # Build HTTP request section
        http_req_section = '[TODO: Fill in — Paste the raw HTTP request here]'
        if proof_data.http_requests:
            req = proof_data.http_requests[0]
            header_lines = '\n'.join(f"{k}: {v}" for k, v in (req.get('headers') or {}).items())
            body_section = f"\n\n{req.get('body')}" if req.get('body') else ''
            http_req_section = (
                f"{req.get('method', 'GET')} {req.get('url', target_url)} HTTP/1.1\n"
                f"{header_lines}"
                f"{body_section}"
            )

        # Build HTTP response section
        http_resp_section = '[TODO: Fill in — Paste the relevant HTTP response here]'
        if proof_data.http_responses:
            resp = proof_data.http_responses[0]
            resp_header_lines = '\n'.join(f"{k}: {v}" for k, v in (resp.get('headers') or {}).items())
            resp_body = str(resp.get('body') or '')[:500]
            base_resp = f"HTTP/1.1 {resp.get('status_code', '')}\n{resp_header_lines}"
            http_resp_section = base_resp + (f"\n\n{resp_body}" if resp_body else '')

        # Build evidence / command output section
        extra_evidence = ''
        if proof_data.command_output:
            extra_evidence += f"\n### 5.5 Command Output\n\n```\n{proof_data.command_output}\n```\n"
        if proof_data.extracted_data:
            extra_evidence += f"\n### 5.6 Extracted Data\n\n```\n{proof_data.extracted_data}\n```\n"

        return f"""# Security Vulnerability Report — {vuln_type}

---

## 1. Vulnerability Summary

| Field | Value |
|---|---|
| **Type** | {vuln_type} |
| **Severity** | [TODO: Fill in — Critical / High / Medium / Low] |
| **CVSS v3.1 Score** | [TODO: Fill in — CVSS score with justification] |
| **CVSS Vector** | [TODO: Fill in] |
| **Affected URL** | {target_url} |
| **Confidence** | {confidence_pct} |
| **Verified** | {verified_label} |
| **Discovery Date** | {discovery_date} |
| **Reported Date** | {discovery_date} |
| **Status** | Open |

---

## 2. Description

[TODO: Fill in — Describe the vulnerability in detail. The scanner detected a
**{vuln_type}** issue at `{target_url}`. Explain the root cause and exploit conditions.]

---

## 3. Steps to Reproduce

> ⚠️ Only perform these steps on systems you are **explicitly authorized** to test.

1. [TODO: Fill in — Step 1]
2. [TODO: Fill in — Step 2]
3. [TODO: Fill in — Step 3]

---

## 4. Impact Analysis

[TODO: Fill in — Describe the business and technical impact of this {vuln_type}
vulnerability. Consider data confidentiality, integrity, and availability impact.]

---

## 5. Evidence

### 5.1 HTTP Request

```http
{http_req_section}
```

### 5.2 HTTP Response

```http
{http_resp_section}
```

### 5.3 Screenshots / Proof of Concept

[TODO: Fill in — Attach screenshots demonstrating exploitation.]{extra_evidence}

### 5.4 Proof of Concept Code

```python
# [TODO: Fill in — Optional PoC script if applicable]
```

---

## 6. Remediation Recommendations

[TODO: Fill in — Provide actionable remediation steps specific to this {vuln_type}
vulnerability. Reference OWASP or vendor documentation where applicable.]

---

## 7. References

- [TODO: CWE Link]
- [TODO: OWASP Link]

---

## 8. Timeline

| Event | Date |
|---|---|
| Discovery | {discovery_date} |
| Report Drafted | {discovery_date} |
| Vendor Notified | [TODO: Fill in] |
| Vendor Response | [TODO: Fill in] |
| Fix Deployed | [TODO: Fill in] |
| Disclosure | [TODO: Fill in] |

---

**Scan Metadata**

| Field | Value |
|---|---|
| Scan Timestamp | {timestamp} |
| Confidence Score | {confidence_pct} |
| Verified | {verified_label} |

*This report was generated by Megido Security Scanner. All testing was performed
on authorized systems only. Ensure responsible disclosure practices are followed.*
"""

    def save_report_template(
        self,
        proof_data: Optional['ProofData'] = None,
        vulnerability_type: str = '',
        affected_url: str = '',
        filename: Optional[str] = None,
    ) -> Optional[str]:
        """
        Save a Markdown report template to the proof output directory.

        When *proof_data* is provided the filled template is generated;
        otherwise a blank template is saved.

        Args:
            proof_data: Optional ProofData instance for a pre-filled template
            vulnerability_type: Vulnerability type (used for blank template)
            affected_url: Affected URL (used for blank template)
            filename: Optional custom filename (`.md` extension added if absent)

        Returns:
            Path to the saved Markdown file, or ``None`` on failure
        """
        try:
            if proof_data is not None:
                content = self.generate_filled_template(proof_data)
                vuln_type_safe = str(proof_data.vulnerability_type).replace('../', '').replace('..\\', '').replace('/', '_').replace('\\', '_')
            else:
                content = self.generate_report_template(vulnerability_type, affected_url)
                vuln_type_safe = str(vulnerability_type).replace('../', '').replace('..\\', '').replace('/', '_').replace('\\', '_') or 'generic'

            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                vuln_id = proof_data.vulnerability_id if proof_data else 'unknown'
                filename = f"{vuln_type_safe}_{vuln_id}_{timestamp}_report_template.md"
            elif not filename.endswith('.md'):
                filename = filename + '.md'

            file_path = self.output_dir / filename
            file_path.write_text(content, encoding='utf-8')

            logger.info(f"Report template saved: {file_path}")
            return str(file_path)

        except Exception as e:
            logger.error(f"Failed to save report template: {e}")
            return None

    def report_proof(self, proof_data: ProofData,
                    save_json: bool = True,
                    save_html: bool = True,
                    store_db: bool = True,
                    vulnerability_model=None,
                    save_template: bool = False) -> Dict[str, Any]:
        """
        Complete proof reporting - save to all configured outputs.
        
        Args:
            proof_data: ProofData instance
            save_json: Save to JSON file
            save_html: Save to HTML report
            store_db: Store in database
            vulnerability_model: Optional Vulnerability model instance
            save_template: Save a Markdown report template alongside other outputs
            
        Returns:
            Dictionary with paths/status of saved outputs
        """
        results = {
            'success': True,
            'json_path': None,
            'html_path': None,
            'template_path': None,
            'db_stored': False
        }
        
        try:
            # Save JSON
            if save_json:
                results['json_path'] = self.save_proof_json(proof_data)
            
            # Save HTML
            if save_html:
                results['html_path'] = self.save_proof_html(proof_data)

            # Save Markdown report template
            if save_template:
                results['template_path'] = self.save_report_template(proof_data)
            
            # Store in database
            if store_db:
                results['db_stored'] = self.store_in_database(proof_data, vulnerability_model)
            
            logger.info(f"Proof reporting complete for {proof_data.vulnerability_type}")
            return results
            
        except Exception as e:
            logger.error(f"Proof reporting failed: {e}")
            results['success'] = False
            return results

    def generate_detection_proof(
        self,
        vulnerability_type: str,
        url: str,
        evidence: str,
        confidence: float,
        http_traffic: Optional[Dict[str, Any]] = None,
        vulnerability_id: Optional[int] = None,
    ) -> ProofData:
        """
        Build a :class:`ProofData` object from detection-phase evidence only.

        Unlike :meth:`create_proof_data` (which requires a full exploitation
        cycle), this method produces a PoC artifact purely from the data
        collected by a detection plugin — no exploitation is needed.

        The resulting ``ProofData`` will:
        * have ``success=False`` and ``verified=False`` (detection-only)
        * carry the HTTP request/response pair from *http_traffic* (if provided)
        * carry the detection *evidence* as a log entry

        Args:
            vulnerability_type: Slug identifying the vulnerability (e.g. ``'xss'``).
            url: Target URL where the vulnerability was found.
            evidence: Human-readable detection evidence string.
            confidence: Detection confidence in the range ``[0.0, 1.0]``.
            http_traffic: Optional dict with ``'request'`` and/or ``'response'``
                keys containing the HTTP pair captured during detection.
            vulnerability_id: Optional database ID of the parent
                :class:`~scanner.models.Vulnerability`.

        Returns:
            A populated :class:`ProofData` instance.
        """
        proof_data = self.create_proof_data(vulnerability_type, vulnerability_id)
        proof_data.set_success(success=False, verified=False, confidence=confidence)

        # Attach detection HTTP traffic when available
        if http_traffic and isinstance(http_traffic, dict):
            req = http_traffic.get('request', {})
            if req and isinstance(req, dict):
                proof_data.add_http_request(
                    method=req.get('method', 'GET'),
                    url=req.get('url', url),
                    headers=req.get('headers', {}),
                    body=req.get('body', ''),
                )
            resp = http_traffic.get('response', {})
            if resp and isinstance(resp, dict):
                proof_data.add_http_response(
                    status_code=resp.get('status_code', 0),
                    headers=resp.get('headers', {}),
                    body=resp.get('body', ''),
                )

        if evidence:
            proof_data.add_log(f"Detection evidence: {evidence}", 'info')

        proof_data.add_metadata('detection_only', True)
        proof_data.add_metadata('target_url', url)
        proof_data.add_metadata('vulnerability_type', vulnerability_type)

        return proof_data


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

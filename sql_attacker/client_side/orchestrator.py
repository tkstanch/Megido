"""
Client-Side Scan Orchestrator

Coordinates all client-side security scans including browser automation,
static JavaScript analysis, HTTP Parameter Pollution, and privacy analysis.
"""

import logging
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

from .browser_automation import BrowserAutomationWorker, BrowserFinding
from .static_scanner import JavaScriptStaticScanner, StaticFinding
from .hpp_detector import HTTPParameterPollutionDetector, HPPFinding
from .privacy_analyzer import PrivacyStorageAnalyzer, PrivacyFinding

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Types of client-side scans"""
    BROWSER_AUTOMATION = "browser_automation"
    STATIC_JAVASCRIPT = "static_javascript"
    HPP_DETECTION = "hpp_detection"
    PRIVACY_ANALYSIS = "privacy_analysis"
    ALL = "all"


@dataclass
class ScanConfiguration:
    """Configuration for client-side scans"""
    scan_types: List[str]
    target_url: Optional[str] = None
    javascript_files: Optional[List[str]] = None
    javascript_code: Optional[str] = None
    use_playwright: bool = True
    headless: bool = True
    timeout: int = 30000
    verify_ssl: bool = True
    follow_redirects: bool = True
    scan_flash_lso: bool = False
    form_selector: Optional[str] = None
    test_params: Optional[Dict[str, str]] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResults:
    """Results from all client-side scans"""
    scan_id: str
    start_time: str
    end_time: Optional[str]
    configuration: ScanConfiguration
    browser_findings: List[BrowserFinding]
    static_findings: List[StaticFinding]
    hpp_findings: List[HPPFinding]
    privacy_findings: List[PrivacyFinding]
    summary: Dict[str, Any]
    status: str = "pending"
    error: Optional[str] = None

    def to_dict(self):
        return {
            'scan_id': self.scan_id,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'configuration': self.configuration.to_dict(),
            'browser_findings': [f.to_dict() for f in self.browser_findings],
            'static_findings': [f.to_dict() for f in self.static_findings],
            'hpp_findings': [f.to_dict() for f in self.hpp_findings],
            'privacy_findings': [f.to_dict() for f in self.privacy_findings],
            'summary': self.summary,
            'status': self.status,
            'error': self.error,
        }


class ClientSideScanOrchestrator:
    """
    Orchestrates all client-side security scans
    """
    
    def __init__(self):
        """Initialize the orchestrator"""
        self.current_scan: Optional[ScanResults] = None
    
    def scan(self, config: ScanConfiguration) -> ScanResults:
        """
        Execute client-side scans based on configuration
        
        Args:
            config: Scan configuration
            
        Returns:
            Scan results
        """
        # Initialize results
        scan_id = f"cs_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now().isoformat()
        
        results = ScanResults(
            scan_id=scan_id,
            start_time=start_time,
            end_time=None,
            configuration=config,
            browser_findings=[],
            static_findings=[],
            hpp_findings=[],
            privacy_findings=[],
            summary={},
            status="running"
        )
        
        self.current_scan = results
        
        try:
            # Run requested scans
            scan_types = config.scan_types
            
            if ScanType.ALL.value in scan_types:
                scan_types = [
                    ScanType.BROWSER_AUTOMATION.value,
                    ScanType.STATIC_JAVASCRIPT.value,
                    ScanType.HPP_DETECTION.value,
                    ScanType.PRIVACY_ANALYSIS.value,
                ]
            
            if ScanType.BROWSER_AUTOMATION.value in scan_types:
                results.browser_findings = self._run_browser_automation(config)
            
            if ScanType.STATIC_JAVASCRIPT.value in scan_types:
                results.static_findings = self._run_static_analysis(config)
            
            if ScanType.HPP_DETECTION.value in scan_types:
                results.hpp_findings = self._run_hpp_detection(config)
            
            if ScanType.PRIVACY_ANALYSIS.value in scan_types:
                results.privacy_findings = self._run_privacy_analysis(config)
            
            # Generate summary
            results.summary = self._generate_summary(results)
            results.status = "completed"
            
        except Exception as e:
            logger.error(f"Error during client-side scan: {e}")
            results.status = "failed"
            results.error = str(e)
        
        finally:
            results.end_time = datetime.now().isoformat()
        
        return results
    
    def _run_browser_automation(self, config: ScanConfiguration) -> List[BrowserFinding]:
        """Run browser automation scan"""
        logger.info("Starting browser automation scan...")
        
        if not config.target_url:
            logger.warning("No target URL provided for browser automation")
            return []
        
        try:
            worker = BrowserAutomationWorker(
                use_playwright=config.use_playwright,
                headless=config.headless,
                timeout=config.timeout
            )
            
            findings = worker.scan_form(config.target_url, config.form_selector)
            
            logger.info(f"Browser automation scan complete: {len(findings)} findings")
            return findings
            
        except Exception as e:
            logger.error(f"Browser automation scan failed: {e}")
            return []
    
    def _run_static_analysis(self, config: ScanConfiguration) -> List[StaticFinding]:
        """Run static JavaScript analysis"""
        logger.info("Starting static JavaScript analysis...")
        
        scanner = JavaScriptStaticScanner()
        all_findings = []
        
        try:
            # Scan provided JavaScript code
            if config.javascript_code:
                findings = scanner.scan_code(config.javascript_code)
                all_findings.extend(findings)
            
            # Scan provided JavaScript files
            if config.javascript_files:
                for file_path in config.javascript_files:
                    findings = scanner.scan_file(file_path)
                    all_findings.extend(findings)
            
            logger.info(f"Static analysis complete: {len(all_findings)} findings")
            return all_findings
            
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            return []
    
    def _run_hpp_detection(self, config: ScanConfiguration) -> List[HPPFinding]:
        """Run HTTP Parameter Pollution detection"""
        logger.info("Starting HPP detection...")
        
        if not config.target_url:
            logger.warning("No target URL provided for HPP detection")
            return []
        
        try:
            detector = HTTPParameterPollutionDetector(
                timeout=config.timeout // 1000,  # Convert to seconds
                verify_ssl=config.verify_ssl,
                follow_redirects=config.follow_redirects
            )
            
            findings = detector.scan_url(config.target_url, config.test_params)
            
            logger.info(f"HPP detection complete: {len(findings)} findings")
            return findings
            
        except Exception as e:
            logger.error(f"HPP detection failed: {e}")
            return []
    
    def _run_privacy_analysis(self, config: ScanConfiguration) -> List[PrivacyFinding]:
        """Run privacy and storage analysis"""
        logger.info("Starting privacy analysis...")
        
        if not config.target_url:
            logger.warning("No target URL provided for privacy analysis")
            return []
        
        try:
            # Get storage data from browser
            worker = BrowserAutomationWorker(
                use_playwright=config.use_playwright,
                headless=config.headless,
                timeout=config.timeout
            )
            
            if not worker.initialize_browser():
                logger.error("Failed to initialize browser for privacy analysis")
                return []
            
            try:
                # Navigate to URL
                if worker.use_playwright:
                    worker.page.goto(config.target_url)
                    storage_data = {
                        'cookies': worker.context.cookies(),
                        'localStorage': worker.page.evaluate('() => Object.assign({}, localStorage)'),
                        'sessionStorage': worker.page.evaluate('() => Object.assign({}, sessionStorage)'),
                        'scan_flash_lso': config.scan_flash_lso,
                    }
                else:
                    worker.browser.get(config.target_url)
                    storage_data = {
                        'cookies': worker.browser.get_cookies(),
                        'localStorage': worker.browser.execute_script('return Object.assign({}, localStorage);'),
                        'sessionStorage': worker.browser.execute_script('return Object.assign({}, sessionStorage);'),
                        'scan_flash_lso': config.scan_flash_lso,
                    }
                
                # Analyze storage
                analyzer = PrivacyStorageAnalyzer()
                findings = analyzer.analyze_all(storage_data)
                
                logger.info(f"Privacy analysis complete: {len(findings)} findings")
                return findings
                
            finally:
                worker.cleanup()
            
        except Exception as e:
            logger.error(f"Privacy analysis failed: {e}")
            return []
    
    def _generate_summary(self, results: ScanResults) -> Dict[str, Any]:
        """Generate summary of scan results"""
        total_findings = (
            len(results.browser_findings) +
            len(results.static_findings) +
            len(results.hpp_findings) +
            len(results.privacy_findings)
        )
        
        # Count by severity/risk level
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for finding in results.browser_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        for finding in results.static_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        for finding in results.hpp_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        for finding in results.privacy_findings:
            severity_counts[finding.risk_level] = severity_counts.get(finding.risk_level, 0) + 1
        
        return {
            'total_findings': total_findings,
            'by_scan_type': {
                'browser_automation': len(results.browser_findings),
                'static_javascript': len(results.static_findings),
                'hpp_detection': len(results.hpp_findings),
                'privacy_analysis': len(results.privacy_findings),
            },
            'by_severity': severity_counts,
            'scan_duration': self._calculate_duration(results.start_time, results.end_time),
        }
    
    def _calculate_duration(self, start_time: str, end_time: Optional[str]) -> str:
        """Calculate scan duration"""
        if not end_time:
            return "N/A"
        
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            duration = end - start
            return str(duration)
        except Exception:
            return "N/A"
    
    def export_results(self, results: ScanResults, output_file: str, 
                      format: str = "json") -> str:
        """
        Export scan results to file
        
        Args:
            results: Scan results
            output_file: Output file path
            format: Output format (json, html)
            
        Returns:
            Path to exported file
        """
        try:
            if format == "json":
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results.to_dict(), f, indent=2)
                logger.info(f"Results exported to JSON: {output_file}")
                return output_file
            
            elif format == "html":
                html = self._generate_html_report(results)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html)
                logger.info(f"Results exported to HTML: {output_file}")
                return output_file
            
            else:
                logger.error(f"Unsupported export format: {format}")
                return ""
        
        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            return ""
    
    def _generate_html_report(self, results: ScanResults) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Client-Side Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; }}
        h1 {{ color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e3f2fd; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .summary-item {{ background: white; padding: 15px; border-radius: 5px; text-align: center; }}
        .summary-item .label {{ color: #666; font-size: 14px; }}
        .summary-item .value {{ font-size: 28px; font-weight: bold; color: #2196F3; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; background: #ffebee; }}
        .high {{ border-left: 5px solid #f57c00; background: #fff3e0; }}
        .medium {{ border-left: 5px solid #ffa000; background: #fffde7; }}
        .low {{ border-left: 5px solid #388e3c; background: #e8f5e9; }}
        .section {{ margin-top: 30px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #d32f2f; color: white; }}
        .badge-high {{ background: #f57c00; color: white; }}
        .badge-medium {{ background: #ffa000; color: white; }}
        .badge-low {{ background: #388e3c; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Client-Side Security Scan Report</h1>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="label">Total Findings</div>
                    <div class="value">{results.summary['total_findings']}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Critical</div>
                    <div class="value" style="color: #d32f2f;">{results.summary['by_severity']['CRITICAL']}</div>
                </div>
                <div class="summary-item">
                    <div class="label">High</div>
                    <div class="value" style="color: #f57c00;">{results.summary['by_severity']['HIGH']}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Medium</div>
                    <div class="value" style="color: #ffa000;">{results.summary['by_severity']['MEDIUM']}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Low</div>
                    <div class="value" style="color: #388e3c;">{results.summary['by_severity']['LOW']}</div>
                </div>
            </div>
            <p><strong>Scan ID:</strong> {results.scan_id}</p>
            <p><strong>Status:</strong> {results.status}</p>
            <p><strong>Duration:</strong> {results.summary['scan_duration']}</p>
        </div>
"""
        
        # Add sections for each scan type
        if results.browser_findings:
            html += self._html_section_browser(results.browser_findings)
        
        if results.static_findings:
            html += self._html_section_static(results.static_findings)
        
        if results.hpp_findings:
            html += self._html_section_hpp(results.hpp_findings)
        
        if results.privacy_findings:
            html += self._html_section_privacy(results.privacy_findings)
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def _html_section_browser(self, findings: List[BrowserFinding]) -> str:
        """Generate HTML section for browser findings"""
        html = f"""
        <div class="section">
            <h2>Browser Automation Findings ({len(findings)})</h2>
"""
        for finding in findings:
            severity_class = finding.severity.lower()
            html += f"""
            <div class="finding {severity_class}">
                <span class="badge badge-{severity_class}">{finding.severity}</span>
                <strong>{finding.finding_type}</strong>
                <p><strong>URL:</strong> {finding.url}</p>
                <p><strong>Payload:</strong> <code>{finding.payload}</code></p>
                {f'<p><strong>Error:</strong> {finding.error_message}</p>' if finding.error_message else ''}
            </div>
"""
        html += """
        </div>
"""
        return html
    
    def _html_section_static(self, findings: List[StaticFinding]) -> str:
        """Generate HTML section for static findings"""
        html = f"""
        <div class="section">
            <h2>Static JavaScript Analysis Findings ({len(findings)})</h2>
"""
        for finding in findings:
            severity_class = finding.severity.lower()
            html += f"""
            <div class="finding {severity_class}">
                <span class="badge badge-{severity_class}">{finding.severity}</span>
                <strong>{finding.vulnerability_type}</strong>
                <p><strong>File:</strong> {finding.file_path}:{finding.line_number}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Code:</strong> <code>{finding.code_snippet}</code></p>
                <p><strong>Recommendation:</strong> {finding.recommendation}</p>
            </div>
"""
        html += """
        </div>
"""
        return html
    
    def _html_section_hpp(self, findings: List[HPPFinding]) -> str:
        """Generate HTML section for HPP findings"""
        html = f"""
        <div class="section">
            <h2>HTTP Parameter Pollution Findings ({len(findings)})</h2>
"""
        for finding in findings:
            severity_class = finding.severity.lower()
            html += f"""
            <div class="finding {severity_class}">
                <span class="badge badge-{severity_class}">{finding.severity}</span>
                <strong>{finding.technique}</strong>
                <p><strong>URL:</strong> {finding.url}</p>
                <p><strong>Behavior:</strong> {finding.behavior}</p>
                <p><strong>Response Code:</strong> {finding.response_code}</p>
            </div>
"""
        html += """
        </div>
"""
        return html
    
    def _html_section_privacy(self, findings: List[PrivacyFinding]) -> str:
        """Generate HTML section for privacy findings"""
        html = f"""
        <div class="section">
            <h2>Privacy & Storage Analysis Findings ({len(findings)})</h2>
"""
        for finding in findings:
            severity_class = finding.risk_level.lower()
            html += f"""
            <div class="finding {severity_class}">
                <span class="badge badge-{severity_class}">{finding.risk_level}</span>
                <strong>{finding.risk_type}</strong>
                <p><strong>Storage:</strong> {finding.storage_location}</p>
                <p><strong>Key:</strong> {finding.key}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Recommendation:</strong> {finding.recommendation}</p>
            </div>
"""
        html += """
        </div>
"""
        return html

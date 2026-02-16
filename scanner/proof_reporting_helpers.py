"""
Common proof reporting methods for exploit plugins.

This module provides reusable proof reporting helpers that can be mixed into
any exploit plugin to quickly add proof reporting capabilities.
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ProofReportingMixin:
    """
    Mixin class providing common proof reporting functionality for exploit plugins.
    
    This mixin provides a generic _generate_proof_report method that can be used
    by any exploit plugin to generate standardized proof reports.
    """
    
    def _generate_proof_report_generic(
        self,
        vulnerability_type: str,
        result: Dict[str, Any],
        target_url: str,
        vulnerability_data: Dict[str, Any],
        config: Dict[str, Any],
        enable_visual_proof: bool = False
    ) -> None:
        """
        Generate a generic proof report for any exploit type.
        
        This method provides basic proof reporting functionality that works for
        most exploit types. Plugins can override this for custom behavior.
        
        Args:
            vulnerability_type: Type of vulnerability (e.g., 'xxe', 'lfi', 'csrf')
            result: Exploitation result dictionary
            target_url: Target URL
            vulnerability_data: Vulnerability data dictionary
            config: Configuration dictionary
            enable_visual_proof: Whether to enable visual proof capture
        """
        try:
            from scanner.proof_reporter import get_proof_reporter
            
            # Initialize proof reporter
            reporter = get_proof_reporter(enable_visual_proof=enable_visual_proof)
            
            # Create proof data container
            vuln_id = vulnerability_data.get('vulnerability_id')
            proof_data = reporter.create_proof_data(vulnerability_type, vuln_id)
            
            # Set success status
            success = result.get('success', False)
            verified = success and (
                result.get('extracted_data') or
                result.get('command_output') or
                result.get('callback_verified') or
                len(result.get('evidence', '')) > 10
            )
            confidence = 0.85 if verified else 0.3
            
            proof_data.set_success(success, verified, confidence)
            
            # Add HTTP request
            method = vulnerability_data.get('method', 'GET')
            parameter = vulnerability_data.get('parameter', 'unknown')
            
            proof_data.add_http_request(
                method=method,
                url=target_url,
                headers={'User-Agent': 'Megido Scanner'},
                body=result.get('request_body', f'{parameter}=<payload>')
            )
            
            # Add HTTP response
            if result.get('response_body'):
                proof_data.add_http_response(
                    status_code=result.get('status_code', 200),
                    headers=result.get('response_headers', {}),
                    body=result.get('response_body', '')
                )
            
            # Add exploitation logs
            proof_data.add_log(f"{vulnerability_type.upper()} exploitation attempt on {target_url}", 'info')
            proof_data.add_log(f"Vulnerable parameter: {parameter}", 'info')
            
            if result.get('evidence'):
                proof_data.add_log(result['evidence'], 'success' if success else 'info')
            
            # Add command output (for RCE-like exploits)
            if result.get('command_output'):
                proof_data.set_command_output(result['command_output'])
            
            # Add extracted data
            if result.get('extracted_data'):
                proof_data.set_extracted_data(result['extracted_data'])
            
            # Add callback evidence
            if result.get('callback_evidence'):
                for callback in result['callback_evidence']:
                    proof_data.add_callback_evidence(callback)
            
            # Add OOB interactions
            if result.get('oob_interactions'):
                for interaction in result['oob_interactions']:
                    proof_data.add_oob_interaction(interaction)
            
            # Capture visual proof if enabled and applicable
            if enable_visual_proof and success and config.get('enable_visual_proof', False):
                try:
                    reporter.capture_visual_proof(
                        proof_data,
                        result.get('exploit_url', target_url),
                        capture_type=config.get('visual_proof_type', 'screenshot')
                    )
                except Exception as e:
                    proof_data.add_log(f"Visual proof capture failed: {e}", 'warning')
            
            # Add metadata
            proof_data.add_metadata('target_url', target_url)
            proof_data.add_metadata('parameter', parameter)
            proof_data.add_metadata('vulnerability_type', vulnerability_type)
            
            # Add plugin-specific metadata if available
            if hasattr(self, 'version'):
                proof_data.add_metadata('plugin_version', self.version)
            
            for key in ['payload', 'file_extracted', 'os_detected', 'injection_point']:
                if key in result:
                    proof_data.add_metadata(key, result[key])
            
            # Generate and save proof reports
            proof_results = reporter.report_proof(
                proof_data,
                save_json=config.get('save_proof_json', True),
                save_html=config.get('save_proof_html', True),
                store_db=config.get('store_proof_db', True),
                vulnerability_model=vulnerability_data.get('vulnerability_model')
            )
            
            # Add proof paths to result
            result['proof_json_path'] = proof_results.get('json_path')
            result['proof_html_path'] = proof_results.get('html_path')
            result['proof_db_stored'] = proof_results.get('db_stored')
            
            logger.info(f"{vulnerability_type.upper()} proof reporting completed successfully")
            
        except ImportError:
            logger.warning("ProofReporter not available, skipping proof generation")
        except Exception as e:
            logger.error(f"Error generating proof report: {e}", exc_info=True)


def add_proof_reporting_to_result(
    plugin_instance,
    vulnerability_type: str,
    result: Dict[str, Any],
    target_url: str,
    vulnerability_data: Dict[str, Any],
    config: Dict[str, Any],
    enable_visual_proof: bool = False
) -> None:
    """
    Helper function to add proof reporting to any exploit plugin result.
    
    This is a convenience function that can be called from any plugin's
    execute_attack method to add proof reporting.
    
    Args:
        plugin_instance: The plugin instance (for accessing version, etc.)
        vulnerability_type: Type of vulnerability
        result: Exploitation result dictionary
        target_url: Target URL
        vulnerability_data: Vulnerability data
        config: Configuration dictionary
        enable_visual_proof: Whether to enable visual proof
    
    Example:
        from scanner.proof_reporting_helpers import add_proof_reporting_to_result
        
        class MyPlugin(ExploitPlugin):
            def execute_attack(self, target_url, vulnerability_data, config):
                # ... perform exploitation ...
                
                if config.get('enable_proof_reporting', True):
                    add_proof_reporting_to_result(
                        self, 'xxe', result, target_url,
                        vulnerability_data, config
                    )
                
                return result
    """
    mixin = ProofReportingMixin()
    # Copy plugin attributes to mixin
    if hasattr(plugin_instance, 'version'):
        mixin.version = plugin_instance.version
    
    mixin._generate_proof_report_generic(
        vulnerability_type,
        result,
        target_url,
        vulnerability_data,
        config,
        enable_visual_proof
    )

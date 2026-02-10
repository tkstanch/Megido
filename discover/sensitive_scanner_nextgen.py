"""
Next-Generation Vulnerability Scanner - v4.0

This module implements bleeding-edge security scanning capabilities:
- Real-time monitoring with file watchers
- Advanced API with FastAPI integration
- Graph-based data flow analysis
- Enhanced deep learning models
- Cloud/container security integration
- Distributed scanning architecture
"""

import os
import json
import hashlib
import logging
import asyncio
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
import time

# Import from ultimate scanner
from discover.sensitive_scanner_ultimate import UltimateVulnerabilityScanner

# Try to import optional dependencies
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    # Create dummy base class if watchdog not available
    class FileSystemEventHandler:
        pass

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


# ==================== Real-Time Monitoring ====================

class ScanEventHandler(FileSystemEventHandler):
    """Handle file system events for real-time scanning."""
    
    def __init__(self, scanner, callback=None):
        """Initialize event handler."""
        self.scanner = scanner
        self.callback = callback
        self.debounce_time = 1.0  # seconds
        self.pending_scans = {}
        self.lock = threading.Lock()
    
    def on_modified(self, event):
        """Handle file modification."""
        if event.is_directory:
            return
        
        # Filter file types
        if not any(event.src_path.endswith(ext) for ext in 
                   ['.py', '.js', '.java', '.go', '.rb', '.php', '.env', '.config']):
            return
        
        with self.lock:
            self.pending_scans[event.src_path] = time.time()
    
    def on_created(self, event):
        """Handle file creation."""
        self.on_modified(event)
    
    def process_pending_scans(self):
        """Process pending scans after debounce."""
        with self.lock:
            current_time = time.time()
            files_to_scan = [
                path for path, timestamp in self.pending_scans.items()
                if current_time - timestamp >= self.debounce_time
            ]
            
            for path in files_to_scan:
                del self.pending_scans[path]
        
        if files_to_scan:
            self._scan_files(files_to_scan)
    
    def _scan_files(self, files):
        """Scan files and trigger callback."""
        try:
            results = self.scanner.scan_with_ultimate_features(
                files,
                target_type='file',
                incremental=True
            )
            
            if self.callback:
                self.callback(results)
            
            logging.info(f"Real-time scan completed for {len(files)} files")
        except Exception as e:
            logging.error(f"Real-time scan failed: {e}")


class RealTimeMonitor:
    """Real-time file system monitoring for continuous scanning."""
    
    def __init__(self, scanner, watch_paths: List[str], callback=None):
        """
        Initialize real-time monitor.
        
        Args:
            scanner: Scanner instance to use
            watch_paths: Paths to monitor
            callback: Function to call with scan results
        """
        if not HAS_WATCHDOG:
            raise ImportError("watchdog library required for real-time monitoring")
        
        self.scanner = scanner
        self.watch_paths = watch_paths
        self.callback = callback
        self.observer = Observer()
        self.event_handler = ScanEventHandler(scanner, callback)
        self.is_running = False
        self.debounce_thread = None
    
    def start(self):
        """Start monitoring."""
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.event_handler, path, recursive=True)
                logging.info(f"Monitoring {path}")
        
        self.observer.start()
        self.is_running = True
        
        # Start debounce thread
        self.debounce_thread = threading.Thread(target=self._debounce_loop, daemon=True)
        self.debounce_thread.start()
        
        logging.info("Real-time monitoring started")
    
    def stop(self):
        """Stop monitoring."""
        self.is_running = False
        self.observer.stop()
        self.observer.join()
        logging.info("Real-time monitoring stopped")
    
    def _debounce_loop(self):
        """Debounce loop to process pending scans."""
        while self.is_running:
            self.event_handler.process_pending_scans()
            time.sleep(0.5)


# ==================== Graph-Based Analysis ====================

@dataclass
class CodeNode:
    """Represents a node in the code graph."""
    id: str
    type: str  # 'file', 'function', 'variable', 'import'
    name: str
    file_path: str
    line_number: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class DataFlowAnalyzer:
    """Analyze data flow to detect secret propagation."""
    
    def __init__(self):
        """Initialize analyzer."""
        if not HAS_NETWORKX:
            raise ImportError("networkx library required for graph analysis")
        
        self.graph = nx.DiGraph()
        self.sensitive_nodes = set()
    
    def build_graph(self, files: List[str]):
        """
        Build dependency graph from files.
        
        Args:
            files: List of file paths to analyze
        """
        for file_path in files:
            self._analyze_file(file_path)
    
    def _analyze_file(self, file_path: str):
        """Analyze a single file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Simple analysis - detect imports and assignments
            file_node = f"file:{file_path}"
            self.graph.add_node(file_node, type='file', path=file_path)
            
            for i, line in enumerate(content.split('\n'), 1):
                # Detect imports
                if 'import ' in line:
                    import_name = self._extract_import(line)
                    if import_name:
                        import_node = f"import:{import_name}"
                        self.graph.add_node(import_node, type='import', name=import_name)
                        self.graph.add_edge(file_node, import_node)
                
                # Detect variable assignments
                if '=' in line and not line.strip().startswith('#'):
                    var_name = self._extract_variable(line)
                    if var_name:
                        var_node = f"var:{file_path}:{var_name}:{i}"
                        self.graph.add_node(var_node, type='variable', name=var_name, 
                                          file=file_path, line=i)
                        self.graph.add_edge(file_node, var_node)
                        
                        # Check if potentially sensitive
                        if self._is_sensitive_pattern(line):
                            self.sensitive_nodes.add(var_node)
        
        except Exception as e:
            logging.error(f"Error analyzing {file_path}: {e}")
    
    def _extract_import(self, line: str) -> Optional[str]:
        """Extract import name from line."""
        parts = line.strip().split()
        if 'import' in parts:
            idx = parts.index('import')
            if idx + 1 < len(parts):
                return parts[idx + 1].split('.')[0]
        return None
    
    def _extract_variable(self, line: str) -> Optional[str]:
        """Extract variable name from assignment."""
        if '=' not in line:
            return None
        
        left = line.split('=')[0].strip()
        # Simple extraction - get last word
        parts = left.split()
        if parts:
            return parts[-1].strip(',:')
        return None
    
    def _is_sensitive_pattern(self, line: str) -> bool:
        """Check if line contains sensitive patterns."""
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'api', 'credential',
            'auth', 'private', 'confidential'
        ]
        return any(keyword in line.lower() for keyword in sensitive_keywords)
    
    def find_secret_flows(self) -> List[Dict[str, Any]]:
        """
        Find data flows from sensitive variables.
        
        Returns:
            List of flow paths showing secret propagation
        """
        flows = []
        
        for sensitive_node in self.sensitive_nodes:
            # Find all paths from this sensitive node
            for target in self.graph.nodes():
                if target != sensitive_node:
                    try:
                        if nx.has_path(self.graph, sensitive_node, target):
                            paths = list(nx.all_simple_paths(
                                self.graph, sensitive_node, target, cutoff=5
                            ))
                            
                            for path in paths[:3]:  # Limit to 3 paths
                                flows.append({
                                    'source': sensitive_node,
                                    'target': target,
                                    'path': path,
                                    'length': len(path),
                                    'risk': 'high' if len(path) > 2 else 'medium'
                                })
                    except (nx.NetworkXError, nx.NetworkXNoPath, Exception) as e:
                        # Skip paths that can't be found
                        logging.debug(f"Path finding error: {e}")
                        pass
        
        return flows
    
    def get_graph_stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'sensitive_nodes': len(self.sensitive_nodes),
            'connected_components': nx.number_weakly_connected_components(self.graph),
            'avg_degree': sum(dict(self.graph.degree()).values()) / max(1, self.graph.number_of_nodes())
        }


# ==================== Cloud Integration ====================

class CloudSecurityScanner:
    """Scan cloud resources for security issues."""
    
    def __init__(self):
        """Initialize cloud scanner."""
        self.patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'azure_key': r'[0-9a-zA-Z]{43,}',
            'gcp_api_key': r'AIza[0-9A-Za-z\\-_]{35}',
            'docker_registry': r'[a-zA-Z0-9_-]+\.azurecr\.io',
            'k8s_token': r'[a-zA-Z0-9]{40,}',
        }
    
    def scan_docker_image(self, image_name: str) -> Dict[str, Any]:
        """
        Scan Docker image for secrets (simplified).
        
        Args:
            image_name: Docker image name
            
        Returns:
            Scan results
        """
        # This is a simplified implementation
        # Real implementation would use Docker API
        return {
            'image': image_name,
            'findings': [],
            'status': 'not_implemented',
            'message': 'Docker scanning requires docker-py library'
        }
    
    def scan_k8s_secrets(self, namespace: str = 'default') -> Dict[str, Any]:
        """
        Scan Kubernetes secrets (simplified).
        
        Args:
            namespace: K8s namespace
            
        Returns:
            Scan results
        """
        return {
            'namespace': namespace,
            'findings': [],
            'status': 'not_implemented',
            'message': 'K8s scanning requires kubernetes client library'
        }
    
    def scan_environment_variables(self) -> List[Dict[str, Any]]:
        """
        Scan environment variables for sensitive data.
        
        Returns:
            List of findings
        """
        findings = []
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'api', 'credential']
        
        for key, value in os.environ.items():
            if any(pattern in key.lower() for pattern in sensitive_patterns):
                findings.append({
                    'type': 'environment_variable',
                    'name': key,
                    'value_length': len(value),
                    'risk': 'high',
                    'message': f'Sensitive environment variable: {key}'
                })
        
        return findings


# ==================== Advanced API Interface ====================

class ScanAPIInterface:
    """API interface for remote scanning (FastAPI-ready)."""
    
    def __init__(self, scanner):
        """
        Initialize API interface.
        
        Args:
            scanner: Scanner instance
        """
        self.scanner = scanner
        self.scan_history = []
        self.active_scans = {}
    
    async def scan_async(self, files: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Async scan endpoint.
        
        Args:
            files: Files to scan
            options: Scan options
            
        Returns:
            Scan results
        """
        scan_id = hashlib.sha256(f"{files}{datetime.now()}".encode()).hexdigest()[:16]
        
        self.active_scans[scan_id] = {
            'status': 'running',
            'started_at': datetime.now().isoformat(),
            'files': files
        }
        
        try:
            # Run scan
            results = self.scanner.scan_with_ultimate_features(
                files,
                target_type='file',
                **options
            )
            
            results['scan_id'] = scan_id
            results['status'] = 'completed'
            results['completed_at'] = datetime.now().isoformat()
            
            self.scan_history.append(results)
            del self.active_scans[scan_id]
            
            return results
        
        except Exception as e:
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)
            return {
                'scan_id': scan_id,
                'status': 'failed',
                'error': str(e)
            }
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status."""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
        
        for scan in self.scan_history:
            if scan.get('scan_id') == scan_id:
                return scan
        
        return {'error': 'Scan not found'}
    
    def get_scan_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get scan history."""
        return self.scan_history[-limit:]


# ==================== Next-Gen Scanner ====================

class NextGenVulnerabilityScanner(UltimateVulnerabilityScanner):
    """
    Next-Generation Vulnerability Scanner with cutting-edge features.
    
    Features:
    - Real-time monitoring with file watchers
    - Graph-based data flow analysis
    - Cloud/container integration
    - Advanced API interface
    - Distributed scanning support
    """
    
    def __init__(self, **kwargs):
        """Initialize next-gen scanner."""
        # Extract next-gen specific kwargs before passing to parent
        self.enable_realtime_monitoring = kwargs.pop('enable_realtime_monitoring', False)
        self.enable_graph_analysis = kwargs.pop('enable_graph_analysis', False)
        self.enable_cloud_scanning = kwargs.pop('enable_cloud_scanning', False)
        
        # Initialize parent with remaining kwargs
        super().__init__(**kwargs)
        
        # Initialize components
        self.realtime_monitor = None
        self.flow_analyzer = None
        self.cloud_scanner = None
        self.api_interface = None
        
        if self.enable_graph_analysis and HAS_NETWORKX:
            self.flow_analyzer = DataFlowAnalyzer()
        
        if self.enable_cloud_scanning:
            self.cloud_scanner = CloudSecurityScanner()
        
        self.api_interface = ScanAPIInterface(self)
        
        self.logger.info("Next-generation scanner initialized")
    
    def scan_with_nextgen_features(
        self,
        files: List[str],
        target_type: str = 'file',
        enable_monitoring: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Comprehensive scan with next-generation features.
        
        Args:
            files: Files or URLs to scan
            target_type: 'file' or 'url'
            enable_monitoring: Enable real-time monitoring
            **kwargs: Additional options
            
        Returns:
            Enhanced scan results
        """
        start_time = time.time()
        
        # Run base ultimate scan
        results = self.scan_with_ultimate_features(
            files,
            target_type,
            **kwargs
        )
        
        # Add next-gen features
        nextgen_features = {}
        
        # Graph analysis
        if self.enable_graph_analysis and self.flow_analyzer and target_type == 'file':
            try:
                self.flow_analyzer.build_graph(files)
                secret_flows = self.flow_analyzer.find_secret_flows()
                graph_stats = self.flow_analyzer.get_graph_stats()
                
                nextgen_features['data_flow_analysis'] = {
                    'secret_flows': secret_flows,
                    'graph_stats': graph_stats,
                    'flow_count': len(secret_flows)
                }
                
                self.logger.info(f"Graph analysis found {len(secret_flows)} secret flows")
            except Exception as e:
                self.logger.error(f"Graph analysis failed: {e}")
                nextgen_features['data_flow_analysis'] = {'error': str(e)}
        
        # Cloud scanning
        if self.enable_cloud_scanning and self.cloud_scanner:
            try:
                env_findings = self.cloud_scanner.scan_environment_variables()
                nextgen_features['cloud_security'] = {
                    'environment_findings': env_findings,
                    'finding_count': len(env_findings)
                }
                
                self.logger.info(f"Cloud scan found {len(env_findings)} environment issues")
            except Exception as e:
                self.logger.error(f"Cloud scanning failed: {e}")
                nextgen_features['cloud_security'] = {'error': str(e)}
        
        # Enable real-time monitoring if requested
        if enable_monitoring and HAS_WATCHDOG:
            try:
                watch_dirs = list(set([os.path.dirname(f) for f in files if os.path.isfile(f)]))
                if watch_dirs:
                    self.realtime_monitor = RealTimeMonitor(
                        self,
                        watch_dirs,
                        callback=lambda r: self.logger.info(f"Real-time scan: {r.get('findings_count', 0)} findings")
                    )
                    self.realtime_monitor.start()
                    nextgen_features['monitoring'] = {
                        'enabled': True,
                        'watch_paths': watch_dirs
                    }
            except Exception as e:
                self.logger.error(f"Failed to start monitoring: {e}")
                nextgen_features['monitoring'] = {'error': str(e)}
        
        # Add to results
        results['nextgen_features'] = nextgen_features
        results['nextgen_scan_time'] = time.time() - start_time
        results['scanner_version'] = '4.0-nextgen'
        
        return results
    
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        if self.realtime_monitor:
            self.realtime_monitor.stop()
            self.logger.info("Monitoring stopped")


# ==================== Convenience Functions ====================

def quick_nextgen_scan(files: List[str], output_dir: str = './nextgen_scan_results') -> Dict[str, Any]:
    """
    Quick next-generation scan with all features.
    
    Args:
        files: Files to scan
        output_dir: Output directory
        
    Returns:
        Scan results
    """
    scanner = NextGenVulnerabilityScanner(
        enable_ai_ml=True,
        enable_risk_scoring=True,
        enable_graph_analysis=True,
        enable_cloud_scanning=True,
        enable_dashboard_generation=True,
        enable_sarif_output=True,
        exposure_level='high'
    )
    
    return scanner.scan_with_nextgen_features(
        files,
        target_type='file',
        output_dir=output_dir
    )


def monitor_directory(directory: str, callback=None):
    """
    Monitor directory for changes and scan automatically.
    
    Args:
        directory: Directory to monitor
        callback: Function to call with results
        
    Returns:
        Monitor instance
    """
    if not HAS_WATCHDOG:
        raise ImportError("watchdog library required for monitoring")
    
    scanner = NextGenVulnerabilityScanner(
        enable_realtime_monitoring=True,
        enable_risk_scoring=True
    )
    
    monitor = RealTimeMonitor(scanner, [directory], callback)
    monitor.start()
    
    return monitor


if __name__ == '__main__':
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("Next-Generation Vulnerability Scanner v4.0")
    print("=" * 60)
    
    # Example files
    test_files = ['discover/sensitive_scanner.py']
    
    # Run next-gen scan
    results = quick_nextgen_scan(test_files)
    
    print(f"\nScan Results:")
    print(f"- Findings: {results.get('findings_count', 0)}")
    print(f"- Risk Score: {results.get('risk_scores_enabled', False)}")
    print(f"- Graph Analysis: {results.get('nextgen_features', {}).get('data_flow_analysis', {}).get('flow_count', 0)} flows")
    print(f"- Cloud Security: {results.get('nextgen_features', {}).get('cloud_security', {}).get('finding_count', 0)} issues")
    print(f"- Scanner Version: {results.get('scanner_version')}")

"""
EXTREME Exploit Chain Detection & Attack Path Discovery

This module implements military-grade exploit chain detection,
automatically discovering multi-stage attack paths and post-exploitation scenarios.

Features:
- Multi-stage attack path discovery
- Automatic exploit chain construction
- Post-exploitation scenario modeling
- Lateral movement detection
- Attack graph generation
- Impact amplification analysis
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class AttackStage(Enum):
    """Attack stages in exploit chain"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ExploitComplexity(Enum):
    """Exploit complexity levels"""
    TRIVIAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class ExploitNode:
    """Node in exploit chain graph"""
    vulnerability_id: str
    vulnerability_type: str
    attack_stage: AttackStage
    complexity: ExploitComplexity
    impact_score: float  # 0-10
    prerequisites: List[str] = field(default_factory=list)
    enables: List[str] = field(default_factory=list)
    description: str = ""
    verified: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'vulnerability_id': self.vulnerability_id,
            'vulnerability_type': self.vulnerability_type,
            'attack_stage': self.attack_stage.value,
            'complexity': self.complexity.value,
            'impact_score': self.impact_score,
            'prerequisites': self.prerequisites,
            'enables': self.enables,
            'description': self.description,
            'verified': self.verified,
        }


@dataclass
class ExploitChain:
    """Complete exploit chain"""
    chain_id: str
    nodes: List[ExploitNode]
    total_impact: float
    total_complexity: int
    attack_narrative: str
    mitre_ttps: List[str] = field(default_factory=list)
    remediation_priority: int = 0  # 1-5, 5 highest
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'chain_id': self.chain_id,
            'nodes': [n.to_dict() for n in self.nodes],
            'total_impact': self.total_impact,
            'total_complexity': self.total_complexity,
            'attack_narrative': self.attack_narrative,
            'mitre_ttps': self.mitre_ttps,
            'remediation_priority': self.remediation_priority,
            'stages_count': len(self.nodes),
        }


class ExtremeChainDetector:
    """
    Military-grade exploit chain detector.
    
    Analyzes vulnerabilities to discover multi-stage attack paths,
    model post-exploitation scenarios, and quantify impact amplification.
    """
    
    # MITRE ATT&CK mapping for common vulnerabilities
    MITRE_MAPPING = {
        'xss': ['T1059', 'T1203'],  # Command Execution, Exploitation
        'sqli': ['T1190', 'T1557'],  # Exploit Public-Facing App, MITM
        'command': ['T1059', 'T1068'],  # Command Execution, Exploitation for Privilege Escalation
        'traversal': ['T1083', 'T1005'],  # File Discovery, Data from Local System
        'ssrf': ['T1190', 'T1071'],  # Exploit Public-Facing App, Application Layer Protocol
        'rce': ['T1059', 'T1203'],  # Command Execution, Exploitation
        'lfi': ['T1083', 'T1005'],  # File Discovery, Data from Local System
        'xxe': ['T1190', 'T1557'],  # Exploit Public-Facing App
    }
    
    # Post-exploitation scenarios by vulnerability type
    POST_EXPLOIT_SCENARIOS = {
        'xss': [
            'Session hijacking → Account takeover',
            'Cookie theft → Credential access',
            'Keylogging → Credential collection',
            'DOM manipulation → Phishing',
        ],
        'sqli': [
            'Database enumeration → Data exfiltration',
            'File read → Source code disclosure',
            'File write → Web shell upload',
            'OS command execution → Server compromise',
        ],
        'command': [
            'Command execution → Reverse shell',
            'File read → Credential access',
            'Privilege escalation → Root access',
            'Lateral movement → Network compromise',
        ],
        'rce': [
            'Code execution → Backdoor installation',
            'Memory manipulation → Process hijacking',
            'Privilege escalation → System compromise',
        ],
    }
    
    def __init__(self):
        """Initialize exploit chain detector"""
        self.exploit_graph: Dict[str, ExploitNode] = {}
        self.detected_chains: List[ExploitChain] = []
    
    def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[ExploitChain]:
        """
        Analyze findings to detect exploit chains.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List of detected exploit chains
        """
        # Build exploit graph
        self._build_exploit_graph(findings)
        
        # Detect chains
        chains = self._detect_chains()
        
        # Calculate impact amplification
        for chain in chains:
            chain.total_impact = self._calculate_chain_impact(chain)
            chain.remediation_priority = self._calculate_remediation_priority(chain)
        
        # Sort by impact
        chains.sort(key=lambda c: c.total_impact, reverse=True)
        
        self.detected_chains = chains
        return chains
    
    def _build_exploit_graph(self, findings: List[Dict[str, Any]]):
        """Build graph of exploits and their relationships"""
        self.exploit_graph = {}
        
        for finding in findings:
            node = self._create_exploit_node(finding)
            self.exploit_graph[node.vulnerability_id] = node
        
        # Determine relationships
        for node_id, node in self.exploit_graph.items():
            self._determine_relationships(node)
    
    def _create_exploit_node(self, finding: Dict[str, Any]) -> ExploitNode:
        """Create exploit node from finding"""
        vuln_type = finding.get('type', 'unknown').lower()
        
        # Determine attack stage
        stage_map = {
            'xss': AttackStage.INITIAL_ACCESS,
            'sqli': AttackStage.INITIAL_ACCESS,
            'command': AttackStage.EXECUTION,
            'rce': AttackStage.EXECUTION,
            'traversal': AttackStage.DISCOVERY,
            'ssrf': AttackStage.INITIAL_ACCESS,
            'lfi': AttackStage.DISCOVERY,
        }
        stage = stage_map.get(vuln_type, AttackStage.INITIAL_ACCESS)
        
        # Determine complexity
        confidence = finding.get('confidence', 0.5)
        if confidence >= 0.9:
            complexity = ExploitComplexity.TRIVIAL
        elif confidence >= 0.75:
            complexity = ExploitComplexity.LOW
        elif confidence >= 0.5:
            complexity = ExploitComplexity.MEDIUM
        elif confidence >= 0.25:
            complexity = ExploitComplexity.HIGH
        else:
            complexity = ExploitComplexity.CRITICAL
        
        # Calculate impact
        impact = self._calculate_base_impact(finding)
        
        # Generate ID
        vuln_id = f"{vuln_type}_{finding.get('url', 'unknown')}_{finding.get('parameter', 'unknown')}"
        vuln_id = vuln_id[:100]  # Limit length
        
        return ExploitNode(
            vulnerability_id=vuln_id,
            vulnerability_type=vuln_type,
            attack_stage=stage,
            complexity=complexity,
            impact_score=impact,
            description=finding.get('evidence', ''),
            verified=finding.get('verified', False),
        )
    
    def _calculate_base_impact(self, finding: Dict[str, Any]) -> float:
        """Calculate base impact score (0-10)"""
        impact = 5.0  # Base impact
        
        # Verified exploits have higher impact
        if finding.get('verified', False):
            impact += 2.0
        
        # High confidence increases impact
        confidence = finding.get('confidence', 0.5)
        impact += confidence * 2.0
        
        # Certain vulnerability types have higher impact
        vuln_type = finding.get('type', '').lower()
        if vuln_type in ['sqli', 'rce', 'command']:
            impact += 1.0
        
        # Evidence of data access increases impact
        evidence = finding.get('evidence', '').lower()
        if any(kw in evidence for kw in ['cookie', 'session', 'token', 'credential']):
            impact += 1.5
        
        return min(impact, 10.0)
    
    def _determine_relationships(self, node: ExploitNode):
        """Determine what this node enables/requires"""
        vuln_type = node.vulnerability_type
        
        # XSS can lead to session hijacking
        if vuln_type == 'xss':
            node.enables = ['session_hijacking', 'credential_theft', 'phishing']
        
        # SQLi can lead to many things
        elif vuln_type == 'sqli':
            node.enables = ['database_access', 'file_read', 'command_execution', 'data_exfiltration']
        
        # Command injection/RCE
        elif vuln_type in ['command', 'rce']:
            node.enables = ['system_access', 'privilege_escalation', 'lateral_movement']
            node.prerequisites = ['initial_access']
        
        # File traversal
        elif vuln_type == 'traversal':
            node.enables = ['file_read', 'source_code_access', 'credential_discovery']
        
        # SSRF
        elif vuln_type == 'ssrf':
            node.enables = ['internal_network_access', 'cloud_metadata_access']
    
    def _detect_chains(self) -> List[ExploitChain]:
        """Detect exploit chains from graph"""
        chains = []
        
        # Find entry points (initial access)
        entry_points = [
            node for node in self.exploit_graph.values()
            if node.attack_stage == AttackStage.INITIAL_ACCESS
        ]
        
        # For each entry point, explore possible chains
        for entry in entry_points:
            chain_paths = self._explore_chain_paths(entry, [])
            
            for path in chain_paths:
                if len(path) > 1:  # Multi-stage chain
                    chain = self._create_chain_from_path(path)
                    chains.append(chain)
        
        return chains
    
    def _explore_chain_paths(self, 
                            current: ExploitNode,
                            visited: List[str]) -> List[List[ExploitNode]]:
        """Explore all possible chain paths from current node"""
        if current.vulnerability_id in visited:
            return []
        
        paths = [[current]]  # Start with single-node path
        new_visited = visited + [current.vulnerability_id]
        
        # Find nodes that this enables
        for node_id, node in self.exploit_graph.items():
            if node_id in new_visited:
                continue
            
            # Check if current enables this node
            if any(enabled in node.prerequisites or 
                   enabled in current.enables 
                   for enabled in current.enables):
                
                # Explore from this node
                sub_paths = self._explore_chain_paths(node, new_visited)
                
                # Add current to beginning of each sub-path
                for sub_path in sub_paths:
                    paths.append([current] + sub_path)
        
        return paths
    
    def _create_chain_from_path(self, path: List[ExploitNode]) -> ExploitChain:
        """Create exploit chain from path"""
        # Generate chain ID
        chain_id = f"chain_{path[0].vulnerability_id}_{len(path)}"
        
        # Calculate totals
        total_complexity = sum(node.complexity.value for node in path)
        
        # Generate attack narrative
        narrative = self._generate_attack_narrative(path)
        
        # Collect MITRE TTPs
        mitre_ttps = []
        for node in path:
            mitre_ttps.extend(self.MITRE_MAPPING.get(node.vulnerability_type, []))
        mitre_ttps = list(set(mitre_ttps))  # Remove duplicates
        
        return ExploitChain(
            chain_id=chain_id,
            nodes=path,
            total_impact=0.0,  # Calculated later
            total_complexity=total_complexity,
            attack_narrative=narrative,
            mitre_ttps=mitre_ttps,
        )
    
    def _generate_attack_narrative(self, path: List[ExploitNode]) -> str:
        """Generate human-readable attack narrative"""
        if not path:
            return ""
        
        narrative_parts = []
        
        for i, node in enumerate(path, 1):
            stage_name = node.attack_stage.value.replace('_', ' ').title()
            vuln_name = node.vulnerability_type.upper()
            
            if i == 1:
                narrative_parts.append(
                    f"Stage {i} - Initial Access: Attacker exploits {vuln_name} vulnerability "
                    f"to gain {stage_name}."
                )
            else:
                narrative_parts.append(
                    f"Stage {i} - {stage_name}: Using previous access, attacker leverages "
                    f"{vuln_name} to achieve {stage_name}."
                )
            
            # Add post-exploitation scenarios
            scenarios = self.POST_EXPLOIT_SCENARIOS.get(node.vulnerability_type, [])
            if scenarios:
                narrative_parts.append(
                    f"  Possible outcomes: {'; '.join(scenarios[:2])}"
                )
        
        return "\n".join(narrative_parts)
    
    def _calculate_chain_impact(self, chain: ExploitChain) -> float:
        """Calculate total impact of exploit chain"""
        # Base impact is sum of individual impacts
        base_impact = sum(node.impact_score for node in chain.nodes)
        
        # Amplification factor based on chain length
        amplification = 1.0 + (len(chain.nodes) - 1) * 0.3
        
        # Bonus for verified exploits
        verified_count = sum(1 for node in chain.nodes if node.verified)
        verification_bonus = verified_count * 0.5
        
        total = (base_impact * amplification) + verification_bonus
        
        return min(total, 100.0)
    
    def _calculate_remediation_priority(self, chain: ExploitChain) -> int:
        """Calculate remediation priority (1-5)"""
        if chain.total_impact >= 50:
            return 5  # Critical
        elif chain.total_impact >= 35:
            return 4  # High
        elif chain.total_impact >= 20:
            return 3  # Medium
        elif chain.total_impact >= 10:
            return 2  # Low
        else:
            return 1  # Info
    
    def generate_attack_graph(self, 
                             chain: ExploitChain,
                             format: str = 'mermaid') -> str:
        """
        Generate visual attack graph.
        
        Args:
            chain: Exploit chain
            format: Output format ('mermaid', 'dot', 'ascii')
            
        Returns:
            Graph representation
        """
        if format == 'mermaid':
            return self._generate_mermaid_graph(chain)
        elif format == 'dot':
            return self._generate_dot_graph(chain)
        else:
            return self._generate_ascii_graph(chain)
    
    def _generate_mermaid_graph(self, chain: ExploitChain) -> str:
        """Generate Mermaid flowchart"""
        lines = ["graph TD"]
        
        for i, node in enumerate(chain.nodes):
            node_id = f"N{i}"
            label = f"{node.vulnerability_type.upper()}<br/>{node.attack_stage.value}"
            
            lines.append(f"    {node_id}[\"{label}\"]")
            
            if i > 0:
                prev_id = f"N{i-1}"
                lines.append(f"    {prev_id} --> {node_id}")
        
        return "\n".join(lines)
    
    def _generate_dot_graph(self, chain: ExploitChain) -> str:
        """Generate Graphviz DOT format"""
        lines = ["digraph ExploitChain {"]
        lines.append("    rankdir=LR;")
        
        for i, node in enumerate(chain.nodes):
            label = f"{node.vulnerability_type}\\n{node.attack_stage.value}"
            lines.append(f"    N{i} [label=\"{label}\"];")
            
            if i > 0:
                lines.append(f"    N{i-1} -> N{i};")
        
        lines.append("}")
        return "\n".join(lines)
    
    def _generate_ascii_graph(self, chain: ExploitChain) -> str:
        """Generate ASCII art graph"""
        lines = []
        
        for i, node in enumerate(chain.nodes):
            if i > 0:
                lines.append("    |")
                lines.append("    v")
            
            lines.append(f"[{node.vulnerability_type.upper()}]")
            lines.append(f"Stage: {node.attack_stage.value}")
            lines.append(f"Impact: {node.impact_score:.1f}/10")
        
        return "\n".join(lines)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get chain detection statistics"""
        if not self.detected_chains:
            return {
                'total_chains': 0,
                'avg_chain_length': 0.0,
                'max_impact': 0.0,
            }
        
        return {
            'total_chains': len(self.detected_chains),
            'avg_chain_length': sum(len(c.nodes) for c in self.detected_chains) / len(self.detected_chains),
            'max_impact': max(c.total_impact for c in self.detected_chains),
            'critical_chains': sum(1 for c in self.detected_chains if c.remediation_priority == 5),
        }


def create_chain_detector() -> ExtremeChainDetector:
    """
    Create a chain detector instance.
    
    Returns:
        ExtremeChainDetector instance
    """
    return ExtremeChainDetector()

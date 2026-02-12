"""
Smart Context Analyzer

Deep application understanding through technology stack detection,
framework fingerprinting, and behavioral pattern analysis.
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import Counter
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class TechnologyStack:
    """Detected technology stack"""
    web_server: Optional[str] = None
    web_framework: Optional[str] = None
    programming_language: Optional[str] = None
    database_type: Optional[str] = None
    cms_platform: Optional[str] = None
    javascript_frameworks: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    cloud_provider: Optional[str] = None
    cdn: Optional[str] = None
    waf: Optional[str] = None
    confidence_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class ApplicationBehavior:
    """Application behavioral patterns"""
    response_time_avg: float = 0.0
    response_time_std: float = 0.0
    error_handling_pattern: str = "unknown"
    session_management: str = "unknown"
    authentication_type: str = "unknown"
    input_validation_level: str = "unknown"
    rate_limiting: bool = False
    csrf_protection: bool = False
    security_headers: List[str] = field(default_factory=list)
    observed_patterns: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityProfile:
    """Predicted vulnerability profile"""
    likely_vulnerabilities: List[str] = field(default_factory=list)
    attack_surface: List[str] = field(default_factory=list)
    security_posture: str = "unknown"  # weak, moderate, strong, hardened
    recommended_techniques: List[str] = field(default_factory=list)
    avoid_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0


class SmartContextAnalyzer:
    """
    Advanced context analyzer that deeply understands target applications
    through multi-faceted analysis and pattern recognition.
    """
    
    # Technology signature patterns
    TECH_SIGNATURES = {
        'web_servers': {
            'nginx': [r'nginx/[\d.]+', r'Server:\s*nginx'],
            'apache': [r'Apache/[\d.]+', r'Server:\s*Apache'],
            'iis': [r'Microsoft-IIS/[\d.]+', r'X-Powered-By:\s*ASP\.NET'],
            'lighttpd': [r'lighttpd/[\d.]+'],
            'tomcat': [r'Apache-Coyote', r'Tomcat'],
        },
        'frameworks': {
            'django': [r'csrfmiddlewaretoken', r'django', r'__admin__'],
            'flask': [r'werkzeug', r'flask'],
            'rails': [r'X-Runtime', r'Ruby on Rails'],
            'laravel': [r'laravel_session', r'laravel'],
            'express': [r'express', r'X-Powered-By:\s*Express'],
            'spring': [r'jsessionid', r'Spring'],
            'asp.net': [r'__VIEWSTATE', r'ASP\.NET', r'\.aspx'],
            'php': [r'PHPSESSID', r'\.php', r'X-Powered-By:\s*PHP'],
        },
        'cms': {
            'wordpress': [r'wp-content', r'wp-includes', r'/wp-json/'],
            'drupal': [r'Drupal', r'/sites/default/', r'X-Drupal'],
            'joomla': [r'Joomla', r'/components/', r'/modules/'],
            'magento': [r'Magento', r'/skin/frontend/'],
        },
        'javascript': {
            'react': [r'react', r'_react', r'data-reactid'],
            'angular': [r'angular', r'ng-app', r'ng-controller'],
            'vue': [r'vue', r'v-if', r'v-for'],
            'jquery': [r'jquery', r'\$\('],
        },
        'waf': {
            'cloudflare': [r'cloudflare', r'cf-ray', r'__cfduid'],
            'akamai': [r'akamai', r'AkamaiGHost'],
            'incapsula': [r'incapsula', r'visid_incap'],
            'f5': [r'F5', r'BIGipServer'],
            'aws_waf': [r'X-Amzn-', r'awselb'],
        }
    }
    
    # Vulnerability patterns by technology
    VULNERABILITY_PATTERNS = {
        'wordpress': ['sql_injection', 'file_upload', 'plugin_vulns', 'theme_vulns'],
        'drupal': ['sql_injection', 'remote_code_execution', 'access_bypass'],
        'php': ['sql_injection', 'file_inclusion', 'command_injection'],
        'asp.net': ['sql_injection', 'viewstate_manipulation', 'deserialization'],
        'django': ['sql_injection', 'template_injection'],
        'rails': ['sql_injection', 'mass_assignment', 'yaml_deserialization'],
    }
    
    def __init__(self):
        """Initialize smart context analyzer"""
        self.analyzed_responses = []
        self.tech_stack = TechnologyStack()
        self.behavior = ApplicationBehavior()
        self.vuln_profile = VulnerabilityProfile()
        self.fingerprint_cache = {}
        
        logger.info("Smart context analyzer initialized")
    
    def analyze_context(self, 
                       responses: List[Any],
                       headers: List[Dict[str, str]],
                       urls: List[str]) -> Dict[str, Any]:
        """
        Perform comprehensive context analysis.
        
        Args:
            responses: List of HTTP responses
            headers: List of response headers
            urls: List of URLs accessed
        
        Returns:
            Complete context analysis
        """
        logger.info(f"Analyzing context from {len(responses)} responses")
        
        # Detect technology stack
        self.tech_stack = self._detect_technology_stack(responses, headers)
        
        # Analyze application behavior
        self.behavior = self._analyze_behavior(responses, headers, urls)
        
        # Generate vulnerability profile
        self.vuln_profile = self._generate_vulnerability_profile(
            self.tech_stack, self.behavior
        )
        
        # Compile comprehensive analysis
        analysis = {
            'technology_stack': self._tech_stack_to_dict(self.tech_stack),
            'behavior': self._behavior_to_dict(self.behavior),
            'vulnerability_profile': self._vuln_profile_to_dict(self.vuln_profile),
            'recommendations': self._generate_recommendations(),
        }
        
        logger.info(f"Context analysis complete: {self.tech_stack.web_framework or 'unknown'} "
                   f"on {self.tech_stack.database_type or 'unknown'}")
        
        return analysis
    
    def _detect_technology_stack(self,
                                responses: List[Any],
                                headers: List[Dict[str, str]]) -> TechnologyStack:
        """Detect technology stack from responses and headers"""
        stack = TechnologyStack()
        evidence_scores = {
            'web_server': Counter(),
            'framework': Counter(),
            'cms': Counter(),
            'javascript': Counter(),
            'waf': Counter(),
        }
        
        # Analyze each response
        for response, header_dict in zip(responses, headers):
            content = str(response) if response else ""
            
            # Check web server
            for server, patterns in self.TECH_SIGNATURES['web_servers'].items():
                for pattern in patterns:
                    if re.search(pattern, str(header_dict), re.IGNORECASE):
                        evidence_scores['web_server'][server] += 2
                    if re.search(pattern, content, re.IGNORECASE):
                        evidence_scores['web_server'][server] += 1
            
            # Check framework
            for framework, patterns in self.TECH_SIGNATURES['frameworks'].items():
                for pattern in patterns:
                    if re.search(pattern, str(header_dict), re.IGNORECASE):
                        evidence_scores['framework'][framework] += 2
                    if re.search(pattern, content, re.IGNORECASE):
                        evidence_scores['framework'][framework] += 1
            
            # Check CMS
            for cms, patterns in self.TECH_SIGNATURES['cms'].items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        evidence_scores['cms'][cms] += 3  # Higher weight for CMS
            
            # Check JavaScript frameworks
            for js_fw, patterns in self.TECH_SIGNATURES['javascript'].items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        evidence_scores['javascript'][js_fw] += 1
            
            # Check WAF
            for waf, patterns in self.TECH_SIGNATURES['waf'].items():
                for pattern in patterns:
                    if re.search(pattern, str(header_dict), re.IGNORECASE):
                        evidence_scores['waf'][waf] += 3  # High confidence from headers
                    if re.search(pattern, content, re.IGNORECASE):
                        evidence_scores['waf'][waf] += 1
        
        # Determine most likely technologies
        if evidence_scores['web_server']:
            server, score = evidence_scores['web_server'].most_common(1)[0]
            stack.web_server = server
            stack.confidence_scores['web_server'] = min(score / (len(responses) * 3), 1.0)
        
        if evidence_scores['framework']:
            framework, score = evidence_scores['framework'].most_common(1)[0]
            stack.web_framework = framework
            stack.confidence_scores['framework'] = min(score / (len(responses) * 3), 1.0)
        
        if evidence_scores['cms']:
            cms, score = evidence_scores['cms'].most_common(1)[0]
            stack.cms_platform = cms
            stack.confidence_scores['cms'] = min(score / (len(responses) * 3), 1.0)
        
        # JavaScript frameworks (can be multiple)
        for js_fw, score in evidence_scores['javascript'].items():
            if score >= 2:  # Threshold
                stack.javascript_frameworks.append(js_fw)
        
        if evidence_scores['waf']:
            waf, score = evidence_scores['waf'].most_common(1)[0]
            stack.waf = waf
            stack.confidence_scores['waf'] = min(score / (len(responses) * 4), 1.0)
        
        # Infer database type from framework
        stack.database_type = self._infer_database_type(stack)
        
        # Infer programming language
        stack.programming_language = self._infer_language(stack)
        
        return stack
    
    def _infer_database_type(self, stack: TechnologyStack) -> Optional[str]:
        """Infer likely database type from framework"""
        framework_db_map = {
            'django': 'postgresql',
            'rails': 'postgresql',
            'laravel': 'mysql',
            'wordpress': 'mysql',
            'drupal': 'mysql',
            'asp.net': 'mssql',
            'spring': 'mysql',
        }
        
        if stack.web_framework in framework_db_map:
            return framework_db_map[stack.web_framework]
        
        if stack.cms_platform in framework_db_map:
            return framework_db_map[stack.cms_platform]
        
        return None
    
    def _infer_language(self, stack: TechnologyStack) -> Optional[str]:
        """Infer programming language from framework"""
        framework_lang_map = {
            'django': 'python',
            'flask': 'python',
            'rails': 'ruby',
            'laravel': 'php',
            'wordpress': 'php',
            'drupal': 'php',
            'express': 'javascript',
            'asp.net': 'c#',
            'spring': 'java',
        }
        
        if stack.web_framework in framework_lang_map:
            return framework_lang_map[stack.web_framework]
        
        if stack.cms_platform in framework_lang_map:
            return framework_lang_map[stack.cms_platform]
        
        return None
    
    def _analyze_behavior(self,
                         responses: List[Any],
                         headers: List[Dict[str, str]],
                         urls: List[str]) -> ApplicationBehavior:
        """Analyze application behavioral patterns"""
        behavior = ApplicationBehavior()
        
        # Analyze response times (if available)
        # This would need actual timing data from responses
        
        # Detect error handling pattern
        error_patterns = []
        for response in responses:
            content = str(response) if response else ""
            if 'error' in content.lower() or 'exception' in content.lower():
                error_patterns.append('verbose_errors')
            elif re.search(r'<h1>[\d]{3}</h1>', content):
                error_patterns.append('generic_error_page')
        
        if error_patterns:
            behavior.error_handling_pattern = Counter(error_patterns).most_common(1)[0][0]
        else:
            behavior.error_handling_pattern = 'silent_errors'
        
        # Detect session management
        session_indicators = []
        for header_dict in headers:
            header_str = str(header_dict).lower()
            if 'cookie' in header_str:
                if 'sessionid' in header_str or 'phpsessid' in header_str:
                    session_indicators.append('cookie_based')
                if 'jwt' in header_str or 'bearer' in header_str:
                    session_indicators.append('token_based')
        
        if session_indicators:
            behavior.session_management = Counter(session_indicators).most_common(1)[0][0]
        
        # Detect security headers
        security_headers_found = []
        for header_dict in headers:
            header_str = str(header_dict).lower()
            if 'x-frame-options' in header_str:
                security_headers_found.append('X-Frame-Options')
            if 'x-xss-protection' in header_str:
                security_headers_found.append('X-XSS-Protection')
            if 'x-content-type-options' in header_str:
                security_headers_found.append('X-Content-Type-Options')
            if 'strict-transport-security' in header_str:
                security_headers_found.append('HSTS')
            if 'content-security-policy' in header_str:
                security_headers_found.append('CSP')
        
        behavior.security_headers = list(set(security_headers_found))
        
        # Detect CSRF protection
        for response in responses:
            content = str(response) if response else ""
            if 'csrf' in content.lower() or 'xsrf' in content.lower():
                behavior.csrf_protection = True
                break
        
        # Detect rate limiting (would need multiple requests to same endpoint)
        # Simplified for now
        
        return behavior
    
    def _generate_vulnerability_profile(self,
                                       tech_stack: TechnologyStack,
                                       behavior: ApplicationBehavior) -> VulnerabilityProfile:
        """Generate vulnerability profile based on tech stack and behavior"""
        profile = VulnerabilityProfile()
        
        # Predict likely vulnerabilities based on tech stack
        if tech_stack.web_framework in self.VULNERABILITY_PATTERNS:
            profile.likely_vulnerabilities.extend(
                self.VULNERABILITY_PATTERNS[tech_stack.web_framework]
            )
        
        if tech_stack.cms_platform in self.VULNERABILITY_PATTERNS:
            profile.likely_vulnerabilities.extend(
                self.VULNERABILITY_PATTERNS[tech_stack.cms_platform]
            )
        
        # Determine attack surface
        profile.attack_surface.append('web_application')
        if tech_stack.waf:
            profile.attack_surface.append('waf_bypass')
        if tech_stack.database_type:
            profile.attack_surface.append('database_injection')
        
        # Assess security posture
        security_score = 0
        
        # Positive security indicators
        if len(behavior.security_headers) >= 3:
            security_score += 2
        if behavior.csrf_protection:
            security_score += 1
        if tech_stack.waf:
            security_score += 2
        if behavior.error_handling_pattern == 'silent_errors':
            security_score += 1
        
        # Negative security indicators
        if behavior.error_handling_pattern == 'verbose_errors':
            security_score -= 2
        if not behavior.security_headers:
            security_score -= 1
        
        # Map score to posture
        if security_score >= 4:
            profile.security_posture = 'hardened'
        elif security_score >= 2:
            profile.security_posture = 'strong'
        elif security_score >= 0:
            profile.security_posture = 'moderate'
        else:
            profile.security_posture = 'weak'
        
        # Recommend techniques
        if profile.security_posture in ['weak', 'moderate']:
            profile.recommended_techniques.extend([
                'error_based_injection',
                'union_based_injection',
                'direct_exploitation'
            ])
        else:
            profile.recommended_techniques.extend([
                'boolean_blind_injection',
                'time_based_injection',
                'advanced_evasion'
            ])
        
        # Techniques to avoid
        if tech_stack.waf:
            profile.avoid_techniques.extend([
                'simple_payloads',
                'high_frequency_requests'
            ])
        
        if behavior.rate_limiting:
            profile.avoid_techniques.append('rapid_scanning')
        
        # Calculate confidence
        avg_confidence = sum(tech_stack.confidence_scores.values()) / max(len(tech_stack.confidence_scores), 1)
        profile.confidence = avg_confidence
        
        return profile
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Based on tech stack
        if self.tech_stack.waf:
            recommendations.append(
                f"WAF detected ({self.tech_stack.waf}): Use advanced evasion techniques and slow down requests"
            )
        
        if self.tech_stack.cms_platform:
            recommendations.append(
                f"CMS detected ({self.tech_stack.cms_platform}): Focus on known plugin/theme vulnerabilities"
            )
        
        # Based on behavior
        if self.behavior.error_handling_pattern == 'verbose_errors':
            recommendations.append(
                "Verbose error messages detected: Error-based injection likely to be effective"
            )
        
        if not self.behavior.security_headers:
            recommendations.append(
                "No security headers detected: Target may have weak security posture"
            )
        
        # Based on vulnerability profile
        if self.vuln_profile.security_posture == 'weak':
            recommendations.append(
                "Weak security posture: Standard techniques should work, start with error-based"
            )
        elif self.vuln_profile.security_posture == 'hardened':
            recommendations.append(
                "Hardened security posture: Use blind injection techniques and advanced evasion"
            )
        
        return recommendations
    
    def _tech_stack_to_dict(self, stack: TechnologyStack) -> Dict[str, Any]:
        """Convert TechnologyStack to dictionary"""
        return {
            'web_server': stack.web_server,
            'web_framework': stack.web_framework,
            'programming_language': stack.programming_language,
            'database_type': stack.database_type,
            'cms_platform': stack.cms_platform,
            'javascript_frameworks': stack.javascript_frameworks,
            'cloud_provider': stack.cloud_provider,
            'cdn': stack.cdn,
            'waf': stack.waf,
            'confidence_scores': stack.confidence_scores,
        }
    
    def _behavior_to_dict(self, behavior: ApplicationBehavior) -> Dict[str, Any]:
        """Convert ApplicationBehavior to dictionary"""
        return {
            'error_handling_pattern': behavior.error_handling_pattern,
            'session_management': behavior.session_management,
            'authentication_type': behavior.authentication_type,
            'csrf_protection': behavior.csrf_protection,
            'security_headers': behavior.security_headers,
            'rate_limiting': behavior.rate_limiting,
        }
    
    def _vuln_profile_to_dict(self, profile: VulnerabilityProfile) -> Dict[str, Any]:
        """Convert VulnerabilityProfile to dictionary"""
        return {
            'likely_vulnerabilities': profile.likely_vulnerabilities,
            'attack_surface': profile.attack_surface,
            'security_posture': profile.security_posture,
            'recommended_techniques': profile.recommended_techniques,
            'avoid_techniques': profile.avoid_techniques,
            'confidence': profile.confidence,
        }
    
    def generate_report(self) -> str:
        """Generate comprehensive context analysis report"""
        report = []
        report.append("=" * 70)
        report.append("SMART CONTEXT ANALYSIS REPORT")
        report.append("=" * 70)
        
        # Technology Stack
        report.append("\n[*] TECHNOLOGY STACK")
        report.append("-" * 70)
        if self.tech_stack.web_server:
            confidence = self.tech_stack.confidence_scores.get('web_server', 0)
            report.append(f"Web Server: {self.tech_stack.web_server} (confidence: {confidence:.1%})")
        if self.tech_stack.web_framework:
            confidence = self.tech_stack.confidence_scores.get('framework', 0)
            report.append(f"Framework: {self.tech_stack.web_framework} (confidence: {confidence:.1%})")
        if self.tech_stack.programming_language:
            report.append(f"Language: {self.tech_stack.programming_language}")
        if self.tech_stack.database_type:
            report.append(f"Database: {self.tech_stack.database_type}")
        if self.tech_stack.cms_platform:
            report.append(f"CMS: {self.tech_stack.cms_platform}")
        if self.tech_stack.waf:
            confidence = self.tech_stack.confidence_scores.get('waf', 0)
            report.append(f"⚠️  WAF: {self.tech_stack.waf} (confidence: {confidence:.1%})")
        
        # Application Behavior
        report.append("\n[*] APPLICATION BEHAVIOR")
        report.append("-" * 70)
        report.append(f"Error Handling: {self.behavior.error_handling_pattern}")
        report.append(f"Session Management: {self.behavior.session_management}")
        report.append(f"CSRF Protection: {'Yes' if self.behavior.csrf_protection else 'No'}")
        if self.behavior.security_headers:
            report.append(f"Security Headers: {', '.join(self.behavior.security_headers)}")
        else:
            report.append("Security Headers: None detected")
        
        # Vulnerability Profile
        report.append("\n[*] VULNERABILITY PROFILE")
        report.append("-" * 70)
        report.append(f"Security Posture: {self.vuln_profile.security_posture.upper()}")
        report.append(f"Confidence: {self.vuln_profile.confidence:.1%}")
        
        if self.vuln_profile.likely_vulnerabilities:
            report.append(f"\nLikely Vulnerabilities:")
            for vuln in set(self.vuln_profile.likely_vulnerabilities):
                report.append(f"  • {vuln.replace('_', ' ').title()}")
        
        if self.vuln_profile.recommended_techniques:
            report.append(f"\nRecommended Techniques:")
            for tech in self.vuln_profile.recommended_techniques:
                report.append(f"  ✓ {tech.replace('_', ' ').title()}")
        
        if self.vuln_profile.avoid_techniques:
            report.append(f"\nAvoid Techniques:")
            for tech in self.vuln_profile.avoid_techniques:
                report.append(f"  ✗ {tech.replace('_', ' ').title()}")
        
        report.append("\n" + "=" * 70)
        return "\n".join(report)

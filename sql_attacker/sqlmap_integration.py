"""
SQLMap Integration Module

Automates SQL injection exploitation using sqlmap through subprocess integration.
Provides a high-level Python API for running sqlmap attacks with various options.

Features:
- Accept raw HTTP requests (GET/POST with headers, cookies, payloads)
- Execute sqlmap in subprocess with comprehensive options
- Support for verbosity, proxying, risk/level tuning, enumeration
- High-level attack orchestration for typical exploitation workflow
- Console output logging and result parsing
- Extensible design for future tools and advanced techniques
"""

import os
import subprocess
import tempfile
import logging
import json
import shutil
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .guardrails import (
    BudgetConfig,
    RequestBudget,
    check_authorization,
    check_scope,
    AuthorizationError,
    ScopeViolationError,
    BudgetExceededError,
)

logger = logging.getLogger(__name__)


class SQLMapRiskLevel(Enum):
    """SQLMap risk levels (1-3)"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class SQLMapLevel(Enum):
    """SQLMap test levels (1-5)"""
    MINIMAL = 1
    BASIC = 2
    INTERMEDIATE = 3
    EXTENSIVE = 4
    COMPREHENSIVE = 5


class EnumerationTarget(Enum):
    """Database enumeration targets"""
    DATABASES = "dbs"
    TABLES = "tables"
    COLUMNS = "columns"
    DUMP = "dump"
    SCHEMA = "schema"
    COUNT = "count"
    ALL = "all"


@dataclass
class SQLMapConfig:
    """Configuration for SQLMap execution"""
    # -----------------------------------------------------------------------
    # Safety guardrails – must be set explicitly before running active tests
    # -----------------------------------------------------------------------
    authorized: bool = False
    """Explicit authorization acknowledgement.  Must be set to True (with
    written permission from the target owner) before any active test will run.
    Defaults to False (fail-closed)."""

    allowed_domains: List[str] = field(default_factory=list)
    """Allowlisted hostnames / wildcard patterns (e.g. ``"*.example.com"``).
    An empty list permits any *public* host while still blocking private IPs."""

    block_private_ips: bool = True
    """Block targets whose host resolves to a private/loopback IP address.
    Set to False only when intentionally testing an internal host that has
    been added to *allowed_domains*."""

    budget: BudgetConfig = field(default_factory=BudgetConfig)
    """Per-target request budget and rate-limit configuration."""

    # Core options
    risk: SQLMapRiskLevel = SQLMapRiskLevel.LOW
    level: SQLMapLevel = SQLMapLevel.MINIMAL
    verbosity: int = 1  # 0-6
    threads: int = 1
    timeout: int = 30
    retries: int = 3
    
    # Proxy settings
    proxy: Optional[str] = None  # e.g., "http://127.0.0.1:8080"
    proxy_cred: Optional[str] = None  # e.g., "user:pass"
    
    # Detection options
    technique: Optional[str] = None  # BEUSTQ (Boolean, Error, Union, Stacked, Time, Query)
    dbms: Optional[str] = None  # mysql, mssql, oracle, postgresql, etc.
    
    # Output options
    output_dir: Optional[str] = None
    batch: bool = True  # Never ask for user input
    flush_session: bool = False
    
    # Additional options
    tamper: Optional[List[str]] = None  # Tamper scripts
    user_agent: Optional[str] = None
    random_agent: bool = False
    delay: float = 0
    safe_url: Optional[str] = None
    safe_freq: int = 0
    
    # Custom arguments
    extra_args: List[str] = field(default_factory=list)


@dataclass
class HTTPRequest:
    """Represents an HTTP request for sqlmap"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None  # POST data
    raw_request: Optional[str] = None  # Raw HTTP request


@dataclass
class SQLMapResult:
    """Result of SQLMap execution"""
    success: bool
    vulnerable: bool
    databases: List[str] = field(default_factory=list)
    tables: Dict[str, List[str]] = field(default_factory=dict)  # db -> tables
    columns: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)  # db -> table -> columns
    dumped_data: Dict[str, Any] = field(default_factory=dict)
    output: str = ""
    error: Optional[str] = None
    log_file: Optional[str] = None
    session_file: Optional[str] = None


class SQLMapAttacker:
    """
    Python integration for sqlmap-based SQL injection exploitation.
    
    Provides a high-level API for running sqlmap attacks with comprehensive
    configuration options and result parsing.
    
    Example:
        >>> attacker = SQLMapAttacker()
        >>> request = HTTPRequest(
        ...     url="http://example.com/login.php?id=1",
        ...     method="GET"
        ... )
        >>> result = attacker.test_injection(request)
        >>> if result.vulnerable:
        ...     print("Vulnerability found!")
        ...     result = attacker.enumerate_databases(request)
        ...     print(f"Databases: {result.databases}")
    """
    
    def __init__(self, config: Optional[SQLMapConfig] = None, sqlmap_path: str = "sqlmap"):
        """
        Initialize SQLMap attacker.
        
        Args:
            config: SQLMap configuration (uses defaults if not provided)
            sqlmap_path: Path to sqlmap executable or command
        """
        self.config = config or SQLMapConfig()
        self.sqlmap_path = sqlmap_path
        self.temp_files = []
        self._budget = RequestBudget(self.config.budget)
        
        # Ensure output directory exists
        if self.config.output_dir:
            os.makedirs(self.config.output_dir, exist_ok=True)
        
        logger.info(f"SQLMapAttacker initialized with sqlmap at: {sqlmap_path}")
    
    def __del__(self):
        """Cleanup temporary files"""
        self._cleanup_temp_files()
    
    def _check_guardrails(self, url: str) -> None:
        """
        Enforce authorization, scope, and budget guardrails before making
        any active request against *url*.

        Raises:
            AuthorizationError: If ``config.authorized`` is not True.
            ScopeViolationError: If *url* is outside the allowed scope.
            BudgetExceededError: If the per-host request budget is exhausted.
        """
        check_authorization(self.config.authorized)
        check_scope(
            url,
            allowed_domains=self.config.allowed_domains,
            block_private_ips=self.config.block_private_ips,
        )
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        self._budget.charge(host)

    def _preflight_check(self, url: str) -> None:
        """
        Perform authorization and scope checks without charging the request
        budget.  Suitable for entry-point methods (like :meth:`orchestrate_attack`)
        that delegate to other methods which each charge the budget themselves.
        """
        check_authorization(self.config.authorized)
        check_scope(
            url,
            allowed_domains=self.config.allowed_domains,
            block_private_ips=self.config.block_private_ips,
        )

    def _cleanup_temp_files(self):
        """Remove temporary files created during execution"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    logger.debug(f"Removed temp file: {temp_file}")
            except Exception as e:
                logger.warning(f"Failed to remove temp file {temp_file}: {e}")
        self.temp_files.clear()
    
    def _extract_url_parts(self, url: str) -> Tuple[str, str]:
        """
        Extract host and path from URL.
        
        Args:
            url: Full URL
            
        Returns:
            Tuple of (host, path)
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path if parsed.path else '/'
        if parsed.query:
            path += '?' + parsed.query
        return host, path
    
    def _save_request_to_file(self, request: HTTPRequest) -> str:
        """
        Save HTTP request to temporary file for sqlmap -r option.
        
        Args:
            request: HTTPRequest object
            
        Returns:
            Path to temporary request file
        """
        # Use raw request if provided
        if request.raw_request:
            content = request.raw_request
        else:
            # Build HTTP request from components
            host, path = self._extract_url_parts(request.url)
            lines = [f"{request.method} {path} HTTP/1.1"]
            
            # Add Host header
            lines.append(f"Host: {host}")
            
            # Add headers
            for header, value in request.headers.items():
                lines.append(f"{header}: {value}")
            
            # Add cookies
            if request.cookies:
                cookie_str = "; ".join([f"{k}={v}" for k, v in request.cookies.items()])
                lines.append(f"Cookie: {cookie_str}")
            
            # Add blank line before body
            lines.append("")
            
            # Add POST data if present
            if request.data and request.method.upper() == "POST":
                from urllib.parse import urlencode
                body = urlencode(request.data)
                lines.append(body)
            
            content = "\r\n".join(lines)
        
        # Write to temporary file
        fd, temp_path = tempfile.mkstemp(suffix=".txt", prefix="sqlmap_request_")
        os.close(fd)
        
        with open(temp_path, 'w') as f:
            f.write(content)
        
        self.temp_files.append(temp_path)
        logger.debug(f"Saved request to: {temp_path}")
        
        return temp_path
    
    def _build_command(self, request: HTTPRequest, 
                       enumeration: Optional[EnumerationTarget] = None,
                       database: Optional[str] = None,
                       table: Optional[str] = None,
                       extra_options: Optional[List[str]] = None) -> List[str]:
        """
        Build sqlmap command line arguments.
        
        Args:
            request: HTTP request object
            enumeration: Enumeration target (dbs, tables, columns, dump, etc.)
            database: Target database name
            table: Target table name
            extra_options: Additional command line options
            
        Returns:
            Command line arguments list
        """
        cmd = [self.sqlmap_path]
        
        # Add request file
        request_file = self._save_request_to_file(request)
        cmd.extend(["-r", request_file])
        
        # Add URL if not using request file
        if not request.raw_request and not request.data:
            cmd.extend(["--url", request.url])
        
        # Core options
        cmd.extend(["--risk", str(self.config.risk.value)])
        cmd.extend(["--level", str(self.config.level.value)])
        cmd.extend(["-v", str(self.config.verbosity)])
        cmd.extend(["--threads", str(self.config.threads)])
        cmd.extend(["--timeout", str(self.config.timeout)])
        cmd.extend(["--retries", str(self.config.retries)])
        
        # Batch mode
        if self.config.batch:
            cmd.append("--batch")
        
        # Flush session
        if self.config.flush_session:
            cmd.append("--flush-session")
        
        # Proxy settings
        if self.config.proxy:
            cmd.extend(["--proxy", self.config.proxy])
        if self.config.proxy_cred:
            cmd.extend(["--proxy-cred", self.config.proxy_cred])
        
        # Detection options
        if self.config.technique:
            cmd.extend(["--technique", self.config.technique])
        if self.config.dbms:
            cmd.extend(["--dbms", self.config.dbms])
        
        # Output directory
        if self.config.output_dir:
            cmd.extend(["--output-dir", self.config.output_dir])
        
        # Tamper scripts
        if self.config.tamper:
            cmd.extend(["--tamper", ",".join(self.config.tamper)])
        
        # User agent
        if self.config.user_agent:
            cmd.extend(["--user-agent", self.config.user_agent])
        elif self.config.random_agent:
            cmd.append("--random-agent")
        
        # Delay
        if self.config.delay > 0:
            cmd.extend(["--delay", str(self.config.delay)])
        
        # Safe URL and frequency
        if self.config.safe_url:
            cmd.extend(["--safe-url", self.config.safe_url])
            cmd.extend(["--safe-freq", str(self.config.safe_freq)])
        
        # Enumeration options
        if enumeration:
            if enumeration == EnumerationTarget.DATABASES:
                cmd.append("--dbs")
            elif enumeration == EnumerationTarget.TABLES:
                cmd.append("--tables")
                if database:
                    cmd.extend(["-D", database])
            elif enumeration == EnumerationTarget.COLUMNS:
                cmd.append("--columns")
                if database:
                    cmd.extend(["-D", database])
                if table:
                    cmd.extend(["-T", table])
            elif enumeration == EnumerationTarget.DUMP:
                cmd.append("--dump")
                if database:
                    cmd.extend(["-D", database])
                if table:
                    cmd.extend(["-T", table])
            elif enumeration == EnumerationTarget.SCHEMA:
                cmd.append("--schema")
            elif enumeration == EnumerationTarget.COUNT:
                cmd.append("--count")
            elif enumeration == EnumerationTarget.ALL:
                cmd.append("--all")
        
        # Extra arguments
        if extra_options:
            cmd.extend(extra_options)
        
        # Custom arguments from config
        cmd.extend(self.config.extra_args)
        
        return cmd
    
    def _execute_sqlmap(self, cmd: List[str]) -> Tuple[int, str, str]:
        """
        Execute sqlmap command and capture output.
        
        Args:
            cmd: Command line arguments
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        logger.info(f"Executing sqlmap: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.config.timeout * 10)
            return_code = process.returncode
            
            logger.debug(f"SQLMap exit code: {return_code}")
            if stdout:
                logger.debug(f"SQLMap stdout: {stdout[:500]}...")
            if stderr:
                logger.debug(f"SQLMap stderr: {stderr[:500]}...")
            
            return return_code, stdout, stderr
            
        except subprocess.TimeoutExpired:
            logger.error("SQLMap execution timed out")
            process.kill()
            return -1, "", "Execution timed out"
        except Exception as e:
            logger.error(f"SQLMap execution failed: {e}")
            return -1, "", str(e)
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse sqlmap output to extract results.
        
        Args:
            output: SQLMap stdout
            
        Returns:
            Dictionary with parsed results
        """
        results = {
            'vulnerable': False,
            'databases': [],
            'tables': {},
            'columns': {},
            'injection_points': [],
            'dbms': None,
        }
        
        # Check if vulnerable
        if "is vulnerable" in output.lower() or "sqlmap identified" in output.lower():
            results['vulnerable'] = True
        
        # Extract databases
        if "available databases" in output.lower():
            # Simple parsing - extract database names
            lines = output.split('\n')
            in_db_section = False
            for line in lines:
                if "available databases" in line.lower():
                    in_db_section = True
                    continue
                if in_db_section:
                    if line.strip().startswith('[*]'):
                        db_name = line.strip()[4:].strip()
                        if db_name:
                            results['databases'].append(db_name)
                    elif not line.strip() or line.strip().startswith('['):
                        in_db_section = False
        
        # Extract DBMS
        if "back-end DBMS:" in output:
            for line in output.split('\n'):
                if "back-end DBMS:" in line:
                    results['dbms'] = line.split("back-end DBMS:")[1].strip()
                    break
        
        return results
    
    def test_injection(self, request: HTTPRequest) -> SQLMapResult:
        """
        Test for SQL injection vulnerability.
        
        Args:
            request: HTTP request to test
            
        Returns:
            SQLMapResult with vulnerability status
        """
        self._check_guardrails(request.url)
        logger.info(f"Testing injection on: {request.url}")
        
        cmd = self._build_command(request)
        return_code, stdout, stderr = self._execute_sqlmap(cmd)
        
        parsed = self._parse_output(stdout)
        
        result = SQLMapResult(
            success=(return_code == 0),
            vulnerable=parsed['vulnerable'],
            output=stdout,
            error=stderr if stderr else None
        )
        
        logger.info(f"Injection test result: vulnerable={result.vulnerable}")
        return result
    
    def enumerate_databases(self, request: HTTPRequest) -> SQLMapResult:
        """
        Enumerate available databases.
        
        Args:
            request: HTTP request
            
        Returns:
            SQLMapResult with database list
        """
        self._check_guardrails(request.url)
        logger.info("Enumerating databases...")
        
        cmd = self._build_command(request, enumeration=EnumerationTarget.DATABASES)
        return_code, stdout, stderr = self._execute_sqlmap(cmd)
        
        parsed = self._parse_output(stdout)
        
        result = SQLMapResult(
            success=(return_code == 0),
            vulnerable=parsed['vulnerable'],
            databases=parsed['databases'],
            output=stdout,
            error=stderr if stderr else None
        )
        
        logger.info(f"Found {len(result.databases)} databases")
        return result
    
    def enumerate_tables(self, request: HTTPRequest, database: str) -> SQLMapResult:
        """
        Enumerate tables in a database.
        
        Args:
            request: HTTP request
            database: Target database name
            
        Returns:
            SQLMapResult with table list
        """
        self._check_guardrails(request.url)
        logger.info(f"Enumerating tables in database: {database}")
        
        cmd = self._build_command(request, enumeration=EnumerationTarget.TABLES, database=database)
        return_code, stdout, stderr = self._execute_sqlmap(cmd)
        
        parsed = self._parse_output(stdout)
        
        # Extract tables from output
        tables = []
        # Check various format patterns for database name
        db_patterns = [
            f"database '{database}'",
            f'database "{database}"',
            f"database: {database}",
            f"database {database}"
        ]
        
        db_found = any(pattern in stdout.lower() for pattern in db_patterns)
        
        if db_found:
            lines = stdout.split('\n')
            in_table_section = False
            for line in lines:
                line_lower = line.lower()
                # Check if we've entered the table section
                if any(pattern in line_lower for pattern in db_patterns) or (
                    database.lower() in line_lower and "table" in line_lower
                ):
                    in_table_section = True
                    continue
                
                if in_table_section:
                    if line.strip().startswith('[*]'):
                        # Extract table name from [*] format
                        table_name = line.strip()[4:].strip()
                        if table_name and table_name not in ['', '+', '-', 'Table']:
                            tables.append(table_name)
                    elif line.strip().startswith('|') and '|' in line:
                        # Extract table name from | format
                        table_name = line.strip().split('|')[-1].strip()
                        if table_name and table_name not in ['', '+', '-', 'Table']:
                            tables.append(table_name)
                    elif not line.strip():
                        # Empty line ends the section
                        in_table_section = False
        
        result = SQLMapResult(
            success=(return_code == 0),
            vulnerable=parsed['vulnerable'],
            tables={database: tables},
            output=stdout,
            error=stderr if stderr else None
        )
        
        logger.info(f"Found {len(tables)} tables in {database}")
        return result
    
    def enumerate_columns(self, request: HTTPRequest, database: str, table: str) -> SQLMapResult:
        """
        Enumerate columns in a table.
        
        Args:
            request: HTTP request
            database: Target database name
            table: Target table name
            
        Returns:
            SQLMapResult with column list
        """
        self._check_guardrails(request.url)
        logger.info(f"Enumerating columns in {database}.{table}")
        
        cmd = self._build_command(request, enumeration=EnumerationTarget.COLUMNS, 
                                 database=database, table=table)
        return_code, stdout, stderr = self._execute_sqlmap(cmd)
        
        parsed = self._parse_output(stdout)
        
        # Extract columns from output
        columns = []
        if f"database '{database}'" in stdout.lower() and f"table '{table}'" in stdout.lower():
            lines = stdout.split('\n')
            in_column_section = False
            for line in lines:
                # Look for column section indicators
                if 'column' in line.lower() and (f"'{table}'" in line.lower() or f'"{table}"' in line.lower()):
                    in_column_section = True
                    continue
                if in_column_section:
                    # Extract column names from various formats
                    line = line.strip()
                    if line.startswith('[*]') or line.startswith('|'):
                        # Format: [*] column_name or | column_name | type |
                        parts = line.split('|')
                        if len(parts) > 1:
                            col_name = parts[1].strip()
                        else:
                            col_name = line[4:].strip() if line.startswith('[*]') else line.strip()
                        
                        if col_name and col_name not in ['', '+', '-', 'Column', 'Type']:
                            columns.append(col_name)
                    elif not line or line.startswith('['):
                        in_column_section = False
        
        result = SQLMapResult(
            success=(return_code == 0),
            vulnerable=parsed['vulnerable'],
            columns={database: {table: columns}},
            output=stdout,
            error=stderr if stderr else None
        )
        
        logger.info(f"Enumerated columns in {database}.{table}")
        return result
    
    def dump_table(self, request: HTTPRequest, database: str, table: str) -> SQLMapResult:
        """
        Dump data from a table.
        
        Args:
            request: HTTP request
            database: Target database name
            table: Target table name
            
        Returns:
            SQLMapResult with dumped data
        """
        self._check_guardrails(request.url)
        logger.info(f"Dumping data from {database}.{table}")
        
        cmd = self._build_command(request, enumeration=EnumerationTarget.DUMP,
                                 database=database, table=table)
        return_code, stdout, stderr = self._execute_sqlmap(cmd)
        
        parsed = self._parse_output(stdout)
        
        result = SQLMapResult(
            success=(return_code == 0),
            vulnerable=parsed['vulnerable'],
            dumped_data={f"{database}.{table}": stdout},
            output=stdout,
            error=stderr if stderr else None
        )
        
        logger.info(f"Dumped data from {database}.{table}")
        return result
    
    def orchestrate_attack(self, request: HTTPRequest, 
                          target_database: Optional[str] = None,
                          target_tables: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        High-level attack orchestration that walks through typical exploitation steps.
        
        This method automates the complete exploitation workflow:
        1. Test for SQL injection vulnerability
        2. Enumerate databases
        3. Enumerate tables in target database(s)
        4. Enumerate columns in target table(s)
        5. Dump data from target table(s)
        
        Args:
            request: HTTP request to exploit
            target_database: Specific database to target (optional)
            target_tables: Specific tables to target (optional)
            
        Returns:
            Dictionary with complete attack results
        """
        self._preflight_check(request.url)
        logger.info("Starting orchestrated attack workflow...")
        
        attack_results = {
            'vulnerability_test': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'dumps': {},
            'success': False,
            'stages_completed': [],
            'errors': []
        }
        
        # Stage 1: Test for vulnerability
        logger.info("Stage 1: Testing for SQL injection vulnerability...")
        vuln_result = self.test_injection(request)
        attack_results['vulnerability_test'] = vuln_result
        attack_results['stages_completed'].append('vulnerability_test')
        
        if not vuln_result.vulnerable:
            logger.warning("No SQL injection vulnerability detected")
            attack_results['errors'].append("No SQL injection vulnerability found")
            return attack_results
        
        logger.info("✓ SQL injection vulnerability confirmed")
        
        # Stage 2: Enumerate databases
        logger.info("Stage 2: Enumerating databases...")
        db_result = self.enumerate_databases(request)
        attack_results['databases'] = db_result.databases
        
        if not db_result.success or not db_result.databases:
            logger.warning("Failed to enumerate databases")
            attack_results['errors'].append("Database enumeration failed")
            return attack_results
        
        attack_results['stages_completed'].append('enumerate_databases')
        logger.info(f"✓ Found {len(db_result.databases)} databases: {db_result.databases}")
        
        # Determine target databases
        if target_database:
            databases_to_target = [target_database] if target_database in db_result.databases else []
        else:
            # Target non-system databases
            system_dbs = ['information_schema', 'mysql', 'performance_schema', 'sys']
            databases_to_target = [db for db in db_result.databases if db.lower() not in system_dbs][:3]
        
        if not databases_to_target:
            logger.warning("No suitable target databases found")
            attack_results['errors'].append("No target databases identified")
            return attack_results
        
        # Stage 3: Enumerate tables
        logger.info(f"Stage 3: Enumerating tables in {len(databases_to_target)} database(s)...")
        for db in databases_to_target:
            logger.info(f"  Enumerating tables in: {db}")
            table_result = self.enumerate_tables(request, db)
            
            if table_result.success and table_result.tables.get(db):
                attack_results['tables'][db] = table_result.tables[db]
                logger.info(f"  ✓ Found {len(table_result.tables[db])} tables in {db}")
            else:
                logger.warning(f"  Failed to enumerate tables in {db}")
                attack_results['errors'].append(f"Table enumeration failed for {db}")
        
        if attack_results['tables']:
            attack_results['stages_completed'].append('enumerate_tables')
        
        # Stage 4 & 5: Enumerate columns and dump data
        logger.info("Stage 4-5: Enumerating columns and dumping data...")
        
        for db, tables in attack_results['tables'].items():
            # Filter tables if target_tables specified
            if target_tables:
                tables_to_dump = [t for t in tables if t in target_tables][:2]
            else:
                tables_to_dump = tables[:2]  # Limit to first 2 tables per database
            
            for table in tables_to_dump:
                logger.info(f"  Processing {db}.{table}")
                
                # Enumerate columns
                col_result = self.enumerate_columns(request, db, table)
                if col_result.success:
                    if db not in attack_results['columns']:
                        attack_results['columns'][db] = {}
                    attack_results['columns'][db][table] = col_result.columns.get(db, {}).get(table, [])
                    logger.info(f"  ✓ Enumerated columns in {db}.{table}")
                
                # Dump data
                dump_result = self.dump_table(request, db, table)
                if dump_result.success:
                    attack_results['dumps'][f"{db}.{table}"] = dump_result.dumped_data
                    logger.info(f"  ✓ Dumped data from {db}.{table}")
                else:
                    logger.warning(f"  Failed to dump {db}.{table}")
                    attack_results['errors'].append(f"Data dump failed for {db}.{table}")
        
        if attack_results['columns']:
            attack_results['stages_completed'].append('enumerate_columns')
        if attack_results['dumps']:
            attack_results['stages_completed'].append('dump_data')
        
        # Mark as successful if we completed at least enumeration
        attack_results['success'] = len(attack_results['stages_completed']) >= 2
        
        logger.info(f"Attack workflow completed. Stages: {attack_results['stages_completed']}")
        return attack_results
    
    def execute_custom_command(self, request: HTTPRequest, extra_options: List[str]) -> SQLMapResult:
        """
        Execute sqlmap with custom command line options.
        
        This method allows for maximum flexibility by accepting arbitrary sqlmap options.
        
        Args:
            request: HTTP request
            extra_options: Additional command line options
            
        Returns:
            SQLMapResult with execution output
        """
        self._check_guardrails(request.url)
        logger.info(f"Executing custom sqlmap command with options: {extra_options}")
        
        cmd = self._build_command(request, extra_options=extra_options)
        return_code, stdout, stderr = self._execute_sqlmap(cmd)
        
        parsed = self._parse_output(stdout)
        
        result = SQLMapResult(
            success=(return_code == 0),
            vulnerable=parsed['vulnerable'],
            output=stdout,
            error=stderr if stderr else None
        )
        
        return result


# Convenience function
def create_attacker(risk: int = 1, level: int = 1, verbosity: int = 1, 
                   proxy: Optional[str] = None,
                   authorized: bool = False,
                   allowed_domains: Optional[List[str]] = None) -> SQLMapAttacker:
    """
    Convenience function to create a SQLMapAttacker instance.
    
    Args:
        risk: Risk level (1-3)
        level: Test level (1-5)
        verbosity: Verbosity level (0-6)
        proxy: Proxy URL (optional)
        authorized: Must be True to run active tests (written permission required).
        allowed_domains: Allowlisted hostnames for scope enforcement (optional).
        
    Returns:
        Configured SQLMapAttacker instance
    """
    config = SQLMapConfig(
        risk=SQLMapRiskLevel(risk),
        level=SQLMapLevel(level),
        verbosity=verbosity,
        proxy=proxy,
        authorized=authorized,
        allowed_domains=allowed_domains or [],
    )
    return SQLMapAttacker(config=config)

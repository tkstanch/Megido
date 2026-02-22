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
import time
from datetime import datetime, timezone
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


class AttackMode(Enum):
    """Operation modes for :meth:`SQLMapAttacker.orchestrate_attack`.

    Modes control which stages are executed and provide safety guardrails:

    Attributes
    ----------
    DETECT_ONLY:
        Only test for SQL injection vulnerability (Stage 1).  No enumeration
        or data retrieval is performed.  Safest mode; suitable for quick
        reconnaissance or CI gating.
    ENUMERATE_SAFE:
        Test for vulnerability and enumerate metadata (databases, tables,
        columns) but **do not dump** table data (Stages 1–4).  Allows
        understanding the attack surface without exfiltrating user data.
    FULL:
        Complete exploitation workflow including data dump (Stages 1–5).
        Still guarded by the existing authorization/scope/budget guardrails.
        Requires explicit authorization (``config.authorized = True``).
    """

    DETECT_ONLY = "detect_only"
    ENUMERATE_SAFE = "enumerate_safe"
    FULL = "full"

    @classmethod
    def from_string(cls, value: str) -> "AttackMode":
        """Parse a mode name (case-insensitive).

        Raises
        ------
        ValueError: If *value* is not a valid mode name.
        """
        try:
            return cls(value.lower().strip())
        except ValueError:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(
                f"Unknown attack mode '{value}'. Valid modes: {valid}"
            )


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_output(value: Any) -> Any:
    """Replace potentially sensitive string output with a redaction marker.

    Non-string values are returned unchanged so that lists and dicts keep
    their structure while their leaf string values are redacted.
    """
    if isinstance(value, str):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: _redact_output(v) for k, v in value.items()}
    if isinstance(value, list):
        return ["[REDACTED]" if isinstance(item, str) else _redact_output(item) for item in value]
    return value


@dataclass
class OrchestrateReport:
    """Structured report produced by :meth:`SQLMapAttacker.orchestrate_attack`.

    Attributes
    ----------
    mode:
        The :class:`AttackMode` used for this run.
    success:
        ``True`` when the attack reached at least two completed stages.
    stages_attempted:
        Ordered list of stage names that were attempted.
    stages_completed:
        Ordered list of stage names that completed successfully.
    per_stage_outputs:
        Mapping of stage name → sanitized output summary.
    databases:
        List of discovered database names.
    tables:
        Mapping of database name → list of table names.
    columns:
        Mapping of database name → table name → list of column names.
    dumps:
        Mapping of ``"db.table"`` → raw dump output (may be redacted on export).
    vulnerability_test:
        The raw :class:`SQLMapResult` from the vulnerability test stage, or
        ``None`` if the stage was not attempted.
    errors:
        List of error messages collected during the run.
    started_at:
        ISO-8601 UTC timestamp when the run started.
    finished_at:
        ISO-8601 UTC timestamp when the run finished.
    duration_seconds:
        Wall-clock duration of the run in seconds.
    """

    mode: AttackMode
    success: bool
    stages_attempted: List[str]
    stages_completed: List[str]
    per_stage_outputs: Dict[str, Any]
    databases: List[str]
    tables: Dict[str, List[str]]
    columns: Dict[str, Any]
    dumps: Dict[str, Any]
    vulnerability_test: Optional[Any]
    errors: List[str]
    started_at: str
    finished_at: str
    duration_seconds: float

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self, *, redact_dumps: bool = True) -> Dict[str, Any]:
        """Serialise to a JSON-compatible dictionary.

        Parameters
        ----------
        redact_dumps:
            When ``True`` (default) the ``dumps`` field is replaced with
            ``"[REDACTED]"`` markers to prevent accidental leakage of
            sensitive table data.
        """
        dumps_value = _redact_output(self.dumps) if redact_dumps else self.dumps
        return {
            "mode": self.mode.value,
            "success": self.success,
            "stages_attempted": list(self.stages_attempted),
            "stages_completed": list(self.stages_completed),
            "per_stage_outputs": self.per_stage_outputs,
            "databases": list(self.databases),
            "tables": {k: list(v) for k, v in self.tables.items()},
            "columns": dict(self.columns),
            "dumps": dumps_value,
            "vulnerability_test": None,  # SQLMapResult is not JSON-serialisable directly
            "errors": list(self.errors),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
        }

    def to_json(self, *, indent: int = 2, redact_dumps: bool = True) -> str:
        """Serialise to a JSON string.

        Parameters
        ----------
        indent:
            JSON indentation level.
        redact_dumps:
            When ``True`` (default) dump data is redacted before export.
        """
        return json.dumps(self.to_dict(redact_dumps=redact_dumps), indent=indent, ensure_ascii=False)

    def to_text(self) -> str:
        """Return a human-readable (Markdown-compatible) summary of the report.

        Dump data is always redacted in the text export.
        """
        lines = [
            "# SQL Attacker Orchestration Report",
            "",
            f"- **Mode**: `{self.mode.value}`",
            f"- **Success**: {self.success}",
            f"- **Started**: {self.started_at}",
            f"- **Finished**: {self.finished_at}",
            f"- **Duration**: {self.duration_seconds:.2f}s",
            "",
            "## Stages",
            f"- Attempted: {', '.join(self.stages_attempted) or '(none)'}",
            f"- Completed: {', '.join(self.stages_completed) or '(none)'}",
        ]
        if self.databases:
            lines += ["", "## Databases", ""]
            for db in self.databases:
                lines.append(f"- `{db}`")
        if self.tables:
            lines += ["", "## Tables", ""]
            for db, tbls in self.tables.items():
                lines.append(f"**{db}**: " + ", ".join(f"`{t}`" for t in tbls))
        if self.columns:
            lines += ["", "## Columns", ""]
            for db, tbl_map in self.columns.items():
                for tbl, cols in tbl_map.items():
                    col_list = ", ".join(f"`{c}`" for c in cols) if cols else "(none)"
                    lines.append(f"**{db}.{tbl}**: {col_list}")
        if self.dumps:
            lines += ["", "## Dump Data", "", "_Dump data is redacted in this export._"]
        if self.errors:
            lines += ["", "## Errors", ""]
            for err in self.errors:
                lines.append(f"- {err}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Backward-compatible dict-like access
    # ------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compatibility."""
        return self.to_dict(redact_dumps=False)[key]

    def __contains__(self, key: str) -> bool:
        """Support ``in`` operator for backward compatibility."""
        return key in self.to_dict(redact_dumps=False)


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
    
    def orchestrate_attack(
        self,
        request: HTTPRequest,
        target_database: Optional[str] = None,
        target_tables: Optional[List[str]] = None,
        mode: AttackMode = AttackMode.FULL,
    ) -> "OrchestrateReport":
        """High-level attack orchestration that walks through typical exploitation steps.

        The *mode* parameter controls which stages are executed:

        * ``AttackMode.DETECT_ONLY`` – Stage 1 only (vulnerability test).
        * ``AttackMode.ENUMERATE_SAFE`` – Stages 1–4 (test + enumerate
          databases / tables / columns).  No data dump.
        * ``AttackMode.FULL`` – All stages 1–5 including data dump.  Still
          guarded by the existing authorization/scope/budget guardrails.

        Args:
            request: HTTP request to exploit.
            target_database: Specific database to target (optional).
            target_tables: Specific tables to target (optional).
            mode: Operation mode controlling which stages run.  Defaults to
                ``AttackMode.FULL`` for backward compatibility.

        Returns:
            :class:`OrchestrateReport` with structured results.  The report
            supports dict-style access (``report['success']``) for backward
            compatibility with code that consumed the previous ``dict`` return.
        """
        self._preflight_check(request.url)
        logger.info(f"Starting orchestrated attack workflow (mode={mode.value})...")

        started_at = _utcnow_iso()
        _start_time = time.monotonic()

        stages_attempted: List[str] = []
        stages_completed: List[str] = []
        per_stage_outputs: Dict[str, Any] = {}
        errors: List[str] = []
        databases: List[str] = []
        tables: Dict[str, List[str]] = {}
        columns: Dict[str, Any] = {}
        dumps: Dict[str, Any] = {}
        vuln_result = None

        # Stage 1: Test for vulnerability
        logger.info("Stage 1: Testing for SQL injection vulnerability...")
        stages_attempted.append('vulnerability_test')
        vuln_result = self.test_injection(request)
        per_stage_outputs['vulnerability_test'] = {
            'vulnerable': vuln_result.vulnerable,
            'output_length': len(vuln_result.output),
        }
        stages_completed.append('vulnerability_test')

        if not vuln_result.vulnerable:
            logger.warning("No SQL injection vulnerability detected")
            errors.append("No SQL injection vulnerability found")
            return self._build_report(
                mode, stages_attempted, stages_completed, per_stage_outputs,
                databases, tables, columns, dumps, vuln_result, errors,
                started_at, _start_time,
            )

        logger.info("✓ SQL injection vulnerability confirmed")

        # Stop here in DETECT_ONLY mode
        if mode == AttackMode.DETECT_ONLY:
            logger.info("Mode is detect_only – skipping enumeration and dump stages.")
            return self._build_report(
                mode, stages_attempted, stages_completed, per_stage_outputs,
                databases, tables, columns, dumps, vuln_result, errors,
                started_at, _start_time,
            )

        # Stage 2: Enumerate databases
        logger.info("Stage 2: Enumerating databases...")
        stages_attempted.append('enumerate_databases')
        db_result = self.enumerate_databases(request)
        databases = db_result.databases
        per_stage_outputs['enumerate_databases'] = {
            'count': len(databases),
            'names': list(databases),
        }

        if not db_result.success or not databases:
            logger.warning("Failed to enumerate databases")
            errors.append("Database enumeration failed")
            return self._build_report(
                mode, stages_attempted, stages_completed, per_stage_outputs,
                databases, tables, columns, dumps, vuln_result, errors,
                started_at, _start_time,
            )

        stages_completed.append('enumerate_databases')
        logger.info(f"✓ Found {len(databases)} databases: {databases}")

        # Determine target databases
        if target_database:
            databases_to_target = [target_database] if target_database in databases else []
        else:
            system_dbs = {'information_schema', 'mysql', 'performance_schema', 'sys'}
            databases_to_target = [db for db in databases if db.lower() not in system_dbs][:3]

        if not databases_to_target:
            logger.warning("No suitable target databases found")
            errors.append("No target databases identified")
            return self._build_report(
                mode, stages_attempted, stages_completed, per_stage_outputs,
                databases, tables, columns, dumps, vuln_result, errors,
                started_at, _start_time,
            )

        # Stage 3: Enumerate tables
        logger.info(f"Stage 3: Enumerating tables in {len(databases_to_target)} database(s)...")
        stages_attempted.append('enumerate_tables')
        for db in databases_to_target:
            logger.info(f"  Enumerating tables in: {db}")
            table_result = self.enumerate_tables(request, db)
            if table_result.success and table_result.tables.get(db):
                tables[db] = table_result.tables[db]
                logger.info(f"  ✓ Found {len(table_result.tables[db])} tables in {db}")
            else:
                logger.warning(f"  Failed to enumerate tables in {db}")
                errors.append(f"Table enumeration failed for {db}")

        if tables:
            per_stage_outputs['enumerate_tables'] = {
                db: list(tbls) for db, tbls in tables.items()
            }
            stages_completed.append('enumerate_tables')

        # Stage 4: Enumerate columns
        logger.info("Stage 4: Enumerating columns...")
        stages_attempted.append('enumerate_columns')
        for db, db_tables in tables.items():
            tables_to_enumerate = (
                [t for t in db_tables if t in target_tables][:2]
                if target_tables else db_tables[:2]
            )
            for table in tables_to_enumerate:
                col_result = self.enumerate_columns(request, db, table)
                if col_result.success:
                    columns.setdefault(db, {})[table] = (
                        col_result.columns.get(db, {}).get(table, [])
                    )
                    logger.info(f"  ✓ Enumerated columns in {db}.{table}")

        if columns:
            per_stage_outputs['enumerate_columns'] = {
                db: {tbl: list(cols) for tbl, cols in tbl_map.items()}
                for db, tbl_map in columns.items()
            }
            stages_completed.append('enumerate_columns')

        # Stop here in ENUMERATE_SAFE mode – no dump
        if mode == AttackMode.ENUMERATE_SAFE:
            logger.info("Mode is enumerate_safe – skipping data dump stage.")
            return self._build_report(
                mode, stages_attempted, stages_completed, per_stage_outputs,
                databases, tables, columns, dumps, vuln_result, errors,
                started_at, _start_time,
            )

        # Stage 5: Dump data (FULL mode only)
        logger.info("Stage 5: Dumping data...")
        stages_attempted.append('dump_data')
        for db, db_tables in tables.items():
            tables_to_dump = (
                [t for t in db_tables if t in target_tables][:2]
                if target_tables else db_tables[:2]
            )
            for table in tables_to_dump:
                logger.info(f"  Dumping {db}.{table}")
                dump_result = self.dump_table(request, db, table)
                if dump_result.success:
                    dumps[f"{db}.{table}"] = dump_result.dumped_data
                    logger.info(f"  ✓ Dumped data from {db}.{table}")
                else:
                    logger.warning(f"  Failed to dump {db}.{table}")
                    errors.append(f"Data dump failed for {db}.{table}")

        if dumps:
            per_stage_outputs['dump_data'] = {"keys": list(dumps.keys())}
            stages_completed.append('dump_data')

        report = self._build_report(
            mode, stages_attempted, stages_completed, per_stage_outputs,
            databases, tables, columns, dumps, vuln_result, errors,
            started_at, _start_time,
        )
        logger.info(f"Attack workflow completed. Stages: {stages_completed}")
        return report

    def _build_report(
        self,
        mode: AttackMode,
        stages_attempted: List[str],
        stages_completed: List[str],
        per_stage_outputs: Dict[str, Any],
        databases: List[str],
        tables: Dict[str, List[str]],
        columns: Dict[str, Any],
        dumps: Dict[str, Any],
        vulnerability_test: Optional[Any],
        errors: List[str],
        started_at: str,
        start_time: float,
    ) -> "OrchestrateReport":
        """Construct an :class:`OrchestrateReport` from collected run data."""
        finished_at = _utcnow_iso()
        duration = time.monotonic() - start_time
        success = len(stages_completed) >= 2
        return OrchestrateReport(
            mode=mode,
            success=success,
            stages_attempted=stages_attempted,
            stages_completed=stages_completed,
            per_stage_outputs=per_stage_outputs,
            databases=databases,
            tables=tables,
            columns=columns,
            dumps=dumps,
            vulnerability_test=vulnerability_test,
            errors=errors,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
        )
    
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

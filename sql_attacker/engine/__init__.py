"""
sql_attacker.engine – Focused sub-modules for the SQL injection testing engine.

Sub-modules
-----------
normalization  – Response normalisation utilities (HTML stripping, token scrubbing,
                 stable fingerprints).
baseline       – Multi-sample baseline collection, median/IQR timing statistics,
                 canary-set scheduling, and baseline caching.
scoring        – Confidence scoring with per-feature contribution breakdown.
adapters       – DB-specific payload adapters (MySQL, PostgreSQL, MSSQL, SQLite,
                 Oracle) with lightweight DBMS fingerprinting.
modes          – Safe operation modes (detect / verify / demonstrate) and policy
                 enforcement.
reporting      – Standardised JSON + SARIF reporting with evidence and remediation.
config         – ScanConfig dataclass centralising all tunable scan parameters.
discovery      – Multi-location injection-point discovery with baseline + differential
                 analysis, boolean/quote-break probes, and error-signature detection.
timeguard      – Time-based confirmation with strict per-host request budgets and
                 configurable delay caps.
"""

from .normalization import (
    strip_html,
    normalize_whitespace,
    scrub_dynamic_tokens,
    normalize_response_body,
    fingerprint,
)
from .baseline import (
    BaselineResult,
    BaselineCollector,
    BaselineCache,
    CanaryScheduler,
)
from .scoring import (
    FeatureContribution,
    ScoringResult,
    compute_confidence,
)
from .adapters import (
    DBType,
    PayloadFamily,
    DBAdapter,
    AdapterRegistry,
    get_adapter,
    fingerprint_from_error,
    TECHNIQUE_ERROR,
    TECHNIQUE_BOOLEAN,
    TECHNIQUE_TIME,
    TECHNIQUE_UNION,
    TECHNIQUE_STACKED,
)
from .modes import (
    OperationMode,
    ModePolicy,
    ModeViolationError,
)
from .reporting import (
    Evidence,
    Finding,
    ReportBuilder,
)
from .config import ScanConfig
from .discovery import (
    InjectionLocation,
    InjectionPoint,
    ProbeSet,
    ResponseComparator,
    ComparisonResult,
    DiscoveryScanner,
    detect_sql_errors,
    ErrorSignature,
)
from .timeguard import (
    TimedConfirmation,
    TimeBasedResult,
    PerHostBudget,
    build_sleep_payload,
)

__all__ = [
    # normalization
    "strip_html",
    "normalize_whitespace",
    "scrub_dynamic_tokens",
    "normalize_response_body",
    "fingerprint",
    # baseline
    "BaselineResult",
    "BaselineCollector",
    "BaselineCache",
    "CanaryScheduler",
    # scoring
    "FeatureContribution",
    "ScoringResult",
    "compute_confidence",
    # adapters
    "DBType",
    "PayloadFamily",
    "DBAdapter",
    "AdapterRegistry",
    "get_adapter",
    "fingerprint_from_error",
    "TECHNIQUE_ERROR",
    "TECHNIQUE_BOOLEAN",
    "TECHNIQUE_TIME",
    "TECHNIQUE_UNION",
    "TECHNIQUE_STACKED",
    # modes
    "OperationMode",
    "ModePolicy",
    "ModeViolationError",
    # reporting
    "Evidence",
    "Finding",
    "ReportBuilder",
    # config
    "ScanConfig",
    # discovery
    "InjectionLocation",
    "InjectionPoint",
    "ProbeSet",
    "ResponseComparator",
    "ComparisonResult",
    "DiscoveryScanner",
    "detect_sql_errors",
    "ErrorSignature",
    # timeguard
    "TimedConfirmation",
    "TimeBasedResult",
    "PerHostBudget",
    "build_sleep_payload",
]

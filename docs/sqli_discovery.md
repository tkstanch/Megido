# SQLi Discovery Engine

This document describes how the SQL injection discovery subsystem works,
its configuration options, and the safety constraints built into the engine.

## Overview

The `sql_attacker.engine` package provides a focused, **detection-only** SQL
injection discovery engine.  The goal is to *identify* likely injection points
with high accuracy and low false-positive rates — **not** to extract data.

### Architecture

```
sql_attacker/engine/
├── config.py         ScanConfig – all tunable parameters
├── discovery.py      DiscoveryScanner – multi-location probe orchestrator
├── timeguard.py      TimedConfirmation – opt-in time-based confirmation
├── adapters.py       DB-specific payload families + DBMS fingerprinting
├── baseline.py       Baseline collection, canary scheduling, confirmation
├── normalization.py  Response normalisation (HTML stripping, token scrubbing)
├── scoring.py        Confidence scoring with per-feature contributions
├── reporting.py      Structured JSON + SARIF output
└── modes.py          Operation-mode policy enforcement (detect/verify/demonstrate)
```

---

## Discovery Process

### 1. Injection-point Enumeration

`DiscoveryScanner` inspects the request and enumerates every testable
parameter based on the active `ScanConfig`:

| Location | Config flag | Default |
|---|---|---|
| URL query parameters | `inject_query_params` | `True` |
| Form-encoded POST body | `inject_form_params` | `True` |
| JSON POST body | `inject_json_params` | `True` |
| Selected HTTP headers | `inject_headers` | **`False`** (opt-in) |

Header injection is disabled by default because it is noisier and has a
higher false-positive risk.  Enable it explicitly and configure
`injectable_headers` to target specific headers.

### 2. Baseline Collection

For each injection point a **baseline request** is sent with the original
(unmodified) parameter values.  The response body is normalised
(HTML stripped, dynamic tokens scrubbed) and its length and status code
are recorded as reference values.

### 3. Probe Injection

Three categories of probe payloads are sent per injection point:

| Category | Purpose |
|---|---|
| **Quote-break probes** (`'`, `"`, `''`, …) | Cause a SQL syntax error in vulnerable backends |
| **Boolean-true probes** (`' OR '1'='1`, `' OR 1=1--`, …) | Should return the same/more results as baseline |
| **Boolean-false probes** (`' AND '1'='2`, `' AND 1=2--`, …) | Should return fewer/no results than baseline |

The number of boolean probe pairs is controlled by `boolean_probe_count`
(default: 2).

### 4. Differential Analysis

Each probe response is compared against the baseline using four metrics:

| Signal | Weight |
|---|---|
| **SQL error pattern** – SQL error message matched | 0.90 |
| **Status code change** – 5xx error | 1.0 (scaled) |
| **Content length delta** – response size changed significantly | 0.60 |
| **Jaccard similarity drop** – text content diverged from baseline | 0.65 |
| **Boolean differential** – true-probe similar to baseline, false-probe not | 0.75 |

Tolerance thresholds:
- `length_delta_threshold` (default: 50 chars)
- `similarity_threshold` (default: 0.10 Jaccard drop)

### 5. Error-based SQL Fingerprinting

The engine maintains a curated set of regex signatures for common DBMS:

- **MySQL / MariaDB** – `You have an error in your SQL syntax`, `com.mysql.jdbc`, …
- **PostgreSQL** – `PSQLException`, `ERROR: syntax error at or near`, …
- **MSSQL / SQL Server** – `Microsoft OLE DB Provider for SQL Server`, `Unclosed quotation mark`, …
- **SQLite** – `unrecognized token:`, `SQLite.Exception`, …
- **Oracle** – `ORA-\d{5}`, `quoted string not properly terminated`, …

Matched signatures are recorded in the finding's evidence bundle, including
which specific signatures matched.

### 6. Confidence Scoring

All detected signals are combined using a probabilistic union formula
(`1 − Π(1 − wᵢ)`) via `scoring.compute_confidence()`.  The final verdict is:

| Verdict | Score threshold | Min features |
|---|---|---|
| `confirmed` | ≥ 0.70 | ≥ 2 distinct features |
| `likely` | ≥ 0.45 | 1+ |
| `uncertain` | < 0.45 | any |

---

## Time-based Confirmation

Time-based detection is **opt-in** and should only be used when other
signals are inconclusive.  Enable it via `ScanConfig(time_based_enabled=True)`.

### How It Works

`TimedConfirmation` injects sleep payloads (e.g. `' AND SLEEP(3)--`,
`'; WAITFOR DELAY '0:0:3'--`) and measures the response time.  A confirmation
is only issued when:

```
median_injected_ms >= baseline_median_ms + 0.8 × expected_delay_ms
```

Measurements are repeated `repetitions` times (default: 3) per payload
template to reduce false positives from network jitter.

### Guardrails

| Setting | Default | Purpose |
|---|---|---|
| `time_based_max_delay_seconds` | 3 s | Maximum SLEEP/WAITFOR delay per probe |
| `time_based_max_requests_per_endpoint` | 6 | Probe limit per injection point |
| `time_based_max_requests_per_host` | 20 | Total time-based budget per host |

The `PerHostBudget` class tracks consumption across all injection points on a
host.  Once the budget is exhausted, no further time-based probes are sent.

---

## WAF / Rate-limit Resilience

The `http_utils` module (used by the existing `SQLInjectionEngine`) detects:

- **Block pages** (403, 406, or body markers like "access denied", "Incapsula", "AWS WAF")
- **Rate limiting** (429 with `Retry-After` header)
- **JS challenges** (Cloudflare, hCaptcha, Turnstile)

The `DiscoveryScanner` uses a per-host request budget (`per_host_request_budget`,
default: 200) and handles `None` responses gracefully, stopping probing when
requests consistently fail.

---

## Safety Constraints

1. **Detection only** – the engine never extracts data.  The `DEMONSTRATE` mode
   (which retrieves a DB version string) is opt-in and strictly bounded.

2. **Per-host budgets** – every host has a configurable maximum request count.

3. **Sensitive-value redaction** – headers listed in `redact_sensitive_headers`
   (default includes `Authorization`, `Cookie`, `X-Auth-Token`) are redacted
   from all log messages and evidence records.

4. **Payload redaction** – set `redact_payloads_in_logs=True` to suppress
   injection payloads from debug logs.

5. **Time-based opt-in** – time-based detection is disabled by default to
   prevent slow, budget-burning scans on safe targets.

6. **Config validation** – `ScanConfig.validate()` enforces:
   - `time_based_max_delay_seconds ≤ 30`
   - `similarity_threshold ∈ [0, 1]`
   - Positive timeout and sample-count values

---

## Configuration Reference

```python
from sql_attacker.engine.config import ScanConfig

cfg = ScanConfig(
    # ── General ──────────────────────────────────────────
    baseline_samples=3,              # benign samples per injection point
    max_concurrent_requests=1,       # sequential by default (safest)
    request_timeout_seconds=10.0,

    # ── Retry / back-off ─────────────────────────────────
    retry_max_attempts=2,
    retry_base_delay_seconds=0.5,
    retry_max_delay_seconds=8.0,

    # ── Safety budgets ────────────────────────────────────
    per_host_request_budget=200,

    # ── Injection-point locations ─────────────────────────
    inject_query_params=True,
    inject_form_params=True,
    inject_json_params=True,
    inject_headers=False,            # opt-in: set True + configure below
    injectable_headers=[
        "X-Forwarded-For",
        "User-Agent",
        "Referer",
    ],

    # ── Redaction ─────────────────────────────────────────
    redact_sensitive_headers=["Authorization", "Cookie"],
    redact_payloads_in_logs=False,

    # ── Time-based (opt-in) ───────────────────────────────
    time_based_enabled=False,        # must be explicitly set True
    time_based_max_delay_seconds=3.0,
    time_based_max_requests_per_endpoint=6,
    time_based_max_requests_per_host=20,

    # ── Probe tuning ──────────────────────────────────────
    boolean_probe_count=2,
    length_delta_threshold=50,
    similarity_threshold=0.10,
    error_detection_enabled=True,
)
cfg.validate()
```

---

## Quick Start

```python
import requests
from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.discovery import DiscoveryScanner
from sql_attacker.engine.reporting import ReportBuilder

def request_fn(url, method, params, data, json_data, headers, cookies):
    """Thin wrapper around requests.request."""
    return requests.request(
        method, url,
        params=params,
        data=data,
        json=json_data,
        headers=headers,
        cookies=cookies,
        timeout=10,
        allow_redirects=True,
    )

cfg = ScanConfig(
    time_based_enabled=False,  # safe default
)

scanner = DiscoveryScanner(request_fn=request_fn, config=cfg)

findings = scanner.scan(
    url="https://example.com/search",
    method="GET",
    params={"q": "test", "category": "1"},
)

builder = ReportBuilder(target_url="https://example.com/search")
for f in findings:
    builder.add_finding(f)
    print(f"[{f.verdict}] {f.parameter} – {f.technique} ({f.db_type}, {f.confidence:.0%})")

builder.finish()
print(builder.to_json())
```

### With time-based confirmation

```python
from sql_attacker.engine.timeguard import TimedConfirmation

# Only run this when other signals are inconclusive
cfg_timed = ScanConfig(
    time_based_enabled=True,
    time_based_max_delay_seconds=3,
    time_based_max_requests_per_host=20,
)
tc = TimedConfirmation(request_fn=request_fn, config=cfg_timed)
result = tc.confirm(
    url="https://example.com/search",
    method="GET",
    params={"q": "test"},
    inject_param="q",
    inject_location="query_param",
    baseline_median_ms=150.0,   # pre-measured from scanner
)
if result.confirmed:
    print(f"Confirmed via time-based detection! delay_factor={result.delay_factor:.1f}×")
```

---

## Running Tests

```bash
# Engine unit tests (no Django required)
python -m pytest sql_attacker/engine/test_engine_modules.py -v
python -m pytest sql_attacker/engine/test_discovery.py -v

# Django-based integration tests
python manage.py test sql_attacker
```

All engine tests are pure-Python and do not require Django, a database, or
network access.  They are deterministic and CI-safe.

# Megido Security Testing Platform

[...]existing intro sections...]

## 🛡️ SQLi Engine: Accuracy, Modularity, Safety & Reporting

The `sql_attacker/engine/` package provides a focused, modular engine for
accurate SQL injection testing.  It is designed to reduce false positives,
operate safely by default, and produce machine-readable reports.

### Verification Profiles

The simplest way to control scan invasiveness is via a **verification profile**
(the recommended user-facing API):

| Profile | Maps to mode | Payloads sent | Verification loop | Demonstration |
|---------|-------------|--------------|-------------------|---------------|
| `detect_only` | `detect` | ✅ | ❌ | ❌ |
| `verify_safe` | `verify` | ✅ | ✅ | ❌ |

```python
from sql_attacker.engine import VerificationProfile, ModePolicy

# Safest default — detection only, no confirmation loops
profile = VerificationProfile.DETECT_ONLY
policy = ModePolicy(profile.to_operation_mode())

# Confirm findings with repeated benign-control probes
profile = VerificationProfile.VERIFY_SAFE
policy = ModePolicy(profile.to_operation_mode())

# Parse from config / CLI
profile = VerificationProfile.from_string("verify_safe")
```

### Operation Modes

Every test run operates under an explicit **mode** that controls what the
engine is allowed to do.  The default is `detect` (safest).

| Mode | Payloads sent | Verification loop | Demonstration |
|------|--------------|-------------------|---------------|
| `detect` | ✅ | ❌ | ❌ |
| `verify` | ✅ | ✅ | ❌ |
| `demonstrate` | ✅ | ✅ | ✅ (bounded + redacted) |

> **Note:** Unrestricted data exfiltration is **never** permitted regardless
> of mode.  In `demonstrate` mode the engine retrieves at most the database
> version string, which is truncated and redacted before inclusion in the
> report.

```python
from sql_attacker.engine import OperationMode, ModePolicy

# Default (safest) – detect only
policy = ModePolicy()

# Confirm findings via repeated probes + benign control
policy = ModePolicy(OperationMode.VERIFY)

# Show exploitability with bounded, redacted version-string retrieval
policy = ModePolicy(OperationMode.DEMONSTRATE)

# Fail-closed guards
policy.assert_may_detect()       # always passes
policy.assert_may_verify()       # raises ModeViolationError in DETECT mode
policy.assert_may_exfiltrate()   # ALWAYS raises ModeViolationError
```

### Safety Budgets

`ScanConfig` enforces strict safety budgets to prevent unintentional
denial-of-service or account lockout:

```python
from sql_attacker.engine import ScanConfig

cfg = ScanConfig(
    # Per-host cap: abort after 200 requests to any single host
    per_host_request_budget=200,

    # Global session cap: abort the entire scan after 1000 total requests
    global_request_cap=1000,

    # Kill-switch: abort after 10 consecutive 5xx/429/WAF-challenge responses
    error_spike_abort_threshold=10,

    # Concurrency cap (default: 1 = sequential/safest)
    max_concurrent_requests=2,

    # WAF lockout detection: abort an endpoint after 3 consecutive 403/429s
    waf_abort_threshold=3,
)
cfg.validate()  # raises ValueError if any value is out of range
```

### Injection Vector Coverage

All injection locations are **opt-in** except query params and body params:

```python
cfg = ScanConfig(
    inject_query_params=True,   # default: on
    inject_form_params=True,    # default: on
    inject_json_params=True,    # default: on
    inject_headers=False,       # opt-in (noisier, higher FP risk)
    inject_cookies=False,       # opt-in
    inject_path_segments=False, # opt-in (may cause 404s)
    inject_graphql_vars=False,  # opt-in (requires inject_json_params=True)
)
```

### Deterministic / Reproducible Payload Selection

Build on PR #172's `payload_seed` and `max_payloads_per_param` to produce
identical probe sequences across runs:

```python
cfg = ScanConfig(
    max_payloads_per_param=20,
    payload_seed=42,
)
```

### EvidencePack – Client-ready PoC Evidence

Every confirmed finding can be captured as a self-contained
:class:`~sql_attacker.engine.evidence_pack.EvidencePack`:

```python
from sql_attacker.engine import EvidencePack, RequestSpec, TimingStats

pack = EvidencePack(
    finding_id="abc-123",
    url="https://example.com/search",
    request=RequestSpec(
        method="GET",
        url="https://example.com/search",
        params={"q": "' OR 1=1--"},
        headers={"Authorization": "Bearer <token>"},  # redacted on save
    ),
    baseline_signature="aabbcc112233",     # SHA-256 fingerprint of baseline body
    mutated_signature="ddeeff445566",      # SHA-256 fingerprint of injected body
    diff_summary={
        "changed": True,
        "ratio": 0.42,
        "length_delta": 312,
        "summary": "Substantial difference detected.",
    },
    timing_stats=TimingStats(samples_ms=[120.0, 118.5, 122.0]),  # median/mean/stddev
    payload_ids=["sqli-bool-mysql-001"],
    deterministic_seed=42,
    parameter="q",
    parameter_location="query_param",
    technique="boolean",
    db_type="mysql",
)

# Persist to disk as JSON (parent dirs created automatically)
pack.save("/var/megido/evidence/finding_abc-123.json")

# Load back
loaded = EvidencePack.load("/var/megido/evidence/finding_abc-123.json")

# Auto-generated reproduction scripts (secrets redacted)
print(pack.to_curl())
print(pack.to_python_repro())
```

**EvidencePack JSON schema (v1.0):**
```json
{
  "schema_version": "1.0",
  "finding_id": "<uuid>",
  "url": "https://...",
  "parameter": "q",
  "technique": "boolean",
  "db_type": "mysql",
  "captured_at": "2026-01-01T00:00:00Z",
  "request": { "method": "GET", "url": "...", "params": {...}, "headers": {...} },
  "baseline_signature": "aabbcc112233",
  "mutated_signature":  "ddeeff445566",
  "diff_summary": { "changed": true, "ratio": 0.42, "length_delta": 312 },
  "timing_stats": { "samples_ms": [...], "median_ms": 120.0, "mean_ms": 120.2, "stddev_ms": 1.8 },
  "payload_ids": ["sqli-bool-mysql-001"],
  "deterministic_seed": 42,
  "repro": {
    "curl": "curl -s ... 'https://example.com/search?q=...'",
    "python": "#!/usr/bin/env python3\n..."
  }
}
```

### Evidence Storage

Use `LocalFileStorage` to persist packs to disk:

```python
from sql_attacker.engine import LocalFileStorage

store = LocalFileStorage("/var/megido/evidence")
store.save(pack)                     # writes finding_<id>.json
store.load("abc-123")               # returns EvidencePack
store.list_all()                    # → [EvidencePack, ...] sorted by captured_at
store.delete("abc-123")             # removes the file
```

Custom back-ends (e.g. a hosted service) can be added by subclassing
`EvidenceStorage`:

```python
from sql_attacker.engine import EvidenceStorage, EvidencePack
from typing import List

class MyRemoteStorage(EvidenceStorage):
    def save(self, pack: EvidencePack) -> str: ...
    def load(self, finding_id: str) -> EvidencePack: ...
    def list_all(self) -> List[EvidencePack]: ...
    def delete(self, finding_id: str) -> bool: ...
```

### Confidence Levels

Each finding carries a numeric **confidence score** (0–1) and a verdict:

| Verdict | Score threshold | Minimum active features |
|---------|-----------------|-------------------------|
| `confirmed` | ≥ 0.70 | ≥ 2 |
| `likely` | ≥ 0.45 | 1+ |
| `uncertain` | < 0.45 | any |

Feature weights (highest contribution first):

| Feature | Weight |
|---------|--------|
| `sql_error_pattern` | 0.90 |
| `timing_delta_significant` | 0.80 |
| `repeatability` | 0.70 |
| `boolean_diff` | 0.75 |
| `similarity_delta` | 0.65 |
| `content_change` | 0.60 |
| `http_error_code` | 0.50 |
| `js_error` | 0.50 |
| `benign_control_negative` | 0.40 |

```python
from sql_attacker.engine import compute_confidence

result = compute_confidence({
    "sql_error_pattern": 1.0,
    "boolean_diff": 1.0,
})
print(result.score, result.verdict)
# → 0.9775 confirmed
```

### DB-Specific Adapters

The adapter registry selects payload families based on the detected DBMS:

```python
from sql_attacker.engine import (
    AdapterRegistry, DBType,
    TECHNIQUE_ERROR, TECHNIQUE_BOOLEAN, TECHNIQUE_TIME,
    fingerprint_from_error, get_adapter,
)

registry = AdapterRegistry()

# Auto-detect DBMS from an error response
db_type, adapter = registry.fingerprint_from_error(response_body)

# Or select explicitly
adapter = get_adapter(DBType.POSTGRESQL)
error_payloads  = adapter.get_payloads(TECHNIQUE_ERROR)
boolean_payloads = adapter.get_payloads(TECHNIQUE_BOOLEAN)
time_payloads   = adapter.get_payloads(TECHNIQUE_TIME)
```

Supported database types: `mysql`, `postgresql`, `mssql`, `sqlite`, `oracle`, `unknown`.

### Standardised Reports (JSON + SARIF)

Every scan can emit a machine-readable report:

```python
from sql_attacker.engine import ReportBuilder, Finding, Evidence, TECHNIQUE_ERROR

builder = ReportBuilder(target_url="https://example.com/search")
builder.add_finding(Finding(
    parameter="q",
    technique=TECHNIQUE_ERROR,
    db_type="mysql",
    confidence=0.92,
    verdict="confirmed",
    evidence=[Evidence(
        payload="' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        request_summary="GET /search?q=%27+AND+EXTRACTVALUE... HTTP/1.1",
        response_body_excerpt="XPATH syntax error: '~5.7.38'",
    )],
    remediation=(
        "Use parameterised queries / prepared statements. "
        "Never interpolate user input directly into SQL."
    ),
))
builder.finish()

# JSON report
json_str = builder.to_json()

# SARIF 2.1.0 report (compatible with GitHub Advanced Security, Azure DevOps, etc.)
sarif_str = builder.to_sarif()
```

**JSON report schema (v1.0):**

```json
{
  "schema_version": "1.0",
  "scan_id": "<uuid>",
  "target_url": "https://...",
  "started_at": "2026-01-01T00:00:00Z",
  "finished_at": "2026-01-01T00:01:00Z",
  "summary": { "total": 1, "by_verdict": {"confirmed": 1}, "by_severity": {"high": 1} },
  "findings": [
    {
      "finding_id": "<uuid>",
      "parameter": "q",
      "url": "https://...",
      "technique": "error",
      "db_type": "mysql",
      "confidence": 0.92,
      "verdict": "confirmed",
      "severity": "high",
      "cwe": "CWE-89",
      "evidence": [ { "payload": "...", "request_summary": "...", ... } ],
      "remediation": "..."
    }
  ]
}
```

## 🔬 Advanced Multi-Engine Scanner Architecture 🚀 ⭐ LATEST

Megido features an **enterprise-grade multi-engine plugin architecture** with **5 production-ready scanner engines**, Django integration, REST API, and advanced CLI:

### 🥷 Advanced Stealth & Exploitation Features ⭐ NEW

Megido now includes **professional-grade stealth capabilities** for realistic penetration testing:

#### Stealth Engine
- ✅ **User-Agent Rotation** - 20+ authentic browser profiles (Chrome, Firefox, Safari, Edge)
- ✅ **Header Randomization** - Dynamic Accept, Accept-Language, Sec-Fetch-* headers
- ✅ **Request Timing** - Configurable delays with jitter to evade rate limiting
- ✅ **Session Rotation** - Automatic cookie and session ID management
- ✅ **Parameter Randomization** - Random URL parameter ordering
- ✅ **Payload Encoding** - Multiple encoding variations (URL, HTML, Unicode, Base64)

#### Adaptive Payload Engine
- ✅ **Context Detection** - Automatic injection context identification (HTML, JSON, JS, SVG)
- ✅ **Smart Payload Selection** - Context-aware payload generation
- ✅ **Response Analysis** - Reflection detection and filter identification
- ✅ **Filter Evasion** - Automatic bypass technique suggestions
- ✅ **WAF Detection** - Identify Cloudflare, Akamai, AWS WAF, Imperva, etc.
- ✅ **Multi-Encoding** - Generate encoded payload variants

#### Callback Verification System
- ✅ **Built-in Callback Server** - Local HTTP server for OOB verification
- ✅ **ngrok Integration** - Automatic tunnel setup for remote testing
- ✅ **External Services** - Burp Collaborator, Interactsh support
- ✅ **Interaction Logging** - Detailed callback metadata capture
- ✅ **Proof of Exploitation** - Verified exploitation evidence

**Quick Start with Stealth:**
```python
from scanner.scan_engine import ScanEngine

# Scan with maximum stealth
findings = ScanEngine().scan('https://target.com', {
    'enable_stealth': True,
    'stealth_min_delay': 2.0,
    'stealth_max_delay': 5.0,
    'enable_callback_verification': True,
    'callback_use_ngrok': True,
})
```

**Scanning ngrok URLs:**
```python
# Scan locally exposed applications via ngrok tunnels
findings = ScanEngine().scan('https://abc123.ngrok-free.app', {
    'verify_ssl': True,  # ngrok provides valid SSL certificates
    'timeout': 30,       # Allow extra time for ngrok latency
})
```

**See:** 
- [STEALTH_FEATURES_GUIDE.md](STEALTH_FEATURES_GUIDE.md) for stealth documentation
- [docs/NGROK_SCANNING_GUIDE.md](docs/NGROK_SCANNING_GUIDE.md) for ngrok scanning guide ⭐ NEW

### 🎯 Scanner Engines (5 Total)

- **🔍 SAST** - Static Application Security Testing
  - **Bandit** - Python security linter with CWE mapping
  - **Semgrep** - Multi-language analysis (Python, JS, Java, Go, C, Ruby, PHP, etc.) ⭐ NEW
- **📦 SCA** - Software Composition Analysis  
  - **Trivy** - CVE detection in dependencies, containers, and IaC ⭐ NEW
- **🔐 Secrets** - Credential Detection
  - **GitLeaks** - Find hardcoded API keys, passwords, tokens
- **🎯 Custom** - Extensible framework for any analyzer

### 💎 Enterprise Features ⭐ LATEST ENHANCEMENTS

- ✅ **Django Integration** - Complete database persistence with 3 new models
- ✅ **RESTful API** - Full CRUD operations via Django REST Framework
- ✅ **Advanced CLI** - Professional command-line tool with colored output
- ✅ **Multiple Report Formats** - JSON, HTML, CSV exports
- ✅ **Deduplication** - Automatic finding deduplication with SHA-256 hashing
- ✅ **Review Workflow** - Mark findings as confirmed/false positive/fixed
- ✅ **Historical Tracking** - Complete scan history with execution details
- ✅ **Parallel Execution** - Run multiple engines concurrently (4 workers default)
- ✅ **Smart Filtering** - By severity, engine, category, duplicates
- ✅ **Config Management** - YAML/JSON configuration with hot-reload

### 🚀 Quick Start

**CLI (Recommended):**
```bash
# List available engines
python advanced_scanner_cli.py list-engines

# Run comprehensive scan
python advanced_scanner_cli.py scan /path/to/code

# Run specific engines
python advanced_scanner_cli.py scan /path/to/code --engines bandit semgrep trivy

# Run by category
python advanced_scanner_cli.py scan /path/to/code --categories sast secrets

# View results
python advanced_scanner_cli.py show-scan 1 --severity high --verbose

# Export HTML report
python advanced_scanner_cli.py export-report 1 --format html --output report.html
```

**Python API:**
```python
from scanner.engine_plugins.engine_service import EngineService

service = EngineService()

# Create and execute scan
scan = service.create_scan(target_path='/path/to/code', categories=['sast', 'sca'])
result = service.execute_scan(scan)

# Get findings
findings = service.get_scan_findings(scan_id=scan.id, severity='high')
```

**REST API:**
```bash
# Create and execute scan
curl -X POST http://localhost:8000/api/engine-scans/ \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/path/to/code", "execute_immediately": true}'

# Get findings
curl http://localhost:8000/api/engine-scans/1/findings/?severity=high

# List scan history
curl http://localhost:8000/api/engine-scans/history/
```

### 📚 Documentation

- **[ADVANCED_ENHANCEMENTS_SUMMARY.md](ADVANCED_ENHANCEMENTS_SUMMARY.md)** - Complete implementation guide ⭐ NEW
- **[MULTI_ENGINE_PLUGIN_GUIDE.md](MULTI_ENGINE_PLUGIN_GUIDE.md)** - User guide for plugin architecture
- **[MULTI_ENGINE_ARCHITECTURE_SUMMARY.md](MULTI_ENGINE_ARCHITECTURE_SUMMARY.md)** - Technical architecture

### 🎯 API Endpoints

```
GET    /api/engines/                       # List all engines
GET    /api/engines/categories/            # Get categories
POST   /api/engine-scans/                  # Create scan
POST   /api/engine-scans/{id}/execute/     # Execute scan
GET    /api/engine-scans/{id}/summary/     # Get summary
GET    /api/engine-scans/{id}/findings/    # Get findings with filters
GET    /api/engine-scans/history/          # Scan history
GET    /api/engine-findings/               # List all findings
POST   /api/engine-findings/{id}/mark_status/ # Update finding status
```

## ⚡ Automated Setup (All Platforms)

Megido provides a **universal, automated setup experience** for Windows, macOS, and Linux users. You can download, install, and run the app with a single command using the provided scripts:

- **Cross-platform Installation Guide:** See [LOCAL_INSTALLATION_GUIDE.md](LOCAL_INSTALLATION_GUIDE.md) (recommended for new users)
- **Linux/macOS:**
  ```bash
  bash setup.sh
  ```
- **Windows (PowerShell):**
  ```powershell
  ./setup.ps1
  ```
- **Docker Quick Start (All OS):**
  ```bash
  git clone https://github.com/tkstanch/Megido.git && cd Megido && docker compose up --build
  ```

These scripts will:
- Install dependencies
- Configure ClamAV and Python (or Docker as selected)
- Run database migrations, create an admin user (admin/admin by default)
- Start the application at http://localhost:8000

> For full details, troubleshooting, and all platform instructions, please see [LOCAL_INSTALLATION_GUIDE.md](LOCAL_INSTALLATION_GUIDE.md).

## 🎨 Modern UI with Professional Design System

Megido features a **professional, classic, and beautiful user interface** built with an advanced Tailwind CSS design system, offering enterprise-grade elegance and responsiveness:

### ✨ Latest UI Features (v2.4 Professional Classic) 💼

#### Professional Classic Design (v2.4) ⭐ NEW
- 💼 **Timeless Elegance** - Classic design patterns that never go out of style
- 🎨 **Refined Typography** - Professional letter-spacing, refined weights, elegant hierarchy
- 🃏 **Classic Cards** - Elevated, bordered, and inset variants with subtle shadows
- 🔘 **Professional Buttons** - Solid, outline, and text variants with refined interactions
- 🎯 **Sophisticated Badges** - Professional and classic badge styles
- 💫 **Gentle Animations** - Subtle fade and slide transitions
- 🎨 **Professional Colors** - Emerald, Sapphire, Ruby, and Slate palettes
- 📊 **Classic Tables** - Professional data display with refined styling
- 🏛️ **Enterprise Layouts** - Professional hero, section, and container styles
- ⚡ **Refined Interactions** - Hover lift and brighten effects
- 🎯 **Status Indicators** - Professional status dots with pulse animation
- 💎 **Elegant Forms** - Classic input styling with professional focus states

#### Core Features (v2.3)
- 🎯 **Fully Responsive Design** - Perfect scaling from mobile (375px) to ultra-wide (3840px+)
- 📱 **Mobile-First Approach** - Optimized touch targets, fluid typography, adaptive layouts
- ✨ **Glassmorphism Effects** - Beautiful frosted glass aesthetics with backdrop blur
- 🌈 **Mesh Gradients** - Multi-color gradient backgrounds for premium visual appeal
- 💫 **Cinema-Grade Textures** - Film grain, vignette, light leaks for artistic depth
- ⚡ **Advanced Particles** - 50 floating particles with network connections
- 🎨 **Custom Cursor** - Animated cursor with glow and spotlight effects
- 🎭 **Premium Shadows** - Sophisticated multi-layer shadow system with glow effects
- 🎬 **Micro-Animations** - Elastic physics, liquid morphing, wave ripples
- 🌙 **Enhanced Dark Mode** - Refined color palette with smooth theme transitions
- 🎪 **Typography Effects** - 3D shadows, gradient strokes, kinetic text, shimmer
- 📐 **Background Patterns** - Subtle dot and grid patterns adapting to theme

#### Ultra-Cinema Enhancements (v2.3+) 🚀
- 🔮 **Multi-Layered Glassmorphism** - 4 glass variants with nested depth effects
- 🌈 **Animated Mesh Gradients** - 4-point radial gradient with 20s drift cycle
- ✨ **Ultra Cursor** - Enhanced with prism trails and 400px spotlight
- 🎨 **Living Borders** - Flowing gradients and pulsing aurora glows
- 💎 **Hyper-Glow Icons** - Pulsing multi-layer glow and holographic hue shifting
- 🎪 **Kinetic Interactions** - Enhanced 3D transforms with spring physics
- 🌟 **Holographic Cards** - Rotating conic gradients on hover
- 💧 **Liquid Glow** - Morphing blobs with pulsing aurora effects
- 🎭 **Advanced Text Animations** - Reveal, burst underlines, sparkles
- 🎨 **Live Theme Customizer** - Real-time colors, WCAG checker, effect toggles
- 🌊 **Extra-Deep Shadows** - 5-layer depths with aurora variants
- ⚡ **Ultra-Smooth Transitions** - Premium cubic-bezier easing everywhere

### 🎯 Responsive Features

- ✅ **Adaptive Breakpoints** - 9 breakpoints (xs, sm, md, lg, xl, 2xl, 3xl, 4K, ultra-wide)
- ✅ **Fluid Typography** - Text scales smoothly using CSS clamp() functions
- ✅ **Responsive Icons** - Icons scale proportionally at every breakpoint
- ✅ **Smart Sidebar** - Always visible on desktop (≥1024px), slide-in on mobile
- ✅ **Touch Targets** - Minimum 44x44px for all interactive elements
- ✅ **Responsive Grids** - Auto-adjusting columns based on viewport
- ✅ **Viewport Aware** - Real viewport height handling for mobile browsers
- ✅ **Orientation Support** - Seamless transitions between portrait/landscape

### 🌍 Device Support

| Device Type | Viewport | Status | Optimizations |
|------------|----------|---------|---------------|
| Mobile Small | 375px | ✅ Perfect | Touch targets, fluid text, compact layout |
| Mobile Large | 414px | ✅ Perfect | Enhanced spacing, readable text |
| Tablet | 768px | ✅ Perfect | 2-column grids, medium text |
| Laptop | 1024px | ✅ Perfect | Sidebar always visible, 3-column grids |
| Desktop | 1920px | ✅ Perfect | Full HD optimized, large text |
| 4K | 3840px | ✅ Perfect | Maximum clarity, extra whitespace |
| Ultra-wide | 2560px+ | ✅ Perfect | Optimized for cinema displays |

### 📸 Screenshots

**Light Mode Dashboard:**
![Megido Light Mode](https://github.com/user-attachments/assets/d892e776-23f3-40db-993f-01c6d1c77879)

**Dark Mode Dashboard:**
![Megido Dark Mode](https://github.com/user-attachments/assets/883298ba-436d-42a2-938c-33eb40f7c3c3)

> Note: Screenshots show the ultra-responsive v2.3 interface with cinema-grade effects and adaptive layouts.

### 📚 Documentation

- **[UI_V2.4_PROFESSIONAL_CLASSIC_GUIDE.md](UI_V2.4_PROFESSIONAL_CLASSIC_GUIDE.md)** - Professional classic design guide ⭐ NEW
  - **Complete v2.4 professional system**
  - **Refined typography and spacing**
  - **Classic card and button styles**
  - **Professional color palettes (emerald, sapphire, ruby, slate)**
  - **Enterprise-ready components**
  - **Timeless design patterns**
  - **Migration guide from v2.3+**

- **[UI_DESIGN_SYSTEM.md](UI_DESIGN_SYSTEM.md)** - Complete design system documentation
  - Extended color palette (50-950 scales)
  - Comprehensive component library with 88+ code examples
  - Glassmorphism and premium effects
  - Enhanced animations and transitions
  - Responsive utilities and breakpoints
  - Background patterns and utilities
  - Dark mode implementation
  - Accessibility guidelines (WCAG AA)
  - Best practices for extending the UI

- **[UI_V2.3_ULTRA_GUIDE.md](UI_V2.3_ULTRA_GUIDE.md)** - Ultra-cinema UI features ⭐ NEW
  - **Beyond v2.3 enhancements** with 360+ lines of ultra CSS effects
  - **Multi-layered glassmorphism** (4 variants)
  - **Animated mesh gradients** and living borders
  - **Ultra cursor system** with prism trails
  - **Holographic and kinetic effects**
  - **Theme customizer** with live color picker
  - **Advanced text animations** and micro-interactions
  - Complete implementation examples
  - Performance optimization guide
  - Migration guide from v2.2

### 🎨 Customization

To modify the UI or add custom styles:

```bash
# Install Node.js dependencies
npm install

# Build CSS for production
npm run build:css

# Watch for changes during development
npm run watch:css
```

All Tailwind configuration is in `tailwind.config.js`. Custom components are defined in `static/css/tailwind.input.css`.

### 🆕 What's New in UI v2.3 Ultra-Responsive

- **Universal Responsiveness**: Perfect scaling across all devices and screen sizes
- **Fluid Typography**: Text that scales smoothly with viewport using clamp()
- **Responsive Icons**: Icons adapt to screen size automatically
- **Smart Sidebar**: Desktop always-visible, mobile slide-in with backdrop
- **Touch-Optimized**: All buttons meet 44x44px minimum touch target
- **Viewport Height Fix**: Handles mobile browser address bars correctly
- **Orientation Support**: Seamless portrait/landscape transitions
- **Breakpoint Detection**: JavaScript utilities for responsive behavior
- **Adaptive Grids**: Auto-adjusting column counts per breakpoint
- **Container System**: Responsive padding and max-width constraints
- **Refined Color Palette**: Extended scales (50-950) for all colors
- **Advanced Shadows**: Premium, glow, and inner shadow variants
- **New Animations**: 12+ animation utilities including shimmer, bounce-subtle, scale-in
- **Form Enhancements**: Validation states, required field styling
- **Table Improvements**: Striped variants, better hover states
- **Alert System**: 4 alert variants with border accents
- **Background Patterns**: Dot and grid patterns for visual depth

## 🔄 Enhanced Intercepting Proxy ⭐ NEW

Megido includes a comprehensive **HTTP/HTTPS/WebSocket intercepting proxy** with advanced features for traffic analysis, request replay, and security testing:

### Key Features
- ✅ **Full Protocol Support** - HTTP, HTTPS, and WebSocket (WS/WSS)
- ✅ **Request Replay** - Replay captured requests to original or test endpoints
- ✅ **Authentication** - Optional proxy auth with token or credentials
- ✅ **Advanced Logging** - Database + file-based structured logs
- ✅ **WebSocket Capture** - Complete bidirectional message logging
- ✅ **IP Filtering** - Whitelist/blacklist support
- ✅ **Error Tracking** - Comprehensive error logging with recovery
- ✅ **CLI Tools** - Full-featured command-line interface
- ✅ **REST API** - Complete API for programmatic access
- ✅ **Django Admin** - Web-based management interface

### Quick Start
```bash
# 1. Apply migrations
python manage.py migrate proxy

# 2. Start Django server
python manage.py runserver

# 3. Start enhanced proxy (in another terminal)
mitmdump -s proxy_addon_enhanced.py --set api_url=http://localhost:8000

# 4. Use the proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
curl https://api.example.com
```

### Request Replay
```bash
# List captured requests
python proxy_replay_cli.py list

# Show request details
python proxy_replay_cli.py show 123

# Replay to original URL
python proxy_replay_cli.py replay 123

# Replay to test server
python proxy_replay_cli.py replay 123 --target-url http://localhost:3000

# Replay multiple requests
python proxy_replay_cli.py replay-range 100 110 --delay 1.0
```

### Features Highlights
- **Structured Logs**: Organized by date and type (requests/responses/websockets/errors/auth)
- **Performance Controls**: Configurable timeouts, body size limits, concurrent connections
- **Security**: Authentication tracking, IP filtering, audit trails
- **Reliability**: Graceful error handling, automatic retry, non-blocking logging

📖 **Complete Documentation**: See [PROXY_README.md](PROXY_README.md) for comprehensive usage guide and API reference.

## 🌐 Desktop Browser with Traffic Interception

Megido now includes a **PyQt6 Desktop Browser** with integrated **mitmproxy** for powerful HTTP/HTTPS traffic interception:

### Quick Launch
```bash
# Linux/Mac
./launch_megido_browser.sh

# Windows
launch_megido_browser.bat

# Python (cross-platform)
python launch_megido_browser.py
```

This launches:
- Django development server
- mitmproxy with Megido addon for traffic interception
- PyQt6 desktop browser with real-time interceptor panel

### Features
- ✅ **Python 3.13 Compatible** (replaces CEF Python)
- ✅ **Full HTTP/HTTPS Interception** via mitmproxy
- ✅ **Payload Injection Rules** - Automatically modify requests
- ✅ **Real-time Request Viewer** - See intercepted traffic instantly
- ✅ **App Integration** - Track traffic by source app (Scanner, Spider, etc.)
- ✅ **Certificate Helper** - Easy HTTPS interception setup

See [BROWSER_INTERCEPTOR_INTEGRATION.md](BROWSER_INTERCEPTOR_INTEGRATION.md) for complete documentation.

## 🎯 Advanced Exploit Plugins

Megido includes a powerful pluggable exploit system with production-quality plugins for automated vulnerability exploitation:

### Clickjacking Exploit Plugin

The **Advanced Clickjacking Exploit Plugin** provides comprehensive clickjacking detection and exploitation capabilities:

- ✅ **HTML PoC Generation** - Interactive proof-of-concept with customizable overlays (transparent, opaque, partial)
- ✅ **Automated Frameability Detection** - Headless browser testing with Selenium/WebDriver  
- ✅ **Security Header Analysis** - X-Frame-Options and CSP frame-ancestors validation
- ✅ **Evidence Collection** - Annotated screenshots and detailed reports
- ✅ **Configurable Testing** - Test mode, browser selection, evidence control
- ✅ **Severity Classification** - Context-aware risk assessment
- ✅ **Comprehensive Remediation** - Detailed fix guidance

**Quick Start:**
```python
from scanner.plugins import get_registry

# Get the clickjacking plugin
plugin = get_registry().get_plugin('clickjacking')

# Test a target
result = plugin.execute_attack(
    target_url='http://example.com',
    vulnerability_data={'action_description': 'user login'},
    config={'browser_type': 'chrome', 'collect_evidence': True}
)

if result['vulnerable']:
    print(f"Vulnerability found! PoC: {result['data']['poc_path']}")
```

**Demo:** Run `python3 demo_clickjacking_plugin.py` for interactive demonstration.

### Other Available Plugins

- **SQL Injection Plugin** - Multi-database support with error-based, time-based, and union-based detection
- **SQL Injection Payload Generator Web UI** - Interactive web interface for generating context-aware SQL injection payloads ⭐ NEW
  - Supports Oracle, MySQL, and Microsoft SQL Server
  - Context-aware payload generation (string, numeric, parenthesis contexts)
  - Rich cheat sheet with syntax examples and error messages
  - RESTful API for programmatic access
  - See [sqli_web/USAGE.md](sqli_web/USAGE.md) for detailed usage guide
- **XSS Plugin** - Advanced cross-site scripting testing with **callback-based verification** and **visual proof (GIF) generation** ⭐ NEW
  - Reduces false positives by verifying actual JavaScript execution
  - Supports Burp Collaborator, Interactsh, internal collaborator, or custom webhooks
  - Provides proof of exploitability for bug bounty submissions
  - Only reports XSS as SUCCESS when callback is confirmed
  - **Automatic GIF recording** of XSS exploitation for visual proof ⭐ NEW

**Documentation:**
- [CLICKJACKING_PLUGIN_GUIDE.md](CLICKJACKING_PLUGIN_GUIDE.md) - Comprehensive clickjacking plugin guide
- [EXPLOIT_PLUGINS_GUIDE.md](EXPLOIT_PLUGINS_GUIDE.md) - Plugin system overview and all available plugins
- [XSS_PLUGIN_GUIDE.md](XSS_PLUGIN_GUIDE.md) - Detailed XSS plugin documentation
- [XSS_CALLBACK_VERIFICATION_GUIDE.md](XSS_CALLBACK_VERIFICATION_GUIDE.md) - Callback verification system guide ⭐ NEW
- [NGROK_CALLBACK_GUIDE.md](NGROK_CALLBACK_GUIDE.md) - ngrok-powered callback verification setup and usage (PR #110) ⭐ NEW
- [docs/SQL_INJECTION_POST_EXPLOITATION.md](docs/SQL_INJECTION_POST_EXPLOITATION.md) - SQL injection post-exploitation techniques for MS-SQL, Oracle, and MySQL ⭐ NEW
- [sqli_web/USAGE.md](sqli_web/USAGE.md) - SQL Injection Payload Generator web UI guide ⭐ NEW

**Demo Scripts:**
- `python demo_xss_callback_verification.py` - Interactive callback verification demo
- `python demo_ngrok_scan.py` - ngrok tunnel setup and callback testing (PR #110) ⭐ NEW
- `cd sqli_web && python app.py` - Launch SQL Injection Payload Generator web UI ⭐ NEW

## 🎥 XSS Visual Proof Generation ⭐ NEW FEATURE

Megido now automatically generates **animated GIF proofs** for verified XSS vulnerabilities! When an XSS exploit is confirmed:

1. **Automatic Browser Launch**: Opens the exploited URL in headless Playwright/Selenium
2. **Screenshot Recording**: Captures 2-3 seconds of the exploitation (alert boxes, DOM effects)
3. **GIF Generation**: Converts screenshots to an animated GIF using Pillow
4. **Report Integration**: GIF is embedded in HTML reports and linked in Markdown/JSON reports
5. **Media Storage**: Saved in `media/xss_gif_proofs/` directory

### Features

- ✅ **Zero Configuration** - Works out of the box when Playwright is installed
- ✅ **Security Focused** - URL sanitization, resource limits, timeout protection
- ✅ **Non-Blocking** - GIF capture errors don't interrupt scanning
- ✅ **Automatic Cleanup** - Old GIFs auto-deleted after 7 days
- ✅ **Multiple Reports** - GIF embedded in HTML, linked in Markdown/JSON
- ✅ **Download Support** - Direct download links in reports

### Requirements

```bash
# Install Playwright (preferred)
pip install playwright
playwright install chromium

# Or use existing Selenium (fallback)
pip install selenium
```

### Usage

GIF generation is automatic for all **VERIFIED** XSS findings:

```python
from scanner.plugins import get_registry

# Get XSS plugin
plugin = get_registry().get_plugin('xss')

# Run scan - GIFs are automatically generated for verified XSS
result = plugin.execute_attack(
    target_url='http://vulnerable-site.com',
    config={'callback_verification_enabled': True}
)

# Check findings for GIF proofs
for finding in result['findings']:
    if finding.get('verified') and finding.get('proof_gif'):
        print(f"Visual proof: {finding['proof_gif']}")
```

### Configuration

GIF capture can be customized via the `XSSGifCapture` class:

```python
from scanner.xss_gif_capture import XSSGifCapture

capture = XSSGifCapture(output_dir='custom/path')

# Capture GIF manually
gif_path = capture.capture_xss_proof(
    url='http://target.com/vuln?xss=<script>alert(1)</script>',
    payload='<script>alert(1)</script>',
    duration=3.0  # Max: 5 seconds
)
```

**Security Limits:**
- Max duration: 5 seconds
- Max file size: 10 MB
- Max screenshots: 10 per capture
- URL validation and sanitization
- Automatic cleanup of old files



## 🔍 Visual Proof of Concept (VPoC) Evidence

Exploit-capable scanner plugins attach a consistent **VPoC evidence artifact**
to every finding that actively verifies a vulnerability.  This makes all
exploit-capable findings fully reproducible and auditable.

### VPoC evidence fields

| Field | Type | Description |
|-------|------|-------------|
| `plugin_name` | `str` | Plugin that produced the finding |
| `target_url` | `str` | Targeted URL (without injected payload) |
| `payload` | `str` | The payload or crafted input that triggered the finding |
| `confidence` | `float` | Confidence score `[0.0, 1.0]` |
| `http_request` | `dict` | Sanitized outgoing HTTP request (method, url, headers, body) |
| `http_response` | `dict` | Sanitized HTTP response (status_code, headers, body) |
| `reproduction_steps` | `str` | Step-by-step human-readable reproduction guide |
| `redirect_chain` | `list[str]` | Ordered redirect URLs (open-redirect findings) |
| `curl_command` | `str` | Ready-to-run `curl` command for manual reproduction |
| `screenshots` | `list[str]` | Paths to screenshot files (when browser context available) |
| `timestamp` | `str` | ISO-8601 UTC timestamp of evidence capture |

### Security: sanitization and bounding

All VPoC artifacts are sanitized before storage:

- **Headers redacted** – `Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Token`,
  `X-Api-Key`, `Proxy-Authorization`, `WWW-Authenticate`, `X-Amz-Security-Token`,
  `X-CSRF-Token`, `X-XSRF-Token` values are replaced with `[REDACTED]`.
- **Bodies truncated** – Request/response bodies are capped at **4 096 characters**
  and a truncation notice (`... [truncated] ...`) is appended when shortened.

### Plugins that emit VPoC evidence

| Plugin | Vulnerability type | VPoC attached |
|--------|--------------------|---------------|
| `open_redirect_detector` | `open_redirect` | ✅ (includes redirect chain) |
| `session_fixation_detector` | `session_fixation` | ✅ (all 4 scenarios) |

### Accessing VPoC in code

```python
from scanner.scan_plugins import get_scan_registry

registry = get_scan_registry()
plugin = registry.get_plugin('open_redirect_detector')
findings = plugin.scan('https://example.com/redirect?next=https://evil.com')

for finding in findings:
    if finding.vpoc:
        print("Plugin:", finding.vpoc.plugin_name)
        print("Payload:", finding.vpoc.payload)
        print("Curl command:", finding.vpoc.curl_command)
        print("Steps:", finding.vpoc.reproduction_steps)
        # Serialise to JSON-safe dict (suitable for reports)
        import json
        print(json.dumps(finding.to_dict(), indent=2))
```

### Shared helpers

The helpers live in `scanner/scan_plugins/vpoc.py` and can be imported from
the `scanner.scan_plugins` package:

```python
from scanner.scan_plugins import (
    VPoCEvidence,
    redact_sensitive_headers,
    truncate_body,
    build_curl_command,
    capture_request_response_evidence,
)

# Redact a headers dict
safe = redact_sensitive_headers({'Authorization': 'Bearer secret', 'Content-Type': 'application/json'})
# → {'Authorization': '[REDACTED]', 'Content-Type': 'application/json'}

# Truncate a large body
body = truncate_body(huge_html_body)

# Build a curl command
cmd = build_curl_command('https://example.com/', method='POST', body='key=value')

# Build complete VPoC from a requests.Response
vpoc = capture_request_response_evidence(
    response=resp,
    plugin_name='my_plugin',
    payload='injected_value',
    confidence=0.9,
    target_url='https://example.com/',
)
```





### Worker Timeout Configuration

The Megido platform includes security scanning plugins (especially XSS exploitation) that perform **long-running operations** such as:
- Smart crawling of target sites (potentially minutes for deep scans)
- DOM-based exploitation with Selenium browser automation
- External site interaction and response analysis

**Important for Production Environments:**

When deploying with Gunicorn or other WSGI servers, the default 30-second worker timeout is insufficient and will cause premature worker termination during heavy scans.

#### Docker Deployment (Recommended)

The provided Docker configuration uses Gunicorn with a **300-second timeout** by default:

```bash
docker compose up --build
```

The timeout is configured in `gunicorn.conf.py` and automatically applied.

#### Manual Gunicorn Deployment

If running Gunicorn manually, use the provided configuration file:

```bash
gunicorn --config gunicorn.conf.py megido_security.wsgi:application
```

Or specify the timeout directly:

```bash
gunicorn --timeout 300 --workers 4 megido_security.wsgi:application
```

#### Development Mode

For local development, the Django development server has no timeout limits:

```bash
python manage.py runserver
# or
python launch.py
```

### Static File Serving with WhiteNoise

Megido uses **WhiteNoise** for efficient static file serving in production. WhiteNoise allows Django to serve static files directly without requiring a separate web server like Nginx for static content.

#### Collecting Static Files

After any changes to static files (CSS, JavaScript, images), you must run the `collectstatic` command to gather all static files into the `staticfiles` directory:

```bash
python manage.py collectstatic --noinput
```

This command:
- Collects all static files from your apps and `STATICFILES_DIRS`
- Copies them to the `STATIC_ROOT` directory (`staticfiles/`)
- Prepares them for serving in production

**When to run collectstatic:**
- Before deploying to production
- After updating CSS, JavaScript, or image files
- After pulling changes that modify static files
- After installing or updating Django apps with static files

#### WhiteNoise Configuration

WhiteNoise is configured in `settings.py` with:
- Middleware placed immediately after `SecurityMiddleware`
- `STATIC_ROOT` set to `staticfiles/` directory
- `STATICFILES_DIRS` pointing to the `static/` directory

For enhanced performance, you can enable compression and caching by uncommenting the following line in `settings.py`:

```python
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
```

This will:
- Compress static files with gzip and Brotli
- Add unique hash to filenames for cache-busting
- Enable far-future cache headers

### Scalable Production Architecture with Celery

Megido includes **Celery** integration for asynchronous operations, preventing Gunicorn worker timeouts and improving scalability. This includes:
- **Asynchronous scan execution** - Scans run in background without blocking Gunicorn workers ⭐ NEW
- **Exploit operations** - Long-running exploits execute via background tasks

#### Background Task Processing

Both scan and exploit operations are automatically executed in the background using Celery workers. The API immediately returns with a scan/task ID that can be polled for status and results.

**Key Benefits:**
- ✅ Gunicorn workers freed immediately - no blocking
- ✅ Better scalability - handle many concurrent scans
- ✅ Dashboard polling for real-time progress
- ✅ Automatic error recovery and retry logic

#### Development Setup

**1. Install Redis (required for Celery broker/backend)**

```bash
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis

# Windows (via WSL2 or Windows native)
# Download from https://redis.io/download
```

**2. Install Python dependencies** (if not already installed)

```bash
pip install -r requirements.txt
# This includes celery>=5.3.0 and redis>=5.0.0
```

**3. Start the Celery worker** (in a separate terminal)

```bash
celery -A megido_security worker --loglevel=info
```

**4. Start the Django development server** (in another terminal)

```bash
python manage.py runserver
# or
python launch.py
```

#### Docker Deployment (Recommended)

The `docker-compose.yml` includes all required services:
- **redis** - Message broker for Celery
- **celery** - Background worker for async tasks
- **web** - Django/Gunicorn application server
- **clamav** - Antivirus scanning

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

**Important:** The `docker-entrypoint.sh` automatically runs:
- Database migrations
- **Static file collection** (includes favicon.ico) ⭐ NEW
- Superuser creation (if needed)

#### Production Deployment

For production, run Celery worker(s) alongside your web server:

```bash
# Start multiple workers for parallel processing
celery -A megido_security worker --loglevel=info --concurrency=4

# Optional: Start Celery Beat for periodic tasks (if needed in future)
celery -A megido_security beat --loglevel=info
```

#### Configuration

Celery settings can be configured via environment variables:

```bash
# Redis connection (defaults shown)
export CELERY_BROKER_URL=redis://localhost:6379/0
export CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

#### Additional Documentation

For detailed information on async features:
- **[ASYNC_SCAN_ARCHITECTURE.md](ASYNC_SCAN_ARCHITECTURE.md)** - Async scan architecture and flow ⭐ NEW
- **[FAVICON_SETUP.md](FAVICON_SETUP.md)** - Favicon setup and troubleshooting ⭐ NEW
- **[docs/SCANNER_POLLING.md](docs/SCANNER_POLLING.md)** - Dashboard polling implementation

#### API Usage

**Submit an exploit task:**

```bash
POST /scanner/api/scans/{scan_id}/exploit/
{
  "action": "all"  # or "selected" with "vulnerability_ids": [1, 2, 3]
}

Response (HTTP 202):
{
  "task_id": "a1b2c3d4-...",
  "message": "Exploitation started in background",
  "status_url": "/scanner/api/exploit_status/a1b2c3d4-.../"
}
```

**Poll for task status:**

```bash
GET /scanner/api/exploit_status/{task_id}/

Response:
{
  "task_id": "a1b2c3d4-...",
  "state": "PROGRESS",  # PENDING, PROGRESS, SUCCESS, or FAILURE
  "current": 2,
  "total": 5,
  "status": "Processing vulnerability 2/5"
}
```

**When complete (state: SUCCESS):**

```bash
{
  "task_id": "a1b2c3d4-...",
  "state": "SUCCESS",
  "status": "Completed",
  "result": {
    "total": 5,
    "exploited": 3,
    "failed": 1,
    "no_plugin": 1,
    "results": [...]
  }
}
```

This architecture allows the web tier to remain responsive while exploitation tasks run in dedicated worker processes, improving reliability and user experience for long-running scans.

### Real-Time WebSocket Updates

The scanner now supports **WebSocket-based real-time updates** for exploitation progress, providing instant feedback as tasks execute. The system automatically falls back to polling if WebSocket connections fail, ensuring reliability across all environments.

#### How It Works

When you trigger an exploitation operation, the UI:
1. **Attempts WebSocket connection** to receive real-time updates
2. **Displays live progress** as vulnerabilities are processed
3. **Automatically falls back to polling** if WebSocket is unavailable
4. **Shows completion results** instantly when the task finishes

#### WebSocket Configuration

WebSockets require Redis as the channel layer backend:

```bash
# Redis is already required for Celery, same instance can be used
export REDIS_URL=redis://localhost:6379/1  # Optional, defaults to localhost
```

The WebSocket endpoint is automatically configured at:
```
ws://localhost:8000/ws/scanner/task/<task_id>/
wss://your-domain.com/ws/scanner/task/<task_id>/  # For HTTPS
```

#### ASGI Deployment for Production

For production deployments with WebSocket support, use **Daphne** (ASGI server) instead of Gunicorn:

```bash
# Install dependencies (already in requirements.txt)
pip install daphne channels channels-redis

# Start Daphne server
daphne -b 0.0.0.0 -p 8000 megido_security.asgi:application

# Or with more workers
daphne -b 0.0.0.0 -p 8000 --workers 4 megido_security.asgi:application
```

**Docker Compose** automatically uses Daphne when the ASGI application is detected.

#### Troubleshooting WebSockets

**Issue: WebSocket connection fails**
- **Cause**: Redis not running or not accessible
- **Solution**: Start Redis (`redis-server`) or check REDIS_URL setting
- **Fallback**: System automatically uses polling - no manual intervention needed

**Issue: No real-time updates in browser**
- **Check browser console** for WebSocket connection messages
- **Verify Redis is running**: `redis-cli ping` should return `PONG`
- **Check firewall rules** if Redis is on a different host

**Issue: WebSocket works locally but not in production**
- **Ensure HTTPS/WSS protocol** match your site protocol
- **Configure reverse proxy** (nginx/Apache) to proxy WebSocket connections:
  ```nginx
  location /ws/ {
      proxy_pass http://localhost:8000;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
  }
  ```

**Testing without Redis**

For testing purposes, you can use the in-memory channel layer (not for production):

```python
# In settings.py, temporarily replace CHANNEL_LAYERS with:
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer'
    }
}
```

> **Note**: The in-memory layer only works with a single server process and doesn't persist across restarts. Always use Redis for production deployments.

#### Benefits

- **Instant feedback**: See exploitation progress in real-time
- **Better UX**: No need to refresh or wait for polling
- **Graceful degradation**: Automatic fallback to polling ensures compatibility
- **Low overhead**: WebSocket connections are lightweight and efficient
- **Production-ready**: Built on battle-tested Django Channels

> **See Also:** [DOCKER_TESTING.md](DOCKER_TESTING.md) for additional production deployment guidance.

---

## 🌐 Network Error Handling & Resilience ⭐ NEW

Megido includes **enterprise-grade network error handling** with automatic retries, health monitoring, and degraded mode operation.

### Features

- ✅ **Exponential Backoff with Jitter** - Prevents thundering herd, backs off gracefully
- ✅ **Intelligent Error Classification** - Distinguishes recoverable from fatal errors
- ✅ **Automatic Retries** - Configurable retry behavior for transient failures
- ✅ **Health Monitoring Dashboard** - Real-time service availability tracking
- ✅ **Degraded Mode** - Continues operation when external services are unavailable
- ✅ **Secure Logging** - Automatically redacts sensitive data (passwords, tokens, API keys)

### Quick Configuration

Set via environment variables:

```bash
# Retry configuration
export MEGIDO_MAX_RETRIES=3          # Number of retry attempts
export MEGIDO_BASE_DELAY=1.0         # Initial delay (seconds)
export MEGIDO_MAX_DELAY=30.0         # Maximum delay (seconds)

# Timeout configuration
export MEGIDO_DEFAULT_TIMEOUT=30     # Default request timeout (seconds)
export MEGIDO_CONNECT_TIMEOUT=10     # Connection timeout (seconds)

# Degraded mode - continue scanning even if services fail
export MEGIDO_DEGRADED_MODE=true
```

### Health Monitoring Dashboard

Access real-time network health monitoring:

```
http://localhost:8000/scanner/health/dashboard/
```

Features:
- ✅ Overall system health status (Healthy/Degraded/Critical)
- 📊 Service-by-service breakdown with response times
- 🔄 Auto-refresh every 60 seconds
- ⚠️ Error details and remediation suggestions
- 📈 Health metrics and statistics

### API Endpoint

Get health status via API:

```bash
curl http://localhost:8000/scanner/health/
```

### Common Network Issues & Solutions

#### Issue: Requests Timing Out

**Symptoms:** Scanner fails to connect to target or external services

**Solutions:**
```bash
# Increase timeout
export MEGIDO_DEFAULT_TIMEOUT=60

# Increase retries for flaky connections
export MEGIDO_MAX_RETRIES=5

# Check health dashboard for service status
# Visit: http://localhost:8000/scanner/health/dashboard/
```

#### Issue: External Service Unavailable

**Symptoms:** Health dashboard shows services as unhealthy

**Solutions:**
- Enable degraded mode to continue scanning:
  ```bash
  export MEGIDO_DEGRADED_MODE=true
  ```
- Check service endpoints in health dashboard
- Verify network connectivity and firewall rules
- Review detailed logs for error messages

#### Issue: Connection Reset by Peer

**Symptoms:** Intermittent connection failures

**Solutions:**
- Automatic retries with exponential backoff (enabled by default)
- Increase jitter to randomize retry timing:
  ```bash
  export MEGIDO_JITTER_MAX=2.0
  ```
- Check target server rate limiting

#### Issue: DNS Resolution Failures

**Symptoms:** "Name or service not known" errors

**Solutions:**
- Check DNS server configuration
- Verify hostname is correct
- Automatic retries will handle transient DNS issues
- Check `/etc/resolv.conf` (Linux) or DNS settings (Windows)

### Detailed Documentation

For comprehensive information:
- **[NETWORK_ERROR_HANDLING.md](NETWORK_ERROR_HANDLING.md)** - Complete guide to network error handling
- **[CONFIGURATION.md](CONFIGURATION.md)** - All configuration options
- **Health Dashboard** - Real-time monitoring at `/scanner/health/dashboard/`

### Production Recommendations

```bash
# Production-optimized settings
export MEGIDO_MAX_RETRIES=5
export MEGIDO_BASE_DELAY=2.0
export MEGIDO_MAX_DELAY=60.0
export MEGIDO_DEFAULT_TIMEOUT=60
export MEGIDO_DEGRADED_MODE=true
export MEGIDO_NETWORK_LOG_LEVEL=WARNING  # Reduce log verbosity
```

---


[...]rest of README untouched...
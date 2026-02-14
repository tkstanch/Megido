# Scanner Dashboard Polling - Visual Flow Diagram

## Before (Broken)
```
User clicks "Start Scan"
         ↓
Create scan target
         ↓
POST /scanner/api/targets/{id}/scan/
         ↓
Wait 2 seconds
         ↓
GET /scanner/api/scans/{id}/results/ (ONCE)
         ↓
Display results or error
         ↓
❌ Network Error (scan not complete yet)
         ↓
No further attempts
         ↓
User sees persistent error
```

## After (Fixed)
```
User clicks "Start Scan"
         ↓
Create scan target
         ↓
POST /scanner/api/targets/{id}/scan/
         ↓
Start polling with ScannerDashboard.startPolling()
         ↓
Wait 2 seconds (initial delay)
         ↓
┌────────────────────────────────────────┐
│  Poll Loop (every 2 seconds)          │
│                                        │
│  GET /scanner/api/scans/{id}/results/ │
│         ↓                              │
│  Check scan.status                     │
│         ↓                              │
│  ┌─────────────────────────────────┐  │
│  │ status = 'pending' or 'running' │  │
│  │         ↓                        │  │
│  │ Show progress (spinner)         │  │
│  │         ↓                        │  │
│  │ Continue polling ──────────────→│──┘
│  └─────────────────────────────────┘  │
│                                        │
│  ┌─────────────────────────────────┐  │
│  │ status = 'completed'            │  │
│  │         ↓                        │  │
│  │ Stop polling                    │  │
│  │         ↓                        │  │
│  │ Show success toast              │  │
│  │         ↓                        │  │
│  │ Display vulnerabilities         │  │
│  │         ↓                        │  │
│  │ Show exploit actions            │  │
│  └─────────────────────────────────┘  │
│                                        │
│  ┌─────────────────────────────────┐  │
│  │ status = 'failed'               │  │
│  │         ↓                        │  │
│  │ Stop polling                    │  │
│  │         ↓                        │  │
│  │ Show error message              │  │
│  └─────────────────────────────────┘  │
│                                        │
│  Network Error Handling:               │
│  - Track consecutive failures          │
│  - Show error after 5 failures         │
│  - Max 150 total attempts (5 min)      │
└────────────────────────────────────────┘
```

## Component Interaction
```
┌─────────────────────┐
│   User Interface    │
│  (dashboard.html)   │
└──────────┬──────────┘
           │
           │ 1. User clicks "Start Scan"
           ↓
┌─────────────────────┐
│   startScan()       │
│  - Create target    │
│  - Start scan       │
└──────────┬──────────┘
           │
           │ 2. Call polling API
           ↓
┌─────────────────────────────┐
│  ScannerDashboard           │
│  (scanner-dashboard.js)     │
│                             │
│  • startPolling()           │
│  • pollScanStatus()         │
│  • stopPolling()            │
└──────────┬──────────────────┘
           │
           │ 3. Fetch API calls (every 2s)
           ↓
┌─────────────────────────────┐
│  Backend API                │
│  /scanner/api/scans/        │
│    {id}/results/            │
│                             │
│  Returns:                   │
│  - scan_id                  │
│  - status                   │
│  - vulnerabilities[]        │
└──────────┬──────────────────┘
           │
           │ 4. Callbacks
           ↓
┌─────────────────────────────┐
│  Callback Functions         │
│                             │
│  • handleScanProgress()     │
│  • handleScanComplete()     │
│  • handleScanError()        │
└──────────┬──────────────────┘
           │
           │ 5. Update UI
           ↓
┌─────────────────────────────┐
│  UI Updates                 │
│                             │
│  • Status indicator         │
│  • Spinner animation        │
│  • Toast notifications      │
│  • Vulnerability list       │
│  • Exploit actions          │
└─────────────────────────────┘
```

## State Machine
```
     ┌──────────┐
     │  IDLE    │
     └────┬─────┘
          │ User starts scan
          ↓
     ┌──────────┐
     │ POLLING  │←──────┐
     └────┬─────┘       │
          │             │
    ┌─────┴─────┬───────┴──────┬──────────┐
    │           │              │          │
    │ Pending   │  Running     │  Failed  │ Completed
    │           │              │          │
    ↓           ↓              ↓          ↓
  Continue   Continue      ┌────────┐  ┌────────┐
  polling    polling       │ FAILED │  │SUCCESS │
                           └────────┘  └────────┘
                                ↓          ↓
                           Show error  Show results
```

## Error Handling Flow
```
Network Error Occurs
         ↓
Increment consecutiveFailures
         ↓
consecutiveFailures < MAX_CONSECUTIVE_FAILURES (5)?
         ↓
    ┌────┴────┐
    │ YES     │ NO
    ↓         ↓
Log error   Show error to user
Continue    "Network error: ..."
polling     
    ↓
Next poll attempt
         ↓
Success?
    ↓
┌───┴───┐
│ YES   │ NO
↓       ↓
Reset   Keep
counter incrementing
```

## File Structure
```
/home/runner/work/Megido/Megido/
│
├── static/js/
│   └── scanner-dashboard.js      ← NEW: Polling module
│
├── templates/scanner/
│   └── dashboard.html             ← MODIFIED: Integrated polling
│
└── docs/
    └── SCANNER_POLLING.md         ← NEW: Documentation
```

## Key Metrics
- **Polling Interval**: 2 seconds
- **Max Attempts**: 150 (5 minutes total)
- **Failure Threshold**: 5 consecutive failures before showing error
- **Initial Delay**: 2 seconds before first poll
- **Security**: All dynamic content escaped via escapeHtml()
- **Dependencies**: MegidoToast for notifications

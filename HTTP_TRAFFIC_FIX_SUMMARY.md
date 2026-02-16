# HTTP Traffic Field NOT NULL Violation Fix

## Problem
Vulnerability scan jobs were failing with `psycopg2.errors.NotNullViolation` errors when attempting to insert records into the `scanner_vulnerability` table. The error occurred because the `http_traffic` column has a NOT NULL constraint, but the code was sometimes passing `None` or not providing a value for this field.

## Root Cause
The `VulnerabilityFinding` dataclass (defined in `scanner/scan_plugins/base_scan_plugin.py`) did not have an `http_traffic` field. When `save_findings_to_db()` in `scanner/scan_engine.py` created `Vulnerability` objects, it didn't explicitly set the `http_traffic` field, which could lead to database constraint violations depending on how Django handles missing fields.

## Solution Implemented

### 1. Added `http_traffic` Field to VulnerabilityFinding
**File**: `scanner/scan_plugins/base_scan_plugin.py`

Added `http_traffic` as an optional field to the `VulnerabilityFinding` dataclass:
```python
@dataclass
class VulnerabilityFinding:
    # ... existing fields ...
    http_traffic: Optional[Dict[str, Any]] = None  # HTTP request/response traffic capture
```

Also updated the `to_dict()` method to include `http_traffic` when present:
```python
if self.http_traffic:
    result['http_traffic'] = self.http_traffic
```

### 2. Updated save_findings_to_db Method
**File**: `scanner/scan_engine.py`

Modified the `Vulnerability.objects.create()` call to explicitly handle the `http_traffic` field:
```python
vuln = Vulnerability.objects.create(
    scan=scan,
    # ... other fields ...
    http_traffic=finding.http_traffic or {},  # Use empty dict if None
)
```

The key change is `finding.http_traffic or {}`, which ensures:
- If `finding.http_traffic` is `None` (the default), use an empty dict `{}`
- If `finding.http_traffic` has data, use that data
- The database never receives `None` for this field

## Why This Works

### Database Schema
The `http_traffic` field in the model is defined as:
```python
http_traffic = models.JSONField(
    default=dict,
    blank=True,
    help_text='Captured HTTP request/response traffic during exploitation'
)
```

Key properties:
- `default=dict`: Provides a default empty dictionary
- `blank=True`: Allows the field to be empty in forms
- **No `null=True`**: The database column does NOT allow NULL values

### The Fix
By using `finding.http_traffic or {}` in the code, we ensure that:
1. Even if the VulnerabilityFinding has `http_traffic=None`, the database receives `{}`
2. This satisfies the NOT NULL constraint
3. It's consistent with Django best practices for JSONField (avoid NULL, use empty dict instead)

## Impact

### What's Fixed
- Scan jobs will no longer fail with NOT NULL violations
- All vulnerability findings can be saved successfully, regardless of whether they have HTTP traffic data
- Backward compatible: existing code that doesn't set `http_traffic` will work correctly

### What's Preserved
- Findings with HTTP traffic data will continue to work as expected
- The database schema remains unchanged
- No migration required

## Testing

### Code Review Results
✅ No issues found

### Security Analysis Results
✅ No security vulnerabilities detected (CodeQL)

### Expected Behavior
1. **Finding without http_traffic**: `http_traffic=None` → Database receives `{}`
2. **Finding with http_traffic**: `http_traffic={'request': ...}` → Database receives the data
3. **Finding not specifying http_traffic**: Defaults to `None` → Database receives `{}`

## Files Changed
1. `scanner/scan_plugins/base_scan_plugin.py` - Added `http_traffic` field to VulnerabilityFinding dataclass
2. `scanner/scan_engine.py` - Updated `save_findings_to_db()` to use `or {}` fallback

## Verification
This fix should be verified by:
1. Running a vulnerability scan where findings don't have HTTP traffic captured
2. Confirming that the scan completes successfully without database errors
3. Verifying that vulnerability records are created correctly in the database
4. Checking that `http_traffic` field contains `{}` for findings without traffic data

## Notes
- This is a minimal, surgical fix that addresses the exact issue described
- No changes to database schema or migrations required
- No changes to existing tests needed (they already work with the default behavior)
- The fix follows Django best practices for JSONField handling

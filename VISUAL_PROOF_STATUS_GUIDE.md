# Visual Proof Status Propagation - Implementation Guide

## Overview

This document describes the implementation of visual proof status propagation from the backend to the UI, addressing the issue where users received only generic messages when visual proof capture failed.

## Problem Statement

Previously, when visual proof capture failed or dependencies were missing:
- Backend only logged errors without updating the Vulnerability model
- UI displayed a generic "No visual proof available" message
- Users had no actionable feedback on why visual proof was unavailable

## Solution Architecture

### Data Flow

```
Backend (exploit_integration.py)
    ↓
    Sets visual_proof_status on Vulnerability model
    ↓
API/Views (views.py)
    ↓
    Serializes visual_proof_status field
    ↓
Frontend (dashboard.html)
    ↓
    Displays status-specific message via getVisualProofStatusMessage()
```

### Status Codes

The `visual_proof_status` field in the Vulnerability model supports the following values:

| Status | Description | When Set | UI Message |
|--------|-------------|----------|------------|
| `not_attempted` | Default status | Model default | "No visual proof available." |
| `captured` | Successfully captured | Proof data returned | Shows proof image/GIF |
| `missing_dependencies` | Dependencies unavailable | `get_visual_proof_capture()` returns None | Installation instructions |
| `failed` | Capture failed | Proof capture returns None or exception | Suggests checking logs |
| `disabled` | Disabled by config | Config sets `enabled: False` | Indicates disabled in config |
| `not_supported` | Not supported | Vulnerability type doesn't support visual proof | Indicates not supported |

## Implementation Details

### Backend Changes (scanner/exploit_integration.py)

The `_capture_visual_proof()` function now sets the status in three scenarios:

1. **Missing Dependencies**
   ```python
   capture = get_visual_proof_capture()
   if not capture:
       vuln.visual_proof_status = 'missing_dependencies'
       return
   ```

2. **Successful Capture**
   ```python
   if proof_data:
       vuln.visual_proof_path = proof_data['path']
       vuln.visual_proof_type = proof_data['type']
       vuln.visual_proof_size = proof_data['size']
       vuln.visual_proof_status = 'captured'  # ← New
   ```

3. **Failed Capture or Exception**
   ```python
   else:
       vuln.visual_proof_status = 'failed'  # ← New
   
   except Exception as e:
       vuln.visual_proof_status = 'failed'  # ← New
   ```

### Frontend Changes (templates/scanner/dashboard.html)

1. **Helper Function** (for maintainability)
   ```javascript
   function getVisualProofStatusMessage(status) {
       const messages = {
           'missing_dependencies': '⚠️ Visual proof unavailable: Missing required dependencies...',
           'disabled': 'ℹ️ Visual proof capture is disabled in configuration.',
           'failed': '❌ Visual proof capture failed. Check logs for details...',
           'not_supported': 'ℹ️ Visual proof is not supported for this vulnerability type.',
           'not_attempted': 'No visual proof available.'
       };
       return messages[status] || 'No visual proof available.';
   }
   ```

2. **Template Usage**
   ```javascript
   ${getVisualProofStatusMessage(vuln.visual_proof_status)}
   ```

### API Layer (scanner/views.py)

The views already serialize the `visual_proof_status` field:
```python
'visual_proof_status': vuln.visual_proof_status if hasattr(vuln, 'visual_proof_status') else 'not_attempted',
```

## Testing

### Unit Tests (scanner/tests_visual_proof_status.py)

Five test cases verify the implementation:

1. `test_visual_proof_status_missing_dependencies` - Verifies status when dependencies missing
2. `test_visual_proof_status_capture_failed` - Verifies status when capture returns None
3. `test_visual_proof_status_captured_success` - Verifies status on successful capture
4. `test_visual_proof_status_exception_handling` - Verifies status on exception
5. `test_visual_proof_status_default_value` - Verifies default status

### Running Tests

```bash
# Run specific test file
python manage.py test scanner.tests_visual_proof_status

# Run all tests
python manage.py test scanner
```

## Usage Examples

### Example 1: Missing Dependencies

**Scenario**: Playwright/Selenium not installed

**Backend Behavior**:
```python
capture = get_visual_proof_capture()  # Returns None
if not capture:
    vuln.visual_proof_status = 'missing_dependencies'
```

**Frontend Display**:
```
⚠️ Visual proof unavailable: Missing required dependencies 
(Playwright/Selenium and Pillow). 
Install with: pip install playwright Pillow && playwright install chromium
```

### Example 2: Capture Failed

**Scenario**: Browser automation fails

**Backend Behavior**:
```python
proof_data = capture.capture_exploit_proof(...)  # Returns None
if not proof_data:
    vuln.visual_proof_status = 'failed'
```

**Frontend Display**:
```
❌ Visual proof capture failed. 
Check logs for details or verify browser automation is working.
```

### Example 3: Successful Capture

**Scenario**: Visual proof captured successfully

**Backend Behavior**:
```python
proof_data = capture.capture_exploit_proof(...)  # Returns dict
vuln.visual_proof_status = 'captured'
vuln.visual_proof_path = proof_data['path']
```

**Frontend Display**:
```
[Shows screenshot/GIF with download button]
```

## Troubleshooting

### Issue: Status not updating

**Check**:
1. Verify `vuln.save()` is called after setting status
2. Check database migration is applied
3. Verify API is returning the field

### Issue: UI showing wrong message

**Check**:
1. Browser cache - hard refresh (Ctrl+Shift+R)
2. Check browser console for JavaScript errors
3. Verify status value in API response

### Issue: Tests failing

**Check**:
1. Django and dependencies installed
2. Test database configured
3. Migrations applied

## Maintenance

### Adding New Status Codes

1. Add to model choices in `scanner/models.py`:
   ```python
   ('new_status', 'Display Name'),
   ```

2. Add message in `templates/scanner/dashboard.html`:
   ```javascript
   'new_status': 'User-friendly message...',
   ```

3. Set in backend where appropriate:
   ```python
   vuln.visual_proof_status = 'new_status'
   ```

4. Add test case in `scanner/tests_visual_proof_status.py`

### Modifying Messages

Messages are centralized in `getVisualProofStatusMessage()` function.
Update the messages object as needed.

## Related Files

- `scanner/exploit_integration.py` - Backend status setting
- `scanner/models.py` - Status field definition
- `scanner/views.py` - API serialization
- `templates/scanner/dashboard.html` - Frontend display
- `scanner/tests_visual_proof_status.py` - Unit tests
- `scanner/visual_proof_capture.py` - Capture implementation
- `scanner/proof_reporter.py` - Alternative proof reporting pattern

## Future Enhancements

1. **Detailed Error Context**: Store specific error messages in a separate field
2. **Retry Mechanism**: Allow users to retry failed captures
3. **Status History**: Track status changes over time
4. **Notifications**: Alert users when status changes
5. **Diagnostics Integration**: Link to visual_proof_diagnostics module for detailed troubleshooting

## References

- Original Issue: Visual Proof not returned after exploitation
- Model Field: `Vulnerability.visual_proof_status` (added in migration 0006)
- Status Choices: Defined in `scanner/models.py` lines 147-159

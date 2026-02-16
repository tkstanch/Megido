# Proof Reporting System Guide

## Overview

The Megido Proof Reporting System provides a unified, extensible framework for collecting and storing exploitation evidence across all vulnerability types. This system standardizes proof collection, making it easy to document, review, and share exploitation results.

## Features

### Core Capabilities

1. **Unified Evidence Collection**
   - HTTP request/response traffic capture
   - Exploitation logs and command output
   - Visual proofs (screenshots, animated GIFs)
   - Callback/OOB interaction evidence
   - Extracted data and metadata

2. **Multiple Output Formats**
   - **JSON**: Machine-readable format for automation
   - **HTML**: Human-readable visual reports
   - **Database**: Persistent storage with Vulnerability model
   - **File System**: Organized proof artifacts

3. **Pluggable Architecture**
   - Easy integration with all exploit plugins
   - Configurable proof types per scan
   - Optional visual proof capture
   - Extensible for future proof types

4. **Database Integration**
   - Automatic storage with vulnerability findings
   - Query-able proof data
   - Attachment support for visual proofs
   - Backward compatible with existing schema

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                     ProofReporter                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ HTTP Capture │  │ Visual Proof │  │ OOB Evidence │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              ProofData Container                     │    │
│  │  - HTTP traffic  - Logs  - Screenshots              │    │
│  │  - Command output  - Callbacks  - Metadata          │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   JSON   │  │   HTML   │  │   File   │  │ Database │   │
│  │  Output  │  │  Report  │  │  Storage │  │ Storage  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### ProofData Container

The `ProofData` class encapsulates all evidence collected during exploitation:

```python
class ProofData:
    - vulnerability_type: str       # xss, rce, sqli, etc.
    - vulnerability_id: int         # DB reference
    - timestamp: str                # ISO format
    
    # HTTP Evidence
    - http_requests: List[Dict]     # Request details
    - http_responses: List[Dict]    # Response details
    
    # Exploitation Output
    - logs: List[str]               # Log messages
    - command_output: str           # RCE output
    - extracted_data: Any           # Exfiltrated data
    
    # Visual Proof
    - screenshots: List[Dict]       # Screenshot metadata
    - visual_proof_path: str        # Primary proof file
    - visual_proof_type: str        # screenshot, gif, video
    
    # Callback Evidence
    - callback_evidence: List[Dict] # Callback data
    - oob_interactions: List[Dict]  # OOB interactions
    
    # Success Indicators
    - success: bool                 # Exploit succeeded
    - verified: bool                # Verified with proof
    - confidence_score: float       # 0.0 - 1.0
    
    # Metadata
    - metadata: Dict[str, Any]      # Additional context
```

## Usage

### Basic Integration in Exploit Plugin

```python
from scanner.proof_reporter import get_proof_reporter

class MyExploitPlugin(ExploitPlugin):
    def execute_attack(self, target_url, vulnerability_data, config):
        # ... perform exploitation ...
        
        # Enable proof reporting (opt-in per config)
        if config.get('enable_proof_reporting', True):
            self._generate_proof_report(result, target_url, 
                                       vulnerability_data, config)
        
        return result
    
    def _generate_proof_report(self, result, target_url, 
                               vulnerability_data, config):
        """Generate unified proof report."""
        try:
            # Get proof reporter instance
            reporter = get_proof_reporter(
                enable_visual_proof=config.get('enable_visual_proof', True)
            )
            
            # Create proof data container
            vuln_id = vulnerability_data.get('vulnerability_id')
            proof_data = reporter.create_proof_data('xss', vuln_id)
            
            # Set success status
            verified = result.get('success', False)
            proof_data.set_success(verified, verified, confidence=0.9)
            
            # Add HTTP traffic
            proof_data.add_http_request(
                method='GET',
                url=target_url,
                headers={'User-Agent': 'Megido'},
                body=''
            )
            
            # Add response
            proof_data.add_http_response(
                status_code=200,
                headers={},
                body=result.get('response_body', '')
            )
            
            # Add logs
            proof_data.add_log(f"Exploitation attempt on {target_url}", 'info')
            if result.get('evidence'):
                proof_data.add_log(result['evidence'], 'success')
            
            # Capture visual proof (if applicable)
            if verified and config.get('enable_visual_proof', True):
                reporter.capture_visual_proof(
                    proof_data,
                    exploit_url,
                    capture_type='screenshot'
                )
            
            # Generate and save proof reports
            proof_results = reporter.report_proof(
                proof_data,
                save_json=True,
                save_html=True,
                store_db=True,
                vulnerability_model=vulnerability_data.get('vulnerability_model')
            )
            
            # Add proof paths to result
            result['proof_json_path'] = proof_results.get('json_path')
            result['proof_html_path'] = proof_results.get('html_path')
            
        except Exception as e:
            logger.error(f"Proof reporting failed: {e}")
```

### XSS Plugin Example

```python
def _generate_proof_report(self, result, target_url, vulnerability_data, config):
    """Generate proof report for XSS exploitation."""
    reporter = get_proof_reporter(enable_visual_proof=True)
    
    vuln_id = vulnerability_data.get('vulnerability_id')
    proof_data = reporter.create_proof_data('xss', vuln_id)
    
    # Success with high confidence if verified
    verified = result.get('success', False) and len(result.get('findings', [])) > 0
    proof_data.set_success(verified, verified, confidence=0.9 if verified else 0.3)
    
    # Add HTTP traffic from findings
    for finding in result.get('findings', []):
        if 'request' in finding:
            req = finding['request']
            proof_data.add_http_request(
                method=req.get('method', 'GET'),
                url=req.get('url', target_url),
                headers=req.get('headers', {}),
                body=req.get('body')
            )
    
    # Add callback evidence
    if self.callback_verifier:
        for finding in result.get('findings', []):
            if finding.get('callback_verified'):
                proof_data.add_callback_evidence({
                    'callback_id': finding.get('callback_id'),
                    'verified': True
                })
    
    # Capture screenshot of XSS execution
    if verified:
        for finding in result.get('findings', [])[:1]:
            reporter.capture_visual_proof(
                proof_data,
                finding.get('exploit_url', target_url),
                capture_type='screenshot'
            )
    
    # Save all proof formats
    reporter.report_proof(proof_data, save_json=True, save_html=True, store_db=True)
```

### RCE Plugin Example

```python
def _generate_proof_report(self, result, target_url, vulnerability_data, config):
    """Generate proof report for RCE exploitation."""
    # Visual proof not applicable for RCE
    reporter = get_proof_reporter(enable_visual_proof=False)
    
    vuln_id = vulnerability_data.get('vulnerability_id')
    proof_data = reporter.create_proof_data('rce', vuln_id)
    
    # High confidence if we got command output
    verified = result.get('success', False) and len(result.get('command_output', '')) > 0
    proof_data.set_success(verified, verified, confidence=0.95 if verified else 0.3)
    
    # Add HTTP traffic
    proof_data.add_http_request(
        method=vulnerability_data.get('method', 'GET'),
        url=target_url,
        headers={'User-Agent': 'Megido'},
        body=f"{parameter}={payload}"
    )
    
    # Add command output as primary evidence
    if result.get('command_output'):
        proof_data.set_command_output(result['command_output'])
    
    # Add metadata
    proof_data.add_metadata('os_detected', result.get('os_detected'))
    proof_data.add_metadata('command', exploitation_result.get('command'))
    
    # Save proof
    reporter.report_proof(proof_data, save_json=True, save_html=True, store_db=True)
```

### SSRF Plugin Example

```python
def _generate_proof_report(self, result, target_url, vulnerability_data, config):
    """Generate proof report for SSRF exploitation."""
    # Visual proof useful for SSRF
    reporter = get_proof_reporter(enable_visual_proof=True)
    
    proof_data = reporter.create_proof_data('ssrf', vuln_id)
    
    # OOB verification increases confidence
    confidence = 0.9 if oob_result and oob_result.get('verified') else 0.7
    proof_data.set_success(result.get('success'), True, confidence)
    
    # Add cloud metadata as extracted data
    if result.get('cloud_metadata'):
        proof_data.set_extracted_data(result['cloud_metadata'])
    
    # Add OOB verification evidence
    if oob_result and oob_result.get('verified'):
        for payload_id, (verified, interactions) in oob_result['verification_results'].items():
            if verified:
                proof_data.add_callback_evidence({
                    'payload_id': payload_id,
                    'interactions': interactions
                })
                for interaction in interactions:
                    proof_data.add_oob_interaction(interaction)
    
    # Save proof
    reporter.report_proof(proof_data)
```

## Configuration

### Global Configuration

Configure proof reporting behavior in your scan configuration:

```python
config = {
    # Enable/disable proof reporting
    'enable_proof_reporting': True,
    
    # Visual proof settings
    'enable_visual_proof': True,
    'visual_proof_type': 'screenshot',  # 'screenshot' or 'gif'
    
    # Output settings
    'save_proof_json': True,
    'save_proof_html': True,
    'store_proof_db': True,
    
    # Visual proof capture settings (optional)
    'capture_visual_proof': True,
}
```

### Per-Plugin Configuration

Different plugins support different proof types:

| Plugin | HTTP Traffic | Logs | Visual Proof | Callbacks |
|--------|--------------|------|--------------|-----------|
| XSS | ✓ | ✓ | ✓ (screenshot) | ✓ |
| RCE | ✓ | ✓ | ✗ | ✗ |
| SQLi | ✓ | ✓ | ✗ | ✓ (OOB) |
| SSRF | ✓ | ✓ | ✓ (screenshot) | ✓ (OOB) |
| LFI | ✓ | ✓ | ✗ | ✗ |
| Open Redirect | ✓ | ✓ | ✓ (screenshot) | ✗ |
| XXE | ✓ | ✓ | ✗ | ✓ (OOB) |

## Output Formats

### JSON Output

Machine-readable format for automation:

```json
{
  "vulnerability_type": "xss",
  "vulnerability_id": 123,
  "timestamp": "2024-01-15T10:30:00",
  "success": true,
  "verified": true,
  "confidence_score": 0.9,
  "http_requests": [
    {
      "method": "GET",
      "url": "http://example.com/search?q=<script>alert(1)</script>",
      "headers": {"User-Agent": "Megido"},
      "timestamp": "2024-01-15T10:30:01"
    }
  ],
  "http_responses": [
    {
      "status_code": 200,
      "body": "<html>...XSS payload...</html>",
      "timestamp": "2024-01-15T10:30:02"
    }
  ],
  "logs": [
    "[2024-01-15T10:30:00] [INFO] XSS exploitation attempt",
    "[2024-01-15T10:30:03] [SUCCESS] XSS payload executed"
  ],
  "screenshots": [
    {
      "path": "media/exploit_proofs/xss_123_abc_20240115.png",
      "type": "screenshot",
      "size": 102400
    }
  ],
  "callback_evidence": [
    {
      "callback_id": "xss_abc123",
      "verified": true
    }
  ],
  "metadata": {
    "target_url": "http://example.com",
    "payload": "<script>alert(1)</script>",
    "plugin_version": "1.0.0"
  }
}
```

### HTML Report

Human-readable visual report with:
- Executive summary
- HTTP traffic details
- Exploitation output
- Visual proofs (embedded screenshots)
- Callback evidence
- Logs timeline

### Database Storage

Proof data is stored in the `Vulnerability` model:

```python
class Vulnerability(models.Model):
    # ... existing fields ...
    
    # Proof reporting fields
    proof_of_impact = models.TextField(
        blank=True, null=True,
        help_text='JSON proof data from ProofReporter'
    )
    http_traffic = models.JSONField(
        default=dict, blank=True,
        help_text='Captured HTTP request/response traffic'
    )
    visual_proof_path = models.CharField(
        max_length=512, blank=True, null=True,
        help_text='Path to visual proof file'
    )
    visual_proof_type = models.CharField(
        max_length=20, blank=True, null=True,
        help_text='Type of visual proof'
    )
    verified = models.BooleanField(
        default=False,
        help_text='Verified with exploitation proof'
    )
    confidence_score = models.FloatField(
        default=0.5,
        help_text='Confidence score (0.0-1.0)'
    )
```

## Visual Proof Capture

### Screenshot Capture

For vulnerabilities with visible impact (XSS, Open Redirect):

```python
# Capture screenshot
reporter.capture_visual_proof(
    proof_data,
    url='http://victim.com/xss',
    capture_type='screenshot',
    duration=3.0  # Not used for screenshots
)
```

### Animated GIF Capture

For dynamic exploits showing interaction:

```python
# Capture animated GIF
reporter.capture_visual_proof(
    proof_data,
    url='http://victim.com/xss',
    capture_type='gif',
    duration=5.0  # Capture 5 seconds
)
```

### Browser Support

Visual proof capture supports both Playwright (preferred) and Selenium:

```bash
# Install Playwright
pip install playwright
playwright install chromium

# Or use Selenium
pip install selenium webdriver-manager
```

## Callback/OOB Evidence

### XSS Callback Verification

```python
# XSS plugin automatically uses callback verifier
if self.callback_verifier:
    for finding in result.get('findings', []):
        if finding.get('callback_verified'):
            proof_data.add_callback_evidence({
                'callback_id': finding.get('callback_id'),
                'callback_data': finding.get('callback_data'),
                'verified': True
            })
```

### SSRF OOB Verification

```python
# SSRF plugin uses OOB framework
if oob_result and oob_result.get('verified'):
    for payload_id, (verified, interactions) in oob_result['verification_results'].items():
        if verified:
            for interaction in interactions:
                proof_data.add_oob_interaction(interaction)
```

## Best Practices

### 1. Always Log Context

```python
proof_data.add_log(f"Exploitation attempt on {target_url}", 'info')
proof_data.add_log(f"Vulnerable parameter: {parameter}", 'info')
proof_data.add_log(f"Payload: {payload}", 'info')
```

### 2. Set Appropriate Confidence Scores

```python
# High confidence: Direct proof (command output, callback verified)
proof_data.set_success(True, True, confidence=0.95)

# Medium confidence: Strong indicators (response reflection, timing)
proof_data.set_success(True, True, confidence=0.7)

# Low confidence: Possible but unconfirmed
proof_data.set_success(True, False, confidence=0.3)
```

### 3. Add Rich Metadata

```python
proof_data.add_metadata('target_url', target_url)
proof_data.add_metadata('parameter', parameter)
proof_data.add_metadata('payload', payload)
proof_data.add_metadata('os_detected', os_type)
proof_data.add_metadata('plugin_version', self.version)
```

### 4. Capture Full HTTP Traffic

```python
# Request
proof_data.add_http_request(
    method=method,
    url=full_url,
    headers=headers,
    body=body
)

# Response
proof_data.add_http_response(
    status_code=response.status_code,
    headers=dict(response.headers),
    body=response.text[:5000]  # Limit large responses
)
```

### 5. Handle Errors Gracefully

```python
def _generate_proof_report(self, ...):
    try:
        reporter = get_proof_reporter()
        # ... proof generation ...
    except ImportError:
        logger.warning("ProofReporter not available")
    except Exception as e:
        logger.error(f"Proof reporting failed: {e}")
        # Don't fail the exploit if proof reporting fails
```

## Testing

Run proof reporter tests:

```bash
# Run all proof reporter tests
python -m unittest scanner.tests_proof_reporter

# Run specific test class
python -m unittest scanner.tests_proof_reporter.TestProofData

# Run with verbose output
python -m unittest scanner.tests_proof_reporter -v
```

## Demo Script

See `demo_proof_reporting.py` for a complete example:

```bash
python demo_proof_reporting.py
```

## Migration

Existing exploit plugins can be gradually migrated to use ProofReporter:

1. Keep existing functionality intact
2. Add proof reporting as optional feature
3. Use `enable_proof_reporting` config flag
4. Proof reporting runs after exploitation
5. Failures in proof reporting don't affect exploit success

## Performance Considerations

### Visual Proof Capture

- Screenshot: ~2-5 seconds per capture
- GIF: ~5-10 seconds per capture
- Disable for high-speed scans: `enable_visual_proof=False`

### Database Storage

- Proof data stored as JSON in `proof_of_impact` field
- HTTP traffic stored in `http_traffic` JSONField
- Visual proofs stored as file references
- Consider archiving old proofs for large databases

### Memory Usage

- ProofData containers are lightweight
- Large responses/outputs are truncated
- Visual proofs optimized (< 10MB each)
- Cleanup temporary files automatically

## Troubleshooting

### Visual Proof Capture Fails

```python
# Check dependencies
pip install playwright pillow
playwright install chromium

# Or use Selenium
pip install selenium webdriver-manager
```

### Database Storage Fails

```python
# Ensure migration is applied
python manage.py migrate scanner

# Check vulnerability model has required fields
python manage.py shell
>>> from scanner.models import Vulnerability
>>> v = Vulnerability.objects.first()
>>> hasattr(v, 'http_traffic')  # Should be True
```

### Large Proof Files

```python
# Limit response body size
body=response.text[:5000]  # First 5000 chars

# Disable visual proof for large-scale scans
config['enable_visual_proof'] = False
```

## Future Enhancements

- [ ] Video recording for complex exploits
- [ ] Network traffic capture (PCAP)
- [ ] Proof comparison and deduplication
- [ ] Automated proof validation
- [ ] Proof export to external tools
- [ ] Cloud storage integration
- [ ] Real-time proof streaming

## Support

For issues or questions:
- GitHub Issues: https://github.com/tkstanch/Megido/issues
- Documentation: See other guides in repository
- Example Code: Check `demo_*.py` scripts

---

**Version**: 1.0.0  
**Last Updated**: 2024-01-15  
**Author**: Megido Development Team

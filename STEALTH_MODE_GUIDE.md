# Spider Stealth Mode - Implementation Guide

## Overview

The Stealth Mode feature makes the spider undetectable by target applications by mimicking real browser behavior, randomizing user agents, adding realistic headers, and implementing intelligent request delays.

## Why Stealth Mode?

Without stealth features, the spider can be easily detected by:
- **Unusual User-Agent strings** - Default Python requests library uses "python-requests/X.X.X"
- **Missing browser headers** - Real browsers send many headers that automated tools don't
- **Fixed timing patterns** - Requests at exact intervals are easily detected
- **No cookie/session management** - Real browsers maintain sessions
- **Missing referer headers** - Browsers send referer for navigation

## Stealth Features

### 1. User-Agent Randomization

The spider rotates through 16 realistic browser user agents including:
- Chrome on Windows, macOS, Linux
- Firefox on Windows, macOS
- Safari on macOS
- Edge on Windows

Each request uses a different user agent to avoid detection patterns.

### 2. Realistic Browser Headers

Every request includes headers that real browsers send:

```python
{
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9...',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
    'Referer': 'https://example.com/previous-page'
}
```

### 3. Intelligent Request Delays

Instead of fixed delays, the spider uses randomized delays:
- **Configurable range**: Default 1-3 seconds between requests
- **Random variation**: Each delay is randomly chosen within the range
- **Occasional long delays**: 10% chance of 1.5-2.5x longer delay
- **Avoids patterns**: No fixed timing that can be detected

### 4. Session Management

Uses `requests.Session()` to:
- Maintain cookies across requests
- Persist connection settings
- Mimic browser session behavior
- Reuse TCP connections when possible

### 5. Referer Spoofing

Automatically sets appropriate `Referer` header:
- Tracks previous URL visited
- Sets referer to simulate navigation
- Updates `Sec-Fetch-Site` based on origin

## Configuration Options

### SpiderTarget Model Fields

```python
enable_stealth_mode = BooleanField(default=True)
    # Master switch for all stealth features

use_random_user_agents = BooleanField(default=True)
    # Rotate user agents between requests

stealth_delay_min = FloatField(default=1.0)
    # Minimum delay between requests in seconds

stealth_delay_max = FloatField(default=3.0)
    # Maximum delay between requests in seconds
```

## Usage

### Via Web UI

1. Navigate to Spider dashboard at `/spider/`
2. Configure your target URL
3. Expand "🔒 Stealth Options" section
4. Enable/disable stealth features:
   - ✓ Enable Stealth Mode
   - ✓ Use Random User Agents
   - Set Min Delay (seconds): 1.0
   - Set Max Delay (seconds): 3.0
5. Click "Start Spider"

### Via API

```bash
# Create target with stealth enabled
curl -X POST http://localhost:8000/spider/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "name": "Stealth Test",
    "enable_stealth_mode": true,
    "use_random_user_agents": true,
    "stealth_delay_min": 1.5,
    "stealth_delay_max": 4.0
  }'
```

### Programmatically

```python
from spider.models import SpiderTarget, SpiderSession
from spider.stealth import create_stealth_session

# Create target
target = SpiderTarget.objects.create(
    url='https://example.com',
    enable_stealth_mode=True,
    use_random_user_agents=True,
    stealth_delay_min=1.0,
    stealth_delay_max=3.0
)

# Create stealth session
stealth_session = create_stealth_session(target, verify_ssl=False)

# Make requests with stealth
response = stealth_session.get('https://example.com/page')

# Session automatically:
# - Applies random delay
# - Rotates user agent
# - Adds realistic headers
# - Maintains cookies
# - Sets referer

stealth_session.close()
```

## How It Works

### StealthSession Class

The `StealthSession` class wraps `requests.Session()` and adds stealth features:

```python
class StealthSession:
    def __init__(self, enable_stealth=True, use_random_user_agents=True,
                 delay_min=1.0, delay_max=3.0, verify_ssl=False):
        self.session = requests.Session()
        self.enable_stealth = enable_stealth
        # ... configuration ...
    
    def get(self, url, **kwargs):
        self.apply_delay()  # Random delay
        headers = self.get_stealth_headers(referer=self.referer)
        # Merge with provided headers
        response = self.session.get(url, headers=headers, **kwargs)
        self.referer = url  # Update for next request
        return response
```

### Request Flow

1. **Pre-request**: Apply intelligent delay
2. **Header generation**: Create realistic browser headers
3. **User agent**: Select random UA if enabled
4. **Referer**: Add previous URL as referer
5. **Request**: Use persistent session
6. **Post-request**: Update referer for next request

### Delay Algorithm

```python
def apply_delay(self):
    delay = random.uniform(self.delay_min, self.delay_max)
    
    # 10% chance of longer delay
    if random.random() < 0.1:
        delay *= random.uniform(1.5, 2.5)
    
    # Wait if needed
    time_since_last = time.time() - self.last_request_time
    if time_since_last < delay:
        time.sleep(delay - time_since_last)
```

## Performance Impact

### With Stealth Enabled (Default: 1-3s delays)

- **DirBuster** (40 paths): ~120 seconds (vs ~10 seconds without stealth)
- **Parameter Discovery** (450 combos): ~750 seconds (vs ~45 seconds)
- **Crawling** (100 URLs): ~200 seconds (vs ~10 seconds)

### Recommendations

For different scenarios:

**Aggressive scan (less stealth)**:
- Min delay: 0.3 seconds
- Max delay: 1.0 seconds
- Use random UA: enabled

**Balanced (default)**:
- Min delay: 1.0 seconds
- Max delay: 3.0 seconds
- Use random UA: enabled

**Maximum stealth**:
- Min delay: 2.0 seconds
- Max delay: 5.0 seconds
- Use random UA: enabled

## Detection Avoidance

### What Stealth Mode Prevents

✓ **User-Agent detection**: No Python/automation signatures
✓ **Missing header detection**: All required browser headers present
✓ **Timing pattern detection**: Randomized delays with variation
✓ **Rate limiting**: Slower, more human-like pace
✓ **Session analysis**: Proper cookie and session management
✓ **Navigation analysis**: Proper referer chains

### What Stealth Mode Does NOT Prevent

✗ **IP-based blocking**: Use proxies/VPNs if needed
✗ **CAPTCHA**: Cannot solve CAPTCHA challenges
✗ **JavaScript detection**: Headless browser fingerprinting
✗ **Behavioral analysis**: Advanced ML-based detection
✗ **Volume detection**: Too many requests from one source

## Admin Interface

In Django admin, stealth options are organized in a dedicated fieldset:

**Stealth Options** section includes:
- Enable Stealth Mode checkbox
- Use Random User Agents checkbox
- Stealth Delay Min (seconds)
- Stealth Delay Max (seconds)

## Testing

Run stealth mode tests:

```bash
python manage.py test spider.tests.StealthModeTest
```

Test cases cover:
- Target creation with stealth options
- Stealth session creation
- User agent randomization
- Header generation
- Referer handling
- Stealth disabled mode
- API integration

## Best Practices

### 1. Always Enable for Production Targets

```python
target = SpiderTarget.objects.create(
    url='https://production-site.com',
    enable_stealth_mode=True,  # Always true for real targets
    stealth_delay_min=2.0,     # Longer delays for production
    stealth_delay_max=5.0
)
```

### 2. Adjust Delays Based on Target

- **Small sites**: 1-3 seconds (default)
- **Large sites**: 2-5 seconds
- **Sensitive sites**: 3-10 seconds

### 3. Monitor Response Times

If you see:
- 429 (Too Many Requests) → Increase delays
- 403 (Forbidden) → Check user agents, enable stealth
- Connection timeouts → May need to reduce delays

### 4. Combine with Other Tools

Stealth mode works best with:
- **Proxy rotation**: Different IPs
- **Request throttling**: Global rate limits
- **Time windows**: Spider during low-traffic periods

## Troubleshooting

### Issue: Still getting detected

**Solutions**:
1. Increase delay range (e.g., 3-8 seconds)
2. Reduce concurrent requests
3. Use proxy rotation
4. Add more variation to user agents

### Issue: Too slow

**Solutions**:
1. Reduce delay range (e.g., 0.5-2 seconds)
2. Disable less critical discovery methods
3. Reduce crawl depth
4. Test on smaller target first

### Issue: Session not maintained

**Check**:
1. Stealth mode is enabled
2. Same StealthSession used for all requests
3. Cookies are not blocked by target
4. Session closed properly after spider run

## Security Considerations

### Legal and Ethical Use

⚠️ **Important**: Stealth features are for **authorized testing only**

- Get written permission before testing
- Only test systems you own or have authorization for
- Respect robots.txt and rate limits
- Comply with all applicable laws
- Be aware that detection avoidance may be illegal in some jurisdictions

### Responsible Disclosure

If you discover vulnerabilities using this tool:
1. Report to the affected organization
2. Give reasonable time to fix (90 days typical)
3. Follow responsible disclosure practices
4. Don't exploit discovered vulnerabilities

## Future Enhancements

Potential improvements:
1. **Proxy rotation**: Built-in proxy support
2. **Custom user agent lists**: Upload your own UAs
3. **Browser fingerprinting**: Mimic specific browser versions
4. **JavaScript execution**: Headless browser integration
5. **ML-based delays**: Learn target's traffic patterns
6. **Geographic distribution**: Requests from multiple regions
7. **Time-based throttling**: Respect peak/off-peak hours

## Technical Details

### User Agent Sources

User agents are from:
- Chrome versions 118-120 (most recent)
- Firefox versions 119-121 (most recent)
- Safari 17.x (current version)
- Edge 119-120 (current version)

Updated regularly to match current browser versions.

### Header Standards

Headers follow:
- HTTP/2 specifications
- Fetch Standard (Sec-Fetch-* headers)
- Modern browser behavior (2023-2024)

### Session Implementation

Uses `requests.Session()` which provides:
- Connection pooling
- Cookie persistence
- SSL certificate caching
- Keep-alive connections

## References

- [HTTP Headers Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Fetch Standard](https://fetch.spec.whatwg.org/)
- [User-Agent Best Practices](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)
- [Responsible Disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)

# Visual Proof of Impact - Complete Guide

## Overview

The **Visual Proof of Impact** feature automatically captures screenshots or animated GIFs when vulnerabilities are successfully exploited, providing undeniable visual evidence of the security impact directly in the scanner dashboard.

## Features

### 🎯 Core Capabilities

- **Automatic Capture**: Screenshots/GIFs captured automatically after successful exploitation
- **Smart Type Selection**: GIFs for dynamic vulnerabilities (XSS, CSRF), screenshots for static (SQL injection, RCE)
- **File Size Optimization**: Automatic compression and optimization to stay under 10MB
- **Multi-Browser Support**: Works with Playwright (preferred) or Selenium (fallback)
- **Dashboard Integration**: Beautiful inline display with fullscreen viewer
- **Download Capability**: Easy export for reports and documentation
- **Non-Blocking**: Failures don't interrupt exploitation flow

### 📊 Supported Vulnerability Types

| Vulnerability Type | Capture Type | Duration | Use Case |
|-------------------|--------------|----------|----------|
| XSS | Animated GIF | 3s | Alert boxes, DOM manipulation |
| CSRF | Animated GIF | 3s | Form submissions, state changes |
| Clickjacking | Animated GIF | 3s | UI overlay attacks |
| SQL Injection | Screenshot | 2s | Database dumps, error messages |
| RCE | Screenshot | 2s | Command execution output |
| LFI/RFI | Screenshot | 2s | File contents, directory listings |
| SSRF | Screenshot | 2s | Internal resource access |
| XXE | Screenshot | 2s | XML parsing, file extraction |
| Open Redirect | Screenshot | 2s | Redirect chains |
| Info Disclosure | Screenshot | 2s | Sensitive data exposure |

## Installation

### Prerequisites

```bash
# Required: Image processing
pip install Pillow

# Required: Browser automation (choose one or both)
pip install playwright
playwright install chromium

# OR

pip install selenium
# Ensure Chrome/Chromium is installed on your system
```

### Verify Installation

```bash
python3 demo_visual_proof.py
```

This will check all dependencies and show examples.

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Exploitation Flow                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. Vulnerability Discovered                                 │
│         ↓                                                     │
│  2. Exploitation Attempted                                   │
│         ↓                                                     │
│  3. ✓ Success → Visual Proof Capture Triggered              │
│         ↓                                                     │
│  4. Screenshot/GIF Captured                                  │
│         ↓                                                     │
│  5. Image Optimized (<10MB)                                  │
│         ↓                                                     │
│  6. File Saved (media/exploit_proofs/)                       │
│         ↓                                                     │
│  7. Database Updated                                         │
│         ↓                                                     │
│  8. Dashboard Displays Visual Proof                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Database Schema

```python
class Vulnerability(models.Model):
    # ... existing fields ...
    
    # Visual proof fields
    visual_proof_path = models.CharField(
        max_length=512,
        blank=True, null=True,
        help_text='Path to screenshot or GIF'
    )
    visual_proof_type = models.CharField(
        max_length=20,
        choices=[
            ('screenshot', 'Screenshot'),
            ('gif', 'Animated GIF'),
            ('video', 'Video')
        ],
        blank=True, null=True
    )
    visual_proof_size = models.IntegerField(
        blank=True, null=True,
        help_text='File size in bytes'
    )
```

### File Organization

```
media/
└── exploit_proofs/
    ├── xss_123_abc12345_20260213_143022.gif      # Animated GIF (100-500KB)
    ├── sqli_124_def67890_20260213_143045.png     # Screenshot (50-200KB)
    ├── rce_125_ghi11213_20260213_143112.png      # Screenshot (50-200KB)
    └── ssrf_126_jkl14151_20260213_143145.png     # Screenshot (50-200KB)
```

## Usage

### Automatic (Recommended)

Visual proofs are captured **automatically by default** during exploitation:

```python
from scanner.exploit_integration import exploit_vulnerabilities

# Visual proofs are captured by default (no config needed!)
result = exploit_vulnerabilities(vulnerabilities)

# Proofs automatically saved and linked to vulnerabilities
```

**Default Behavior (Since v2.6):**
- ✅ Visual proof capture is **enabled by default**
- ✅ Proof reporting is **enabled by default**
- ✅ No configuration required for basic usage
- ✅ Smart type selection (GIF for dynamic, screenshot for static)
- ⚠️ If dependencies are missing, a warning is logged but exploitation continues

**Dependencies:**
Visual proof capture requires:
- **Playwright** (preferred) or **Selenium** - for browser automation
- **Pillow** - for image processing

If these are not installed, you'll see a warning message with installation instructions:
```
Visual proof capture requires Playwright or Selenium for browser automation.
Install with: pip install playwright (preferred) or pip install selenium
For Playwright, also run: playwright install chromium
```

### Manual Capture

For custom exploitation code:

```python
from scanner.visual_proof_capture import get_visual_proof_capture

# Get capture instance
capture = get_visual_proof_capture()

# Capture screenshot
proof = capture.capture_exploit_proof(
    vuln_type='xss',
    vuln_id=123,
    url='https://example.com/vulnerable?param=<script>alert(1)</script>',
    capture_type='gif',
    duration=3.0
)

if proof:
    print(f"Proof saved: {proof['path']}")
    print(f"Type: {proof['type']}")
    print(f"Size: {proof['size']} bytes")
    
    # Update vulnerability
    vulnerability.visual_proof_path = proof['path']
    vulnerability.visual_proof_type = proof['type']
    vulnerability.visual_proof_size = proof['size']
    vulnerability.save()
```

### Configuration

```python
config = {
    'visual_proof': {
        'enabled': True,          # Enable/disable feature
        'type': 'auto',           # 'auto', 'screenshot', or 'gif'
        'duration': 3.0,          # GIF duration in seconds
        'wait_time': 2.0,         # Wait before screenshot
        'viewport': (1280, 720),  # Browser viewport size
    }
}

result = exploit_vulnerabilities(vulnerabilities, config)
```

## Dashboard Display

### Visual Proof Section

The visual proof appears as a purple-themed section in the vulnerability card:

```
┌────────────────────────────────────────────────────────────┐
│ 📸 Visual Proof of Exploitation                            │
│                                                             │
│ Type: gif • Size: 234.5 KB                                 │
│                                                             │
│ ┌────────────────────────────────────────┐                │
│ │                                          │                │
│ │         [Animated GIF Preview]          │                │
│ │                                          │                │
│ └────────────────────────────────────────┘                │
│                                                             │
│ 🎬 Click to view in fullscreen                             │
│                                                             │
│ [📥 Download Proof]                                         │
└────────────────────────────────────────────────────────────┘
```

### Fullscreen Viewer

Click on any visual proof to open the fullscreen viewer:

- **Dark overlay** with 90% opacity
- **Centered image** (up to 90% viewport)
- **Close button** (top-right, or ESC key)
- **Download button** below image
- **Click outside** to close
- **Responsive** on all devices

### Features in Dashboard

✅ Inline thumbnail preview (max 400px height)  
✅ File type and size indicators  
✅ Click-to-fullscreen functionality  
✅ Download button with icon  
✅ Smooth animations and transitions  
✅ Dark mode compatible  
✅ Mobile responsive  

## Optimization & Performance

### File Size Management

The system ensures files never exceed 10MB through multiple stages:

1. **Initial Compression** (85% quality)
2. **GIF Palette Reduction** (128 colors)
3. **Frame Reduction** (take every other frame)
4. **Dimension Scaling** (0.8x scale factor)
5. **Hard Limit Enforcement** (reject if still >10MB)

### Typical File Sizes

| Type | Typical Size | Max Size |
|------|--------------|----------|
| Screenshot (PNG) | 50-200 KB | 2 MB |
| Animated GIF (3s) | 100-500 KB | 3 MB |
| Animated GIF (5s) | 200-800 KB | 5 MB |

### Performance Impact

- **Capture Time**: 2-5 seconds per proof
- **CPU Usage**: Low (headless browser)
- **Memory**: ~50-100MB during capture
- **Storage**: ~500KB average per proof
- **Impact on Exploitation**: Minimal (async capture)

## Security Considerations

### URL Validation

All URLs are validated before capture:

```python
# Valid URLs
✓ https://example.com
✓ http://localhost:8000
✓ https://192.168.1.1:3000

# Invalid URLs (rejected)
✗ ftp://example.com
✗ javascript:alert(1)
✗ file:///etc/passwd
✗ <empty string>
```

### File Security

- **Secure filenames**: Hash-based with timestamp
- **Path validation**: No directory traversal
- **Size limits**: Hard 10MB maximum
- **Type validation**: Only image types allowed
- **Cleanup**: Automatic old file removal (optional)

### Privacy

- **No PII capture**: Only visual interface
- **Sanitized URLs**: Query params removed from filenames
- **Access control**: Files in media directory (serve with authentication)

## Troubleshooting

### Automated Diagnostics

The scanner now includes automated diagnostics for visual proof issues. Check scan results for warnings:

```json
{
  "scan_id": 123,
  "warnings": [
    {
      "category": "visual_proof",
      "severity": "high",
      "component": "Pillow",
      "message": "Pillow (PIL) is not installed - required for image processing",
      "recommendation": "pip install Pillow"
    }
  ],
  "vulnerabilities": [...]
}
```

Each vulnerability now includes a `visual_proof_status` field:
- **`captured`**: Visual proof successfully captured
- **`disabled`**: Visual proof disabled by configuration
- **`failed`**: Capture attempted but failed (check warnings)
- **`not_supported`**: Not supported for this vulnerability type
- **`missing_dependencies`**: Required dependencies not installed
- **`not_attempted`**: Visual proof not attempted

### Diagnostic Check

Run a comprehensive diagnostic check:

```python
from scanner.visual_proof_diagnostics import check_visual_proof_dependencies

result = check_visual_proof_dependencies()
print(f"Overall Status: {result['overall_status']}")
print(f"Dependencies: {result['dependencies']}")
print(f"Browsers: {result['browsers']}")
print(f"Filesystem: {result['filesystem']}")

# Print recommendations
for recommendation in result['recommendations']:
    print(f"→ {recommendation}")
```

### Common Issues

#### 1. "No visual proof available" - Missing Dependencies

**Symptoms:**
- Scan results show `visual_proof_status: "missing_dependencies"`
- Warnings list missing components (Playwright, Selenium, Pillow)
- Backend logs show dependency warnings

**Solution:**
```bash
# Install all required dependencies
pip install playwright selenium Pillow

# For Playwright, also install browser
playwright install chromium
```

**Verification:**
```python
from scanner.visual_proof_diagnostics import check_visual_proof_dependencies
result = check_visual_proof_dependencies()
assert result['overall_status'] == 'ok', f"Issues: {result['recommendations']}"
```

#### 2. "Visual proof capture failed" - Browser Issues

**Symptoms:**
- `visual_proof_status: "failed"`
- Warning: "Browser binary not found" or "Browser automation failed"

**Solution:**
```bash
# For Playwright
playwright install chromium

# For Selenium - Install Chrome/Chromium
# Ubuntu/Debian:
sudo apt-get install chromium-browser

# macOS:
brew install --cask google-chrome

# Verify browser is accessible
which google-chrome || which chromium || which chromium-browser
```

#### 3. "Directory not writable" - Permission Issues

**Symptoms:**
- Warning: "Cannot create media directory" or "Directory not writable"
- Visual proofs not saved to disk

**Solution:**
```bash
# Check directory permissions
ls -la media/exploit_proofs/

# Fix permissions
chmod 755 media/exploit_proofs/
chown -R www-data:www-data media/  # For web server

# Check disk space
df -h media/
```

#### 4. "Playwright not available"

```bash
pip install playwright
playwright install chromium
```

#### 5. "Selenium WebDriver not found"

```bash
pip install selenium
# Install Chrome or Chromium on your system
```

#### 6. "PIL/Pillow not available"

```bash
pip install Pillow
```

#### 7. "Screenshot capture timeout"

Increase wait time or check network connectivity:

```python
config = {
    'visual_proof': {
        'wait_time': 5.0,  # Increase wait time
    }
}
```

#### 8. "File size exceeds limit"

Reduce duration for GIFs:

```python
config = {
    'visual_proof': {
        'duration': 2.0,  # Shorter GIF
    }
}
```

### Debug Mode

Enable detailed logging:

```python
import logging
logging.getLogger('scanner.visual_proof_capture').setLevel(logging.DEBUG)
logging.getLogger('scanner.visual_proof_diagnostics').setLevel(logging.DEBUG)
logging.getLogger('scanner.proof_reporter').setLevel(logging.DEBUG)
```

### Understanding Visual Proof Status in API

When fetching vulnerability results, the `visual_proof_status` field tells you exactly what happened:

```javascript
// Frontend example
fetch('/api/scans/123/results/')
  .then(res => res.json())
  .then(data => {
    data.vulnerabilities.forEach(vuln => {
      switch(vuln.visual_proof_status) {
        case 'captured':
          console.log('✓ Visual proof available:', vuln.visual_proof_path);
          break;
        case 'missing_dependencies':
          console.warn('⚠ Cannot capture: dependencies missing');
          console.log('Install:', data.warnings
            .filter(w => w.category === 'visual_proof')
            .map(w => w.recommendation));
          break;
        case 'failed':
          console.error('✗ Capture failed - check logs');
          break;
        case 'disabled':
          console.info('ℹ Visual proof disabled in config');
          break;
        case 'not_supported':
          console.info('ℹ Not supported for this vulnerability type');
          break;
        default:
          console.info('ℹ Visual proof not attempted');
      }
    });
  });
```

### Scan-Level Warnings

Check scan-level warnings for system-wide issues:

```python
# Backend example
scan = Scan.objects.get(id=123)
if scan.warnings:
    for warning in scan.warnings:
        if warning['category'] == 'visual_proof':
            print(f"[{warning['severity'].upper()}] {warning['component']}")
            print(f"  {warning['message']}")
            print(f"  → {warning['recommendation']}")
```

## Best Practices

### 1. Capture Type Selection

- **Use GIFs** for interactive vulnerabilities (XSS alerts, form submissions)
- **Use Screenshots** for static content (error messages, file contents)
- **Use 'auto'** to let the system decide

### 2. Performance Optimization

- **Enable caching** for repeated scans
- **Limit duration** to 3 seconds or less
- **Run headless** browsers (enabled by default)
- **Batch processing** for multiple vulnerabilities

### 3. Storage Management

- **Set up cleanup** for old proofs (30-day retention)
- **Monitor disk usage** in media directory
- **Archive** proofs for important findings
- **Compress** old proofs for long-term storage

### 4. Reporting

- **Include in reports** for stakeholders
- **Export as ZIP** for bulk sharing
- **Annotate** screenshots with context
- **Create galleries** for presentations

## API Reference

### VisualProofCapture Class

```python
class VisualProofCapture:
    """Main class for visual proof capture."""
    
    def __init__(self, output_dir='media/exploit_proofs'):
        """Initialize capture instance."""
    
    def capture_screenshot(self, url, wait_time=2.0) -> Optional[bytes]:
        """Capture single screenshot."""
    
    def capture_gif(self, url, duration=3.0) -> Optional[List[bytes]]:
        """Capture multiple screenshots for GIF."""
    
    def capture_exploit_proof(self, vuln_type, vuln_id, url, 
                             capture_type='screenshot') -> Optional[Dict]:
        """High-level capture method (recommended)."""
    
    def sanitize_url(self, url) -> bool:
        """Validate URL for security."""
    
    def optimize_image(self, image_bytes) -> bytes:
        """Optimize image size."""
```

### Helper Functions

```python
def get_visual_proof_capture(output_dir='media/exploit_proofs'):
    """Get or create global capture instance."""
```

## Examples

### Example 1: Basic Usage

```python
from scanner.visual_proof_capture import get_visual_proof_capture

capture = get_visual_proof_capture()
proof = capture.capture_exploit_proof(
    vuln_type='xss',
    vuln_id=123,
    url='https://example.com/xss',
    capture_type='gif'
)

if proof:
    print(f"✓ Proof captured: {proof['path']}")
```

### Example 2: Custom Configuration

```python
config = {
    'visual_proof': {
        'enabled': True,
        'type': 'gif',
        'duration': 5.0,
        'viewport': (1920, 1080),
    }
}

result = exploit_vulnerabilities(vulnerabilities, config)
```

### Example 3: Batch Processing

```python
from scanner.visual_proof_capture import get_visual_proof_capture

capture = get_visual_proof_capture()

for vuln in vulnerabilities:
    if vuln.exploited:
        proof = capture.capture_exploit_proof(
            vuln_type=vuln.vulnerability_type,
            vuln_id=vuln.id,
            url=vuln.url
        )
        if proof:
            vuln.visual_proof_path = proof['path']
            vuln.save()
```

## Future Enhancements

### Planned Features

- [ ] **Video capture** for complex interactions
- [ ] **Timeline view** for GIF frames
- [ ] **Annotations** on screenshots (arrows, text)
- [ ] **Comparison view** (before/after)
- [ ] **Thumbnail generation** for performance
- [ ] **Proof gallery** view in dashboard
- [ ] **Export to PDF** with proofs
- [ ] **Automated cleanup** with retention policies
- [ ] **Cloud storage** integration (S3, Azure Blob)
- [ ] **Proof verification** with checksums

### Suggestions Welcome!

Have ideas for improvements? Please open an issue or PR!

## Support

For issues or questions:

1. Check the **Troubleshooting** section
2. Run `demo_visual_proof.py` for diagnostics
3. Enable debug logging
4. Check GitHub issues
5. Open a new issue with details

## License

Part of the Megido vulnerability scanner project.

## Credits

Developed to provide visual evidence of exploitation impact, making security reports more compelling and actionable for both technical and non-technical stakeholders.

---

**Made with ❤️ for better security testing**

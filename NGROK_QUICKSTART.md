# 🚀 Quick Start: Scanning ngrok URLs with Megido

## What's New?

Megido now has enhanced support for scanning web applications exposed through **ngrok tunnels**! This makes it incredibly easy to scan:

- 🏠 Local development servers
- 🔒 Applications behind firewalls  
- 🧪 Testing environments
- 🤝 Shared preview environments

## 3-Step Quick Start

### 1️⃣ Start Your Local Application

```bash
# Example: Start a web server
python -m http.server 8080
# or
npm run dev
# or
python manage.py runserver 3000
```

### 2️⃣ Create ngrok Tunnel

```bash
ngrok http 8080
```

You'll see output like:
```
Forwarding   https://abc123.ngrok-free.app -> http://localhost:8080
```

**Copy the `https://abc123.ngrok-free.app` URL**

### 3️⃣ Scan with Megido

#### Option A: Web Dashboard (Easiest)

1. Open Megido: `http://localhost:8000/scanner/`
2. Paste your ngrok URL: `https://abc123.ngrok-free.app`
3. Click "Start Scan"
4. View results in real-time!

#### Option B: REST API

```bash
curl -X POST http://localhost:8000/scanner/api/targets/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token YOUR_TOKEN" \
  -d '{
    "url": "https://abc123.ngrok-free.app",
    "name": "My Local App Scan"
  }'
```

#### Option C: Python Script

```python
from scanner.scan_engine import ScanEngine

findings = ScanEngine().scan('https://abc123.ngrok-free.app', {
    'verify_ssl': True,
    'timeout': 30,
})

print(f"Found {len(findings)} vulnerabilities")
```

## Configuration (Optional)

### For Better Stability

Set environment variable for automatic CSRF configuration:

```bash
# Linux/macOS
export NGROK_URL="https://abc123.ngrok-free.app"

# Windows (PowerShell)
$env:NGROK_URL="https://abc123.ngrok-free.app"

# Windows (CMD)
set NGROK_URL=https://abc123.ngrok-free.app
```

Then start Megido:
```bash
python manage.py runserver
```

### In .env File

Add to your `.env` file:
```
NGROK_URL=https://abc123.ngrok-free.app
NGROK_AUTH_TOKEN=your_ngrok_token_here  # Optional, for stable tunnels
```

## Common Use Cases

### 🧪 Test Before Deploying

```bash
# Terminal 1: Local dev server
npm run dev

# Terminal 2: ngrok tunnel
ngrok http 3000

# Terminal 3 or Browser: Scan with Megido
# Use ngrok URL in scanner
```

### 🏢 Test Internal Applications

```bash
# Expose internal app
ngrok http internal-app.company:8080

# Scan from your machine
# Use generated ngrok URL
```

### 🤖 CI/CD Integration

```bash
#!/bin/bash
# Start app and scan in CI pipeline
npm run dev &
ngrok http 3000 &
sleep 5
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
curl -X POST $MEGIDO_API/targets/ -d "{\"url\": \"$NGROK_URL\"}"
```

## Troubleshooting

### "CSRF verification failed"

**Solution:** Set the `NGROK_URL` environment variable:
```bash
export NGROK_URL="https://your-subdomain.ngrok-free.app"
```

### ngrok tunnel closes during scan

**Solution:** Keep the ngrok terminal open, or use:
```bash
ngrok http 3000 --log=stdout
```

### Slow scan performance

**Expected!** ngrok introduces network latency. Consider:
- Using a faster ngrok region: `ngrok http 3000 --region us`
- Increasing scan timeouts in configuration

### "Host not allowed"

**Solution:** Already fixed! The default configuration accepts all ngrok domains.

## Next Steps

📚 **Want to learn more?** Check out the comprehensive guide:
- **Full Documentation**: `docs/NGROK_SCANNING_GUIDE.md`
  - Advanced configuration
  - ngrok installation for all platforms
  - Best practices
  - Security considerations
  - Multiple examples

🔐 **Need ngrok for callbacks too?** See `NGROK_CALLBACK_GUIDE.md` for using ngrok to verify XSS exploits (different from scanning targets).

## Example Session

```bash
# Complete example from start to finish

# 1. Start local test app
$ python -m http.server 8080 &
Serving HTTP on 0.0.0.0 port 8080...

# 2. Start ngrok
$ ngrok http 8080
Session Status: online
Forwarding: https://abc123.ngrok-free.app -> http://localhost:8080

# 3. Test ngrok URL works
$ curl https://abc123.ngrok-free.app
<!DOCTYPE HTML>...

# 4. Optional: Set environment variable
$ export NGROK_URL="https://abc123.ngrok-free.app"

# 5. Start Megido (if not running)
$ python manage.py runserver

# 6. Open browser to Megido scanner
$ open http://localhost:8000/scanner/

# 7. Enter ngrok URL and scan!
# Enter: https://abc123.ngrok-free.app
# Click: Start Scan

# 8. View results
# Scan completes and shows vulnerabilities found

# 9. Cleanup
$ kill %1  # Stop test server
$ pkill ngrok  # Stop ngrok
```

## Tips & Best Practices

✅ **DO:**
- Use HTTPS ngrok tunnels (default for ngrok)
- Keep ngrok terminal open during scans
- Test ngrok URL in browser before scanning
- Use ngrok auth token for better stability
- Set `NGROK_URL` environment variable

❌ **DON'T:**
- Use HTTP for sensitive applications (use HTTPS)
- Hardcode ngrok URLs (they change on restart)
- Share ngrok URLs publicly (they expose your local machine)
- Scan without testing ngrok tunnel first

## Features Supported

✅ All vulnerability scan types:
- Cross-Site Scripting (XSS)
- SQL Injection
- CSRF
- XXE
- SSRF
- Open Redirect
- Information Disclosure
- And more!

✅ All scanner features:
- Stealth mode
- Callback verification
- Visual proof capture
- Exploit plugins
- Custom payloads

✅ All ngrok domain formats:
- `*.ngrok-free.app`
- `*.ngrok-free.dev`
- `*.ngrok.io`
- Custom subdomains (paid plans)

## Support

**Need Help?**
- 📖 Full guide: `docs/NGROK_SCANNING_GUIDE.md`
- 🔧 Test your setup: `python test_ngrok_scanner.py`
- 🐛 Report issues: [GitHub Issues](https://github.com/tkstanch/Megido/issues)
- 📚 ngrok docs: https://ngrok.com/docs

**Common Questions:**
- Q: Do I need a paid ngrok account?
  - A: No, free tier works fine! Paid gives stable URLs.

- Q: Can I scan multiple ngrok URLs?
  - A: Yes! Create separate targets for each URL.

- Q: Does this work with other tunneling services?
  - A: Yes! Works with any public URL (localhost.run, serveo, etc.)

---

**That's it!** You're ready to scan ngrok URLs with Megido. Happy scanning! 🎉

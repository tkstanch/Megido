# Megido Security - Quick Start Guide

Get started with Megido Security in 5 minutes!

## Step 1: Install

```bash
# Clone the repository
git clone https://github.com/tkstanch/Megido.git
cd Megido

# Install dependencies
pip install -r requirements.txt

# Run setup (creates database)
python manage.py migrate
```

Or use the automated setup scripts:
- **Windows**: Double-click `setup.bat`
- **Linux/Mac**: Run `./setup.sh`

## Step 2: Launch

```bash
# Smart launcher (auto-detects best mode)
python launch.py

# Or explicitly choose:
python launch.py web      # Web mode
python launch.py desktop  # Desktop mode
```

The application will start at `http://localhost:8000`

## Step 3: Explore

### Test the HTTP Repeater
1. Navigate to `/repeater/`
2. Enter a URL: `http://example.com`
3. Select method: `GET`
4. Click "Send Request"
5. View the response!

### Run a Vulnerability Scan
1. Navigate to `/scanner/`
2. Enter target URL: `http://example.com`
3. Click "Start Scan"
4. View discovered vulnerabilities

## Quick Tour

### Main Features

| Feature | URL | Purpose |
|---------|-----|---------|
| **Home** | `/` | Overview and navigation |
| **Proxy** | `/proxy/` | Monitor HTTP traffic |
| **Interceptor** | `/interceptor/` | Capture and modify requests |
| **Repeater** | `/repeater/` | Manual request testing |
| **Scanner** | `/scanner/` | Automated vulnerability scanning |
| **Admin** | `/admin/` | Database management |

### API Endpoints

Test the API with curl:

```bash
# List scan targets
curl http://localhost:8000/scanner/api/targets/

# Create a target
curl -X POST http://localhost:8000/scanner/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com", "name": "Test"}'

# Start a scan
curl -X POST http://localhost:8000/scanner/api/targets/1/scan/

# Get results
curl http://localhost:8000/scanner/api/scans/1/results/
```

## Next Steps

### Learn More
- Read [USAGE_GUIDE.md](USAGE_GUIDE.md) for detailed instructions
- Check [CONFIGURATION.md](CONFIGURATION.md) for settings
- Review [SECURITY.md](SECURITY.md) for security considerations

### Try the Demo
```bash
# Make sure the server is running, then:
python demo.py
```

### Configure
Set environment variables for production:
```bash
export DJANGO_SECRET_KEY="your-secret-key"
export DJANGO_DEBUG=False
export DJANGO_ALLOWED_HOSTS=yourdomain.com
```

## Common Tasks

### Create Admin User
```bash
python manage.py createsuperuser
```

### Run on Different Port
```bash
python manage.py runserver 8080
```

### Reset Database
```bash
rm db.sqlite3
python manage.py migrate
```

## Troubleshooting

### Port Already in Use
```bash
# Use a different port
python manage.py runserver 8080
```

### Desktop Mode Fails
```bash
# Use web mode instead
python launch.py web
```

### Dependencies Won't Install
```bash
# Try installing individually
pip install django djangorestframework
pip install requests beautifulsoup4
pip install PySide6  # Optional, for desktop mode
```

## Getting Help

- 📖 Read the [README.md](README.md)
- 📚 Check [USAGE_GUIDE.md](USAGE_GUIDE.md)
- 🔧 Review [CONFIGURATION.md](CONFIGURATION.md)
- 🛡️ See [SECURITY.md](SECURITY.md)
- 💬 Open an issue on GitHub

## Important Reminders

⚠️ **Always use responsibly**:
- Get authorization before testing
- Only test systems you own or have permission to test
- Follow all applicable laws and regulations
- Use in controlled environments

🎯 **Perfect for**:
- Security professionals
- Penetration testers
- Security researchers
- Educational purposes

---

**You're ready to go!** Start exploring Megido Security and enhance your security testing workflow.

For more details, see the comprehensive [README.md](README.md) and [USAGE_GUIDE.md](USAGE_GUIDE.md).

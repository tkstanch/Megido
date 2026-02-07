# Megido Security Testing Platform

[...]existing intro sections...]

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

[...]rest of README untouched...
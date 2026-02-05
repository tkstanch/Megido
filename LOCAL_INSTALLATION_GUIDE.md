# Megido Local Installation & Download Guide

This guide explains how to **download, install, and run Megido locally** on **Windows**, **macOS**, and **Linux** – both with Docker (recommended) and standard Python (manual setup). Follow the method that best fits your environment and comfort level!

---

## Table of Contents

- [Quick Download](#quick-download)
- [Recommended: Run with Docker (All OS)](#recommended-run-with-docker-all-os)
- [Manual Python Installation](#manual-python-installation)
  - [Linux / macOS](#linux--macos-manual-install)
  - [Windows](#windows-manual-install)
- [First-time User Checklist](#first-time-user-checklist)
- [Troubleshooting & Support](#troubleshooting--support)
- [Uninstall / Clean Up](#uninstall--clean-up)
- [Legal and Security Notice](#legal-and-security-notice)

---

## Quick Download

You can download Megido directly from GitHub:

- **Git (all OS):**
  ```bash
  git clone https://github.com/tkstanch/Megido.git
  cd Megido
  ```
- **ZIP Download:**
  1. Go to https://github.com/tkstanch/Megido
  2. Click the green "Code" button > "Download ZIP"
  3. Unzip to a folder of your choice
  4. Open a terminal (PowerShell / Terminal / Git Bash), `cd` to the unzipped folder

---

## Recommended: Run with Docker (All OS)

Docker provides the simplest, most reliable setup, including all required dependencies (Python, ClamAV, etc.).

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS)
- [Docker Engine](https://docs.docker.com/engine/install/) (Linux)
- Terminal or PowerShell

### Quick Start

1. **Clone or download Megido and `cd` into the folder**
2. **Start the Docker services:**
   ```bash
   docker compose up --build
   ```
3. **First launch takes 3–5 minutes (ClamAV downloads virus definitions).**
4. **Access the app:**
   - Launch your browser and go to http://localhost:8000
   - Login with:  
     - Username: `admin`  
     - Password: `admin`
   - Navigate to `/malware-analyser/` for malware scanning.
5. **To stop:**
   - Press `Ctrl+C` in terminal, then:
     ```bash
     docker compose down
     ```
6. **(Optional) To remove all data:**
   ```bash
   docker compose down -v
   ```

**For advanced Docker usage or troubleshooting, see [DOCKER_TESTING.md](DOCKER_TESTING.md)**

---

## Manual Python Installation

If you prefer or need to run Megido without Docker, follow these OS-specific guides.

### Linux & macOS (Manual Install)

#### 1. Prerequisites

- **Python 3.12+** (install from https://www.python.org/downloads/)
- **pip** (Python package manager, usually included)
- **ClamAV Antivirus**  
  - Ubuntu/Debian:
    ```bash
    sudo apt update
    sudo apt install clamav clamav-daemon
    sudo systemctl enable clamav-daemon
    sudo systemctl start clamav-daemon
    ```
  - macOS (with [Homebrew](https://brew.sh/)):
    ```bash
    brew install clamav
    sudo mkdir -p /usr/local/var/run/clamav
    sudo clamav-freshclam
    sudo clamd
    ```

#### 2. Setup Project

```bash
git clone https://github.com/tkstanch/Megido.git
cd Megido
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. Database & App Setup

```bash
python manage.py migrate
python manage.py createsuperuser  # follow prompts for admin account
python manage.py collectstatic
```

#### 4. Run the App

Start ClamAV daemon if not running (see above), then:

```bash
python manage.py runserver
```

Open `http://localhost:8000` in your browser. Login with your superuser account.

---

### Windows (Manual Install)

#### 1. Prerequisites

- [Python 3.12+](https://www.python.org/downloads/windows/) and pip
- [ClamAV for Windows](https://www.clamav.net/downloads) (install, and launch the **clamd** service)
- [Git for Windows](https://git-scm.com/download/win) (or download ZIP as above)
- **(Optional but recommended) [Windows Terminal](https://aka.ms/terminal) or PowerShell**

#### 2. Setup the Project

Open Command Prompt or PowerShell:

```powershell
git clone https://github.com/tkstanch/Megido.git
cd Megido
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

#### 3. Database & App Setup

```powershell
python manage.py migrate
python manage.py createsuperuser     # create admin credentials
python manage.py collectstatic
```

#### 4. Run Megido

Make sure ClamAV daemon is running (`clamd.exe`) on the default port (3310):

```powershell
python manage.py runserver
```

- Go to `http://localhost:8000` in your browser and sign in.

---

## External Network Access Configuration

For local testing with external targets:

1. The application is pre-configured to allow external requests in development mode
2. SSL verification is disabled by default for testing purposes
3. All Django apps (browser, proxy, scanner, spider, etc.) can reach external sites

### Environment Variables

Control network behavior via environment variables:

- `ALLOW_EXTERNAL_REQUESTS=true` - Enable external network access
- `VERIFY_SSL=false` - Disable SSL certificate verification (testing only)
- `REQUESTS_TIMEOUT=30` - Request timeout in seconds

### Security Warning

⚠️ **IMPORTANT**: These settings are for LOCAL TESTING ONLY!

- Never deploy to production with `ALLOWED_HOSTS = ['*']`
- Never disable SSL verification in production
- Always obtain explicit permission before testing external targets
- This is a security testing tool - use responsibly and ethically

### Testing External Access

Test that external requests work:

```bash
python manage.py shell
```

```python
import requests
from django.conf import settings

# Use the configured timeout and SSL verification settings
response = requests.get(
    'https://example.com',
    verify=settings.REQUESTS_VERIFY_SSL,
    timeout=settings.REQUESTS_TIMEOUT,
    allow_redirects=settings.REQUESTS_ALLOW_REDIRECTS
)
print(response.status_code)  # Should print 200
```

**Note**: Django apps should use `settings.REQUESTS_VERIFY_SSL`, `settings.REQUESTS_TIMEOUT`, and `settings.REQUESTS_ALLOW_REDIRECTS` when making external requests to ensure consistent behavior across the application.

---

## First-time User Checklist

- [ ] Clone or download the code.
- [ ] Install Docker (recommended) or all dependencies manually.
- [ ] Launch ClamAV daemon (manual mode only).
- [ ] Run `docker compose up` *or* `python manage.py runserver` as above.
- [ ] Login and try uploading/scanning a file (see [README.md](README.md) for EICAR test file).
- [ ] For help: see [README.md](README.md), [DOCKER_TESTING.md](DOCKER_TESTING.md), or open an issue.

---

## Troubleshooting & Support

- ClamAV errors?  
  See "Troubleshooting" in [DOCKER_TESTING.md](DOCKER_TESTING.md) or Google your platform for "run ClamAV daemon".
- App doesn't start?  
  Re-check prerequisites and [README.md](README.md).
- Need help?  
  Visit https://github.com/tkstanch/Megido/issues

---

## Uninstall / Clean Up

- **Docker:**  
  ```bash
  docker compose down -v
  ```
- **Manual install:**  
  Simply delete the Megido folder and all data.

---

## Legal and Security Notice

- **Megido and Malware Analyser are for authorized educational and research use only.**
- Never scan files or systems without explicit permission!
- Always use in a secure, isolated environment.
- See [malware_analyser/README.md](malware_analyser/README.md) for legal disclaimers and ethical guidelines.

---

Enjoy exploring security with Megido!
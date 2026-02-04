# Megido Security Testing Platform

A cutting-edge **cross-platform desktop application** for web and mobile security testing, built with Django and PySide6. Megido provides professional-grade security testing tools similar to Burp Suite Professional, with advanced features for vulnerability scanning, request interception, HTTP proxying, and automated security testing.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Django](https://img.shields.io/badge/django-6.0%2B-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

## 🌟 Features

### Core Security Testing Modules

1. **🔄 HTTP Proxy**
   - Intercept and analyze all HTTP/HTTPS traffic
   - SSL/TLS support for secure connections
   - Real-time traffic monitoring
   - Request/response history with database storage
   - Automatic content type detection

2. **✋ Request Interceptor**
   - Capture HTTP requests in real-time
   - Modify requests before forwarding to server
   - Drop or forward intercepted requests
   - Manual inspection and editing capabilities
   - Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)

3. **🔁 HTTP Repeater**
   - Manual HTTP request crafting and testing
   - Custom header and body support
   - Response time measurement
   - Request history and templating
   - Support for complex authentication scenarios

4. **🔍 Vulnerability Scanner**
   - Automated security vulnerability detection
   - Support for common vulnerability types:
     - Cross-Site Scripting (XSS)
     - SQL Injection
     - CSRF vulnerabilities
     - Security header analysis
     - SSL/TLS configuration issues
     - Information disclosure
     - And more...
   - Severity-based classification (Critical, High, Medium, Low)
   - Detailed remediation recommendations
   - Evidence-based reporting

5. **🦠 Malware Analyser with ClamAV Integration** ⚠️
   - **REAL malware detection** using ClamAV antivirus engine
   - File upload and scanning with virus signature detection
   - EICAR test file support for safe testing
   - Scan results with threat level classification
   - **⚠️ EDUCATIONAL USE ONLY - FOR DEMONSTRATION PURPOSES**
   - **Never use with real malware outside secure sandboxes**
   - See detailed warnings in the Malware Analyser section below

### Technical Features

- ✅ **Cross-Platform Desktop Application**: Runs natively on Windows, macOS, and Linux
- ✅ **Django Backend**: Robust, scalable backend framework
- ✅ **REST API**: Full API support for automation and integration
- ✅ **Database-Backed**: SQLite database for persistent storage
- ✅ **Modern UI**: Clean, responsive web-based interface
- ✅ **Real-time Updates**: Live monitoring and auto-refresh capabilities
- ✅ **Extensible Architecture**: Easy to add new security testing modules
- ✅ **Docker Support**: Easy deployment with Docker Compose (Django + ClamAV)

## ⚠️ Malware Analyser - Critical Safety Warnings

The Malware Analyser module integrates with **ClamAV for REAL malware detection**. This is a powerful feature that comes with serious responsibilities:

### 🚨 LEGAL AND SAFETY WARNINGS

**THIS IS FOR EDUCATIONAL AND DEMONSTRATION PURPOSES ONLY**

- ❌ **NEVER** use for production malware analysis
- ❌ **NEVER** analyze real malware outside secure, isolated sandboxes
- ❌ **NEVER** use on systems containing sensitive data
- ✅ **ALWAYS** use in controlled, authorized testing environments only
- ✅ **ALWAYS** ensure compliance with all applicable laws and regulations
- ✅ **ALWAYS** obtain proper authorization before use

### Legal Considerations

Creating, distributing, or analyzing malware without authorization is **ILLEGAL** in most jurisdictions under laws including:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Council of Europe Convention on Cybercrime - International

**Users are solely responsible for their use of this tool and compliance with all laws.**

### Safe Testing

For safe testing of the malware detection features:
- Use the **EICAR test file** - a standard, safe test file that antivirus engines detect
- EICAR is specifically designed for testing antivirus software
- EICAR is NOT malware and is completely safe to use
- More info: https://www.eicar.org/

## 🚀 Installation

### Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a 5-minute setup guide!

### Prerequisites

- Python 3.12 or higher
- pip (Python package manager)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tkstanch/Megido.git
   cd Megido
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run database migrations:**
   ```bash
   python manage.py migrate
   ```

4. **Start the desktop application:**
   ```bash
   python desktop_app.py
   ```

   Or run as a web application:
   ```bash
   python manage.py runserver
   ```
   Then open your browser to `http://localhost:8000`

## 🐳 Docker Setup (Recommended for Malware Analyser)

For the **Malware Analyser with ClamAV**, we recommend using Docker for easy setup and isolation:

### Prerequisites

- Docker and Docker Compose installed
- At least 2GB of free RAM (ClamAV requires memory for virus definitions)
- Internet connection for initial ClamAV signature download

### Quick Start with Docker

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tkstanch/Megido.git
   cd Megido
   ```

2. **Start with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

3. **Wait for ClamAV initialization:**
   - First startup takes 2-5 minutes as ClamAV downloads virus definitions
   - Watch logs: `docker-compose logs -f clamav`
   - Look for "clamd[X]: Self checking every 3600 seconds" message

4. **Access the application:**
   - Open browser to `http://localhost:8000`
   - Default superuser: `admin` / `admin` (created automatically)
   - Navigate to `/malware-analyser/` for file scanning

### Docker Services

The `docker-compose.yml` includes:
- **web**: Django application (port 8000)
- **clamav**: ClamAV antivirus daemon (port 3310)

### Testing with EICAR

To test malware detection safely, use the EICAR test file:

1. Navigate to `/malware-analyser/`
2. Upload a file containing: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
3. Run a scan - ClamAV should detect it as "Eicar-Signature"

### Docker Commands

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up --build

# Check ClamAV status
docker-compose exec clamav clamdscan --version
```

### Troubleshooting Docker Setup

**ClamAV not detecting files:**
- Ensure ClamAV container is fully started: `docker-compose logs clamav`
- Check health status: `docker ps` (should show "healthy")
- Wait for virus definition updates to complete

**Connection refused errors:**
- ClamAV takes time to start (especially first time)
- Check if clamav container is running: `docker ps`
- Verify network connectivity: `docker-compose exec web ping clamav`

**Out of memory:**
- ClamAV needs ~1GB RAM minimum
- Increase Docker memory limit in Docker Desktop settings

## 📖 Usage Guide

For detailed usage instructions, see [USAGE_GUIDE.md](USAGE_GUIDE.md)

### Starting the Application

#### Smart Launcher (Recommended)
```bash
python launch.py
```
Automatically detects your environment and chooses the best mode (desktop or web).

#### Desktop Mode
```bash
python launch.py desktop
# or
python desktop_app.py
```

#### Web Mode
```bash
python launch.py web
# or
python manage.py runserver
```
Then open your browser to `http://localhost:8000`

### Quick Feature Overview

- **Proxy**: Navigate to `/proxy/` to monitor HTTP/HTTPS traffic
- **Interceptor**: Navigate to `/interceptor/` to intercept and modify requests
- **Repeater**: Navigate to `/repeater/` to craft custom HTTP requests
- **Scanner**: Navigate to `/scanner/` to perform vulnerability scans
- **Malware Analyser**: Navigate to `/malware-analyser/` for file scanning with ClamAV ⚠️ (Educational use only)

See the [USAGE_GUIDE.md](USAGE_GUIDE.md) for detailed instructions on each feature.

## 🏗️ Architecture

### Project Structure

```
Megido/
├── desktop_app.py          # Desktop application entry point
├── manage.py               # Django management script
├── requirements.txt        # Python dependencies
├── megido_security/        # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── proxy/                  # HTTP Proxy module
│   ├── models.py
│   ├── views.py
│   └── urls.py
├── interceptor/            # Request Interceptor module
│   ├── models.py
│   ├── views.py
│   └── urls.py
├── repeater/               # HTTP Repeater module
│   ├── models.py
│   ├── views.py
│   └── urls.py
├── scanner/                # Vulnerability Scanner module
│   ├── models.py
│   ├── views.py
│   └── urls.py
└── templates/              # HTML templates
    ├── base.html
    ├── home.html
    └── [module templates]
```

### Technology Stack

- **Backend**: Django 6.0+ (Python web framework)
- **Desktop Framework**: PySide6 (Qt for Python)
- **Database**: SQLite (can be upgraded to PostgreSQL/MySQL)
- **API**: Django REST Framework
- **HTTP Client**: Requests library
- **HTML Parsing**: BeautifulSoup4
- **Proxy**: mitmproxy (for advanced proxy features)

## 🔧 Configuration

### Environment Variables

The application can be configured using environment variables. See [CONFIGURATION.md](CONFIGURATION.md) for detailed configuration options.

Key settings:
- `DJANGO_SECRET_KEY` - Secret key for Django (required for production)
- `DJANGO_DEBUG` - Enable/disable debug mode (default: True)
- `DJANGO_ALLOWED_HOSTS` - Comma-separated list of allowed hosts
- `MEGIDO_VERIFY_SSL` - Enable/disable SSL verification for testing (default: False)

### Django Settings

Edit `megido_security/settings.py` to configure:
- Database settings
- Allowed hosts
- Security settings
- Static files location

### Desktop Application Settings

Edit `desktop_app.py` to configure:
- Server port (default: 8000)
- Window size and position
- Application name and branding

## 🔌 API Reference

### Proxy API

- `GET /proxy/api/requests/` - List all proxy requests
- `GET /proxy/api/requests/<id>/` - Get request details

### Interceptor API

- `GET /interceptor/api/intercepted/` - List intercepted requests
- `GET /interceptor/api/intercepted/<id>/` - Get intercepted request
- `PUT /interceptor/api/intercepted/<id>/` - Update intercepted request

### Repeater API

- `GET /repeater/api/requests/` - List repeater requests
- `POST /repeater/api/requests/` - Create new request
- `POST /repeater/api/requests/<id>/send/` - Send request

### Scanner API

- `GET /scanner/api/targets/` - List scan targets
- `POST /scanner/api/targets/` - Create scan target
- `POST /scanner/api/targets/<id>/scan/` - Start scan
- `GET /scanner/api/scans/<id>/results/` - Get scan results

## 🛡️ Security Considerations

**Important**: This tool is designed for **authorized security testing only**.

- Always obtain proper authorization before testing any system
- Use only on systems you own or have explicit permission to test
- Be aware of legal and ethical implications
- Keep the application updated with the latest security patches
- **SSL Verification**: By default, SSL certificate verification is disabled for testing purposes. Set `MEGIDO_VERIFY_SSL=True` to enable it.
- **Secret Key**: Change the `DJANGO_SECRET_KEY` in production (see [CONFIGURATION.md](CONFIGURATION.md))
- **Debug Mode**: Disable `DJANGO_DEBUG` in production environments
- **Allowed Hosts**: Configure `DJANGO_ALLOWED_HOSTS` properly for production

For production deployment, see [CONFIGURATION.md](CONFIGURATION.md) for security best practices.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by Burp Suite Professional and other security testing tools
- Built with Django, PySide6, and other open-source technologies
- Thanks to the security research community

## 📞 Support

For issues, questions, or contributions, please:
- Open an issue on GitHub
- Check existing documentation
- Review the code comments and examples

## 🚀 Future Enhancements

Planned features for future releases:
- Advanced proxy filtering and scope management
- WebSocket support
- Custom vulnerability plugins
- Export reports (PDF, HTML, JSON)
- Collaborative testing features
- Advanced authentication handling (OAuth, JWT, etc.)
- Browser extension for easier proxy configuration
- Performance optimization for large-scale scans
- Machine learning-based vulnerability detection

---

**Disclaimer**: This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations.


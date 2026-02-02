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

### Technical Features

- ✅ **Cross-Platform Desktop Application**: Runs natively on Windows, macOS, and Linux
- ✅ **Django Backend**: Robust, scalable backend framework
- ✅ **REST API**: Full API support for automation and integration
- ✅ **Database-Backed**: SQLite database for persistent storage
- ✅ **Modern UI**: Clean, responsive web-based interface
- ✅ **Real-time Updates**: Live monitoring and auto-refresh capabilities
- ✅ **Extensible Architecture**: Easy to add new security testing modules

## 🚀 Installation

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


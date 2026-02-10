# SQL Injection Attacker App

A comprehensive SQL injection detection and exploitation tool integrated into the Megido security platform.

## Overview

The `sql_attacker` app provides automated SQL injection vulnerability detection and exploitation capabilities, inspired by SQLMAP but implemented entirely in pure Python. It offers both a web UI and REST API for managing attack tasks and reviewing results.

## Features

### 🔍 Automatic Parameter Discovery (NEW!)
- **Intelligent parameter extraction**: Automatically discovers all testable parameters from target pages
- **Form field detection**: Finds both visible and hidden form fields
- **Link parameter extraction**: Discovers parameters from anchor tags, scripts, images, and iframes
- **JavaScript analysis**: Extracts variables and parameters from inline and on-page JavaScript
- **Source tracking**: Tags each discovered parameter with its origin (form, hidden, link, JS, URL)
- **No manual input required**: Fully automated discovery process runs before testing

### Detection Capabilities
- **Error-based SQL injection detection**: Tests for SQL syntax errors in responses
- **Time-based (blind) SQL injection detection**: Detects blind SQLi using time delays
- Support for multiple database types: MySQL, PostgreSQL, MSSQL, Oracle, SQLite

### Exploitation Features
- Database version extraction
- Current database name extraction
- Current database user extraction
- Table name enumeration (planned)
- Data extraction from tables (planned)

### Stealth Features
- Random delays between requests
- Randomized User-Agent headers
- Payload obfuscation for WAF evasion
- Configurable request timing

### Integration
- **Automatic integration with response_analyser app**: All findings are automatically forwarded to the `response_analyser` app for centralized vulnerability tracking
- Full evidence capture including requests, responses, and exploitation results

## Installation

The app is already installed as part of the Megido platform. No additional setup required.

## Usage

### Web UI

1. **Dashboard**: Navigate to `/sql-attacker/` to view the dashboard
   - View statistics on tasks and vulnerabilities
   - Access recent attack tasks and findings

2. **Create New Task**: Click "Create New Attack Task" or go to `/sql-attacker/tasks/create/`
   - Enter target URL
   - Enable/disable automatic parameter discovery (enabled by default)
   - Optionally specify manual parameters (GET/POST/cookies/headers)
   - Select attack types (error-based, time-based, exploitation)
   - Configure stealth options
   - Execute immediately or schedule for later

3. **Automatic Parameter Discovery**: When enabled (default), the attacker will:
   - Fetch the target page
   - Extract all form fields (visible and hidden)
   - Parse links and URLs for parameters
   - Analyze JavaScript for variables and parameters
   - Display discovered parameters in task details
   - Test all discovered parameters with SQL injection payloads

4. **View Results**: Tasks show status and all vulnerability findings
   - View detailed information about each vulnerability
   - See parameter source (form, hidden, link, JS, URL, manual)
   - Access exploitation results when available

### REST API

#### Create a new attack task:
```bash
POST /sql-attacker/api/tasks/
Content-Type: application/json

{
  "target_url": "https://example.com/page?id=1",
  "http_method": "GET",
  "get_params": {"id": "1"},
  "auto_discover_params": true,
  "enable_error_based": true,
  "enable_time_based": true,
  "enable_exploitation": true,
  "use_random_delays": false,
  "randomize_user_agent": true,
  "execute_now": true
}
```

**Note**: When `auto_discover_params` is `true` (default), the attacker will automatically discover and test additional parameters from the target page.
```

#### Get task details and results:
```bash
GET /sql-attacker/api/tasks/{task_id}/
```

#### Execute a task:
```bash
POST /sql-attacker/api/tasks/{task_id}/execute/
```

#### List all results:
```bash
GET /sql-attacker/api/results/
```

## Models

### SQLInjectionTask
Stores attack task configuration and status:
- Target URL, HTTP method, parameters
- Attack configuration (error-based, time-based, exploitation)
- **Parameter discovery** (auto_discover_params, discovered_params)
- Stealth configuration
- Status tracking (pending, running, completed, failed)

### SQLInjectionResult
Stores vulnerability findings:
- Injection type (error-based, time-based, etc.)
- Vulnerable parameter and type
- **Parameter source** (manual, form, hidden, link, js, url)
- Test payload and detection evidence
- Exploitation results (database info, extracted data)
- Request/response details

## Architecture

### Core Components

1. **param_discovery.py**: Automatic parameter discovery engine (NEW!)
   - `ParameterDiscoveryEngine` class for intelligent parameter extraction
   - `DiscoveredParameter` data structure for tracking parameter metadata
   - HTML parsing with BeautifulSoup for form fields and links
   - JavaScript analysis with regex for variables and parameters
   - Deduplication and merging of discovered parameters

2. **sqli_engine.py**: Pure Python SQL injection engine
   - `SQLInjectionEngine` class handles all attack logic
   - Payload generation and obfuscation
   - Request handling with stealth features
   - Error pattern matching
   - Time-based detection
   - Exploitation methods

3. **views.py**: Web UI and REST API views
   - Dashboard, task creation, task/result viewing
   - Background task execution using threading
   - Parameter discovery integration
   - Automatic forwarding to response_analyser

4. **models.py**: Django models for data persistence
   - Task tracking and configuration
   - Result storage with full evidence
   - Parameter discovery metadata

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only.

- Always obtain proper authorization before testing any target
- SSL verification is disabled by default for security testing environments
- Configure stealth options appropriately for your testing scenario
- Be aware of rate limiting and blocking mechanisms

## Integration with response_analyser

All SQL injection findings are automatically forwarded to the `response_analyser` app using the `save_vulnerability()` function. This provides:

- Centralized vulnerability management
- Unified reporting across all attack types
- Evidence preservation for compliance and reporting

## Future Enhancements

- [ ] UNION-based SQL injection detection
- [ ] Boolean-based blind SQL injection
- [ ] Enhanced table and column enumeration
- [ ] Automated data dumping
- [ ] WAF fingerprinting
- [ ] Custom payload library
- [ ] Report generation
- [ ] Task scheduling and automation

## Admin Interface

Access the Django admin at `/admin/` to:
- View and manage all tasks
- Review vulnerability findings
- Monitor task execution status
- Access detailed request/response data

## API Documentation

Full API documentation is available through Django REST Framework's browsable API. Navigate to any API endpoint in your browser while authenticated to see the interactive documentation.

## Troubleshooting

### Task stays in "running" state
- Check error_message field in admin
- Review application logs
- Verify target URL is accessible

### No vulnerabilities found
- Verify target is actually vulnerable
- Try adjusting stealth settings
- Check if WAF is blocking requests

### Integration issues with response_analyser
- Ensure response_analyser app is installed and migrated
- Check that the app has proper database access

## Contributing

To extend the SQL injection engine:
1. Add new payloads to `sqli_engine.py`
2. Implement new detection methods
3. Enhance exploitation capabilities
4. Update tests accordingly

## License

Part of the Megido security platform.

# SQL Injection Payload Generator

A user-friendly web UI for generating SQL injection payloads based on comprehensive cheat sheets for Oracle, MySQL, and Microsoft SQL Server.

## Features

- 🎯 **Multi-DBMS Support**: Oracle, MySQL, MSSQL
- 🔄 **Context-Aware Payloads**: String, Numeric, Parenthesis contexts
- 📖 **Rich Cheat Sheets**: Syntax examples and error messages
- 🚀 **RESTful API**: Programmatic access to payload generation
- 💻 **Modern UI**: Clean, intuitive web interface
- 📋 **Copy to Clipboard**: One-click payload copying
- 🔒 **Secure by Default**: Environment-based configuration

## Quick Start

```bash
# Navigate to the sqli_web directory
cd sqli_web

# Start the Flask server
python app.py

# Open your browser
# Navigate to http://localhost:5000
```

## File Structure

```
sqli_web/
├── app.py                      # Flask application with REST API
├── sql_syntax_and_errors.py    # Cheat sheet dictionary
├── generate_sql_payloads.py    # Payload generation utility
├── templates/
│   └── index.html             # Web UI frontend
├── USAGE.md                    # Comprehensive usage guide
├── README.md                   # This file
└── __init__.py                 # Module initialization
```

## Components

### sql_syntax_and_errors.py
Comprehensive SQL syntax and error message cheat sheet for:
- Version detection
- UNION-based injection
- Time-based blind injection
- Error-based detection
- Information gathering
- String concatenation
- Comment syntax
- And more...

### generate_sql_payloads.py
Utility for generating context-aware payloads:
- `SQLPayloadGenerator`: Main class for payload generation
- `generate_payloads()`: Convenience function
- `get_cheat_sheet_reference()`: Retrieve reference data

### app.py
Flask web application with:
- Web UI serving at `/`
- REST API endpoints at `/api/*`
- Health check at `/health`
- Environment-based configuration

### templates/index.html
Modern, responsive web interface with:
- DBMS selection dropdown
- Injection type selection
- Context selection
- Real-time payload generation
- Syntax examples and error messages
- Copy to clipboard functionality

## API Endpoints

### Get Injection Types
```http
GET /api/injection-types/<dbms>
```

### Generate Payloads
```http
POST /api/generate-payload
Content-Type: application/json

{
    "dbms": "mysql",
    "injection_type": "version_detection",
    "context": "string"
}
```

### Get Cheat Sheet
```http
GET /api/cheat-sheet/<dbms>/<injection_type>
```

### Health Check
```http
GET /health
```

## Usage as Python Module

```python
from sqli_web import SQLPayloadGenerator, generate_payloads

# Generate a specific payload
generator = SQLPayloadGenerator('mysql')
payload = generator.get_payload('union_injection', 'string')
print(payload['payload'])  # ' UNION SELECT NULL--

# Generate all contexts
payloads = generate_payloads('oracle', 'version_detection')
for p in payloads:
    print(f"{p['context']}: {p['payload']}")
```

## Configuration

### Environment Variables

- `SECRET_KEY`: Flask secret key (auto-generated if not set)
- `FLASK_DEBUG`: Enable/disable debug mode (default: False)

### Production Deployment

```bash
# Set environment variables
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export FLASK_DEBUG=False

# Use Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 sqli_web.app:app
```

## Supported DBMS and Injection Types

### Oracle
- Version Detection
- Error Messages
- String Concatenation (||)
- Comment Syntax
- UNION Injection (with FROM dual)
- Time Delay (DBMS_LOCK.SLEEP)
- Information Gathering (all_tables, all_tab_columns)

### MySQL / MariaDB
- Version Detection (@@version)
- Error Messages
- String Concatenation (CONCAT)
- Comment Syntax (--, #, /**/)
- UNION Injection
- Time Delay (SLEEP)
- Information Gathering (information_schema)

### Microsoft SQL Server
- Version Detection (@@version)
- Error Messages
- String Concatenation (+)
- Comment Syntax
- UNION Injection
- Time Delay (WAITFOR DELAY)
- Stacked Queries
- Information Gathering (sysobjects, information_schema)

## Security Considerations

⚠️ **For authorized testing only**
- Always obtain proper authorization
- Use in controlled environments
- Follow responsible disclosure
- Comply with applicable laws

## Documentation

See [USAGE.md](USAGE.md) for comprehensive usage guide including:
- Installation instructions
- Step-by-step usage guide
- API examples
- Configuration options
- Security best practices
- Troubleshooting

## Integration with Megido

This tool is part of the Megido Security Testing Platform and integrates with:
- SQL Attacker module
- Proxy/Interceptor for real-time testing
- Advanced scanner for automated testing

## Testing

Run the test suite:
```bash
python test_sqli_web.py
```

## License

Part of the Megido Security Testing Platform.

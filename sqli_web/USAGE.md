# SQL Injection Payload Generator - Usage Guide

## Overview

The SQL Injection Payload Generator is a user-friendly web application that helps security testers and penetration testers quickly generate SQL injection payloads tailored to specific database management systems (DBMS) and injection contexts.

## Features

- **Multi-DBMS Support**: Generate payloads for Oracle, MySQL, and Microsoft SQL Server
- **Context-Aware Payloads**: Supports string, numeric, and parenthesis injection contexts
- **Rich Cheat Sheet**: Displays syntax examples and common error messages for reference
- **Ready-to-Use Payloads**: Generates payloads that can be copied and used immediately
- **Clean Interface**: Modern, intuitive web interface with real-time payload generation

## Installation

### Prerequisites

- Python 3.8 or higher
- Flask web framework

### Setup

1. Ensure you're in the Megido repository root directory:
   ```bash
   cd /path/to/Megido
   ```

2. Install dependencies (Flask will be installed from requirements.txt):
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Quick Start

1. Navigate to the `sqli_web` directory:
   ```bash
   cd sqli_web
   ```

2. Start the Flask server:
   ```bash
   python app.py
   ```

3. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

4. You should see the SQL Injection Payload Generator interface.

### Alternative: Run from Repository Root

You can also run the application from the repository root:
```bash
cd /path/to/Megido
python -m sqli_web.app
```

Or using Flask's command:
```bash
export FLASK_APP=sqli_web/app.py
flask run
```

## Using the Web Interface

### Step 1: Select Database Management System

Choose the target DBMS from the dropdown:
- **Oracle**: Oracle Database
- **MySQL**: MySQL / MariaDB
- **MSSQL**: Microsoft SQL Server

### Step 2: Select Injection Type

After selecting a DBMS, choose the type of injection you want to perform:
- **Version Detection**: Payloads to detect database version
- **Union Injection**: UNION-based SQL injection payloads
- **Time Delay**: Time-based blind SQL injection
- **Information Gathering**: Payloads to extract schema information
- **String Concatenation**: String manipulation techniques
- **Comments**: Comment syntax for the selected DBMS
- And more...

### Step 3: Select Injection Context

Choose the injection context based on where the injection point is located:
- **All Contexts**: Generate payloads for all contexts (default)
- **String Context**: When injecting into a string field (e.g., `WHERE name='USER_INPUT'`)
- **Numeric Context**: When injecting into a numeric field (e.g., `WHERE id=USER_INPUT`)
- **Parenthesis Context**: When injecting with parentheses (e.g., `WHERE (status='USER_INPUT')`)

### Step 4: Generate Payloads

Click the **"🚀 Generate Payloads"** button to generate the payloads. The results will appear in the right panel.

### Step 5: Use Generated Payloads

- Review the generated payloads displayed in colored code blocks
- Click the **"📋 Copy"** button to copy any payload to your clipboard
- Review the syntax examples and error messages in the cheat sheet reference below the payloads

## Understanding the Output

### Generated Payloads

Each payload is displayed with:
- **Context Label**: Shows which injection context the payload is for (STRING, NUMERIC, or PARENTHESIS)
- **Payload Code**: The actual SQL injection payload in a code block
- **Copy Button**: Quick copy functionality

### Cheat Sheet Reference

Below the payloads, you'll see reference information including:
- **Description**: What the injection type does
- **Syntax Examples**: Valid SQL syntax for the selected technique
- **Common Error Messages**: Typical error messages that indicate successful injection

## API Endpoints

The application also provides REST API endpoints for programmatic access:

### Get Injection Types for a DBMS
```bash
GET /api/injection-types/<dbms>
```

Example:
```bash
curl http://localhost:5000/api/injection-types/mysql
```

### Generate Payloads
```bash
POST /api/generate-payload
Content-Type: application/json

{
    "dbms": "mysql",
    "injection_type": "version_detection",
    "context": "string"
}
```

Example:
```bash
curl -X POST http://localhost:5000/api/generate-payload \
  -H "Content-Type: application/json" \
  -d '{"dbms":"mysql","injection_type":"version_detection","context":"string"}'
```

### Get Cheat Sheet Reference
```bash
GET /api/cheat-sheet/<dbms>/<injection_type>
```

Example:
```bash
curl http://localhost:5000/api/cheat-sheet/oracle/union_injection
```

### Health Check
```bash
GET /health
```

## Examples

### Example 1: MySQL Version Detection (String Context)

1. Select: **DBMS** = MySQL
2. Select: **Injection Type** = Version Detection
3. Select: **Context** = String Context
4. Click: **Generate Payloads**

**Result**: `' UNION SELECT @@version-- `

### Example 2: Oracle UNION Injection (All Contexts)

1. Select: **DBMS** = Oracle
2. Select: **Injection Type** = UNION-based Injection
3. Select: **Context** = All Contexts
4. Click: **Generate Payloads**

**Results**:
- String: `' UNION SELECT NULL FROM dual--`
- Numeric: ` UNION SELECT NULL FROM dual--`
- Parenthesis: `') UNION SELECT NULL FROM dual--`

### Example 3: MSSQL Time-based Blind Injection

1. Select: **DBMS** = MSSQL
2. Select: **Injection Type** = Time-based Blind Injection
3. Select: **Context** = String Context
4. Click: **Generate Payloads**

**Result**: `'; WAITFOR DELAY '00:00:05'--`

## Configuration

### Changing the Port

By default, the application runs on port 5000. To change it, edit `app.py`:

```python
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8080,  # Change this to your desired port
        debug=True
    )
```

### Production Deployment

For production use:

1. Set environment variables for security:
   ```bash
   export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
   export FLASK_DEBUG=False
   ```

2. Use a production WSGI server like Gunicorn:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 sqli_web.app:app
   ```

3. Consider using HTTPS to enable the modern Clipboard API for copy functionality

4. Use a reverse proxy (nginx, Apache) for additional security and performance

## Extending the Cheat Sheet

To add new injection types or DBMS support, edit `sql_syntax_and_errors.py`:

1. Add new DBMS to the `SQL_CHEAT_SHEET` dictionary
2. Add new injection types with their syntax, descriptions, and payloads
3. Follow the existing structure for consistency

Example structure:
```python
'new_injection_type': {
    'name': 'Display Name',
    'description': 'What this injection does',
    'syntax': ['Example 1', 'Example 2'],
    'payloads': {
        'string': "'payload for string context",
        'numeric': " payload for numeric context",
        'parenthesis': "') payload for parenthesis context",
    }
}
```

## Troubleshooting

### Port Already in Use

If you get an error that port 5000 is already in use:
```bash
# Find what's using the port
lsof -i :5000

# Kill the process or use a different port
python app.py --port 8080
```

### Module Import Errors

If you get import errors, ensure you're running from the correct directory:
```bash
# From sqli_web directory
cd sqli_web
python app.py

# Or add sqli_web to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/path/to/Megido"
python sqli_web/app.py
```

### Flask Not Found

Install Flask:
```bash
pip install Flask>=3.0.0
```

Or install all dependencies:
```bash
pip install -r requirements.txt
```

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only. Always:
- Obtain proper authorization before testing any system
- Use in controlled environments or with explicit permission
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

## Integration with Megido

This tool integrates with the Megido Security Testing Platform and can be used alongside other Megido tools:
- Use generated payloads in Megido's SQL Attacker module
- Combine with the Proxy/Interceptor for real-time injection testing
- Reference the cheat sheet when analyzing SQLi detection results

## Support

For issues, questions, or contributions:
- Review the main Megido README.md
- Check the project's issue tracker on GitHub
- Consult the SQL Attacker documentation in the repository

## License

This component is part of the Megido Security Testing Platform and follows the same license terms.

# Manipulator App - Payload Crafting and Encoding Tool

## Overview

The Manipulator app is a comprehensive Django-based payload crafting and encoding tool designed for security testing. It provides a structured approach to managing, encoding, and manipulating payloads for various vulnerability types including XSS, SQLi, LFI, RCE, CSRF, and more.

## Features

### 1. Vulnerability Management
- **10 Major Vulnerability Types**: XSS, SQLi, LFI, RFI, RCE, CSRF, XXE, SSRF, Path Traversal, Command Injection
- Each vulnerability type includes:
  - Detailed descriptions
  - Severity levels (Critical, High, Medium, Low)
  - Category classification
  - Pre-loaded example payloads

### 2. Payload Library
- **31+ Pre-loaded Payloads** across all vulnerability types
- Each payload includes:
  - Name and description
  - Platform information (Web, Linux, Windows, PHP, Python, etc.)
  - Bypass technique used
  - Success rate tracking
  - Custom vs. pre-loaded classification
- Support for user-submitted custom payloads

### 3. Encoding Utilities
The app provides 23+ encoding techniques including:
- **URL Encoding**: Single and double URL encoding
- **Base64**: Standard Base64 encoding
- **Hexadecimal**: Hex encoding with and without 0x prefix
- **Unicode**: Unicode escape sequences
- **HTML Entities**: Named, numeric, and hex entities
- **Octal**: Octal escape sequences
- **ROT13**: Simple Caesar cipher
- **Case Manipulation**: Mixed case for filter bypass
- **SQL Obfuscation**: Comment injection, space replacement
- **Path Obfuscation**: Slash encoding (single and double)
- **JavaScript**: CharCode and Unicode escape
- **Special Techniques**: Null byte injection, string reversal

### 4. Manipulation Tricks
- **13+ Bypass Techniques** for various vulnerability types
- Each trick includes:
  - Effectiveness rating (High, Medium, Low)
  - Target defense mechanism
  - Example usage
  - Detailed technique explanation

### 5. Payload Crafting Interface
- Interactive web UI for crafting payloads
- Multi-step process:
  1. Select vulnerability type and base payload
  2. Choose encoding techniques (multiple can be applied)
  3. Generate crafted payload
  4. Copy to clipboard
- Support for chaining multiple encodings

### 6. Encoding Tools
- Quick encoding interface
- Single encoding application
- Real-time results
- Copy to clipboard functionality

### 7. Database-Backed Storage
- **VulnerabilityType Model**: Store vulnerability definitions
- **Payload Model**: Persist payloads with metadata
- **EncodingTechnique Model**: Track available encodings
- **PayloadManipulation Model**: Store bypass techniques
- **CraftedPayload Model**: History of crafted payloads with testing metadata

### 8. Django Admin Integration
- Full CRUD operations for all models
- Custom admin interfaces with:
  - List displays
  - Filters
  - Search functionality
  - Fieldsets for organized editing
  - Readonly fields where appropriate

## Installation

### 1. Add to INSTALLED_APPS

The app is already registered in `megido_security/settings.py`:

```python
INSTALLED_APPS = [
    # ... other apps
    'manipulator',
]
```

### 2. Run Migrations

```bash
python manage.py migrate
```

### 3. Populate Initial Data

```bash
python manage.py populate_manipulator_data
```

This command will populate:
- 10 vulnerability types
- 31 pre-loaded payloads
- 13 manipulation tricks
- 9 encoding techniques

### 4. Access the App

Navigate to: `http://localhost:8000/manipulator/`

## URL Structure

- `/manipulator/` - Home page with vulnerability types
- `/manipulator/vulnerability/<id>/` - Vulnerability detail with payloads and tricks
- `/manipulator/craft/` - Payload crafting interface
- `/manipulator/library/` - Browse all payloads
- `/manipulator/add-payload/` - Add custom payload
- `/manipulator/crafted/` - View crafted payload history
- `/manipulator/tricks/` - Browse manipulation tricks
- `/manipulator/encoding-tools/` - Quick encoding tools
- `/manipulator/encode-ajax/` - AJAX endpoint for real-time encoding

## Models

### VulnerabilityType
```python
- name: Unique vulnerability name (e.g., "XSS", "SQLi")
- description: Detailed description
- category: Classification (injection, file_inclusion, etc.)
- severity: Risk level (critical, high, medium, low)
- created_at: Timestamp
```

### Payload
```python
- vulnerability: Foreign key to VulnerabilityType
- name: Payload identifier
- payload_text: The actual payload code
- description: Explanation of functionality
- is_obfuscated: Boolean flag
- bypass_technique: Technique used
- platform: Target platform
- is_custom: User-submitted vs pre-loaded
- submitted_by: User identifier
- success_rate: Percentage (0-100)
- created_at: Timestamp
```

### EncodingTechnique
```python
- name: Encoding name
- description: How it works
- encoding_type: Category (url, base64, hex, etc.)
- is_reversible: Can be decoded
```

### PayloadManipulation
```python
- vulnerability: Foreign key to VulnerabilityType
- name: Trick name
- technique: The manipulation pattern
- description: Explanation
- example: Example usage
- effectiveness: Rating (high, medium, low)
- target_defense: What it bypasses
- created_at: Timestamp
```

### CraftedPayload
```python
- base_payload: Foreign key to Payload
- crafted_text: Final encoded payload
- encodings_applied: JSON list of encodings
- manipulations_applied: JSON list of manipulations
- tested: Boolean flag
- successful: Test result
- test_notes: Testing feedback
- test_date: When tested
- created_at: Timestamp
```

## Encoding Utilities API

The `encoding_utils.py` module provides utility functions:

```python
# Apply single encoding
from manipulator.encoding_utils import apply_encoding

encoded, success, error = apply_encoding('<script>alert(1)</script>', 'url')
# Returns: ('%3Cscript%3Ealert%281%29%3C%2Fscript%3E', True, None)

# Apply multiple encodings
from manipulator.encoding_utils import apply_multiple_encodings

result, success, errors = apply_multiple_encodings(
    '<script>alert(1)</script>', 
    ['url', 'base64']
)

# Get available encodings
from manipulator.encoding_utils import get_available_encodings

encodings = get_available_encodings()
# Returns dict of encoding_key: description
```

## Management Commands

### populate_manipulator_data
Populates the database with initial vulnerability types, payloads, manipulation tricks, and encoding techniques.

```bash
python manage.py populate_manipulator_data
```

Output:
```
Populating initial data...
Creating vulnerability types...
  ✓ Created XSS
  ✓ Created SQLi
  ...
Created 31 payloads
Created 13 manipulation tricks
Created 9 encoding techniques
```

## Django Admin

Access at: `http://localhost:8000/admin/`

Available admin interfaces:
- **Vulnerability Types**: Manage vulnerability definitions
- **Payloads**: Browse and edit all payloads
- **Encoding Techniques**: Manage encoding methods
- **Payload Manipulations**: Edit bypass techniques
- **Crafted Payloads**: View payload crafting history

## Extending the App

### Adding New Vulnerability Types

```python
from manipulator.models import VulnerabilityType

vuln = VulnerabilityType.objects.create(
    name='IDOR',
    description='Insecure Direct Object Reference',
    category='authorization',
    severity='medium'
)
```

### Adding Custom Payloads

```python
from manipulator.models import Payload, VulnerabilityType

xss = VulnerabilityType.objects.get(name='XSS')
payload = Payload.objects.create(
    vulnerability=xss,
    name='Custom XSS',
    payload_text='<svg onload=alert(document.domain)>',
    description='SVG-based XSS with domain output',
    platform='Web',
    bypass_technique='SVG element',
    is_custom=True
)
```

### Adding New Encoding Functions

Edit `manipulator/encoding_utils.py` and add your function:

```python
def custom_encoding(payload):
    """
    Your custom encoding logic here.
    """
    return encoded_result

# Add to the encoding_functions dict in apply_encoding()
```

### Adding Manipulation Tricks

```python
from manipulator.models import PayloadManipulation, VulnerabilityType

sqli = VulnerabilityType.objects.get(name='SQLi')
trick = PayloadManipulation.objects.create(
    vulnerability=sqli,
    name='Hex Encoding',
    technique='0x...',
    description='Use hex encoding to bypass filters',
    effectiveness='high',
    target_defense='String matching WAF',
    example="SELECT 0x61646d696e -- 'admin' in hex"
)
```

## Security Considerations

⚠️ **WARNING**: This app is designed for legitimate security testing and education purposes only.

- All payloads are examples and should only be used in authorized security assessments
- User-submitted payloads are stored without validation - use appropriate access controls
- The app does not execute payloads, only stores and encodes them
- Consider implementing authentication and authorization for production use
- Add CSRF protection for forms if exposed to untrusted users

## Testing

The app includes integration with Django's test framework. Create tests in `manipulator/tests.py`:

```python
from django.test import TestCase
from manipulator.models import VulnerabilityType, Payload

class PayloadTestCase(TestCase):
    def setUp(self):
        self.vuln = VulnerabilityType.objects.create(
            name='XSS',
            description='Cross-Site Scripting',
            category='injection',
            severity='high'
        )
    
    def test_payload_creation(self):
        payload = Payload.objects.create(
            vulnerability=self.vuln,
            name='Test XSS',
            payload_text='<script>alert(1)</script>'
        )
        self.assertEqual(payload.name, 'Test XSS')
```

Run tests:
```bash
python manage.py test manipulator
```

## Future Enhancements

Potential areas for expansion:

1. **Payload Templates**: Create parameterized payloads with variable substitution
2. **Testing Integration**: Automatically test payloads against vulnerable targets
3. **Export/Import**: Export payloads to various formats (JSON, CSV, XML)
4. **Payload Rating**: Community rating system for payload effectiveness
5. **Collaboration**: Share payloads with team members
6. **API Endpoints**: RESTful API for programmatic access
7. **Payload Chaining**: Combine multiple payloads for complex attacks
8. **WAF Detection**: Identify which WAF/filter is in use
9. **Automatic Encoding Selection**: AI-powered encoding recommendation
10. **Payload Analytics**: Track which payloads work best

## Contributing

To contribute new payloads or bypass techniques:

1. Use the web interface to add custom payloads
2. Or edit `manipulator/initial_data.py` and add to the appropriate dictionaries
3. Run `python manage.py populate_manipulator_data` to update the database

## Support

For issues or questions:
- Check the Django admin interface for model documentation
- Review the inline code comments in models, views, and utilities
- Consult the Django documentation for framework-specific questions

## License

This app is part of the Megido Security platform.

## Changelog

### Version 1.0 (Initial Release)
- 10 vulnerability types with 31 pre-loaded payloads
- 23+ encoding techniques
- 13 manipulation tricks
- Full Django admin integration
- Interactive web UI for payload crafting
- Database-backed persistence
- Management command for initial data population

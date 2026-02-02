# Hidden Parameter Discovery Feature - Implementation Guide

## Overview

The Hidden Parameter Discovery feature extends the Spider app to automatically detect hidden debug parameters, test flags, and developer backdoors in web applications through systematic parameter fuzzing and brute force techniques.

## Feature Description

This feature implements automated discovery of hidden parameters by:
1. Testing common debug parameter names against target URLs
2. Testing multiple common values for each parameter
3. Analyzing responses to detect behavioral changes
4. Recording parameters that reveal information or change behavior
5. Brute forcing discovered parameters to find more valid values

## Models

### ParameterDiscoveryAttempt
Tracks every parameter testing attempt made during discovery.

**Key Fields:**
- `parameter_name` - Name of the parameter tested (e.g., "debug")
- `parameter_value` - Value tested (e.g., "true")
- `http_method` - GET or POST
- `parameter_location` - Where parameter was placed (query, body, or both)
- `response_diff` - Boolean indicating if response differed from baseline
- `behavior_changed` - Boolean indicating behavior change
- `error_revealed` - Boolean indicating error/debug info in response
- `content_revealed` - Boolean indicating new content appeared

### DiscoveredParameter
Stores successfully discovered hidden parameters.

**Key Fields:**
- `parameter_name` - The discovered parameter name
- `parameter_value` - The working value
- `parameter_type` - Category (debug, test, admin, developer, feature_flag, other)
- `risk_level` - Risk assessment (info, low, medium, high, critical)
- `reveals_debug_info` - Boolean flag
- `reveals_source_code` - Boolean flag
- `reveals_hidden_content` - Boolean flag
- `discovery_evidence` - Text description of what changed

### ParameterBruteForce
Tracks brute force attempts on discovered parameters.

**Key Fields:**
- `discovered_parameter` - Foreign key to the parameter being tested
- `test_value` - Alternate value being tested
- `success` - Boolean indicating if this value worked
- `finding_description` - What was discovered with this value

## Discovery Process

### Phase 1: URL Selection
- Primary target URL is always tested
- Up to 10 "interesting" discovered URLs are tested
- If no interesting URLs, up to 5 regular discovered URLs are tested
- Prevents overwhelming the target with too many requests

### Phase 2: Baseline Capture
For each URL:
1. Make a clean request without any parameters
2. Store baseline response (status code, content length, content, headers)
3. Use baseline for comparison to detect changes

### Phase 3: Parameter Fuzzing

**Parameter Names Tested (30+):**
```
debug, test, hide, source, dev, developer, admin, trace, verbose,
log, logging, show, display, output, print, dump, echo, preview,
view, mode, env, environment, config, configuration, demo, example,
sample, internal, backdoor, old, legacy, deprecate, obsolete, temp, tmp
```

**Parameter Values Tested (15+):**
```
true, false, yes, no, on, off, 1, 0,
enabled, disabled, enable, disable,
all, full, complete, verbose, detailed
```

For each URL and each parameter name/value combination:

**GET Request Testing:**
1. Add parameter to URL query string
2. Make GET request
3. Compare response to baseline
4. Record as ParameterDiscoveryAttempt
5. If response differs, mark as discovered parameter

**POST Request Testing:**
1. Add parameter to URL query string
2. Add same parameter to POST body
3. Make POST request with both locations (as required by spec)
4. Compare response to baseline
5. Record as ParameterDiscoveryAttempt
6. If response differs, mark as discovered parameter

### Phase 4: Response Analysis

For each response, the system checks:

**Response Difference Detection:**
- Status code change
- Content length change (>100 bytes difference)

**Error Pattern Detection:**
Searches response content for keywords:
- error, exception, traceback, stack trace
- warning, debug, sql, query, database
- path, file not found, undefined, null

**Content Revelation Detection:**
Searches response content for keywords:
- hidden, secret, internal, admin, developer
- config, configuration, debug, trace, log

**Source Code Detection:**
Looks for code patterns:
- PHP: `<?php`, `<?=`
- ASP: `<%`
- Python: `def `
- General: `function `, `class `

### Phase 5: Parameter Recording

When a parameter causes a response change, it's recorded as a DiscoveredParameter with:

**Type Classification:**
- `debug` - Contains "debug" or "trace"
- `test` - Contains "test" or "demo"
- `admin` - Contains "admin"
- `developer` - Contains "dev" or "developer"
- `feature_flag` - Contains "show", "hide", "display", "view"
- `other` - Everything else

**Risk Level Assessment:**
- `critical` - Reveals source code
- `high` - Reveals debug/error information
- `medium` - Changes behavior or reveals content
- `low` - Minor changes

### Phase 6: Brute Force Discovered Parameters

For each discovered parameter (up to 10 for performance):

**Test Values (20+):**
- Boolean variations: True, False, TRUE, FALSE, Yes, No, YES, NO
- Numbers: 2, 3, 10, 100, 1000, -1
- Special: null, none, undefined, *, all, everything
- Strings: admin, root, system, test, dev, prod
- Path traversal: ../, ../../, ../../../
- SQL detection: ' OR '1'='1, 1' OR '1'='1

For each test value:
1. Build test URL with parameter
2. Make request (GET or POST based on original discovery method)
3. Check for interesting response
4. Record as ParameterBruteForce
5. Mark success if reveals something new

## API Integration

### Create Target with Parameter Discovery
```bash
POST /spider/api/targets/
Content-Type: application/json

{
  "url": "https://example.com",
  "name": "Test Target",
  "enable_parameter_discovery": true
}
```

### Get Results with Discovered Parameters
```bash
GET /spider/api/sessions/1/results/
```

Response includes:
```json
{
  "statistics": {
    "parameters_discovered": 5
  },
  "discovered_parameters": [
    {
      "parameter_name": "debug",
      "parameter_value": "true",
      "parameter_type": "debug",
      "target_url": "https://example.com/page",
      "risk_level": "high",
      "http_method": "GET",
      "reveals_debug_info": true,
      "reveals_source_code": false,
      "reveals_hidden_content": false
    }
  ]
}
```

## User Interface

### Configuration
- Checkbox: "Enable Parameter Discovery" (enabled by default)
- Located in spider configuration form alongside other options

### Results Display

**Statistics Card:**
- Shows count of "Parameters Found"
- Updates after spider session completes

**Hidden Parameters Tab:**
Displays discovered parameters with:
- HTTP method badge (GET in blue, POST in pink)
- Risk level (color-coded border)
- Parameter name and value
- Target URL
- Visual indicators:
  - ⚠️ Reveals Debug Information
  - ⚠️ Reveals Source Code
  - 📂 Reveals Hidden Content

## Performance Considerations

**Rate Limiting:**
- 0.1 second delay between parameter tests
- 0.05 second delay between brute force attempts
- Total time: ~45 seconds per URL (30 params × 15 values × 0.1s)

**Request Limits:**
- Tests up to 10-15 URLs maximum
- Limits brute force to 10 discovered parameters
- Prevents overwhelming target servers

**Timeout Settings:**
- 5 seconds for parameter tests
- 3 seconds for brute force tests
- Prevents hanging on slow responses

## Security Notes

**This tool is for authorized testing only:**
- Always get written permission before testing
- Only test systems you own or have authorization to test
- Be aware of rate limits and blocking mechanisms
- Comply with all applicable laws and regulations

**Detection Techniques:**
- SQL injection strings are detection-only
- Path traversal attempts are logged but not exploited
- All requests are logged for audit trails
- No active exploitation of discovered vulnerabilities

## Admin Interface

All parameter discovery models are registered in Django admin:

**ParameterDiscoveryAttempt Admin:**
- List display: parameter_name, parameter_value, http_method, response_diff, behavior_changed
- Filters: http_method, parameter_location, response_diff, behavior_changed, error_revealed
- Search: parameter_name, parameter_value, target_url

**DiscoveredParameter Admin:**
- List display: parameter_name, parameter_value, parameter_type, risk_level, http_method
- Filters: parameter_type, risk_level, http_method, reveals_debug_info, reveals_source_code
- Search: parameter_name, parameter_value, target_url, discovery_evidence

**ParameterBruteForce Admin:**
- List display: discovered_parameter, test_value, success, status_code
- Filters: success, status_code
- Search: test_value, test_description, finding_description

## Testing

Run parameter discovery tests:
```bash
python manage.py test spider.tests.ParameterDiscoveryTest
```

Test cases cover:
- Parameter discovery attempt creation
- Discovered parameter creation
- Parameter brute force tracking
- Session statistics updates

## Troubleshooting

**No parameters discovered:**
- Check that URLs respond without errors
- Verify parameter names/values are appropriate for target
- Review ParameterDiscoveryAttempt records to see what was tested
- Check if responses differ significantly from baseline

**Too many false positives:**
- Review discovery evidence to understand what changed
- Adjust response_diff threshold in code
- Filter by risk_level to focus on high-risk findings

**Performance issues:**
- Reduce max_depth to limit URL discovery
- Disable other discovery methods if only testing parameters
- Reduce number of parameter names/values to test
- Increase delay between requests

## Future Enhancements

Potential improvements:
1. Custom parameter wordlists
2. Custom value wordlists
3. Configurable response difference threshold
4. Smart parameter value suggestions based on discovered type
5. Parameter relationship mapping
6. Automated exploitation of discovered parameters
7. Export parameter findings to other tools
8. Integration with vulnerability scanners

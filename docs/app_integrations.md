# App Integrations Guide

This guide explains how each Megido app integrates with the new interceptor system and mitmproxy browser.

## Overview

All Megido apps can now leverage the interceptor to:
- Track HTTP/HTTPS traffic by source app
- Apply payload rules automatically
- Access intercepted request/response history
- Coordinate attack campaigns with logged traffic

## Integration Pattern

Each app follows this pattern:

1. **Tag Requests**: Set `source_app` when making requests
2. **Create Payload Rules**: Define app-specific payloads
3. **Query History**: Retrieve relevant intercepted requests
4. **Display Results**: Show traffic in app UI

## App-by-App Integration

### 1. Scanner

**Purpose**: Security vulnerability scanner

**Integration:**
```python
# scanner/scanner.py
from interceptor.models import InterceptedRequest, PayloadRule

class Scanner:
    def scan_url(self, url):
        # All traffic is automatically tagged with source_app='scanner'
        
        # Create scanner-specific payload rules
        PayloadRule.objects.create(
            name="Scanner - SQL Injection Test",
            target_url_pattern=".*",
            injection_type="param",
            injection_point="id",
            payload_content="1' OR '1'='1--",
            active=True,
            created_by=self.user,
            target_apps=["scanner"]
        )
        
        # Retrieve scanner requests
        scanner_requests = InterceptedRequest.objects.filter(
            source_app='scanner'
        ).order_by('-timestamp')[:100]
```

**Benefits:**
- Automatic payload injection for common vulnerabilities
- Track all scan traffic
- Identify successful exploits

### 2. SQL Attacker

**Purpose**: SQL injection testing tool

**Integration:**
```python
# sql_attacker/attacker.py
from interceptor.models import InterceptedRequest, InterceptedResponse, PayloadRule

class SQLAttacker:
    def test_sql_injection(self, url, param):
        # Create SQL injection payload rules
        payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "1' AND 1=2--"
        ]
        
        for payload in payloads:
            PayloadRule.objects.create(
                name=f"SQL - {payload}",
                target_url_pattern=url,
                injection_type="param",
                injection_point=param,
                payload_content=payload,
                active=True,
                created_by=self.user,
                target_apps=["sql_attacker"]
            )
        
        # Check responses for SQL errors
        requests = InterceptedRequest.objects.filter(source_app='sql_attacker')
        for req in requests:
            try:
                response = req.response
                if self.detect_sql_error(response.body):
                    # SQL injection found!
                    pass
            except:
                pass
```

**Benefits:**
- Systematic SQL injection testing
- Automatic error detection
- Track successful injections

### 3. Spider

**Purpose**: Web crawler/spider

**Integration:**
```python
# spider/spider.py
from interceptor.models import InterceptedRequest

class Spider:
    def discover_urls(self, base_url):
        # Spider traffic is tagged with source_app='spider'
        
        # Use interceptor history to discover new URLs
        discovered_urls = set()
        
        for req in InterceptedRequest.objects.filter(source_app='spider'):
            discovered_urls.add(req.url)
            
            # Parse response for more URLs
            try:
                response = req.response
                # Extract URLs from response.body
                pass
            except:
                pass
        
        return discovered_urls
```

**Benefits:**
- Automatic URL discovery
- Traffic logging for analysis
- Cross-reference with other tools

### 4. Repeater

**Purpose**: Request repeater/replayer

**Integration:**
```python
# repeater/repeater.py
from interceptor.models import InterceptedRequest

class Repeater:
    def load_request(self, request_id):
        # Load request from interceptor history
        req = InterceptedRequest.objects.get(id=request_id)
        
        return {
            'url': req.url,
            'method': req.method,
            'headers': req.headers,
            'body': req.body
        }
    
    def repeat_request(self, request_data, modifications):
        # Apply modifications and repeat
        # New request is tagged with source_app='repeater'
        pass
```

**Benefits:**
- Load any intercepted request
- Modify and replay
- Compare responses

### 5. Mapper

**Purpose**: Application mapping tool

**Integration:**
```python
# mapper/mapper.py
from interceptor.models import InterceptedRequest
from collections import defaultdict

class Mapper:
    def build_site_map(self):
        # Build site map from intercepted traffic
        endpoints = defaultdict(list)
        
        for req in InterceptedRequest.objects.all():
            path = urlparse(req.url).path
            endpoints[path].append({
                'method': req.method,
                'source_app': req.source_app,
                'timestamp': req.timestamp
            })
        
        return endpoints
```

**Benefits:**
- Automatic endpoint discovery
- Traffic visualization
- Cross-app analysis

### 6. Bypasser

**Purpose**: WAF/filter bypass testing

**Integration:**
```python
# bypasser/bypasser.py
from interceptor.models import PayloadRule

class Bypasser:
    def test_bypass_techniques(self, url):
        # Create bypass payload rules
        techniques = [
            ("Case variation", "SELECT", "sElEcT"),
            ("Comment insertion", "UNION", "UN/**/ION"),
            ("Encoding", "<script>", "%3Cscript%3E")
        ]
        
        for name, original, bypass in techniques:
            PayloadRule.objects.create(
                name=f"Bypass - {name}",
                target_url_pattern=url,
                injection_type="param",
                injection_point="test",
                payload_content=bypass,
                active=True,
                created_by=self.user,
                target_apps=["bypasser"]
            )
```

**Benefits:**
- Systematic bypass testing
- Track successful bypasses
- Reuse successful techniques

### 7. Malware Analyser

**Purpose**: Malware analysis tool

**Integration:**
```python
# malware_analyser/analyser.py
from interceptor.models import InterceptedRequest

class MalwareAnalyser:
    def intercept_downloads(self):
        # Intercept file downloads
        download_requests = InterceptedRequest.objects.filter(
            source_app='malware_analyser',
            headers__contains={'Content-Type': 'application/'}
        )
        
        for req in download_requests:
            try:
                response = req.response
                # Scan downloaded file
                self.scan_file(response.body)
            except:
                pass
```

**Benefits:**
- Automatic file interception
- Track malicious downloads
- Analyze file transfer patterns

### 8. Response Analyser

**Purpose**: HTTP response analyzer

**Integration:**
```python
# response_analyser/analyser.py
from interceptor.models import InterceptedResponse

class ResponseAnalyser:
    def analyse_responses(self):
        # Analyze all intercepted responses
        for response in InterceptedResponse.objects.all():
            # Check for sensitive data exposure
            if self.contains_sensitive_data(response.body):
                self.flag_response(response)
            
            # Check for unusual patterns
            if response.response_time > 5000:  # > 5 seconds
                self.flag_slow_response(response)
```

**Benefits:**
- Automatic response analysis
- Detect sensitive data
- Performance monitoring

### 9. Data Tracer

**Purpose**: Data flow tracking

**Integration:**
```python
# data_tracer/tracer.py
from interceptor.models import InterceptedRequest

class DataTracer:
    def trace_data(self, data_marker):
        # Track where specific data appears
        requests_with_data = []
        
        for req in InterceptedRequest.objects.all():
            # Check URL
            if data_marker in req.url:
                requests_with_data.append(req)
            
            # Check body
            if data_marker in req.body:
                requests_with_data.append(req)
        
        return requests_with_data
```

**Benefits:**
- Track data flow
- Identify data leakage
- Cross-reference with other tools

### 10. Discover

**Purpose**: Parameter discovery tool

**Integration:**
```python
# discover/discover.py
from interceptor.models import InterceptedRequest, PayloadRule

class Discover:
    def discover_parameters(self, url):
        # Create parameter discovery rules
        common_params = ['id', 'page', 'user', 'admin', 'debug']
        
        for param in common_params:
            PayloadRule.objects.create(
                name=f"Discover - {param}",
                target_url_pattern=url,
                injection_type="param",
                injection_point=param,
                payload_content="test",
                active=True,
                created_by=self.user,
                target_apps=["discover"]
            )
        
        # Analyze responses to see which parameters are valid
        discover_requests = InterceptedRequest.objects.filter(
            source_app='discover'
        )
        
        valid_params = []
        for req in discover_requests:
            try:
                response = req.response
                if response.status_code == 200:
                    # Parameter likely exists
                    valid_params.append(req.url)
            except:
                pass
```

**Benefits:**
- Automated parameter discovery
- Response analysis
- Track successful discoveries

### 11. Manipulator

**Purpose**: Request manipulation tool

**Integration:**
```python
# manipulator/manipulator.py
from interceptor.models import PayloadRule

class Manipulator:
    def manipulate_requests(self, url, manipulations):
        # Create manipulation rules
        for manip_type, manip_data in manipulations.items():
            PayloadRule.objects.create(
                name=f"Manipulate - {manip_type}",
                target_url_pattern=url,
                injection_type=manip_data['type'],
                injection_point=manip_data['point'],
                payload_content=manip_data['content'],
                active=True,
                created_by=self.user,
                target_apps=["manipulator"]
            )
```

**Benefits:**
- Systematic request manipulation
- Track modifications
- Reuse successful manipulations

### 12. Proxy

**Purpose**: Built-in proxy server

**Integration:**
```python
# proxy/proxy.py
from interceptor.models import InterceptedRequest

class Proxy:
    def configure_proxy(self):
        # Proxy uses mitmproxy backend
        # All proxy traffic is intercepted
        
        # Configuration can be unified
        proxy_settings = {
            'mitmproxy_port': 8080,
            'intercept_enabled': True
        }
        
        return proxy_settings
```

**Benefits:**
- Unified proxy configuration
- Leverage mitmproxy features
- Central traffic logging

### 13. Browser

**Purpose**: Web browser interface

**Integration:**
```python
# browser/views.py
from interceptor.models import InterceptedRequest

class BrowserView:
    def display_traffic(self):
        # Show interceptor data in browser UI
        browser_requests = InterceptedRequest.objects.filter(
            source_app='browser'
        ).order_by('-timestamp')[:50]
        
        return {
            'requests': browser_requests,
            'interceptor_enabled': self.is_interceptor_enabled()
        }
```

**Benefits:**
- Real-time traffic viewing
- Filter by current session
- WebSocket for live updates

### 14. Collaborator

**Purpose**: Out-of-band interaction testing

**Integration:**
```python
# collaborator/collaborator.py
from interceptor.models import InterceptedRequest, PayloadRule

class Collaborator:
    def generate_payload(self, collaborator_url):
        # Create collaborator payload rules
        PayloadRule.objects.create(
            name="Collaborator - SSRF Test",
            target_url_pattern=".*",
            injection_type="param",
            injection_point="callback",
            payload_content=collaborator_url,
            active=True,
            created_by=self.user,
            target_apps=["collaborator"]
        )
        
        # Track which requests included collaborator payload
        collab_requests = InterceptedRequest.objects.filter(
            source_app='collaborator',
            url__contains=collaborator_url
        )
```

**Benefits:**
- Track OAST payloads
- Link interactions to requests
- Correlate with collaborator callbacks

## Common Integration Patterns

### 1. Tagging Requests

Always tag requests with source app:

```python
# In your app's request handler
request_data = {
    'url': url,
    'method': method,
    'headers': headers,
    'body': body,
    'source_app': 'your_app_name'  # Important!
}

response = requests.post(
    'http://localhost:8000/interceptor/api/request/',
    json=request_data
)
```

### 2. Querying History

Retrieve your app's requests:

```python
from interceptor.models import InterceptedRequest

my_requests = InterceptedRequest.objects.filter(
    source_app='my_app'
).order_by('-timestamp')
```

### 3. Creating Payload Rules

Define app-specific payloads:

```python
from interceptor.models import PayloadRule

rule = PayloadRule.objects.create(
    name="My App - Test Payload",
    target_url_pattern=".*target.*",
    injection_type="param",
    injection_point="param_name",
    payload_content="payload_value",
    active=True,
    created_by=user,
    target_apps=["my_app"]  # Only applies to your app
)
```

### 4. Accessing Responses

Get request with response:

```python
from interceptor.models import InterceptedRequest

req = InterceptedRequest.objects.get(id=request_id)

try:
    response = req.response
    status_code = response.status_code
    response_body = response.body
    response_time = response.response_time
except InterceptedResponse.DoesNotExist:
    # No response yet
    pass
```

## API Integration

All apps can use the interceptor API:

```python
import requests

# Base URL
API_BASE = "http://localhost:8000/interceptor/api"

# Get active payload rules for your app
response = requests.get(
    f"{API_BASE}/payload-rules/active/",
    params={'source_app': 'my_app'}
)

# Get your app's history
response = requests.get(
    f"{API_BASE}/history/",
    params={'source_app': 'my_app'},
    headers={'Authorization': 'Token YOUR_TOKEN'}
)

# Create a payload rule
response = requests.post(
    f"{API_BASE}/payload-rules/",
    json={
        'name': 'My Rule',
        'target_url_pattern': '.*',
        'injection_type': 'header',
        'injection_point': 'X-Test',
        'payload_content': 'test',
        'active': True,
        'target_apps': ['my_app']
    },
    headers={'Authorization': 'Token YOUR_TOKEN'}
)
```

## UI Integration

Display interceptor data in your app's UI:

```html
<!-- my_app/templates/my_app/dashboard.html -->
<div class="interceptor-panel">
    <h3>Recent Traffic</h3>
    <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Method</th>
                <th>URL</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {% for request in intercepted_requests %}
            <tr>
                <td>{{ request.timestamp|date:"H:i:s" }}</td>
                <td>{{ request.method }}</td>
                <td>{{ request.url|truncatechars:50 }}</td>
                <td>
                    {% if request.response %}
                        {{ request.response.status_code }}
                    {% else %}
                        -
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <a href="{% url 'interceptor:dashboard' %}?source_app=my_app">
        View All in Interceptor →
    </a>
</div>
```

## WebSocket Integration (Future)

For real-time updates:

```javascript
// Connect to interceptor WebSocket
const socket = new WebSocket('ws://localhost:8000/ws/interceptor/');

socket.onmessage = function(e) {
    const data = JSON.parse(e.data);
    
    // Filter by source app
    if (data.source_app === 'my_app') {
        // Update UI with new request
        updateRequestsTable(data);
    }
};
```

## Best Practices

1. **Always Tag Requests**: Set `source_app` for all requests
2. **Use Specific Patterns**: Don't use `.*` for URL patterns unless necessary
3. **Clean Up Rules**: Deactivate or delete old payload rules
4. **Handle Missing Responses**: Not all requests have responses immediately
5. **Limit History Queries**: Use `.filter()` and `.order_by()` with limits
6. **Document Integration**: Add comments explaining interceptor usage
7. **Test Payload Rules**: Test rules before activating them
8. **Monitor Performance**: Too many active rules can slow traffic

## Migration Guide

For existing apps:

1. **Identify Request Points**: Where does your app make HTTP requests?
2. **Add Source Tags**: Tag all requests with your app name
3. **Create Payload Rules**: Define app-specific payloads
4. **Update UI**: Display interceptor data in your dashboard
5. **Test Integration**: Verify traffic is being intercepted correctly

## Support

- API Documentation: `docs/interceptor_api.md`
- Payload Rules Guide: `docs/payload_rules.md`
- Main Integration Guide: `BROWSER_INTERCEPTOR_INTEGRATION.md`
- GitHub Issues: https://github.com/tkstanch/Megido/issues

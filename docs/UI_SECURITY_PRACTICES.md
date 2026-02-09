# Megido Security - UI Security Practices

## Overview

This document outlines the security practices implemented in the Megido Security Platform UI revamp. All frontend code follows OWASP secure coding guidelines and Django security best practices.

## 🔒 Core Security Principles

### 1. XSS (Cross-Site Scripting) Prevention

**Problem:** User-supplied data displayed without escaping can execute malicious JavaScript.

**Solutions Implemented:**

#### a) Django Template Auto-Escaping
All Django templates have auto-escaping enabled by default:
```django
{# Safe - automatically escaped #}
<p>{{ user_input }}</p>

{# Only use |safe when content is trusted #}
<div>{{ trusted_html|safe }}</div>
```

#### b) JavaScript XSS Prevention
Use `escapeHtml()` utility for all dynamic content:
```javascript
// ✅ SAFE - Escapes HTML entities
const safeText = MegidoUtils.Security.escapeHtml(userInput);
element.textContent = userInput;  // Also safe

// ❌ UNSAFE - Never use innerHTML with user data
element.innerHTML = userInput;  // XSS vulnerability!
```

#### c) DOM Manipulation Security
```javascript
// ✅ SAFE - Create elements programmatically
const div = document.createElement('div');
div.textContent = userData;  // Safe, no HTML parsing
div.className = 'my-class';
parent.appendChild(div);

// ✅ SAFE - Use our utility
const element = MegidoUtils.DOM.createElement('div', userData, 'my-class');

// ❌ UNSAFE
element.innerHTML = '<div>' + userData + '</div>';  // XSS!
```

### 2. CSRF (Cross-Site Request Forgery) Protection

**Problem:** Unauthorized requests can be made on behalf of authenticated users.

**Solutions Implemented:**

#### a) Django CSRF Middleware
Enabled in `settings.py`:
```python
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]
```

#### b) CSRF Tokens in Forms
All forms include CSRF token:
```django
<form method="POST">
    {% csrf_token %}
    <!-- form fields -->
</form>
```

#### c) CSRF Tokens in AJAX Requests
```javascript
// Get CSRF token from cookies
const csrfToken = MegidoUtils.Security.getCsrfToken();

// Include in fetch requests
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'X-CSRFToken': csrfToken,
        'Content-Type': 'application/json'
    },
    credentials: 'same-origin',
    body: JSON.stringify(data)
});

// Or use the utility
const response = await MegidoUtils.HTTP.postJSON('/api/endpoint', data);
```

### 3. Input Validation and Sanitization

**Problem:** Malicious or malformed input can cause security issues.

**Solutions Implemented:**

#### a) Client-Side Validation
```javascript
// Sanitize input before processing
const clean = MegidoUtils.Security.sanitizeInput(userInput);

// Validate specific formats
if (!MegidoUtils.Security.isValidUrl(url)) {
    MegidoToast.error('Invalid URL format');
    return;
}

// Validate severity values
const severity = MegidoUtils.Security.validateSeverity(input);
```

#### b) Server-Side Validation (Django)
```python
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

def my_view(request):
    url = request.POST.get('url', '')
    
    # Validate URL
    validator = URLValidator()
    try:
        validator(url)
    except ValidationError:
        return JsonResponse({'error': 'Invalid URL'}, status=400)
    
    # Process validated input
    # ...
```

### 4. Content Security Policy (CSP) Ready

**Problem:** Inline scripts and styles can execute malicious code.

**Solutions Implemented:**

#### a) No Inline JavaScript
```html
<!-- ❌ UNSAFE - Inline event handler -->
<button onclick="doSomething()">Click</button>

<!-- ✅ SAFE - Event listener in external JS -->
<button id="myButton">Click</button>
<script src="/static/js/app.js"></script>
<!-- In app.js: -->
document.getElementById('myButton').addEventListener('click', doSomething);
```

#### b) No Inline Styles (except page-specific)
```html
<!-- ❌ AVOID - Inline styles -->
<div style="color: red;">Text</div>

<!-- ✅ PREFERRED - CSS classes -->
<div class="text-danger">Text</div>

<!-- ✅ ACCEPTABLE - Page-specific styles in <style> block -->
{% block extra_style %}
<style>
.page-specific-class { color: red; }
</style>
{% endblock %}
```

#### c) External JavaScript Files
```html
<!-- All JS in separate files -->
<script src="/static/js/megido-utils.js"></script>
<script src="/static/js/megido-toast.js"></script>
```

### 5. Secure Event Handling

**Problem:** Inline event handlers are CSP violations and harder to secure.

**Solutions Implemented:**

#### a) Event Listeners
```javascript
// ✅ SAFE - Add event listeners in JS
document.addEventListener('DOMContentLoaded', function() {
    const button = document.getElementById('submit-btn');
    if (button) {
        button.addEventListener('click', handleSubmit);
    }
});

// ✅ SAFE - Event delegation for dynamic elements
document.body.addEventListener('click', function(e) {
    if (e.target.matches('.delete-btn')) {
        handleDelete(e);
    }
});
```

#### b) IIFE Pattern for Scope Isolation
```javascript
(function() {
    'use strict';
    
    // Variables scoped to this function
    let privateVar = 'value';
    
    // Functions also scoped
    function privateFunction() {
        // ...
    }
    
    // Initialize when ready
    document.addEventListener('DOMContentLoaded', init);
})();
```

### 6. Secure Data Storage

**Problem:** Sensitive data in localStorage can be accessed by XSS attacks.

**Solutions Implemented:**

#### a) Storage Utilities with Validation
```javascript
// Store non-sensitive data only
MegidoUtils.Storage.set('theme', 'dark');
MegidoUtils.Storage.set('preferences', {fontSize: 14});

// Never store sensitive data
// ❌ NEVER DO THIS:
// localStorage.setItem('password', pwd);
// localStorage.setItem('apiKey', key);
```

#### b) Session Storage for Temporary Data
```javascript
// Use session storage for temporary data
MegidoUtils.Storage.set('tempData', value, 'session');
```

## 🛠️ Security Utilities Reference

### MegidoUtils.Security

```javascript
// Escape HTML entities
const safe = MegidoUtils.Security.escapeHtml('<script>alert("XSS")</script>');
// Result: "&lt;script&gt;alert("XSS")&lt;/script&gt;"

// Sanitize input (remove control characters)
const clean = MegidoUtils.Security.sanitizeInput(userInput);

// Get CSRF token
const token = MegidoUtils.Security.getCsrfToken();

// Validate severity
const severity = MegidoUtils.Security.validateSeverity('critical'); // returns 'critical'
const invalid = MegidoUtils.Security.validateSeverity('invalid'); // returns 'low'

// Validate URL
if (MegidoUtils.Security.isValidUrl(url)) {
    // Process URL
}
```

### MegidoUtils.DOM

```javascript
// Safely set text content
MegidoUtils.DOM.setText(element, userInput);

// Create element with text content
const div = MegidoUtils.DOM.createElement('div', 'Safe text', 'my-class');

// Add event listener safely
MegidoUtils.DOM.addListener(element, 'click', handler);

// Toggle visibility
MegidoUtils.DOM.toggleVisibility(element, true);
```

### MegidoUtils.HTTP

```javascript
// Secure fetch with CSRF
const response = await MegidoUtils.HTTP.secureFetch('/api/endpoint', {
    method: 'POST',
    body: JSON.stringify(data)
});

// POST JSON with CSRF
const result = await MegidoUtils.HTTP.postJSON('/api/endpoint', data);

// Parse JSON safely
const json = await MegidoUtils.HTTP.parseJSON(response);
```

### MegidoToast

```javascript
// All toast messages are automatically escaped
MegidoToast.success('Operation completed!');
MegidoToast.error('An error occurred: ' + errorMessage);
MegidoToast.warning('Please review your input');
MegidoToast.info('Processing...');

// Custom toast with options
MegidoToast.show({
    message: 'Custom message',
    type: 'info',
    duration: 5000,
    dismissible: true
});
```

## 🔍 Security Checklist for New Features

When adding new features, ensure:

- [ ] **No inline JavaScript:** All event handlers use `addEventListener`
- [ ] **No inline styles:** Use CSS classes or `<style>` blocks
- [ ] **Escape user input:** Use `escapeHtml()` or `textContent`
- [ ] **CSRF tokens:** Include in all POST/PUT/DELETE requests
- [ ] **Input validation:** Validate on both client and server
- [ ] **Safe DOM manipulation:** Use `createElement()` and `textContent`
- [ ] **Error handling:** Display errors using MegidoToast
- [ ] **No eval():** Never use `eval()`, `Function()`, or `setTimeout(string)`
- [ ] **URL validation:** Validate URLs before navigation
- [ ] **Storage security:** Never store sensitive data in localStorage

## 🚨 Common Vulnerabilities to Avoid

### 1. XSS through innerHTML
```javascript
// ❌ VULNERABLE
element.innerHTML = userData;
element.innerHTML = '<div>' + userData + '</div>';

// ✅ SAFE
element.textContent = userData;
const div = document.createElement('div');
div.textContent = userData;
element.appendChild(div);
```

### 2. CSRF Missing Token
```javascript
// ❌ VULNERABLE
fetch('/api/endpoint', {
    method: 'POST',
    body: JSON.stringify(data)
});

// ✅ SAFE
const csrfToken = MegidoUtils.Security.getCsrfToken();
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'X-CSRFToken': csrfToken,
        'Content-Type': 'application/json'
    },
    credentials: 'same-origin',
    body: JSON.stringify(data)
});
```

### 3. Unsafe Event Handlers
```html
<!-- ❌ VULNERABLE -->
<button onclick="deleteItem(<?php echo $id; ?>)">Delete</button>

<!-- ✅ SAFE -->
<button class="delete-btn" data-item-id="{{ item.id }}">Delete</button>
<script>
document.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const id = parseInt(this.dataset.itemId);
        deleteItem(id);
    });
});
</script>
```

### 4. Eval() Usage
```javascript
// ❌ NEVER DO THIS
eval(userData);
new Function(userData)();
setTimeout(userData, 1000);

// ✅ USE ALTERNATIVES
JSON.parse(jsonString);
setTimeout(function() { doSomething(); }, 1000);
```

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## 🔄 Regular Security Tasks

1. **Code Review:** Review all template and JavaScript changes for security issues
2. **Dependency Updates:** Keep Django and JavaScript dependencies up to date
3. **Security Scanning:** Run security scanners (Bandit, ESLint security plugins)
4. **Penetration Testing:** Perform regular security assessments
5. **Audit Logs:** Monitor for suspicious activity
6. **Update Documentation:** Keep this document current with new features

---

**Last Updated:** 2026-02-09  
**Version:** 2.0  
**Maintainer:** Megido Security Team

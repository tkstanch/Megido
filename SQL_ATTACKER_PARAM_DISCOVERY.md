# SQL Attacker: Automatic Parameter Discovery Guide

## Overview

The SQL Attacker now includes **automatic parameter discovery**, making it fully automated for finding and testing SQL injection vulnerabilities. This feature eliminates the need to manually specify every parameter, discovering hidden fields, JavaScript variables, and more.

## What Gets Discovered

### 1. Form Fields (Visible and Hidden)

**Visible Fields:**
```html
<form method="POST">
    <input type="text" name="username">
    <input type="password" name="password">
    <textarea name="comment"></textarea>
    <select name="category"></select>
</form>
```
✅ Discovers: `username`, `password`, `comment`, `category` (tagged as **form**)

**Hidden Fields:**
```html
<form method="POST">
    <input type="hidden" name="csrf_token" value="abc123">
    <input type="hidden" name="session_id" value="xyz789">
</form>
```
✅ Discovers: `csrf_token`, `session_id` (tagged as **hidden**)

### 2. Link Parameters

```html
<a href="/article?id=123&type=news">Article</a>
<a href="/user/profile?user_id=456&tab=posts">Profile</a>
```
✅ Discovers: `id`, `type`, `user_id`, `tab` (tagged as **link**)

### 3. URL Parameters (from src attributes)

```html
<script src="/js/app.js?version=1.2.3&debug=true"></script>
<img src="/image.png?size=large&format=webp">
<iframe src="/embed?video_id=abc123"></iframe>
```
✅ Discovers: `version`, `debug`, `size`, `format`, `video_id` (tagged as **url**)

### 4. JavaScript Variables

**Variable Declarations:**
```javascript
var userId = "12345";
let apiKey = "key_abcdef";
const sessionToken = "token_xyz";
```
✅ Discovers: `userId`, `apiKey`, `sessionToken` (tagged as **js**)

**Parameter Patterns:**
```javascript
var url = "/api?userId=789&action=fetch";
params["search_query"] = "test";
data.get("article_id");
request.getParameter("filter_type");
```
✅ Discovers: `userId`, `action`, `search_query`, `article_id`, `filter_type` (tagged as **js**)

## How It Works

### Workflow

1. **Page Fetching** → Engine fetches target URL
2. **HTML Parsing** → BeautifulSoup extracts forms, links, scripts
3. **JS Analysis** → Regex patterns extract variables and parameters
4. **Deduplication** → Remove duplicates by (name, method)
5. **Merging** → Combine with manual parameters
6. **Testing** → Run all SQL injection payloads on ALL parameters
7. **Reporting** → Track source for each vulnerability

### Example Discovery Result

Given a test page, the engine discovered 37 unique parameters:
- 12 from forms (9 POST, 3 GET)
- 12 from links and URLs
- 13 from JavaScript code

All were automatically tested with 19 error-based and 8 time-based SQL injection payloads!

## Using the Feature

### Web UI

1. Navigate to `/sql-attacker/tasks/create/`
2. Enter target URL
3. Ensure "🔍 Automatically Discover Parameters" is checked (default)
4. Optionally add manual parameters
5. Click "Create Task"

### REST API

```bash
POST /sql-attacker/api/tasks/
Content-Type: application/json

{
  "target_url": "https://example.com/login",
  "auto_discover_params": true,
  "enable_error_based": true,
  "enable_time_based": true,
  "enable_exploitation": true,
  "execute_now": true
}
```

## Source Tags

| Source | Icon | Description |
|--------|------|-------------|
| **form** | 📝 | Visible form field |
| **hidden** | 🔒 | Hidden form field |
| **link** | 🔗 | Link parameter |
| **url** | 🌐 | URL parameter (src/href) |
| **js** | 📜 | JavaScript variable |
| **manual** | ✋ | Manually specified |

## Best Practices

1. **Always enable auto-discovery first** - It finds parameters you might miss
2. **Supplement with manual parameters** - Add cookies, headers, auth tokens
3. **Review discovered parameters** - Check the table in task details
4. **Pay attention to hidden fields** - Often overlooked but vulnerable
5. **Use stealth options** - Balance speed with detection avoidance

## Security Notes

⚠️ **Important:**
- Only test authorized targets
- Auto-discovery generates many requests
- May trigger WAF/IDS alerts
- Discovered data (tokens, IDs) stored in results
- Review and sanitize before sharing

## Performance

- **Discovery:** 1-3 seconds per page
- **Testing:** 2-5 seconds per parameter per payload type
- **Example:** 10 params × 27 payloads ≈ 3-7 minutes

For detailed information, see the main README at `/sql_attacker/README.md`

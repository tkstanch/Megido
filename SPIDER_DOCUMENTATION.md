# Spider App Documentation

## Overview

The Spider app is a comprehensive web content discovery and security testing tool integrated into the Megido Security platform. It automates the process of discovering hidden content, performing brute force attacks on paths, inferring potential URLs, and integrating with popular security tools like DirBuster, Nikto, and Wikto.

## Features

### 1. **Automated Web Crawling**
- Recursively crawls websites starting from a target URL
- Configurable maximum depth to control crawl scope
- Option to follow external links
- Extracts links from HTML, forms, scripts, and images
- Records response codes, timing, and content information

### 2. **DirBuster Integration**
- Directory and file discovery using common path wordlists
- Checks for backup files, configuration files, admin panels
- Identifies hidden directories and sensitive files
- Risk assessment for discovered content

### 3. **Nikto Scanning**
- Server information disclosure detection
- Common vulnerability checks
- HTTP methods testing
- Header security analysis

### 4. **Wikto Scanning**
- Windows/IIS-focused security testing
- ASP.NET-specific checks
- Exchange and SharePoint detection
- Configuration file discovery

### 5. **Brute Force Path Discovery**
- Systematic testing of common path patterns
- API endpoint enumeration
- Version-based path testing
- Year-based archive discovery

### 6. **Content Inference**
- Pattern-based URL prediction
- Version inference (e.g., /v1 → /v2)
- File extension variations
- Backup file detection
- Technology stack inference
- Automatic verification of inferred URLs

## Models

### SpiderTarget
Stores target configuration for spider sessions.

**Fields:**
- `url` - Target website URL
- `name` - Optional friendly name
- `max_depth` - Maximum crawl depth (default: 3)
- `follow_external_links` - Whether to follow links to other domains
- `use_dirbuster` - Enable DirBuster-style discovery
- `use_nikto` - Enable Nikto scanning
- `use_wikto` - Enable Wikto scanning
- `enable_brute_force` - Enable brute force path testing
- `enable_inference` - Enable content inference

### SpiderSession
Tracks individual spider runs and their statistics.

**Fields:**
- `target` - Foreign key to SpiderTarget
- `status` - Session status (pending/running/completed/failed)
- `urls_discovered` - Count of discovered URLs
- `urls_crawled` - Count of crawled URLs
- `hidden_content_found` - Count of hidden content items
- `inference_results` - Count of inferred URLs

### DiscoveredURL
Records each URL discovered during spidering.

**Fields:**
- `url` - The discovered URL
- `discovery_method` - How it was found (crawl/dirbuster/nikto/wikto/brute_force/inference)
- `status_code` - HTTP response code
- `is_hidden` - Whether content is not linked from main site
- `is_interesting` - Flagged as potentially interesting

### HiddenContent
Stores information about hidden or unlinked content.

**Fields:**
- `url` - URL of hidden content
- `content_type` - Type (directory/file/api_endpoint/backup/config/admin_panel/test_file)
- `discovery_method` - How it was discovered
- `risk_level` - Risk assessment (info/low/medium/high/critical)
- `status_code` - HTTP response code

### BruteForceAttempt
Logs brute force attempts on paths.

**Fields:**
- `base_url` - Base URL tested
- `path_tested` - Path that was tested
- `full_url` - Complete URL
- `success` - Whether path exists (200-399 status)
- `status_code` - HTTP response code

### InferredContent
Stores URLs inferred from patterns in discovered content.

**Fields:**
- `source_url` - URL from which inference was made
- `inferred_url` - Predicted/inferred URL
- `inference_type` - Type of inference (pattern/naming/version/technology/structure)
- `confidence` - Confidence score (0-1)
- `reasoning` - Explanation of the inference
- `verified` - Whether the URL has been checked
- `exists` - Whether the inferred URL exists

### ToolScanResult
Stores results from external security tools.

**Fields:**
- `tool_name` - Tool used (dirbuster/nikto/wikto)
- `status` - Scan status
- `findings_count` - Number of findings
- `raw_output` - Raw tool output
- `parsed_results` - Structured JSON results

## API Endpoints

### GET/POST `/spider/api/targets/`
List all spider targets or create a new one.

**POST Request Body:**
```json
{
  "url": "https://example.com",
  "name": "My Target",
  "max_depth": 3,
  "use_dirbuster": true,
  "use_nikto": true,
  "use_wikto": true,
  "enable_brute_force": true,
  "enable_inference": true,
  "follow_external_links": false
}
```

### POST `/spider/api/targets/{target_id}/spider/`
Start a spider session on a target.

**Response:**
```json
{
  "id": 1,
  "message": "Spider session completed",
  "urls_discovered": 45,
  "hidden_content_found": 12
}
```

### GET `/spider/api/sessions/{session_id}/results/`
Get detailed results of a spider session.

**Response:**
```json
{
  "session_id": 1,
  "status": "completed",
  "statistics": {
    "urls_discovered": 45,
    "urls_crawled": 38,
    "hidden_content_found": 12,
    "inference_results": 23
  },
  "discovered_urls": [...],
  "hidden_content": [...],
  "tool_results": [...],
  "inferred_content": [...]
}
```

## Usage Examples

### Web Interface

1. Navigate to `/spider/` in your browser
2. Enter target URL and configure options:
   - Set maximum crawl depth
   - Enable/disable DirBuster, Nikto, Wikto
   - Enable/disable brute force and inference
3. Click "Start Spider"
4. View results in organized tabs:
   - **Discovered URLs**: All URLs found during crawling
   - **Hidden Content**: Content not linked from the main site
   - **Tool Results**: Findings from DirBuster, Nikto, Wikto
   - **Inferred Content**: Verified inferred URLs

### API Usage

**Create a target:**
```bash
curl -X POST http://localhost:8000/spider/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "name": "Example Site",
    "max_depth": 2,
    "use_dirbuster": true,
    "use_nikto": true
  }'
```

**Start spider session:**
```bash
curl -X POST http://localhost:8000/spider/api/targets/1/spider/
```

**Get results:**
```bash
curl http://localhost:8000/spider/api/sessions/1/results/
```

### Django Admin

All spider models are registered in the Django admin interface at `/admin/`:
- View and manage spider targets
- Monitor active spider sessions
- Browse discovered URLs and hidden content
- Review tool scan results
- Examine inferred content

## Configuration

### SSL Verification
Set the `MEGIDO_VERIFY_SSL` environment variable to control SSL certificate verification:
```bash
export MEGIDO_VERIFY_SSL=False  # Default for security testing
```

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only. Always:
- Get written permission before testing any website
- Only test systems you own or have explicit authorization to test
- Be aware that aggressive scanning may be detected and blocked
- Respect robots.txt and rate limits
- Comply with all applicable laws and regulations

## Performance Notes

- The spider limits crawling to 500 URLs per session to prevent runaway processes
- Timeouts are set to 10 seconds for regular requests, 5 seconds for discovery
- Brute force and tool scanning run in sequence to avoid overwhelming targets
- Content inference is limited to the first 50 discovered URLs for performance

## Troubleshooting

**Spider session fails:**
- Check that the target URL is accessible
- Verify SSL certificate if using HTTPS
- Check firewall and network settings
- Review error_message field in SpiderSession

**No hidden content found:**
- Increase max_depth to crawl deeper
- Enable all discovery methods
- Try different brute force patterns
- Check that target has discoverable content

**Slow performance:**
- Reduce max_depth
- Disable some discovery methods
- Use follow_external_links=False
- Test on smaller targets first

## Testing

Run the test suite:
```bash
python manage.py test spider
```

This will run 18 comprehensive tests covering:
- Model creation and validation
- API endpoints
- View functionality
- URL routing
- Admin registration

## Future Enhancements

Potential improvements for future versions:
- Asynchronous spider execution for better performance
- Custom wordlists for brute force discovery
- Machine learning-based content prediction
- Integration with additional security tools
- Export results to various formats (JSON, XML, CSV, PDF)
- Scheduled/periodic spider runs
- Comparison of spider results over time
- Visual site mapping and relationship diagrams

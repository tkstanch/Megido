# Discover App - Enhanced OSINT & Information Gathering

A comprehensive Open Source Intelligence (OSINT) tool for the Megido Security platform with advanced features including ML-powered recommendations, analytics, and RESTful API.

## 🚀 Features

### Core Functionality
- **Multi-Source Data Collection**
  - Wayback Machine: Historical URLs and archived pages
  - Shodan: Infrastructure data, open ports, and services
  - Hunter.io: Email addresses associated with domains
  - Google Dorks: Pre-built search queries for sensitive information

- **Sensitive Information Detection**
  - 20+ pattern types (AWS keys, API tokens, credentials, etc.)
  - Multi-threaded background scanning
  - Severity classification (Critical, High, Medium, Low, Info)
  - False positive management

### Advanced Features

#### 📊 Analytics & Insights
- User-specific analytics dashboard
- Admin-level global insights
- Trending targets tracking
- Finding type distribution
- Activity timeline visualization

#### 🤖 AI/ML Recommendations
- ML-powered target recommendations
- Confidence scoring
- Pattern-based learning from scan history

#### 🔐 Security & Permissions
- Role-Based Access Control (RBAC)
  - Scanners: Can start scans
  - Analysts: Can verify findings
  - Viewers: Read-only access
- Audit logging for all security-sensitive actions
- Granular permissions per resource

#### 📤 Data Export
- **Multiple Formats**:
  - JSON: Full structured data
  - CSV: Tabular findings data
  - SARIF: Security tool interchange format (GitHub/GitLab compatible)

#### ⚡ Performance
- Redis caching for frequently accessed data
- Database query optimization with indexes
- Efficient pagination for large datasets
- Background processing with threading/Celery

#### 🌐 REST API
- Full CRUD operations
- Advanced filtering and search
- Real-time scan status
- Export endpoints
- Statistics and analytics endpoints
- OpenAPI/Swagger documentation

## 📋 Installation

### Prerequisites
- Python 3.8+
- Django 6.0+
- PostgreSQL (recommended) or SQLite
- Redis (for caching)

### Dependencies
```bash
pip install -r requirements.txt
```

Key dependencies:
- Django >= 6.0.0
- djangorestframework >= 3.14.0
- redis >= 5.0.0
- celery >= 5.3.0
- beautifulsoup4 >= 4.12.0
- waybackpy >= 3.0.6

### Database Setup
```bash
# Create migrations
python manage.py makemigrations discover

# Apply migrations
python manage.py migrate discover
```

### Initial Setup
```python
# In Django shell
from discover.permissions import setup_groups
setup_groups()  # Creates default permission groups
```

## 🎯 Usage

### Web Interface

#### Starting a Scan
1. Navigate to `/discover/`
2. Enter target domain (e.g., `example.com`)
3. Configure scan options:
   - Enable sensitive information scanning
   - Enable automated dork searches
4. Click "Start Scan"

#### Viewing Results
- Navigate to `/discover/report/{scan_id}/`
- Review findings by severity
- Mark findings as verified or false positive
- Export results in various formats

#### Analytics Dashboard
- **User Dashboard**: `/discover/dashboard/`
  - Personal scan statistics
  - Recent scans and findings
  - ML-powered recommendations
  
- **Admin Dashboard**: `/discover/dashboard/admin/`
  - Global statistics
  - Trending targets
  - Top finding types
  - User activity monitoring

### REST API

#### Base URL
```
/discover/api/v1/
```

#### Key Endpoints

**Scans**
```bash
# List all scans
GET /discover/api/v1/scans/

# Create a new scan
POST /discover/api/v1/scans/
{
    "target": "example.com",
    "enable_sensitive_scan": true,
    "enable_dork_search": false
}

# Get scan details
GET /discover/api/v1/scans/{id}/

# Get scan status
GET /discover/api/v1/scans/{id}/status/

# Get scan findings
GET /discover/api/v1/scans/{id}/findings/?severity=critical

# Get statistics
GET /discover/api/v1/scans/statistics/

# Export scan
GET /discover/api/v1/scans/{id}/export_single/
```

**Findings**
```bash
# List findings
GET /discover/api/v1/findings/

# Filter findings
GET /discover/api/v1/findings/?severity=critical&verified=false

# Get finding details
GET /discover/api/v1/findings/{id}/

# Verify a finding
POST /discover/api/v1/findings/{id}/verify/

# Mark as false positive
POST /discover/api/v1/findings/{id}/mark_false_positive/

# Export findings
GET /discover/api/v1/findings/export/?format=csv
GET /discover/api/v1/findings/export/?format=json
GET /discover/api/v1/findings/export/?format=sarif
```

**Health Check**
```bash
GET /discover/api/v1/health/
```

#### API Examples

**Python**
```python
import requests

# Start a scan
response = requests.post('http://localhost:8000/discover/api/v1/scans/', json={
    'target': 'example.com',
    'enable_sensitive_scan': True
})
scan = response.json()

# Get scan status
status = requests.get(f'http://localhost:8000/discover/api/v1/scans/{scan["id"]}/status/')
print(status.json())

# Get findings
findings = requests.get(f'http://localhost:8000/discover/api/v1/scans/{scan["id"]}/findings/')
print(findings.json())
```

**cURL**
```bash
# Start a scan
curl -X POST http://localhost:8000/discover/api/v1/scans/ \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "enable_sensitive_scan": true}'

# Get findings
curl http://localhost:8000/discover/api/v1/findings/?severity=critical

# Export as SARIF
curl http://localhost:8000/discover/api/v1/findings/export/?format=sarif > findings.sarif
```

## 🔧 Configuration

### API Keys
Configure in `settings.py`:
```python
# Shodan API
SHODAN_API_KEY = 'your_shodan_api_key'

# Hunter.io API
HUNTER_API_KEY = 'your_hunter_api_key'

# Google Custom Search API
GOOGLE_CSE_API_KEY = 'your_google_api_key'
GOOGLE_CSE_ID = 'your_search_engine_id'
```

### Caching
```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

### Celery (Optional)
For production, use Celery instead of threading:
```python
# In settings.py
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
```

## 🧪 Testing

### Run All Tests
```bash
python manage.py test discover
```

### Run Specific Test Suites
```bash
# API tests
python manage.py test discover.test_api

# Analytics tests
python manage.py test discover.test_analytics

# Scanner tests
python manage.py test discover.tests
```

### Coverage
```bash
coverage run --source='discover' manage.py test discover
coverage report
coverage html
```

## 🛡️ Security Best Practices

1. **API Keys**: Never commit API keys to version control
2. **Authentication**: Enable authentication in production
3. **Rate Limiting**: Configure rate limits to prevent abuse
4. **HTTPS**: Always use HTTPS in production
5. **Permissions**: Review and configure RBAC appropriately
6. **Audit Logs**: Regularly review audit logs for suspicious activity

## 📈 Performance Optimization

### Database Indexing
The app includes optimized indexes for:
- Scan date and target lookups
- Finding severity and type queries
- User activity tracking

### Caching Strategy
- Scan data: 30 minutes
- User stats: 5 minutes
- Global stats: 5 minutes
- Trending targets: 30 minutes

### Query Optimization
- Use `select_related()` and `prefetch_related()` for related objects
- Aggregate queries for statistics
- Pagination for large result sets

## 🤝 Contributing

1. Follow Django best practices
2. Write tests for new features
3. Update documentation
4. Use meaningful commit messages

## 📝 License

This project is part of the Megido Security platform.

## 🐛 Known Issues

- Threading for background scans (consider migrating to Celery for production)
- API authentication is disabled by default (configure for production)

## 📞 Support

For issues, questions, or contributions:
- GitHub: https://github.com/tkstanch/Megido
- Issues: https://github.com/tkstanch/Megido/issues

## 🗺️ Roadmap

- [ ] Real-time WebSocket updates for scan progress
- [ ] Advanced ML models for anomaly detection
- [ ] Integration with external SIEM systems
- [ ] Custom plugin system for data sources
- [ ] Multi-tenancy support
- [ ] Advanced visualization dashboards with charts
- [ ] Scheduled/recurring scans
- [ ] Collaborative features (sharing, comments)

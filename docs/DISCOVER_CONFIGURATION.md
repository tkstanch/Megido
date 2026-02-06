# Discover App Configuration

## Wayback Machine Settings

The Discover app uses the Wayback Machine to collect historical URLs. You can configure this feature using environment variables:

### Environment Variables

- `ENABLE_WAYBACK_MACHINE`: Enable/disable Wayback Machine integration (default: `true`)
- `WAYBACK_MACHINE_TIMEOUT`: Timeout in seconds for Wayback Machine requests (default: `10`)
- `WAYBACK_MACHINE_MAX_RETRIES`: Maximum retry attempts for failed requests (default: `2`)

### Example: Disable Wayback Machine for Offline Development

```bash
export ENABLE_WAYBACK_MACHINE=false
python manage.py runserver
```

### Example: Increase Timeout for Slow Networks

```bash
export WAYBACK_MACHINE_TIMEOUT=30
python manage.py runserver
```

### Troubleshooting

**Error: "Unable to connect to web.archive.org"**
- Check your internet connection
- Verify DNS is working: `nslookup web.archive.org`
- Check if web.archive.org is blocked by firewall
- Disable Wayback Machine for offline development: `export ENABLE_WAYBACK_MACHINE=false`

**Error: "Request timeout"**
- Increase timeout: `export WAYBACK_MACHINE_TIMEOUT=30`
- Check network speed
- Try again later (web.archive.org may be slow)

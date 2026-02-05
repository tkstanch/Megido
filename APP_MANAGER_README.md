# App Manager

## Overview

The App Manager is a centralized control panel that allows users to manage all Django apps in the Megido Security platform. It provides a modern UI to enable/disable apps with toggle switches and persists the state in the database.

## Features

- **Visual Dashboard**: Modern, responsive interface with app cards
- **Toggle Controls**: Easy-to-use toggle switches for each app
- **State Persistence**: App enabled/disabled state is stored in the database
- **Status Indicators**: Clear visual indicators showing app status
- **Audit Logging**: All state changes are logged with user and timestamp information
- **Real-time Updates**: Statistics update in real-time as apps are toggled
- **Middleware Integration**: Automatically blocks access to disabled apps

## Database Models

### AppConfiguration
Stores app configuration and enabled/disabled state:
- `app_name`: Internal app name (e.g., 'proxy', 'scanner')
- `display_name`: User-friendly display name
- `description`: App description and purpose
- `is_enabled`: Boolean flag for enabled/disabled state
- `icon`: Emoji icon for the app
- `category`: App category (e.g., 'security', 'analysis')
- `capabilities`: Comma-separated list of app capabilities

### AppStateChange
Tracks all app state changes for audit purposes:
- `app_config`: Foreign key to AppConfiguration
- `user`: User who made the change
- `previous_state`: State before change
- `new_state`: State after change
- `timestamp`: When the change occurred
- `ip_address`: IP address of the user

### AppSettings
Stores app-specific settings in JSON format:
- `app_config`: One-to-one relationship with AppConfiguration
- `settings_json`: JSON field for flexible settings storage

## API Endpoints

### List All Apps
```
GET /app-manager/api/apps/
```

Returns a list of all apps with their configuration.

### Get App Details
```
GET /app-manager/api/apps/<app_id>/
```

Returns detailed information about a specific app.

### Toggle App State
```
POST /app-manager/api/apps/<app_id>/toggle/
```

Toggles the enabled/disabled state of an app and logs the change.

### Get App History
```
GET /app-manager/api/apps/<app_id>/history/
```

Returns the state change history for an app.

## Management Commands

### Populate Apps
```bash
python manage.py populate_apps
```

Populates the database with initial app configuration for all 15 Megido apps.

## Middleware

The `AppEnabledMiddleware` automatically checks if apps are enabled before processing requests. If a user tries to access a disabled app, they receive a 403 response with a message explaining that the app is disabled.

### Exempt Apps
The following apps are always accessible:
- admin
- app_manager
- browser

## Usage

1. Navigate to `/app-manager/` to access the dashboard
2. View all installed apps with their current status
3. Toggle apps on/off using the switch controls
4. View statistics showing total, enabled, and disabled apps
5. All changes are automatically saved and logged

## Security

- Audit logging tracks all state changes
- IP addresses are recorded for security monitoring
- Middleware enforces app state at the request level
- CSRF protection on all state-changing operations

## Screenshots

See the UI screenshots for visual representation of the dashboard.

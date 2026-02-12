"""
API Documentation using OpenAPI/Swagger.
"""
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
    openapi.Info(
        title="Megido Discover API",
        default_version='v1',
        description="""
# Megido Discover REST API

The Discover app provides comprehensive OSINT (Open Source Intelligence) capabilities
through a RESTful API.

## Features

- **Scan Management**: Create, retrieve, update, and delete OSINT scans
- **Finding Analysis**: Access and manage sensitive information findings
- **Analytics**: Get insights and statistics about scans and findings
- **Export**: Export data in multiple formats (JSON, CSV, SARIF)
- **Real-time Status**: Monitor scan progress in real-time

## Authentication

Currently, the API allows anonymous access for development purposes. In production,
you should configure proper authentication using:

- Token Authentication
- Session Authentication
- OAuth2

## Rate Limiting

API rate limiting is not currently enforced but should be configured in production.

## Pagination

List endpoints support pagination with the following parameters:
- `page`: Page number (default: 1)
- `page_size`: Results per page (default: 20, max: 100)

## Filtering

List endpoints support filtering via query parameters. See individual endpoints
for available filters.

## Contact

For issues or questions, please visit: https://github.com/tkstanch/Megido
        """,
        terms_of_service="https://github.com/tkstanch/Megido",
        contact=openapi.Contact(email="contact@example.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

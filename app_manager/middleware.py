from django.http import HttpResponse
from django.shortcuts import redirect
from app_manager.models import AppConfiguration
import logging

logger = logging.getLogger(__name__)


class AppEnabledMiddleware:
    """
    Middleware to check if apps are enabled before processing requests
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Apps that should always be accessible
        self.exempt_apps = ['admin', 'app_manager', 'browser']
        # URL patterns that should always be accessible
        self.exempt_paths = ['/', '/admin/', '/app-manager/', '/browser/']
        logger.info("AppEnabledMiddleware initialized")
    
    def __call__(self, request):
        logger.debug(f"Checking path: {request.path}")
        
        # Check if path should be exempt
        if any(request.path.startswith(path) for path in self.exempt_paths):
            logger.debug(f"Path {request.path} is exempt")
            return self.get_response(request)
        
        # Extract app name from path
        path_parts = request.path.strip('/').split('/')
        if path_parts:
            app_name = path_parts[0].replace('-', '_')
            logger.debug(f"Extracted app name: {app_name}")
            
            # Skip exempt apps
            if app_name in self.exempt_apps:
                logger.debug(f"App {app_name} is exempt")
                return self.get_response(request)
            
            # Check if app exists and is enabled
            try:
                app_config = AppConfiguration.objects.get(app_name=app_name)
                logger.debug(f"App {app_name} found, enabled: {app_config.is_enabled}")
                if not app_config.is_enabled:
                    logger.info(f"Blocking access to disabled app: {app_name}")
                    return HttpResponse(
                        f'<html><body style="font-family: Arial; padding: 50px; text-align: center;">'
                        f'<h1>🚫 App Disabled</h1>'
                        f'<p>The <strong>{app_config.display_name}</strong> app is currently disabled.</p>'
                        f'<p>Please enable it in the <a href="/app-manager/">App Manager</a>.</p>'
                        f'</body></html>',
                        status=403
                    )
            except AppConfiguration.DoesNotExist:
                logger.debug(f"App {app_name} not in configuration, allowing access")
                # App not in configuration, allow access
                pass
        
        return self.get_response(request)

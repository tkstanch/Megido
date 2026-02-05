from django.http import HttpResponse
from django.shortcuts import redirect
from app_manager.models import AppConfiguration


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
    
    def __call__(self, request):
        # Check if path should be exempt
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return self.get_response(request)
        
        # Extract app name from path
        path_parts = request.path.strip('/').split('/')
        if path_parts:
            app_name = path_parts[0].replace('-', '_')
            
            # Skip exempt apps
            if app_name in self.exempt_apps:
                return self.get_response(request)
            
            # Check if app exists and is enabled
            try:
                app_config = AppConfiguration.objects.get(app_name=app_name)
                if not app_config.is_enabled:
                    return HttpResponse(
                        f'<html><body style="font-family: Arial; padding: 50px; text-align: center;">'
                        f'<h1>🚫 App Disabled</h1>'
                        f'<p>The <strong>{app_config.display_name}</strong> app is currently disabled.</p>'
                        f'<p>Please enable it in the <a href="/app-manager/">App Manager</a>.</p>'
                        f'</body></html>',
                        status=403
                    )
            except AppConfiguration.DoesNotExist:
                # App not in configuration, allow access
                pass
        
        return self.get_response(request)

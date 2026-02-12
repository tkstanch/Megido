"""
Audit logging for security events and actions in the Discover app.
"""
from django.utils import timezone
from django.contrib.auth.models import User
import json
import logging

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Centralized audit logging for security-sensitive actions.
    """
    
    EVENT_TYPES = {
        'scan_created': 'Scan Created',
        'scan_deleted': 'Scan Deleted',
        'scan_viewed': 'Scan Viewed',
        'finding_verified': 'Finding Verified',
        'finding_false_positive': 'Finding Marked False Positive',
        'finding_deleted': 'Finding Deleted',
        'permission_changed': 'Permission Changed',
        'role_assigned': 'Role Assigned',
        'role_removed': 'Role Removed',
        'login_success': 'Login Success',
        'login_failed': 'Login Failed',
        'unauthorized_access': 'Unauthorized Access Attempt',
        'data_exported': 'Data Exported',
        'api_key_created': 'API Key Created',
        'api_key_deleted': 'API Key Deleted',
    }
    
    def __init__(self):
        self.logger = logging.getLogger('discover.audit')
    
    def log(self, event_type, user=None, target=None, details=None, ip_address=None, request=None):
        """
        Log an audit event.
        
        Args:
            event_type: Type of event (from EVENT_TYPES)
            user: User object or username
            target: Target of the action (e.g., scan ID, finding ID)
            details: Additional details dict
            ip_address: IP address of the user
            request: HttpRequest object (will extract IP if ip_address not provided)
        """
        # Get IP address from request if not provided
        if not ip_address and request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
        
        # Format user
        if isinstance(user, User):
            username = user.username
            user_id = user.id
        elif user:
            username = str(user)
            user_id = None
        else:
            username = 'Anonymous'
            user_id = None
        
        # Build log message
        event_name = self.EVENT_TYPES.get(event_type, event_type)
        log_data = {
            'timestamp': timezone.now().isoformat(),
            'event_type': event_type,
            'event_name': event_name,
            'user': username,
            'user_id': user_id,
            'target': target,
            'ip_address': ip_address,
            'details': details or {},
        }
        
        # Log as structured JSON
        self.logger.info(json.dumps(log_data))
        
        # Also store in database for queryability
        self._store_in_db(log_data)
    
    def _store_in_db(self, log_data):
        """Store audit log in database."""
        try:
            from .models import UserActivity
            
            # Map audit events to activity types
            activity_map = {
                'scan_created': 'scan_start',
                'scan_viewed': 'scan_view',
                'finding_verified': 'finding_verify',
                'finding_false_positive': 'finding_false_positive',
                'data_exported': 'export_data',
            }
            
            action = activity_map.get(log_data['event_type'])
            if action:
                UserActivity.objects.create(
                    user_id=log_data.get('user_id'),
                    action=action,
                    target=log_data.get('target', ''),
                    ip_address=log_data.get('ip_address'),
                    metadata=json.dumps(log_data.get('details', {}))
                )
        except Exception as e:
            logger.error(f"Error storing audit log in DB: {e}")
    
    def log_scan_created(self, user, scan_id, target, request=None):
        """Log scan creation."""
        self.log('scan_created', user=user, target=target, 
                details={'scan_id': scan_id}, request=request)
    
    def log_scan_viewed(self, user, scan_id, target, request=None):
        """Log scan view."""
        self.log('scan_viewed', user=user, target=target,
                details={'scan_id': scan_id}, request=request)
    
    def log_finding_verified(self, user, finding_id, scan_id, request=None):
        """Log finding verification."""
        self.log('finding_verified', user=user, target=f"Finding {finding_id}",
                details={'finding_id': finding_id, 'scan_id': scan_id}, request=request)
    
    def log_unauthorized_access(self, user, resource, request=None):
        """Log unauthorized access attempt."""
        self.log('unauthorized_access', user=user, target=resource,
                details={'resource': resource}, request=request)
    
    def log_permission_changed(self, admin_user, target_user, permission, granted, request=None):
        """Log permission change."""
        self.log('permission_changed', user=admin_user, target=f"User {target_user}",
                details={
                    'target_user': str(target_user),
                    'permission': permission,
                    'granted': granted
                }, request=request)
    
    def log_data_export(self, user, data_type, record_count, request=None):
        """Log data export."""
        self.log('data_exported', user=user, target=data_type,
                details={
                    'data_type': data_type,
                    'record_count': record_count
                }, request=request)


# Global audit logger instance
audit_logger = AuditLogger()

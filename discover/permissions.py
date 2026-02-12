"""
Permissions and Role-Based Access Control for the Discover app.
"""
from rest_framework import permissions
from django.contrib.auth.models import Group


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission to only allow owners of a scan or admins to view/edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admin users have full access
        if request.user and request.user.is_staff:
            return True
        
        # Check if object has a user field and if it matches
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        # Check if object has a scan field with a user
        if hasattr(obj, 'scan') and hasattr(obj.scan, 'user'):
            return obj.scan.user == request.user
        
        return False


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Permission to allow read-only access to everyone,
    but only admins can modify.
    """
    
    def has_permission(self, request, view):
        # Read permissions for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for admin
        return request.user and request.user.is_staff


class CanStartScan(permissions.BasePermission):
    """
    Permission to control who can start scans.
    Checks user group membership.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Staff always can
        if request.user.is_staff:
            return True
        
        # Check if user is in 'scanners' group
        return request.user.groups.filter(name='scanners').exists()


class CanVerifyFindings(permissions.BasePermission):
    """
    Permission to control who can verify findings.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Staff always can
        if request.user.is_staff:
            return True
        
        # Check if user is in 'analysts' group
        return request.user.groups.filter(name='analysts').exists()


class CanViewAnalytics(permissions.BasePermission):
    """
    Permission to control who can view analytics dashboards.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Staff always can
        if request.user.is_staff:
            return True
        
        # Check if user is in 'analysts' or 'scanners' group
        return request.user.groups.filter(
            name__in=['analysts', 'scanners']
        ).exists()


def setup_groups():
    """
    Set up default permission groups for the Discover app.
    Call this once during app initialization.
    """
    # Create groups if they don't exist
    scanner_group, _ = Group.objects.get_or_create(name='scanners')
    analyst_group, _ = Group.objects.get_or_create(name='analysts')
    viewer_group, _ = Group.objects.get_or_create(name='viewers')
    
    return {
        'scanners': scanner_group,
        'analysts': analyst_group,
        'viewers': viewer_group,
    }


def assign_user_role(user, role):
    """
    Assign a role to a user.
    
    Args:
        user: User object
        role: Role name ('scanner', 'analyst', 'viewer')
    """
    role_group_map = {
        'scanner': 'scanners',
        'analyst': 'analysts',
        'viewer': 'viewers',
    }
    
    group_name = role_group_map.get(role)
    if group_name:
        group, _ = Group.objects.get_or_create(name=group_name)
        user.groups.add(group)


def remove_user_role(user, role):
    """
    Remove a role from a user.
    
    Args:
        user: User object
        role: Role name ('scanner', 'analyst', 'viewer')
    """
    role_group_map = {
        'scanner': 'scanners',
        'analyst': 'analysts',
        'viewer': 'viewers',
    }
    
    group_name = role_group_map.get(role)
    if group_name:
        try:
            group = Group.objects.get(name=group_name)
            user.groups.remove(group)
        except Group.DoesNotExist:
            pass


def get_user_roles(user):
    """
    Get all roles assigned to a user.
    
    Args:
        user: User object
        
    Returns:
        List of role names
    """
    group_role_map = {
        'scanners': 'scanner',
        'analysts': 'analyst',
        'viewers': 'viewer',
    }
    
    user_groups = user.groups.values_list('name', flat=True)
    roles = [group_role_map.get(group) for group in user_groups if group in group_role_map]
    
    return roles


def can_user_start_scan(user):
    """Check if user can start scans."""
    if not user or not user.is_authenticated:
        return False
    return user.is_staff or user.groups.filter(name='scanners').exists()


def can_user_verify_findings(user):
    """Check if user can verify findings."""
    if not user or not user.is_authenticated:
        return False
    return user.is_staff or user.groups.filter(name='analysts').exists()


def can_user_view_analytics(user):
    """Check if user can view analytics."""
    if not user or not user.is_authenticated:
        return False
    return user.is_staff or user.groups.filter(name__in=['analysts', 'scanners']).exists()

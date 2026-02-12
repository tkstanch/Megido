"""
Caching utilities for the Discover app.
Uses Redis for caching frequently accessed data.
"""
from django.core.cache import cache
from django.conf import settings
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

# Cache timeouts (in seconds)
CACHE_TIMEOUT_SHORT = 300  # 5 minutes
CACHE_TIMEOUT_MEDIUM = 1800  # 30 minutes
CACHE_TIMEOUT_LONG = 3600  # 1 hour
CACHE_TIMEOUT_DAY = 86400  # 24 hours


def get_cache_key(prefix, *args, **kwargs):
    """
    Generate a cache key from prefix and arguments.
    
    Args:
        prefix: Cache key prefix
        *args: Additional arguments to include in key
        **kwargs: Additional keyword arguments to include in key
        
    Returns:
        Cache key string
    """
    # Create a unique key from arguments
    key_parts = [prefix]
    key_parts.extend([str(arg) for arg in args])
    key_parts.extend([f"{k}:{v}" for k, v in sorted(kwargs.items())])
    
    key_string = ":".join(key_parts)
    
    # Hash long keys
    if len(key_string) > 200:
        key_hash = hashlib.md5(key_string.encode()).hexdigest()
        return f"{prefix}:{key_hash}"
    
    return key_string


def cached_scan_data(scan_id):
    """
    Get cached scan data or fetch from database.
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Scan data dict or None
    """
    cache_key = get_cache_key('scan_data', scan_id)
    data = cache.get(cache_key)
    
    if data is None:
        from .models import Scan
        try:
            scan = Scan.objects.get(id=scan_id)
            data = {
                'id': scan.id,
                'target': scan.target,
                'scan_date': scan.scan_date.isoformat(),
                'total_urls': scan.total_urls,
                'total_emails': scan.total_emails,
                'total_findings': scan.total_findings,
                'high_risk_findings': scan.high_risk_findings,
                'sensitive_scan_completed': scan.sensitive_scan_completed,
            }
            cache.set(cache_key, data, CACHE_TIMEOUT_MEDIUM)
            logger.debug(f"Cached scan data for scan {scan_id}")
        except Scan.DoesNotExist:
            return None
    
    return data


def cached_user_stats(user_id, days=30):
    """
    Get cached user statistics.
    
    Args:
        user_id: User ID
        days: Number of days to look back
        
    Returns:
        User stats dict
    """
    cache_key = get_cache_key('user_stats', user_id, days=days)
    data = cache.get(cache_key)
    
    if data is None:
        from django.contrib.auth.models import User
        from .analytics import get_user_stats
        
        try:
            user = User.objects.get(id=user_id)
            data = get_user_stats(user, days=days)
            cache.set(cache_key, data, CACHE_TIMEOUT_SHORT)
            logger.debug(f"Cached user stats for user {user_id}")
        except User.DoesNotExist:
            return None
    
    return data


def cached_global_stats(days=30):
    """
    Get cached global statistics.
    
    Args:
        days: Number of days to look back
        
    Returns:
        Global stats dict
    """
    cache_key = get_cache_key('global_stats', days=days)
    data = cache.get(cache_key)
    
    if data is None:
        from .analytics import get_global_stats
        data = get_global_stats(days=days)
        cache.set(cache_key, data, CACHE_TIMEOUT_SHORT)
        logger.debug(f"Cached global stats for {days} days")
    
    return data


def cached_trending_targets(days=7, limit=10):
    """
    Get cached trending targets.
    
    Args:
        days: Number of days to look back
        limit: Maximum number of targets
        
    Returns:
        List of trending target dicts
    """
    cache_key = get_cache_key('trending_targets', days=days, limit=limit)
    data = cache.get(cache_key)
    
    if data is None:
        from .analytics import get_trending_targets
        data = get_trending_targets(days=days, limit=limit)
        cache.set(cache_key, data, CACHE_TIMEOUT_MEDIUM)
        logger.debug(f"Cached trending targets")
    
    return data


def invalidate_scan_cache(scan_id):
    """
    Invalidate cache for a specific scan.
    Call this when scan data is updated.
    
    Args:
        scan_id: Scan ID
    """
    cache_key = get_cache_key('scan_data', scan_id)
    cache.delete(cache_key)
    logger.debug(f"Invalidated cache for scan {scan_id}")


def invalidate_user_cache(user_id):
    """
    Invalidate cache for a specific user.
    Call this when user data is updated.
    
    Args:
        user_id: User ID
    """
    # Invalidate user stats for common day ranges
    for days in [7, 30, 90]:
        cache_key = get_cache_key('user_stats', user_id, days=days)
        cache.delete(cache_key)
    logger.debug(f"Invalidated cache for user {user_id}")


def invalidate_global_cache():
    """
    Invalidate global statistics cache.
    Call this when new scans or findings are created.
    """
    # Invalidate global stats for common day ranges
    for days in [7, 30, 90]:
        cache_key = get_cache_key('global_stats', days=days)
        cache.delete(cache_key)
    
    # Invalidate trending targets
    for days in [7, 14, 30]:
        for limit in [10, 20, 50]:
            cache_key = get_cache_key('trending_targets', days=days, limit=limit)
            cache.delete(cache_key)
    
    logger.debug("Invalidated global cache")


def warm_cache():
    """
    Warm up cache with commonly accessed data.
    Can be called periodically via cron or celery task.
    """
    logger.info("Warming up cache...")
    
    # Cache global stats for common ranges
    for days in [7, 30, 90]:
        cached_global_stats(days=days)
    
    # Cache trending targets
    for days in [7, 14, 30]:
        cached_trending_targets(days=days, limit=10)
    
    logger.info("Cache warming completed")

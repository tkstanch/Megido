"""
Analytics and tracking utilities for the Discover app.
"""
from django.utils import timezone
from django.db.models import Count, Avg, Q, F
from datetime import timedelta
import json
import logging

from .models import Scan, SensitiveFinding, UserActivity, ScanRecommendation

logger = logging.getLogger(__name__)


def track_activity(user, action, target='', scan=None, request=None, metadata=None):
    """
    Track user activity for analytics.
    
    Args:
        user: User object (can be None for anonymous)
        action: Action type (see UserActivity.ACTION_CHOICES)
        target: Target domain/URL
        scan: Related Scan object
        request: HttpRequest object to extract IP and user agent
        metadata: Dict of additional metadata
    """
    try:
        ip_address = None
        user_agent = ''
        
        if request:
            # Get IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            
            # Get user agent
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        
        metadata_json = json.dumps(metadata) if metadata else ''
        
        UserActivity.objects.create(
            user=user,
            action=action,
            target=target,
            scan=scan,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata_json
        )
        logger.debug(f"Tracked activity: {action} for user {user}")
    except Exception as e:
        logger.error(f"Error tracking activity: {e}")


def get_user_stats(user, days=30):
    """
    Get statistics for a specific user.
    
    Args:
        user: User object
        days: Number of days to look back
        
    Returns:
        Dict with user statistics
    """
    since = timezone.now() - timedelta(days=days)
    
    scans = Scan.objects.filter(user=user, scan_date__gte=since)
    activities = UserActivity.objects.filter(user=user, timestamp__gte=since)
    
    total_scans = scans.count()
    total_findings = scans.aggregate(total=Count('sensitive_findings'))['total'] or 0
    high_risk_findings = SensitiveFinding.objects.filter(
        scan__user=user,
        scan__scan_date__gte=since,
        severity__in=['critical', 'high']
    ).count()
    
    # Most scanned targets
    top_targets = scans.values('target').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Activity breakdown
    activity_breakdown = list(activities.values('action').annotate(
        count=Count('id')
    ).order_by('-count'))
    
    # Calculate percentages for activity breakdown
    max_count = max([a['count'] for a in activity_breakdown], default=1)
    for activity in activity_breakdown:
        activity['percentage'] = int((activity['count'] / max_count) * 100) if max_count > 0 else 0
    
    # Average scan duration
    avg_duration = scans.aggregate(avg=Avg('scan_duration_seconds'))['avg'] or 0
    
    return {
        'period_days': days,
        'total_scans': total_scans,
        'total_findings': total_findings,
        'high_risk_findings': high_risk_findings,
        'top_targets': list(top_targets),
        'activity_breakdown': list(activity_breakdown),
        'avg_scan_duration_seconds': avg_duration,
    }


def get_global_stats(days=30):
    """
    Get global statistics across all users.
    
    Args:
        days: Number of days to look back
        
    Returns:
        Dict with global statistics
    """
    since = timezone.now() - timedelta(days=days)
    
    scans = Scan.objects.filter(scan_date__gte=since)
    findings = SensitiveFinding.objects.filter(scan__scan_date__gte=since)
    
    total_scans = scans.count()
    total_findings = findings.count()
    
    # Findings by severity
    severity_stats = findings.aggregate(
        critical=Count('id', filter=Q(severity='critical')),
        high=Count('id', filter=Q(severity='high')),
        medium=Count('id', filter=Q(severity='medium')),
        low=Count('id', filter=Q(severity='low')),
        info=Count('id', filter=Q(severity='info')),
    )
    
    # Top finding types
    top_finding_types = findings.values('finding_type').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Most active users
    top_users = scans.values('user__username').annotate(
        scan_count=Count('id')
    ).order_by('-scan_count')[:10]
    
    # Scans over time (daily aggregation)
    daily_scans = []
    for i in range(days):
        day_start = (timezone.now() - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count = scans.filter(scan_date__gte=day_start, scan_date__lt=day_end).count()
        daily_scans.append({
            'date': day_start.date().isoformat(),
            'count': count
        })
    
    return {
        'period_days': days,
        'total_scans': total_scans,
        'total_findings': total_findings,
        'findings_by_severity': severity_stats,
        'top_finding_types': list(top_finding_types),
        'top_users': list(top_users),
        'daily_scans': daily_scans,
    }


def generate_recommendations(user, limit=5):
    """
    Generate ML-powered scan recommendations for a user.
    
    This is a simple rule-based implementation that can be enhanced
    with actual ML models.
    
    Args:
        user: User object
        limit: Maximum number of recommendations to generate
        
    Returns:
        List of recommendation dicts
    """
    recommendations = []
    
    try:
        # Get user's recent scans
        recent_scans = Scan.objects.filter(user=user).order_by('-scan_date')[:10]
        
        if not recent_scans:
            # No scan history, provide default recommendations
            default_targets = [
                ('example.com', 'Popular testing target', 0.8),
                ('test.com', 'Common test domain', 0.7),
            ]
            for target, reason, score in default_targets[:limit]:
                recommendations.append({
                    'target': target,
                    'reason': reason,
                    'confidence_score': score,
                })
            return recommendations
        
        # Analyze scan patterns
        target_domains = [scan.target for scan in recent_scans]
        
        # Extract TLDs and subdomains for pattern analysis
        tlds = set()
        for target in target_domains:
            parts = target.split('.')
            if len(parts) >= 2:
                tlds.add(parts[-1])
        
        # Recommend related domains (simple heuristic)
        # In production, this would use actual ML models
        for scan in recent_scans[:3]:
            if scan.high_risk_findings > 0:
                # Suggest rescanning targets with high-risk findings
                recommendations.append({
                    'target': scan.target,
                    'reason': f'Re-scan recommended: {scan.high_risk_findings} high-risk findings previously detected',
                    'confidence_score': 0.9,
                })
        
        # Save recommendations to database
        for rec in recommendations[:limit]:
            ScanRecommendation.objects.get_or_create(
                user=user,
                recommended_target=rec['target'],
                defaults={
                    'reason': rec['reason'],
                    'confidence_score': rec['confidence_score'],
                }
            )
        
    except Exception as e:
        logger.error(f"Error generating recommendations: {e}")
    
    return recommendations[:limit]


def get_trending_targets(days=7, limit=10):
    """
    Get trending scan targets across all users.
    
    Args:
        days: Number of days to look back
        limit: Maximum number of targets to return
        
    Returns:
        List of target dicts with scan counts
    """
    since = timezone.now() - timedelta(days=days)
    
    trending = Scan.objects.filter(scan_date__gte=since).values('target').annotate(
        scan_count=Count('id'),
        high_risk_count=Count('id', filter=Q(high_risk_findings__gt=0))
    ).order_by('-scan_count')[:limit]
    
    return list(trending)


def get_finding_trends(days=30):
    """
    Get trends in findings over time.
    
    Args:
        days: Number of days to look back
        
    Returns:
        Dict with trend data
    """
    since = timezone.now() - timedelta(days=days)
    
    findings = SensitiveFinding.objects.filter(discovered_at__gte=since)
    
    # Findings over time (daily aggregation)
    daily_findings = []
    for i in range(days):
        day_start = (timezone.now() - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        day_data = findings.filter(
            discovered_at__gte=day_start,
            discovered_at__lt=day_end
        ).aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
        )
        
        daily_findings.append({
            'date': day_start.date().isoformat(),
            'total': day_data['total'] or 0,
            'critical': day_data['critical'] or 0,
            'high': day_data['high'] or 0,
        })
    
    return {
        'daily_findings': daily_findings,
    }

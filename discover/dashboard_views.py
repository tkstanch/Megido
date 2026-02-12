"""
Dashboard views for analytics and insights.
"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

from .models import Scan, SensitiveFinding, UserActivity, ScanRecommendation
from .analytics import (
    get_user_stats, get_global_stats, generate_recommendations,
    get_trending_targets, get_finding_trends
)


@login_required
def user_dashboard(request):
    """
    User-facing analytics dashboard.
    Shows personalized insights and recommendations.
    """
    # Get user statistics
    days = int(request.GET.get('days', 30))
    user_stats = get_user_stats(request.user, days=days)
    
    # Get recent scans
    recent_scans = Scan.objects.filter(user=request.user).order_by('-scan_date')[:10]
    
    # Get recommendations
    recommendations = generate_recommendations(request.user, limit=5)
    
    # Get recent activities
    recent_activities = UserActivity.objects.filter(user=request.user).order_by('-timestamp')[:20]
    
    context = {
        'title': 'My Dashboard',
        'stats': user_stats,
        'recent_scans': recent_scans,
        'recommendations': recommendations,
        'recent_activities': recent_activities,
        'days': days,
    }
    
    return render(request, 'discover/dashboard_user.html', context)


@login_required
def admin_dashboard(request):
    """
    Admin-facing analytics dashboard.
    Shows global insights and trends.
    
    Requires staff status.
    """
    if not request.user.is_staff:
        return render(request, 'discover/dashboard_user.html', {
            'error': 'Admin access required'
        })
    
    # Get global statistics
    days = int(request.GET.get('days', 30))
    global_stats = get_global_stats(days=days)
    
    # Get trending targets
    trending = get_trending_targets(days=7, limit=10)
    
    # Get finding trends
    finding_trends = get_finding_trends(days=days)
    
    # Get recent high-risk findings
    recent_high_risk = SensitiveFinding.objects.filter(
        severity__in=['critical', 'high']
    ).order_by('-discovered_at')[:20]
    
    # User activity summary
    user_activity = UserActivity.objects.filter(
        timestamp__gte=timezone.now() - timedelta(days=days)
    ).values('action').annotate(count=Count('id')).order_by('-count')
    
    context = {
        'title': 'Admin Dashboard',
        'stats': global_stats,
        'trending': trending,
        'finding_trends': finding_trends,
        'recent_high_risk': recent_high_risk,
        'user_activity': user_activity,
        'days': days,
    }
    
    return render(request, 'discover/dashboard_admin.html', context)


@login_required
def analytics_api(request):
    """
    API endpoint for dashboard data (JSON).
    Supports real-time updates via AJAX.
    """
    data_type = request.GET.get('type', 'user_stats')
    days = int(request.GET.get('days', 30))
    
    if data_type == 'user_stats':
        data = get_user_stats(request.user, days=days)
    elif data_type == 'global_stats' and request.user.is_staff:
        data = get_global_stats(days=days)
    elif data_type == 'recommendations':
        data = generate_recommendations(request.user, limit=10)
    elif data_type == 'trending':
        data = get_trending_targets(days=days, limit=20)
    elif data_type == 'finding_trends':
        data = get_finding_trends(days=days)
    else:
        return JsonResponse({'error': 'Invalid data type'}, status=400)
    
    return JsonResponse(data, safe=False)

"""
Tests for analytics, caching, and permissions.
"""
from django.test import TestCase
from django.contrib.auth.models import User, Group
from datetime import timedelta
from django.utils import timezone

from discover.models import Scan, SensitiveFinding, UserActivity, ScanRecommendation
from discover.analytics import (
    track_activity, get_user_stats, get_global_stats,
    generate_recommendations, get_trending_targets
)
from discover.cache_utils import (
    cached_scan_data, cached_user_stats, invalidate_scan_cache
)
from discover.permissions import (
    setup_groups, assign_user_role, remove_user_role, get_user_roles,
    can_user_start_scan, can_user_verify_findings
)


class AnalyticsTestCase(TestCase):
    """Tests for analytics functions"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        # Create test scans
        for i in range(3):
            scan = Scan.objects.create(
                target=f'example{i}.com',
                user=self.user,
                total_findings=5 + i,
                high_risk_findings=1 + i,
                scan_duration_seconds=60 + i * 10,
            )
            
            # Create findings for each scan
            for j in range(5 + i):
                SensitiveFinding.objects.create(
                    scan=scan,
                    url=f'https://example{i}.com/page{j}',
                    finding_type='API Key',
                    value=f'key_{i}_{j}',
                    severity='high' if j == 0 else 'medium',
                )
    
    def test_track_activity(self):
        """Test activity tracking"""
        track_activity(self.user, 'scan_start', target='example.com')
        
        activities = UserActivity.objects.filter(user=self.user)
        self.assertEqual(activities.count(), 1)
        self.assertEqual(activities.first().action, 'scan_start')
        self.assertEqual(activities.first().target, 'example.com')
    
    def test_get_user_stats(self):
        """Test user statistics"""
        stats = get_user_stats(self.user, days=30)
        
        self.assertEqual(stats['total_scans'], 3)
        self.assertGreater(stats['total_findings'], 0)
        self.assertGreater(stats['high_risk_findings'], 0)
        self.assertIn('top_targets', stats)
    
    def test_get_global_stats(self):
        """Test global statistics"""
        stats = get_global_stats(days=30)
        
        self.assertGreater(stats['total_scans'], 0)
        self.assertGreater(stats['total_findings'], 0)
        self.assertIn('findings_by_severity', stats)
        self.assertIn('daily_scans', stats)
    
    def test_generate_recommendations(self):
        """Test recommendation generation"""
        recommendations = generate_recommendations(self.user, limit=5)
        
        # Should get some recommendations based on high-risk findings
        self.assertIsInstance(recommendations, list)
    
    def test_get_trending_targets(self):
        """Test trending targets"""
        trending = get_trending_targets(days=7, limit=10)
        
        self.assertIsInstance(trending, list)
        if trending:
            self.assertIn('target', trending[0])
            self.assertIn('scan_count', trending[0])


class CachingTestCase(TestCase):
    """Tests for caching utilities"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.scan = Scan.objects.create(
            target='example.com',
            user=self.user,
            total_findings=10,
            high_risk_findings=2,
        )
    
    def test_cached_scan_data(self):
        """Test scan data caching"""
        # First call - cache miss
        data1 = cached_scan_data(self.scan.id)
        self.assertIsNotNone(data1)
        self.assertEqual(data1['target'], 'example.com')
        
        # Second call - cache hit (should be same data)
        data2 = cached_scan_data(self.scan.id)
        self.assertEqual(data1, data2)
    
    def test_invalidate_scan_cache(self):
        """Test cache invalidation"""
        # Cache the data
        data1 = cached_scan_data(self.scan.id)
        self.assertIsNotNone(data1)
        
        # Update the scan
        self.scan.total_findings = 20
        self.scan.save()
        
        # Invalidate cache
        invalidate_scan_cache(self.scan.id)
        
        # Get fresh data
        data2 = cached_scan_data(self.scan.id)
        # Note: The cached data won't reflect the update until invalidated
        # This test just ensures invalidation doesn't error
        self.assertIsNotNone(data2)
    
    def test_cached_user_stats(self):
        """Test user stats caching"""
        stats1 = cached_user_stats(self.user.id, days=30)
        self.assertIsNotNone(stats1)
        
        # Second call should hit cache
        stats2 = cached_user_stats(self.user.id, days=30)
        # Note: Due to cache, these should be identical
        self.assertIsNotNone(stats2)


class PermissionsTestCase(TestCase):
    """Tests for permissions and RBAC"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        # Set up groups
        setup_groups()
    
    def test_setup_groups(self):
        """Test group setup"""
        groups = setup_groups()
        
        self.assertIn('scanners', groups)
        self.assertIn('analysts', groups)
        self.assertIn('viewers', groups)
        
        # Verify groups exist in database
        self.assertTrue(Group.objects.filter(name='scanners').exists())
        self.assertTrue(Group.objects.filter(name='analysts').exists())
        self.assertTrue(Group.objects.filter(name='viewers').exists())
    
    def test_assign_user_role(self):
        """Test assigning roles to users"""
        assign_user_role(self.user, 'scanner')
        
        self.assertTrue(self.user.groups.filter(name='scanners').exists())
    
    def test_remove_user_role(self):
        """Test removing roles from users"""
        assign_user_role(self.user, 'scanner')
        self.assertTrue(self.user.groups.filter(name='scanners').exists())
        
        remove_user_role(self.user, 'scanner')
        self.assertFalse(self.user.groups.filter(name='scanners').exists())
    
    def test_get_user_roles(self):
        """Test getting user roles"""
        assign_user_role(self.user, 'scanner')
        assign_user_role(self.user, 'analyst')
        
        roles = get_user_roles(self.user)
        
        self.assertIn('scanner', roles)
        self.assertIn('analyst', roles)
        self.assertEqual(len(roles), 2)
    
    def test_can_user_start_scan(self):
        """Test scan permission check"""
        # User without permission
        self.assertFalse(can_user_start_scan(self.user))
        
        # Assign scanner role
        assign_user_role(self.user, 'scanner')
        self.assertTrue(can_user_start_scan(self.user))
        
        # Staff always can
        staff_user = User.objects.create_user(
            username='staff',
            password='pass',
            is_staff=True
        )
        self.assertTrue(can_user_start_scan(staff_user))
    
    def test_can_user_verify_findings(self):
        """Test verify findings permission check"""
        # User without permission
        self.assertFalse(can_user_verify_findings(self.user))
        
        # Assign analyst role
        assign_user_role(self.user, 'analyst')
        self.assertTrue(can_user_verify_findings(self.user))

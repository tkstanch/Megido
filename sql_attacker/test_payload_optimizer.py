"""
Unit tests for payload optimizer
"""

from django.test import TestCase
from sql_attacker.payload_optimizer import PayloadOptimizer


class PayloadOptimizerTest(TestCase):
    """Test intelligent payload optimizer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.optimizer = PayloadOptimizer()
    
    def test_initialization(self):
        """Test optimizer initializes correctly"""
        self.assertIsNotNone(self.optimizer)
        self.assertEqual(len(self.optimizer.payload_stats), 0)
        self.assertEqual(len(self.optimizer.target_profiles), 0)
    
    def test_record_payload_result_success(self):
        """Test recording successful payload"""
        payload = "' OR 1=1--"
        
        self.optimizer.record_payload_result(payload, success=True, response_time=0.5)
        
        self.assertIn(payload, self.optimizer.payload_stats)
        stats = self.optimizer.payload_stats[payload]
        self.assertEqual(stats['total_uses'], 1)
        self.assertEqual(stats['successes'], 1)
        self.assertEqual(stats['failures'], 0)
        self.assertEqual(stats['success_rate'], 1.0)
    
    def test_record_payload_result_failure(self):
        """Test recording failed payload"""
        payload = "' OR 1=2--"
        
        self.optimizer.record_payload_result(payload, success=False, response_time=0.3)
        
        stats = self.optimizer.payload_stats[payload]
        self.assertEqual(stats['total_uses'], 1)
        self.assertEqual(stats['successes'], 0)
        self.assertEqual(stats['failures'], 1)
        self.assertEqual(stats['success_rate'], 0.0)
    
    def test_record_multiple_results(self):
        """Test recording multiple results for same payload"""
        payload = "' UNION SELECT NULL--"
        
        self.optimizer.record_payload_result(payload, success=True, response_time=0.5)
        self.optimizer.record_payload_result(payload, success=True, response_time=0.6)
        self.optimizer.record_payload_result(payload, success=False, response_time=0.4)
        
        stats = self.optimizer.payload_stats[payload]
        self.assertEqual(stats['total_uses'], 3)
        self.assertEqual(stats['successes'], 2)
        self.assertEqual(stats['failures'], 1)
        self.assertAlmostEqual(stats['success_rate'], 2/3, places=2)
    
    def test_record_with_context(self):
        """Test recording with context tracking"""
        payload = "1 AND 1=1"
        
        self.optimizer.record_payload_result(
            payload, success=True, context='numeric'
        )
        
        stats = self.optimizer.payload_stats[payload]
        self.assertIn('numeric', stats['contexts'])
        self.assertEqual(stats['contexts']['numeric'], 1)
    
    def test_record_with_db_type(self):
        """Test recording with database type tracking"""
        payload = "' AND SLEEP(5)--"
        
        self.optimizer.record_payload_result(
            payload, success=True, db_type='mysql'
        )
        
        stats = self.optimizer.payload_stats[payload]
        self.assertIn('db_types', stats)
        self.assertIn('mysql', stats['db_types'])
        self.assertEqual(stats['db_types']['mysql']['success'], 1)
        self.assertEqual(stats['db_types']['mysql']['total'], 1)
    
    def test_get_ranked_payloads_insufficient_data(self):
        """Test ranking with insufficient data"""
        payload = "' OR 1=1--"
        self.optimizer.record_payload_result(payload, success=True)
        
        # Default min_uses is 3
        ranked = self.optimizer.get_ranked_payloads()
        
        self.assertEqual(len(ranked), 0)
    
    def test_get_ranked_payloads_sufficient_data(self):
        """Test ranking with sufficient data"""
        payload = "' OR 1=1--"
        
        # Record 3 successes
        for _ in range(3):
            self.optimizer.record_payload_result(payload, success=True, response_time=0.5)
        
        ranked = self.optimizer.get_ranked_payloads(min_uses=3)
        
        self.assertEqual(len(ranked), 1)
        ranked_payload, score = ranked[0]
        self.assertEqual(ranked_payload, payload)
        self.assertGreater(score, 0.5)
    
    def test_get_ranked_payloads_sorted(self):
        """Test that payloads are sorted by score"""
        # Payload 1: High success, fast
        for _ in range(5):
            self.optimizer.record_payload_result("payload1", success=True, response_time=0.3)
        
        # Payload 2: Medium success, slow
        for _ in range(5):
            self.optimizer.record_payload_result("payload2", success=True, response_time=2.0)
            self.optimizer.record_payload_result("payload2", success=False, response_time=2.0)
        
        # Payload 3: Low success
        for _ in range(5):
            self.optimizer.record_payload_result("payload3", success=False, response_time=0.5)
        
        ranked = self.optimizer.get_ranked_payloads(min_uses=3)
        
        self.assertEqual(len(ranked), 3)
        # Payload 1 should be first (best)
        self.assertEqual(ranked[0][0], "payload1")
        # Payload 3 should be last (worst)
        self.assertEqual(ranked[2][0], "payload3")
    
    def test_get_ranked_payloads_context_filter(self):
        """Test filtering by context"""
        # Record with different contexts
        self.optimizer.record_payload_result("payload1", success=True, context='numeric')
        self.optimizer.record_payload_result("payload1", success=True, context='numeric')
        self.optimizer.record_payload_result("payload1", success=True, context='numeric')
        
        self.optimizer.record_payload_result("payload2", success=True, context='string')
        self.optimizer.record_payload_result("payload2", success=True, context='string')
        self.optimizer.record_payload_result("payload2", success=True, context='string')
        
        numeric_ranked = self.optimizer.get_ranked_payloads(context='numeric', min_uses=3)
        
        self.assertEqual(len(numeric_ranked), 1)
        self.assertEqual(numeric_ranked[0][0], "payload1")
    
    def test_get_ranked_payloads_db_filter(self):
        """Test filtering by database type"""
        # Record with different databases
        for _ in range(3):
            self.optimizer.record_payload_result("mysql_payload", success=True, db_type='mysql')
            self.optimizer.record_payload_result("pgsql_payload", success=True, db_type='postgresql')
        
        mysql_ranked = self.optimizer.get_ranked_payloads(db_type='mysql', min_uses=3)
        
        self.assertEqual(len(mysql_ranked), 1)
        self.assertEqual(mysql_ranked[0][0], "mysql_payload")
    
    def test_get_optimal_payloads(self):
        """Test getting optimal payloads"""
        # Create several payloads with different performance
        for i in range(1, 6):
            payload = f"payload{i}"
            success_rate = i / 5  # 0.2, 0.4, 0.6, 0.8, 1.0
            
            for j in range(5):
                success = j < i
                self.optimizer.record_payload_result(payload, success=success, response_time=0.5)
        
        optimal = self.optimizer.get_optimal_payloads(count=3)
        
        self.assertEqual(len(optimal), 3)
        # Best performers should be returned
        self.assertIn("payload5", optimal)
        self.assertIn("payload4", optimal)
    
    def test_create_target_profile(self):
        """Test creating target profile"""
        url = "https://example.com/test"
        characteristics = {
            'db_type': 'mysql',
            'waf_detected': True,
        }
        
        self.optimizer.create_target_profile(url, characteristics)
        
        self.assertIn(url, self.optimizer.target_profiles)
        profile = self.optimizer.target_profiles[url]
        self.assertEqual(profile['characteristics'], characteristics)
    
    def test_update_target_profile(self):
        """Test updating target profile"""
        url = "https://example.com/test"
        self.optimizer.create_target_profile(url, {})
        
        optimal_payloads = ["payload1", "payload2", "payload3"]
        self.optimizer.update_target_profile(url, optimal_payloads)
        
        profile = self.optimizer.target_profiles[url]
        self.assertEqual(profile['optimal_payloads'], optimal_payloads)
    
    def test_get_recommendations_insufficient_data(self):
        """Test recommendations with no data"""
        recommendations = self.optimizer.get_recommendations()
        
        self.assertEqual(recommendations['status'], 'insufficient_data')
        self.assertIn('message', recommendations)
    
    def test_get_recommendations_with_data(self):
        """Test recommendations with sufficient data"""
        # Add some payload data
        for _ in range(5):
            self.optimizer.record_payload_result("good_payload", success=True, response_time=0.3)
        
        recommendations = self.optimizer.get_recommendations()
        
        self.assertEqual(recommendations['status'], 'success')
        self.assertIn('top_payloads', recommendations)
        self.assertIn('average_success_rate', recommendations)
        self.assertIn('recommendations', recommendations)
        self.assertGreater(len(recommendations['recommendations']), 0)
    
    def test_export_import_stats(self):
        """Test exporting and importing statistics"""
        # Record some data
        self.optimizer.record_payload_result("payload1", success=True)
        self.optimizer.create_target_profile("http://test.com", {'db': 'mysql'})
        
        # Export
        exported = self.optimizer.export_stats()
        
        self.assertIn('payload_stats', exported)
        self.assertIn('target_profiles', exported)
        
        # Import to new optimizer
        new_optimizer = PayloadOptimizer()
        new_optimizer.import_stats(exported)
        
        self.assertIn("payload1", new_optimizer.payload_stats)
        self.assertIn("http://test.com", new_optimizer.target_profiles)
    
    def test_generate_report_no_data(self):
        """Test report generation without data"""
        report = self.optimizer.generate_report()
        
        self.assertIsInstance(report, str)
        self.assertIn('PAYLOAD OPTIMIZATION', report)
        self.assertIn('Total Payloads Tracked: 0', report)
    
    def test_generate_report_with_data(self):
        """Test report generation with data"""
        # Add payload data
        for _ in range(3):
            self.optimizer.record_payload_result("test_payload", success=True, response_time=0.5)
        
        report = self.optimizer.generate_report()
        
        self.assertIn('PAYLOAD OPTIMIZATION', report)
        self.assertIn('Total Payloads Tracked: 1', report)
        self.assertIn('Top 5 Performing', report)

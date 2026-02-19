"""
Demo: Adaptive SQL Injection Testing with 1000+ Payloads

This demo showcases the new adaptive SQL injection testing capabilities:
- Comprehensive payload library with 1772+ unique payloads
- Real-time learning and adaptive payload selection
- Fuzzy logic detection for false positive reduction
- Payload mutation based on successful patterns

Usage:
    python demo_adaptive_sqli.py

Features demonstrated:
1. Payload generation (1000+ payloads)
2. Adaptive payload selection with learning
3. Fuzzy logic detection
4. Filter behavior analysis
5. Payload mutation
"""

import logging
import sys
from sql_attacker.sqli_engine import SQLInjectionEngine
from sql_attacker.payload_generator import generate_comprehensive_payloads
from sql_attacker.adaptive_payload_selector import AdaptivePayloadSelector
from sql_attacker.fuzzy_logic_detector import FuzzyLogicDetector
from sql_attacker.payload_integration import PayloadIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def demo_payload_generation():
    """Demo: Generate comprehensive payload set"""
    print("\n" + "="*80)
    print("DEMO 1: Comprehensive Payload Generation (1000+ payloads)")
    print("="*80)
    
    logger.info("Generating comprehensive SQL injection payloads...")
    all_payloads, categorized = generate_comprehensive_payloads()
    
    print(f"\n✓ Generated {len(all_payloads)} unique payloads")
    print("\nPayload breakdown by category:")
    for category, payloads in categorized.items():
        if payloads:
            print(f"  • {category:25} {len(payloads):4} payloads")
    
    print("\nSample payloads:")
    for i, payload in enumerate(all_payloads[:10], 1):
        print(f"  {i}. {payload[:70]}..." if len(payload) > 70 else f"  {i}. {payload}")
    
    print("\n✓ Payload generation complete!")
    return all_payloads


def demo_payload_integration():
    """Demo: Payload integration system"""
    print("\n" + "="*80)
    print("DEMO 2: Payload Integration System")
    print("="*80)
    
    logger.info("Initializing payload integration system...")
    integrator = PayloadIntegration(storage_path='/tmp/demo_payloads')
    
    # Generate comprehensive payloads
    count = integrator.generate_comprehensive_payloads()
    print(f"\n✓ Integrated {count} payloads into library")
    
    # Get statistics
    stats = integrator.get_statistics()
    print(f"\nLibrary statistics:")
    print(f"  • Total payloads: {stats['total_payloads']}")
    print(f"  • Total sources: {stats['total_sources']}")
    print(f"  • Enabled sources: {stats['enabled_sources']}")
    
    print(f"\nPayloads by category:")
    for category, count in sorted(stats['payloads_by_category'].items()):
        print(f"  • {category:25} {count:4} payloads")
    
    # Get payloads by tag
    union_payloads = integrator.get_payloads_by_tag('union-based')
    time_payloads = integrator.get_payloads_by_tag('time-based')
    
    print(f"\nPayloads by technique:")
    print(f"  • UNION-based: {len(union_payloads)}")
    print(f"  • Time-based: {len(time_payloads)}")
    
    print("\n✓ Payload integration demo complete!")
    return integrator


def demo_adaptive_selector():
    """Demo: Adaptive payload selector with learning"""
    print("\n" + "="*80)
    print("DEMO 3: Adaptive Payload Selector (Real-time Learning)")
    print("="*80)
    
    from sql_attacker.adaptive_payload_selector import ResponseClass
    
    selector = AdaptivePayloadSelector(learning_rate=0.1)
    
    # Simulate testing various payloads
    test_payloads = [
        ("' OR '1'='1", ResponseClass.SUCCESS),
        ("' OR 1=1--", ResponseClass.SUCCESS),
        ("' UNION SELECT NULL--", ResponseClass.BLOCKED),
        ("admin' --", ResponseClass.SUCCESS),
        ("' AND SLEEP(5)--", ResponseClass.TIMEOUT),
        ("' OR 'x'='x", ResponseClass.ALLOWED),
    ]
    
    logger.info("Simulating payload testing with learning...")
    print("\nRecording payload attempts:")
    
    for payload, response_class in test_payloads:
        selector.record_attempt(
            payload=payload,
            response_class=response_class,
            response_time=0.1 if response_class != ResponseClass.TIMEOUT else 5.2,
            status_code=200 if response_class != ResponseClass.BLOCKED else 403,
            response_body=f"Response for {response_class.value}",
            payload_category="test"
        )
        status_icon = {
            ResponseClass.SUCCESS: "✓",
            ResponseClass.BLOCKED: "✗",
            ResponseClass.TIMEOUT: "⏱",
            ResponseClass.ALLOWED: "→",
        }.get(response_class, "?")
        print(f"  {status_icon} {payload:30} → {response_class.value}")
    
    # Get statistics
    stats = selector.get_statistics()
    print(f"\n✓ Learning statistics:")
    print(f"  • Total payloads tried: {stats['total_payloads_tried']}")
    print(f"  • Total attempts: {stats['total_attempts']}")
    print(f"  • Overall success rate: {stats['overall_success_rate']:.2%}")
    print(f"  • Block rate: {stats['block_rate']:.2%}")
    
    # Show top performing payloads
    print(f"\n✓ Top performing payloads:")
    for payload_stat in stats['top_payloads']:
        print(f"  • {payload_stat['payload']:40} {payload_stat['success_rate']:>6} ({payload_stat['successes']}/{payload_stat['attempts']})")
    
    # Generate mutations of successful payload
    print(f"\n✓ Generating mutations of successful payload...")
    mutations = selector.generate_mutations("' OR '1'='1", count=5)
    print(f"  Generated {len(mutations)} mutations:")
    for i, mutation in enumerate(mutations, 1):
        print(f"  {i}. {mutation}")
    
    # Get filter insights
    insights = selector.get_filter_insights()
    print(f"\n✓ Filter behavior insights:")
    print(f"  • Blocks quotes: {insights['characteristics']['blocks_quotes']}")
    print(f"  • Blocks comments: {insights['characteristics']['blocks_comments']}")
    print(f"  • Blocks UNION: {insights['characteristics']['blocks_union']}")
    
    if insights['recommendations']:
        print(f"\n✓ Recommendations:")
        for rec in insights['recommendations']:
            print(f"  • {rec}")
    
    print("\n✓ Adaptive selector demo complete!")
    return selector


def demo_fuzzy_logic_detection():
    """Demo: Fuzzy logic detection"""
    print("\n" + "="*80)
    print("DEMO 4: Fuzzy Logic Detection (False Positive Reduction)")
    print("="*80)
    
    detector = FuzzyLogicDetector(
        similarity_threshold=0.85,
        confidence_threshold=0.70
    )
    
    # Set baseline
    logger.info("Setting baseline response...")
    detector.set_baseline(
        status_code=200,
        headers={'content-type': 'text/html', 'server': 'nginx'},
        body="<html><body><h1>Welcome</h1><p>Normal page content</p></body></html>",
        response_time=0.1
    )
    print("✓ Baseline response set")
    
    # Test cases
    test_cases = [
        {
            'name': 'SQL Error (MySQL)',
            'status': 200,
            'body': "Error: You have an error in your SQL syntax near '1'",
            'time': 0.12,
        },
        {
            'name': 'Normal Response (Similar)',
            'status': 200,
            'body': "<html><body><h1>Welcome</h1><p>Normal page content</p></body></html>",
            'time': 0.11,
        },
        {
            'name': 'Time-based SQLi',
            'status': 200,
            'body': "<html><body><h1>Welcome</h1><p>Normal page content</p></body></html>",
            'time': 5.2,  # 5 second delay
        },
        {
            'name': 'Content Anomaly',
            'status': 200,
            'body': "<html><body><h1>Error</h1><p>Something went wrong</p></body></html>",
            'time': 0.13,
        },
    ]
    
    print("\nAnalyzing responses with fuzzy logic:")
    for i, test_case in enumerate(test_cases, 1):
        result = detector.analyze_response(
            status_code=test_case['status'],
            headers={'content-type': 'text/html', 'server': 'nginx'},
            body=test_case['body'],
            response_time=test_case['time'],
            payload="' OR 1=1--"
        )
        
        verdict_icons = {
            'vulnerable': '🔴',
            'suspicious': '🟡',
            'not_vulnerable': '🟢',
            'uncertain': '⚪',
        }
        icon = verdict_icons.get(result.verdict, '❓')
        
        print(f"\n  Test Case {i}: {test_case['name']}")
        print(f"    {icon} Verdict: {result.verdict.upper()}")
        print(f"    • Confidence: {result.confidence:.2%}")
        print(f"    • Similarity: {result.similarity_score:.2%}")
        print(f"    • Matched patterns: {len(result.matched_patterns)}")
        
        if result.anomaly_indicators:
            print(f"    • Anomalies:")
            for anomaly in result.anomaly_indicators:
                print(f"      - {anomaly}")
    
    # Get statistics
    stats = detector.get_statistics()
    print(f"\n✓ Detection statistics:")
    print(f"  • Baseline count: {stats['baseline_count']}")
    print(f"  • Response history: {stats['response_history_count']}")
    print(f"  • Similarity threshold: {stats['similarity_threshold']:.2%}")
    print(f"  • Confidence threshold: {stats['confidence_threshold']:.2%}")
    
    print("\n✓ Fuzzy logic detection demo complete!")
    return detector


def demo_integrated_testing():
    """Demo: Integrated adaptive SQL injection testing"""
    print("\n" + "="*80)
    print("DEMO 5: Integrated Adaptive SQL Injection Testing")
    print("="*80)
    
    # Note: This is a simulation - in real use, this would test against an actual target
    config = {
        'use_random_delays': False,
        'randomize_user_agent': True,
        'use_payload_obfuscation': False,
        'verify_ssl': False,
        'enable_advanced_payloads': True,
        'enable_false_positive_reduction': True,
        'enable_stealth': False,
        'enable_comprehensive_payloads': True,
        'learning_rate': 0.1,
        'similarity_threshold': 0.85,
        'confidence_threshold': 0.70,
    }
    
    logger.info("Initializing SQL injection engine with adaptive features...")
    # Note: This will take a moment to load 1700+ payloads
    print("\n⏳ Loading comprehensive payload library (1700+ payloads)...")
    
    engine = SQLInjectionEngine(config)
    
    print(f"✓ Engine initialized with:")
    print(f"  • {len(engine.payload_integration.payloads)} payloads loaded")
    print(f"  • Adaptive selector ready")
    print(f"  • Fuzzy logic detector ready")
    print(f"  • Learning rate: {config['learning_rate']}")
    
    print("\n✓ The engine is now ready for adaptive SQL injection testing!")
    print("\nKey features enabled:")
    print("  ✓ 1700+ unique payloads across all SQL dialects")
    print("  ✓ Real-time learning from response patterns")
    print("  ✓ Automatic payload mutation")
    print("  ✓ Fuzzy logic false positive reduction")
    print("  ✓ Filter behavior analysis")
    print("  ✓ Adaptive bypass techniques")
    
    print("\n✓ Integrated testing demo complete!")
    return engine


def main():
    """Run all demos"""
    print("\n" + "="*80)
    print("🚀 ADAPTIVE SQL INJECTION TESTING - COMPREHENSIVE DEMO")
    print("="*80)
    print("\nThis demo showcases the enhanced SQL injection testing capabilities:")
    print("  • 1772+ unique SQL injection payloads")
    print("  • Real-time learning and adaptation")
    print("  • Fuzzy logic detection")
    print("  • Advanced WAF bypass techniques")
    
    try:
        # Run all demos
        payloads = demo_payload_generation()
        integrator = demo_payload_integration()
        selector = demo_adaptive_selector()
        detector = demo_fuzzy_logic_detection()
        engine = demo_integrated_testing()
        
        # Summary
        print("\n" + "="*80)
        print("✓ ALL DEMOS COMPLETED SUCCESSFULLY!")
        print("="*80)
        print("\nSummary:")
        print(f"  ✓ Generated {len(payloads)} unique payloads")
        print(f"  ✓ Integrated {len(integrator.payloads)} payloads into library")
        print(f"  ✓ Adaptive selector trained with {selector.get_statistics()['total_attempts']} attempts")
        print(f"  ✓ Fuzzy detector analyzed {detector.get_statistics()['response_history_count']} responses")
        print(f"  ✓ SQL injection engine ready with all enhancements")
        
        print("\n🎯 The system is ready for advanced SQL injection testing!")
        print("   Use SQLInjectionEngine.test_adaptive_sqli() for adaptive testing.")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

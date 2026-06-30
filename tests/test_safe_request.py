#!/usr/bin/env python3
"""
test_safe_request_end_to_end.py - Submit a safe request through the proxy and verify it's logged
Run: python test_safe_request_end_to_end.py
"""
import os
import sys
import json
import time
import requests
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def test_safe_request_through_proxy():
    """Submit a safe request through the actual proxy"""
    
    # Configure proxy endpoint (adjust port if needed)
    proxy_url = "http://localhost:8000"
    test_endpoint = f"{proxy_url}/health"
    
    print("\n" + "="*70)
    print("END-TO-END SAFE REQUEST TEST")
    print("="*70)
    print(f"Target: {test_endpoint}\n")
    
    try:
        # Submit the safe request
        print("📤 Submitting safe GET request to /health...")
        response = requests.get(
            test_endpoint,
            headers={'user-agent': 'Mozilla/5.0 (test-safe-request)'},
            timeout=5
        )
        print(f"✅ Response: {response.status_code}")
        print(f"   Time: {response.elapsed.total_seconds():.3f}s\n")
        
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Could not connect to proxy at http://localhost:8000")
        print("   Make sure the proxy is running: uvicorn main:app --reload\n")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}\n")
        return False
    
    # Wait for analyzer to process
    print("⏳ Waiting for analyzer to process (5 seconds)...")
    time.sleep(5)
    
    # Check alerts.json
    alerts_file = os.path.join(os.path.dirname(__file__), '../phase2/alerts.json')
    
    if not os.path.exists(alerts_file):
        print(f"❌ Alerts file not found: {alerts_file}\n")
        return False
    
    try:
        with open(alerts_file, 'r') as f:
            alerts_data = json.load(f)
        
        alerts = alerts_data.get('alerts', [])
        print(f"📋 Total alerts in file: {len(alerts)}\n")
        
        # Look for our safe request
        found_safe_request = False
        for alert in alerts:
            req = alert.get('original_request', {})
            if req.get('path') == 'health' and 'test-safe-request' in req.get('user_agent', ''):
                found_safe_request = True
                print("✅ FOUND: Safe request recorded in alerts.json")
                print(f"   Severity: {alert.get('severity')}")
                print(f"   Timestamp: {alert.get('timestamp')}")
                print(f"   Category: {alert.get('threat_type')}")
                print(f"   Alert ID: {alert.get('alert_id')}\n")
                break
        
        if not found_safe_request:
            print("⚠️  Safe request not found in alerts (may still be processing)\n")
            print("Recent alerts:")
            for alert in alerts[-3:]:
                req = alert.get('original_request', {})
                print(f"   - {req.get('method')} {req.get('path')} (severity: {alert.get('severity')})")
        
        return found_safe_request
        
    except json.JSONDecodeError as e:
        print(f"❌ ERROR reading alerts.json: {e}\n")
        return False


if __name__ == '__main__':
    print("\n⚠️  PREREQUISITES:")
    print("   1. Proxy must be running: uvicorn main:app --reload")
    print("   2. Analyzer must be running: python phase2/analyzer.py")
    print("   3. Wait 5-10 seconds after starting for system to initialize\n")
    
    success = test_safe_request_through_proxy()
    sys.exit(0 if success else 1)

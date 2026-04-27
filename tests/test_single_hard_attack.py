#!/usr/bin/env python3
"""
Single Hard Attack Test - Tests Tier 2 Isolation Forest Detection
An attack that bypasses Tier 1 regex rules but triggers anomaly heuristics (score 4-7)
"""
import asyncio
import httpx
import sys
import os
import random
import string

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def generate_high_entropy_payload(size=100):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(size))

ATTACK = {
    "name": "Zero-Day Encoded Exploit - High Entropy Body",
    "method": "POST",
    "path": "/",
    "payload": "",
    "body": generate_high_entropy_payload(150),
    "headers": {}
}


async def main():
    proxy_url = "http://localhost:8000"

    async with httpx.AsyncClient(timeout=30.0) as client:
        print(f"\n{'='*70}")
        print(f"🎯 Testing Single Hard Attack (Tier 2 ML Detection)")
        print(f"{'='*70}")
        print(f"Attack: {ATTACK['name']}")
        print(f"Method: {ATTACK['method']}")
        print(f"Path: {ATTACK['path']}")
        print(f"Body (high entropy): {ATTACK['body'][:80]}...")
        print(f"{'='*70}\n")

        try:
            response = await client.request(
                method=ATTACK['method'],
                url=f"{proxy_url}{ATTACK['path']}{ATTACK['payload']}",
                headers=ATTACK['headers'],
                content=ATTACK['body'].encode() if ATTACK['body'] else None
            )

            print(f"✅ Response Status: {response.status_code}")
            print(f"   Content-Length: {len(response.content)}")

        except httpx.ConnectError:
            print("❌ Could not connect to proxy. Is main.py running?")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)

    print(f"\n{'='*70}")
    print("📋 Check phase2/alerts.json for Tier 2 detection result")
    print("   Expected: severity > 0, threat_type = 'zeroday' or 'anomaly'")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(main())
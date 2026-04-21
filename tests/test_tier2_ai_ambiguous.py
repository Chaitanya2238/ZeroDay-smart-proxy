#!/usr/bin/env python3
"""
Tier 2 AI Model Test - Ambiguous Threats (4-7 score range)
Tests attacks that score 4-7 in Tier 1, forwarded to Tier 2 for semantic analysis

These attacks are designed to:
1. Score 4-7 in Tier 1 (ambiguous - not obviously malicious, but suspicious)
2. Trigger Tier 2 (Gemini AI) analysis
3. Test if AI correctly classifies weak vs real threats
"""
import asyncio
import httpx
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Single ambiguous attack designed to score 4-7 in Tier 1 via ANOMALIES
# Strategy: Use ONLY one attack to avoid Gemini rate limiting (60 req/min quota)
TIER2_TEST_ATTACKS = [
    {
        "name": "Empty Root POST (score: 4)",
        "description": "POST to root path - anomaly rule triggers (empty_path_with_post)",
        "method": "POST",
        "path": "/",
        "payload": "",
        "headers": {"Content-Type": "application/json"},
        "expected_tier1_score": "4",
        "expected_tier2_action": "AI decides: Malicious root exploit or legitimate request?"
    }
]


async def send_attack(client, proxy_url, attack):
    """Send a single attack through proxy"""
    try:
        print(f"\n{'='*70}")
        print(f"🎯 Attack: {attack['name']}")
        print(f"{'='*70}")
        print(f"Description: {attack['description']}")
        print(f"Expected Tier 1 Score: {attack['expected_tier1_score']}")
        print(f"Expected Tier 2 Action: {attack['expected_tier2_action']}")
        print(f"Method: {attack['method']}")
        
        target_url = f"{proxy_url}{attack['path']}{attack['payload']}"
        print(f"URL: {target_url[:100]}...")
        
        # Handle POST vs GET
        if attack['method'] == 'POST':
            response = await client.post(target_url, headers=attack['headers'], content="")
        else:
            response = await client.get(target_url, headers=attack['headers'])
        
        print(f"Response Status: {response.status_code}")
        print(f"✅ Payload delivered to proxy")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False


async def test_tier2_ambiguous_attacks():
    """Run Tier 2-specific attacks (4-7 score range)"""
    
    proxy_url = "http://localhost:8000"
    
    print("\n" + "="*70)
    print("TIER 2 AI MODEL TEST - Ambiguous Threat Detection")
    print("="*70)
    print("\nTest Objectives:")
    print("  1. Send attacks that score 4-7 in Tier 1 (ambiguous)")
    print("  2. Verify Tier 2 (Gemini AI) is triggered")
    print("  3. Evaluate if AI correctly classifies threats")
    print("\nExpected Flow:")
    print("  Tier 1: Scores 4-7 → 'SUSPICIOUS' category")
    print("  Tier 2: AI analyzes → 'REAL_THREAT' or 'FALSE_POSITIVE'")
    print("\nCheck alerts.json for Tier 2 results with AI reasoning")
    print("\nNOTE: Using 1 attack only to avoid Gemini rate limiting (60 req/min)")
    print("      Exponential backoff: 3s, 6s, 12s, 24s (up to 45s total if rate limited)")
    
    async with httpx.AsyncClient() as client:
        results = []
        for i, attack in enumerate(TIER2_TEST_ATTACKS, 1):
            success = await send_attack(client, proxy_url, attack)
            results.append({
                "attack": attack['name'],
                "delivered": success
            })
    
    # Summary
    print("\n" + "="*70)
    print("ATTACK DELIVERY SUMMARY")
    print("="*70)
    delivered = sum(1 for r in results if r['delivered'])
    print(f"\n✅ {delivered}/{len(TIER2_TEST_ATTACKS)} attacks delivered successfully")
    
    print("\nNext Steps:")
    print("  1. Wait 50 seconds for analyzer to process and Tier 2 to respond")
    print("     (Tier 2 may retry: 3s, 6s, 12s, 24s if rate limited)")
    print("  2. Check phase2/alerts.json for results")
    print("  3. Verify 'analyzed_by_ai': 1 in phase2/statistics.json")
    print("  4. Verify 'threat_type' is NOT 'API_RATE_LIMITED' (AI should respond)")
    print("  5. Look for Gemini's reasoning about POST to / exploit")


if __name__ == '__main__':
    asyncio.run(test_tier2_ambiguous_attacks())

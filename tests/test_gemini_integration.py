#!/usr/bin/env python3
"""
Test script to verify Gemini API integration works correctly.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phase2.ai_engine import AISecurityAnalyzer

async def test_gemini_integration():
    """Test that Gemini API integration works with the provided key"""
    
    # Use the API key from environment variable
    api_key = os.getenv('GOOGLE_API_KEY')
    
    if not api_key:
        print("=" * 70)
        print("❌ No GOOGLE_API_KEY found!")
        print("=" * 70)
        print("\nSet the environment variable:")
        print("  $env:GOOGLE_API_KEY = 'your-api-key-here'")
        print("\nOr create a .env file in the smart-proxy directory with:")
        print("  GOOGLE_API_KEY=your-api-key-here")
        return False
    
    print("=" * 70)
    print("🧪 Testing Google Gemini Integration")
    print("=" * 70)
    
    try:
        # Initialize the analyzer with provided API key
        analyzer = AISecurityAnalyzer(api_key=api_key)
        print("✅ AISecurityAnalyzer initialized with Gemini API")
        
        # Test with a sample request
        test_request = {
            'method': 'POST',
            'path': '/api/upload',
            'request_body_preview': "{'file': 'test.txt'}",
            'headers': {'user-agent': 'Mozilla/5.0'},
            'client_ip': '203.0.113.1',
            'response_status': 200,
            'response_time_ms': 150
        }
        
        print("\n📤 Sending test request to Gemini API...")
        print(f"   Method: {test_request['method']}")
        print(f"   Path: {test_request['path']}")
        
        # Call analyze method
        result = await analyzer.analyze(test_request)
        
        print("\n✅ Received response from Gemini API:")
        print(f"   Severity: {result.get('severity')}/10")
        print(f"   Threat Type: {result.get('threat_type')}")
        print(f"   Confidence: {result.get('confidence'):.2f}")
        print(f"   Reasoning: {result.get('reasoning')[:100]}...")
        
        # Verify response structure
        required_fields = ['severity', 'threat_type', 'confidence', 'reasoning', 'recommended_action']
        missing_fields = [f for f in required_fields if f not in result]
        
        if missing_fields:
            print(f"\n❌ Missing fields in response: {missing_fields}")
            return False
        
        # Get stats
        stats = analyzer.get_stats()
        print("\n📊 Usage Statistics:")
        print(f"   Requests analyzed: {stats['requests_analyzed']}")
        print(f"   API Provider: {stats['api_provider']}")
        print(f"   Estimated cost: ${stats['estimated_cost_usd']}")
        
        await analyzer.close()
        
        print("\n✅ Gemini integration test PASSED!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error during Gemini integration test:")
        print(f"   {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = asyncio.run(test_gemini_integration())
    exit(0 if success else 1)

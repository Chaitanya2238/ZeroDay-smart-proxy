#!/usr/bin/env python3
"""
Test to check if the Google Gemini API key works at all.
"""
import asyncio
import httpx

async def test_api_key():
    """Test if the API key is valid"""
    api_key = "AIzaSyB3fSb9XX2yOlgOwjkkzN1ebjNUYGKFO0s"
    
    print("=" * 70)
    print("🔍 Testing Google Gemini API Key")
    print("=" * 70)
    
    # Try to list available models
    url = f"https://generativelanguage.googleapis.com/v1/models?key={api_key}"
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            print(f"\n📡 Calling: {url}")
            response = await client.get(url)
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                models = response.json()
                print(f"\n✅ API Key is valid!")
                print(f"   Available models:")
                for model in models.get('models', []):
                    print(f"   - {model.get('name')}")
            else:
                print(f"\n❌ API Key seems invalid or doesn't have access")
                print(f"   Response: {response.text[:200]}")
        except Exception as e:
            print(f"\n❌ Error: {e}")

if __name__ == '__main__':
    asyncio.run(test_api_key())

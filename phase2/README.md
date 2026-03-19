# Phase 2: Nervous System - AI-Driven Threat Detection

## Overview

Phase 2 adds an "out-of-band" security analysis system that continuously monitors `proxy.log` for potential zero-day exploits and anomalous traffic patterns. It uses a two-tier approach:

1. **Tier 1 (Rules)**: Fast regex-based filtering to eliminate 90% of normal traffic
2. **Tier 2 (AI/LLM)**: Semantic analysis using OpenAI GPT for ambiguous threats

---

## Architecture

```
proxy.log (from Phase 1)
    ↓
analyzer.py (reads continuously)
    ↓
    ├─→ Tier 1: rules.py (fast filtering)
    │        ├─ Static Signatures (SQLi, XSS, etc)
    │        ├─ Anomaly Heuristics
    │        └─ Pass Rules (ignore normal traffic)
    │
    ├─→ Tier 2: ai_engine.py (LLM analysis)
    │        └─ OpenAI GPT semantic analysis
    │
    ├─→ StatisticsTracker (metrics)
    │
    └─→ alerts.json (threats)
```

---

## Installation

### 1. Install Phase 2 Dependencies

```powershell
cd D:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy
pip install -r phase2/requirements.txt
```

### 2. Configure OpenAI API Key

```powershell
# Set environment variable (Windows)
$env:OPENAI_API_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxx"

# Or create .env file in smart-proxy directory
echo "OPENAI_API_KEY=sk_live_xxxxxxxxxxxxxxxxxxxx" > .env
```

---

## Usage

### Quick Start

```powershell
# From smart-proxy directory
cd D:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy

# Run analyzer (will continuously monitor proxy.log)
python -m phase2.analyzer
```

### Advanced Usage

```python
# From Python code
from phase2 import SecurityAnalyzerPipeline

# Create pipeline
pipeline = SecurityAnalyzerPipeline(
    proxy_log='proxy.log',
    check_interval=5  # Check every 5 seconds
)

# Run analyzer
pipeline.run()
```

---

## How It Works

### Request Flow

```
1. Proxy receives request
   └─ Logs to proxy.log (JSON line)

2. Analyzer (every 5 seconds)
   ├─ Read new lines from proxy.log
   └─ For each request:
      ├─ TIER 1: SecurityRules.analyze()
      │  ├─ Check static signatures (regex patterns)
      │  ├─ Check anomaly heuristics
      │  ├─ Check pass rules (ignore normal)
      │  └─ Return severity score (0-10)
      │
      ├─ TIER 2: If severity 4-7 (ambiguous)
      │  ├─ Send to OpenAI GPT
      │  ├─ AI analyzes semantic meaning
      │  └─ Return threat verdict
      │
      └─ If severity >= 7
         └─ Create ALERT → save to alerts.json
```

### Tier 1: Static Signatures (rules.py)

**Detected attacks:**

- SQL Injection (`' OR '1'='1`, `UNION SELECT`)
- XSS (`<script>`, `onerror=`)
- Command Injection (`; rm -rf`, `| cat`)
- Path Traversal (`../`, `\windows\`)
- LDAP Injection (`${jndi:`)
- XXE (`<!ENTITY`, `<!DOCTYPE`)

**Anomaly heuristics:**

- Missing User-Agent
- Known scanner User-Agents
- Response size > 1MB
- Health endpoint with large body
- Response time > 5 seconds
- Server errors (5xx)

**Pass rules (ignored):**

- Health checks (GET /health)
- Browser requests (GET with Chrome/Firefox UA)
- Static files (.js, .css, .png)

### Tier 2: AI Semantic Analysis (ai_engine.py)

**Uses:** OpenAI GPT-3.5-turbo (or GPT-4)

**Analyzes for:**

- Zero-Day logic flaws
- Polyglot payloads
- Encoding/obfuscation tricks
- Template injection
- Unusual API patterns

**Returns:**

```json
{
  "severity": 8,
  "threat_type": "JNDI_Injection",
  "confidence": 0.92,
  "is_zerodday": true,
  "reasoning": "Detected JNDI LDAP pattern with external IP",
  "recommended_action": "block"
}
```

---

## Output Files

### alerts.json

Detected threats with full context

```json
{
  "alerts": [
    {
      "alert_id": 1,
      "timestamp": "2026-03-18T14:32:15.123456",
      "severity": 8,
      "threat_type": "SQLi_OR_ZeroDay",
      "confidence": 0.85,
      "original_request": {...},
      "tier1_analysis": {...},
      "tier2_analysis": {...},
      "recommended_action": "block"
    }
  ]
}
```

### statistics.json

Real-time metrics

```json
{
  "total_requests_processed": 1523,
  "requests_by_status": {
    "passed_tier1": 1401,
    "flagged_tier1": 98,
    "analyzed_by_ai": 24,
    "threat_detected": 3
  },
  "threats_by_type": {
    "sql_injection": 1,
    "xss_attempt": 1,
    "unknown_payload": 1
  }
}
```

### analyzer_state.json

Tracks last log position (for efficient tailing)

```json
{
  "last_position": 12847,
  "last_update": "2026-03-18T15:00:00"
}
```

### phase2_analyzer.log

Detailed debug logs

---

## Cost Estimation

**Per 1000 requests:**

| Scenario       | Tier 1 Only | With Tier 2 | Tier 2 Cost                |
| -------------- | ----------- | ----------- | -------------------------- |
| Normal traffic | Free        | $0.03       | 100 AI requests × $0.0003  |
| Peak traffic   | Free        | $0.30       | 1000 AI requests × $0.0003 |

**Assumptions:**

- Tier 1 filters 90% of normal traffic
- Tier 2 costs ~$0.0003 per request (GPT-3.5)
- Average ~150 tokens per analysis request

---

## Testing

### Test Tier 1 Only

```python
from phase2.rules import SecurityRules
import json

# Test SQLi detection
test_request = {
    'method': 'POST',
    'path': 'api/users',
    'request_body_preview': "{'id': ' OR '1'='1'}",
    'headers': {'user-agent': 'Mozilla/5.0'},
}

result = SecurityRules.analyze(test_request)
print(json.dumps(result, indent=2))

# Output: severity >= 8 (known threat)
```

### Test Tier 2 Analysis

```python
import asyncio
from phase2.ai_engine import AISecurityAnalyzer

async def test():
    analyzer = AISecurityAnalyzer()

    test_request = {
        'method': 'POST',
        'path': 'api/process',
        'request_body_preview': "{ 'data': '${jndi:ldap://...}' }",
        'headers': {'user-agent': 'Mozilla/5.0'},
        'client_ip': '203.0.113.45',
        'response_status': 200,
    }

    result = await analyzer.analyze(test_request)
    print(json.dumps(result, indent=2))

    await analyzer.close()

asyncio.run(test())
```

---

## Troubleshooting

### "OpenAI API key not found"

```powershell
# Set environment variable
$env:OPENAI_API_KEY = "your-key-here"

# Or create .env file
```

### Slow analysis?

- Tier 1 should process requests instantly
- Tier 2 adds ~1-2 seconds per request (network + LLM)
- Increase check_interval if too aggressive

### High costs?

- Tier 1 is filtering out too many requests (should be 90%+)
- Consider using local LLM (Ollama) instead of OpenAI

### Log not updating?

- Check proxy.log path is correct
- Ensure Phase 1 proxy is still running
- Check analyzer_state.json file permissions

---

## Next Steps

1. **Run analyzer with test data** (see Testing section)
2. **Monitor alerts.json** for detections
3. **Tune Tier 1 rules** based on false positives
4. **Integrate with alerting system** (email, Slack, etc)
5. **Phase 3**: Add response/blocking mechanism

---

## Files Reference

| File                  | Purpose                                |
| --------------------- | -------------------------------------- |
| `rules.py`            | Tier 1: Static signatures & heuristics |
| `ai_engine.py`        | Tier 2: OpenAI LLM integration         |
| `analyzer.py`         | Main coordinator & log tailing         |
| `__init__.py`         | Package initialization                 |
| `alerts.json`         | Detected threats (output)              |
| `statistics.json`     | Metrics & stats (output)               |
| `analyzer_state.json` | Log position tracking (internal)       |
| `phase2_analyzer.log` | Debug logs (output)                    |

---

**Phase 2 is ready!** 🚀

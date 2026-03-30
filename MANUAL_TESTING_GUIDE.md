# Manual Testing Guide - Zero-Day Attack Detection

## Issues I Faced & Solutions

### **Issue 1: httpx.AsyncClient proxy parameter doesn't exist**

**Error:**

```
TypeError: AsyncClient.__init__() got an unexpected keyword argument 'proxies'
```

**Root Cause:**

- Old documentation used `proxies` parameter
- Modern httpx doesn't support it

**Solution:**

- Don't use `proxies` parameter
- Instead, send requests directly to proxy URL (http://localhost:8000)
- Backend forwarding handled by proxy itself

---

### **Issue 2: Analyzer looking for wrong log file path**

**Error:**

```
WARNING - Log file not found: ../proxy.log
```

**Root Cause:**

- Analyzer script runs from `smart-proxy/` directory
- Used relative path `../proxy.log` (goes up one level)
- Correct path is `proxy.log` (same directory)

**Solution:**

```bash
# Run analyzer WITH correct path argument
python -m phase2.analyzer proxy.log    # ✅ CORRECT
python -m phase2.analyzer ../proxy.log # ❌ WRONG
```

---

### **Issue 3: POST requests mixing payload with URL**

**Error:**

```
URL: http://localhost:8000/api/comments{"text": ...}
```

**Root Cause:**

- POST requests were concatenating payload to path
- Should only use path for URL, payload is in request body

**Solution:**

```python
# WRONG - for POST
target_url = f"{proxy_url}{attack['path']}{attack['payload']}"

# CORRECT - for POST
target_url = f"{proxy_url}{attack['path']}"
response = await client.post(target_url, content=attack['payload'])
```

---

### **Issue 4: All services failing silently**

**Error:**

```
All connection attempts failed (for all 20 attacks)
```

**Root Cause:**

- Services weren't starting properly
- `python main.py` doesn't work - FastAPI needs uvicorn
- `python mock_backend.py` crashed silently

**Solution:**

```bash
# Use uvicorn explicitly
uvicorn main:app --host localhost --port 8000 --reload

# Use full path for mock backend
python .\mock_backend.py

# Set API key before running analyzer
$env:GOOGLE_API_KEY = 'your-key'
```

---

## Complete Manual Testing Guide

### **STEP 0: Auto-Load API Key from .env (Optional but Recommended)**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'

# Option A: Use load_env.ps1 script (if it exists)
.\load_env.ps1

# Option B: Manual one-liner
(Get-Content .env) | ForEach-Object { if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2]) } }

# Verify it loaded
Write-Host "API Key loaded: $env:GOOGLE_API_KEY"
```

---

### **STEP 1: Prepare Environment**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'

# Set encoding for UTF-8 output
$env:PYTHONIOENCODING='utf-8'

# API key is already loaded from .env in STEP 0
# (or manually set above if not using .env)
```

---

### **STEP 2: Start Services (3 PowerShell Terminals)**

#### **Terminal 1 - Mock Backend (Port 3000)**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
python .\mock_backend.py
```

**Expected Output:**

```
======================================================================
🖥️  MOCK BACKEND STARTED
======================================================================
Running on: http://localhost:3000
Press Ctrl+C to stop
======================================================================
```

✅ If you see this, mock backend is running successfully.

---

#### **Terminal 2 - Reverse Proxy (Port 8000)**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
$env:PYTHONIOENCODING='utf-8'
uvicorn main:app --host localhost --port 8000 --reload
```

**Expected Output:**

```
INFO:     Uvicorn running on http://localhost:8000
INFO:     Application startup complete
```

✅ If you see this, proxy is running successfully.

---

#### **Terminal 3 - Security Analyzer (Monitoring)**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
$env:PYTHONIOENCODING='utf-8'
# API key already loaded from .env (from STEP 0)
python -m phase2.analyzer proxy.log
```

**Expected Output:**

```
2026-03-30 11:42:28,779 - __main__ - INFO - Starting Phase 2 Analyzer for: proxy.log
2026-03-30 11:42:28,779 - __main__ - INFO - SecurityAnalyzerPipeline initialized (check_interval=5s)
2026-03-30 11:42:28,779 - __main__ - INFO - Starting analyzer loop...
```

✅ If analyzer is running, it will monitor proxy.log every 5 seconds.

---

### **STEP 3: Send Attack Payloads (Terminal 4 - New)**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
$env:PYTHONIOENCODING='utf-8'
# API key already loaded from .env (from STEP 0)
python .\tests\test_reallife_zeroday.py
```

**Expected Output:**

```
======================================================================
🚀 ZERO-DAY ATTACK DETECTION TEST
======================================================================
Proxy: http://localhost:8000
Target Backend: http://localhost:3000
Attacks to simulate: 20
======================================================================

🎯 Attack: SQL Injection - Classic
Method: GET
URL: http://localhost:8000/api/users?id=1' OR '1'='1' --...
Response Status: 200
✅ Attack payload delivered!

[... 19 more attacks ...]

📊 ATTACK SIMULATION SUMMARY
======================================================================
✅ Successful: 20/20
❌ Failed: 0/20
```

---

### **STEP 4: Monitor Results While Test Runs**

**In Terminal 3 (Analyzer), you should see:**

```
2026-03-30 11:49:40,003 - __main__ - INFO - Processing 3 new log entries
2026-03-30 11:49:45,053 - __main__ - INFO - Processing 7 new log entries
2026-03-30 11:49:45,053 - __main__ - WARNING - THREAT DETECTED: KNOWN_THREAT (severity=8)
2026-03-30 11:49:45,053 - __main__ - WARNING - THREAT DETECTED: KNOWN_THREAT (severity=9)
2026-03-30 11:49:50,076 - __main__ - INFO - Sending to Tier 2 (AI):
```

✅ This means threats are being detected!

---

### **STEP 5: Check Results After Test (Terminal 4 or New)**

#### **A. View Proxy Logs (all requests logged)**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
Get-Content proxy.log -Tail 30
```

**Expected Output:**

```json
{"timestamp": "2026-03-30T11:49:37.479677", "method": "GET", "path": "api/users", "query": "id=1%27+OR+%271%27%3D%271%27+--", ...}
{"timestamp": "2026-03-30T11:49:38.362136", "method": "GET", "path": "api/search", "query": "q=test%27+UNION+...", ...}
```

Each line = one request logged

---

#### **B. View Detected Threats**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
$alerts = Get-Content phase2/alerts.json -Raw | ConvertFrom-Json
$alerts.alerts | Format-Table threat_type, severity, confidence -AutoSize
```

**Expected Output:**

```
threat_type       severity confidence
-----------       -------- ----------
KNOWN_THREAT             8          0
KNOWN_THREAT             9          0
...
```

---

#### **C. View Detection Statistics**

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
Get-Content phase2/statistics.json | ConvertFrom-Json | Format-Table -AutoSize
```

**Expected Output:**

```
session_start              total_requests_processed requests_by_status
-------------              ----------------------   ------------------
2026-03-30T11:42:28       20                       @{passed_tier1=x; flagged_tier1=y; ...}
```

---

## Manual Testing Individual Attacks

Instead of running all 20 attacks, you can test one-by-one:

### **Test 1: SQL Injection**

```powershell
$uri = "http://localhost:8000/api/users?id=1' OR '1'='1' --"
Invoke-WebRequest -Uri $uri -UseBasicParsing
```

**Check analyzer Terminal:** Should see threat detection

### **Test 2: XSS Attack**

```powershell
$uri = "http://localhost:8000/search?q=<script>alert('XSS')</script>"
Invoke-WebRequest -Uri $uri -UseBasicParsing
```

### **Test 3: Path Traversal**

```powershell
$uri = "http://localhost:8000/api/file?file=../../../etc/passwd"
Invoke-WebRequest -Uri $uri -UseBasicParsing
```

### **Test 4: Command Injection**

```powershell
$uri = "http://localhost:8000/api/ping?host=localhost; cat /etc/passwd"
Invoke-WebRequest -Uri $uri -UseBasicParsing
```

Each one will be logged and analyzed!

---

## Troubleshooting Manual Testing

| Problem                      | Solution                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------ |
| **Mock backend won't start** | Check port 3000 is free: `netstat -ano \| findstr :3000`                       |
| **Proxy connection refused** | Make sure uvicorn is running, not `python main.py`                             |
| **Analyzer not detecting**   | Check: 1) API key set, 2) proxy.log path correct, 3) analyzer terminal running |
| **No alerts generated**      | Wait 5+ seconds - analyzer checks every 5 seconds                              |
| **404 errors**               | Make sure all 3 services running (mock backend, proxy, analyzer)               |
| **API rate limited**         | Gemini has 60 req/min limit - space out attacks or use Tier 1 only             |

---

## Understanding Output

### **What does each file contain?**

**proxy.log:**

```json
{
  "timestamp": "2026-03-30T11:49:37.479677",
  "method": "GET",
  "path": "api/users",
  "query": "id=1%27+OR+%271%27%3D%271%27+--",   ← SQL Injection payload
  "client_ip": "127.0.0.1",
  "response_status": 200,
  "response_time_ms": 338.179
}
```

**→ All requests pass through proxy**

---

**phase2/alerts.json:**

```json
{
  "alert_id": 1,
  "severity": 8,
  "threat_type": "KNOWN_THREAT",
  "confidence": 0,
  "tier1_analysis": {
    "severity": 8,
    "category": "KNOWN_THREAT",
    "triggered_rules": ["SQL_INJECTION_PATTERN"]
  },
  "tier2_analysis": {}
}
```

**→ Only threats with severity >= 7 create alerts**

---

**phase2/statistics.json:**

```json
{
  "total_requests_processed": 20,
  "requests_by_status": {
    "passed_tier1": 0,        ← Normal requests
    "flagged_tier1": 20,      ← Suspicious requests
    "analyzed_by_ai": 3,      ← Sent to Gemini
    "threat_detected": 2      ← Final threats
  }
}
```

**→ Summary of detection statistics**

---

## Quick Reference: Commands to Copy-Paste

**FIRST TIME ONLY:** Load API key from .env

```powershell
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy'
(Get-Content .env) | ForEach-Object { if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2]) } }
Write-Host "✅ API Key loaded"
```

**THEN START SERVICES:**

```powershell
# Terminal 1 - Start Mock Backend
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy' ; python .\mock_backend.py

# Terminal 2 - Start Proxy
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy' ; $env:PYTHONIOENCODING='utf-8' ; uvicorn main:app --host localhost --port 8000 --reload

# Terminal 3 - Start Analyzer (API key already set)
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy' ; $env:PYTHONIOENCODING='utf-8' ; python -m phase2.analyzer proxy.log

# Terminal 4 - Run Tests (API key already set)
cd 'd:\AI_Driven_ReverseProxy_with_HostLogMonitoring\smart-proxy' ; $env:PYTHONIOENCODING='utf-8' ; python .\tests\test_reallife_zeroday.py

# Check Results
Get-Content proxy.log -Tail 20
Get-Content phase2/alerts.json
Get-Content phase2/statistics.json
```

---

## What to Expect

✅ **Success Indicators:**

- All 20 attacks show: `✅ Attack payload delivered!`
- Analyzer Terminal shows: `THREAT DETECTED`
- alerts.json contains threat entries
- statistics.json shows: total_requests_processed = 20

❌ **Issues Mean:**

- Connection failed = services not running
- No alerts = analyzer not running or wrong path
- 429 errors = Gemini API rate limited (normal, Tier 1 still works)

---

Done! You can now run manual tests anytime. 🚀

# Tier 1 & Tier 2 Detection Flow

## How Threats Are Scored & Analyzed

### Tier 1 Scoring (Rule-Based)

Analyzer uses 446 regex patterns to identify known threats.

**Score Assignment:**

- SQL Injection, XSS, Command Injection: **8-9** (HIGH confidence)
- XXE, LDAP: **9** (VERY HIGH confidence)
- Path Traversal, File Inclusion, Privilege Escalation: **7** (HIGH confidence)
- Buffer Overflow, NoSQL Injection, CRLF: **7** (HIGH confidence)
- Scanner Detection: **5** (MEDIUM confidence)
- Other anomalies: **4-6** (LOW to MEDIUM confidence)

### Decision Tree

```
Request arrives
    ↓
Tier 1: Check regex patterns
    ↓
├─ Score > 7: KNOWN_THREAT (HIGH confidence)
│  └─ ✅ CREATE ALERT IMMEDIATELY
│  └─ ❌ SKIP Tier 2 (no need for AI)
│  └─ Example: SQL Injection, XSS detected
│
├─ Score 4-7: SUSPICIOUS (AMBIGUOUS)
│  └─ ⚠️  SEND TO TIER 2 (AI verification)
│  └─ Gemini analyzes context
│  └─ Example: Buffer Overflow pattern detected
│
└─ Score < 4: NORMAL
   └─ ❌ NO ALERT
   └─ Normal traffic passes through
```

### Examples

#### Example 1: SQL Injection (Score = 9)

```
Request: /api/users?id=1' OR '1'='1' --
Tier 1: Detects SQL_INJECTION pattern → Score 9 (VERY HIGH)
Decision: requires_ai = False
Action: ✅ CREATE ALERT IMMEDIATELY (no Tier 2 needed)
Reason: Signature match is definitive
```

#### Example 2: Buffer Overflow (Score = 7)

```
Request: POST /api/data with 10,000 A's
Tier 1: Detects overflow pattern → Score 7 (HIGH)
Decision: requires_ai = True (borderline)
Action: ⚠️ SEND TO TIER 2
Tier 2: LLM analyzes context → Confirms threat
```

#### Example 3: Normal Request (Score = 0)

```
Request: /api/users/123
Tier 1: No patterns match → Score 0
Decision: requires_ai = False
Action: ❌ NO ALERT (normal traffic)
```

---

## Why Two Tiers?

**Tier 1 (Rules):** Fast, deterministic, but can miss novel attacks

- ✅ Instant detection
- ✅ Known threats caught
- ❌ Can't handle zero-days

**Tier 2 (AI):** Slow, contextual, catches novel patterns

- ✅ Detects logical flaws
- ✅ Understands context
- ⚠️ Rate limited (60 req/min free tier)
- ⚠️ Subject to hallucinations

**Solution:** Only use Tier 2 when Tier 1 is uncertain (4-7 score)

---

## Analyzer Logs Example

```
Tier 1 analysis: /api/users → severity=9, requires_ai=False
Tier 1 confidence high (score=9) → Skipping Tier 2
THREAT DETECTED: KNOWN_THREAT (severity=9)  ← Alert created

---

Tier 1 analysis: /api/data → severity=7, requires_ai=True
Sending to Tier 2 (AI): /api/data (Score 7 is ambiguous)
Tier 2 result: severity=8
THREAT DETECTED: KNOWN_THREAT (severity=8)  ← Alert created

---

Tier 1 analysis: /health → severity=0, requires_ai=False
(No alert - normal traffic)
```

---

## Current Config (March 30, 2026)

- **Alert Threshold:** >= 4 (all detections create alerts)
- **Tier 2 Range:** 4 <= score <= 7
- **High Confidence:** > 7
- **Attack Signatures:** 446 patterns
- **Gemini Model:** gemini-2.0-flash (free tier: 60 req/min)

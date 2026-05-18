# main.py
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware  # ✨ NEW IMPORT
import httpx
import json
import logging
import os  # ✨ NEW IMPORT
import re
from datetime import datetime
from urllib.parse import urlparse
from phase2.rules import SecurityRules
from phase2.tier2_inference import Tier2AI

# Configure logging - console only
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Smart Proxy")

# ✨ NEW: CORS Configuration
# This allows your React frontend to make requests to this backend without browser security errors.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for local development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a reusable HTTPX client
client = httpx.AsyncClient(timeout=30.0)
tier2_analyzer = None


def get_tier2_analyzer():
    global tier2_analyzer
    if tier2_analyzer is None:
        tier2_analyzer = Tier2AI()
    return tier2_analyzer


def load_json_file(path, fallback):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return fallback


def save_json_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def severity_to_action(severity):
    if severity >= 7:
        return "block"
    if severity >= 4:
        return "investigate"
    return "allow"


def build_manual_log_entry(payload, request, fetched_content=None, response_status=200, response_headers=None, scan_type="manual"):
    content = str(payload.get("content", "")).strip()
    parsed_url = urlparse(content if "://" in content else "")
    path = parsed_url.path.lstrip("/") if parsed_url.netloc else f"manual/{scan_type}"
    query = parsed_url.query if parsed_url.netloc else ""

    body_preview = fetched_content if fetched_content is not None else content

    return {
        "timestamp": datetime.now().isoformat(),
        "method": "MANUAL_GET" if scan_type == "website" else "MANUAL",
        "path": path or parsed_url.netloc or f"manual/{scan_type}",
        "query": query,
        "client_ip": request.client.host if request.client else "manual",
        "user_agent": "manual-dashboard-input",
        "headers": response_headers if response_headers else {
            "source": "manual-dashboard-input",
            "scan_type": scan_type,
            "target": payload.get("target", ""),
        },
        "response_status": response_status,
        "response_time_ms": 0,
        "request_body_preview": body_preview[:2000],
        "response_size": len(body_preview.encode("utf-8", errors="ignore")),
    }


def apply_manual_package_rules(content, scan_type, tier1_result):
    if scan_type != "packages":
        return tier1_result

    lowered = content.lower()
    package_rules = [
        ("log4j_core_log4shell", r"(log4j-core|org\.apache\.logging\.log4j)[^\n\r]{0,80}(2\.(0|1[0-6])(\.|\"|'))", 10),
        ("apache_struts_legacy", r"(struts2-core|org\.apache\.struts)[^\n\r]{0,80}(2\.[0-5]\.)", 9),
        ("lodash_prototype_pollution", r"lodash[^\n\r]{0,80}(4\.17\.(0|1[0-9]|20)(\"|'|\s|,))", 8),
        ("jquery_legacy_xss", r"jquery[^\n\r]{0,80}([\"']?[12]\.|3\.[0-4]\.)", 7),
        ("spring4shell_indicator", r"(spring-core|spring-webmvc)[^\n\r]{0,80}(5\.3\.(0|1[0-7])|5\.2\.)", 8),
        ("django_legacy_security", r"django[^\n\r]{0,80}([\"']?[12]\.|3\.[0-1]\.)", 7),
        ("express_legacy_dependency", r"express[^\n\r]{0,80}([\"']?[0-3]\.)", 6),
        ("debug_legacy_redos", r"debug[^\n\r]{0,80}([\"']?[0-2]\.)", 6),
    ]

    triggered = []
    package_score = 0
    import re
    for rule_name, pattern, score in package_rules:
        if re.search(pattern, lowered):
            triggered.append(f"package_vulnerability:{rule_name}")
            package_score = max(package_score, score)

    if not triggered:
        return tier1_result

    updated = dict(tier1_result)
    updated["triggered_rules"] = tier1_result.get("triggered_rules", []) + triggered
    updated["manual_package_score"] = package_score
    updated["severity"] = max(tier1_result.get("severity", 0), package_score)
    updated["category"] = "KNOWN_VULNERABLE_PACKAGE" if updated["severity"] >= 8 else "SUSPICIOUS_PACKAGE"
    updated["reason"] = f"{tier1_result.get('reason', '')}, Package indicators: {len(triggered)}"
    updated["requires_ai"] = 4 <= updated["severity"] <= 7
    return updated


def create_manual_alert(log_entry, tier1_result, tier2_result, severity):
    alerts_path = os.path.join(os.path.dirname(__file__), "phase2", "alerts.json")
    current_alerts = load_json_file(alerts_path, {"alerts": []}).get("alerts", [])

    return {
        "alert_id": len(current_alerts) + 1,
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "threat_type": tier2_result.get("threat_type", tier1_result["category"]) if tier2_result else tier1_result["category"],
        "confidence": tier2_result.get("confidence", 0.0) if tier2_result else 0.0,
        "original_request": {
            "method": log_entry.get("method"),
            "path": log_entry.get("path"),
            "body_preview": log_entry.get("request_body_preview"),
            "client_ip": log_entry.get("client_ip"),
            "user_agent": log_entry.get("user_agent"),
            "response_status": log_entry.get("response_status"),
        },
        "tier1_analysis": tier1_result,
        "tier2_analysis": tier2_result or {},
        "recommended_action": tier2_result.get("recommended_action") if tier2_result else severity_to_action(severity),
        "source": "manual_input",
    }


def update_manual_statistics(log_entry, tier1_result, tier2_result):
    stats_path = os.path.join(os.path.dirname(__file__), "phase2", "statistics.json")
    stats = load_json_file(stats_path, {
        "session_start": datetime.now().isoformat(),
        "total_requests_processed": 0,
        "requests_by_status": {
            "passed_tier1": 0,
            "flagged_tier1": 0,
            "analyzed_by_ai": 0,
            "threat_detected": 0,
        },
        "threats_by_type": {},
        "top_attacking_ips": {},
    })

    stats["total_requests_processed"] = stats.get("total_requests_processed", 0) + 1
    status_counts = stats.setdefault("requests_by_status", {})
    if tier1_result["severity"] == 0:
        status_counts["passed_tier1"] = status_counts.get("passed_tier1", 0) + 1
    else:
        status_counts["flagged_tier1"] = status_counts.get("flagged_tier1", 0) + 1

    final_severity = tier2_result.get("severity", tier1_result["severity"]) if tier2_result else tier1_result["severity"]
    if tier2_result:
        status_counts["analyzed_by_ai"] = status_counts.get("analyzed_by_ai", 0) + 1
    if final_severity >= 4:
        status_counts["threat_detected"] = status_counts.get("threat_detected", 0) + 1
        threat_type = tier2_result.get("threat_type", tier1_result["category"]) if tier2_result else tier1_result["category"]
        threats_by_type = stats.setdefault("threats_by_type", {})
        threats_by_type[threat_type] = threats_by_type.get(threat_type, 0) + 1

        client_ip = log_entry.get("client_ip", "manual")
        attacking_ips = stats.setdefault("top_attacking_ips", {})
        attacking_ips.setdefault(client_ip, {"count": 0, "threats": []})
        attacking_ips[client_ip]["count"] += 1
        attacking_ips[client_ip]["threats"].append(threat_type)

    save_json_file(stats_path, stats)

# ✨ NEW: The Frontend Integration Endpoint
# MUST be placed before the catch-all proxy route!
@app.get("/api/alerts")
async def get_alerts():
    """Serves the alerts.json file to the React dashboard"""
    try:
        alerts_path = os.path.join(os.path.dirname(__file__), "phase2", "alerts.json")
        if os.path.exists(alerts_path):
            with open(alerts_path, "r") as f:
                return json.load(f)
        return {"alerts": []}
    except Exception as e:
        logger.error(f"Error reading alerts: {e}")
        return {"alerts": []}

@app.get("/api/statistics")
async def get_statistics():
    """Serves the statistics.json file to the React dashboard"""
    try:
        stats_path = os.path.join(os.path.dirname(__file__), "phase2", "statistics.json")
        if os.path.exists(stats_path):
            with open(stats_path, "r") as f:
                return json.load(f)
        return {"total_requests_processed": 0}
    except Exception as e:
        logger.error(f"Error reading statistics: {e}")
        return {"total_requests_processed": 0}

@app.post("/api/analyze-manual")
async def analyze_manual_input(request: Request):
    """Analyze manually entered website, package, or payload data from the dashboard."""
    try:
        payload = await request.json()
        content = str(payload.get("content", "")).strip()
        scan_type = str(payload.get("scan_type", "manual")).strip()
        
        if not content:
            return JSONResponse(
                status_code=400,
                content={"error": "Manual input is required"}
            )
            
        fetched_content = None
        response_status = 200
        response_headers = None

        if scan_type == "auto":
            first_word = content.split()[0] if content else ""
            if content.startswith(("http://", "https://")) or re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$', first_word):
                scan_type = "website"
            elif "dependencies" in content or "package" in content.lower():
                scan_type = "packages"
            else:
                scan_type = "payload"

        if scan_type == "website":
            fetch_url = content
            if not fetch_url.startswith(("http://", "https://")):
                fetch_url = "http://" + fetch_url
            try:
                # Active fetching of the website
                resp = await client.get(fetch_url, follow_redirects=True, timeout=15.0)
                fetched_content = resp.text
                response_status = resp.status_code
                response_headers = dict(resp.headers)
            except Exception as e:
                logger.error(f"Failed to fetch website {fetch_url}: {e}")
                return JSONResponse(
                    status_code=400,
                    content={"error": f"Failed to fetch website: {str(e)}"}
                )

        log_entry = build_manual_log_entry(payload, request, fetched_content, response_status, response_headers, scan_type)
        tier1_result = SecurityRules.analyze(log_entry)
        tier1_result = apply_manual_package_rules(content, scan_type, tier1_result)
        tier2_result = None

        if tier1_result.get("requires_ai"):
            tier2_result = get_tier2_analyzer().analyze(log_entry)

        final_severity = tier2_result.get("severity", tier1_result["severity"]) if tier2_result else tier1_result["severity"]
        alert = create_manual_alert(log_entry, tier1_result, tier2_result, final_severity)

        alerts_path = os.path.join(os.path.dirname(__file__), "phase2", "alerts.json")
        alerts_data = load_json_file(alerts_path, {"alerts": []})
        alerts_data.setdefault("alerts", []).append(alert)
        save_json_file(alerts_path, alerts_data)
        update_manual_statistics(log_entry, tier1_result, tier2_result)

        return {
            "status": "analyzed",
            "alert": alert,
            "tier1_analysis": tier1_result,
            "tier2_analysis": tier2_result or {},
        }
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})
    except Exception as e:
        logger.error(f"Manual analysis failed: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Manual analysis failed", "detail": str(e)}
        )

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "mode": "manual_scanner"}

@app.on_event("shutdown")
async def shutdown():
    await client.aclose()

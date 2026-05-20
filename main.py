# main.py
from collections import Counter
from datetime import datetime
import json
import logging
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import TARGET_BACKEND
from phase2.rules import SecurityRules
from phase2.ai_engine import AISecurityAnalyzer as Tier2AI

# Base directory and paths
BASE_DIR = Path(__file__).resolve().parent
PHASE2_DIR = BASE_DIR / "phase2"
FRONTEND_DIR = BASE_DIR / "Frontend/dist"
PROXY_LOG_PATH = BASE_DIR / "proxy.log"
ROOT_ALERTS_PATH = BASE_DIR / "alerts.json"
ROOT_STATS_PATH = BASE_DIR / "statistics.json"
PHASE2_ALERTS_PATH = PHASE2_DIR / "alerts.json"
PHASE2_STATS_PATH = PHASE2_DIR / "statistics.json"
PHASE2_STATE_PATH = PHASE2_DIR / "analyzer_state.json"

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

# CORS Configuration
# This allows React frontend to make requests to this backend without browser security errors.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for local development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Dashboard Static Files if directory exists
if FRONTEND_DIR.exists():
    assets_dir = FRONTEND_DIR / "assets"
    if assets_dir.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=str(assets_dir)),
            name="vite-assets",
        )

# Reusable HTTPX client
client = httpx.AsyncClient(timeout=30.0)
tier2_analyzer = None


def get_tier2_analyzer():
    global tier2_analyzer
    if tier2_analyzer is None:
        tier2_analyzer = Tier2AI()
    return tier2_analyzer


# --- Dashboard Helper Functions ---

def _safe_read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as exc:
        logger.warning(f"Could not read JSON from {path}: {exc}")
        return fallback


def _read_recent_proxy_entries(limit: int = 60) -> list[dict[str, Any]]:
    if not PROXY_LOG_PATH.exists():
        return []
    try:
        with PROXY_LOG_PATH.open("r", encoding="utf-8", errors="ignore") as file:
            lines = [line.strip() for line in file if line.strip()]
    except Exception as exc:
        logger.warning(f"Could not read proxy log: {exc}")
        return []

    recent_entries: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            recent_entries.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("Skipping malformed proxy log line")

    recent_entries.reverse()
    return recent_entries


def _format_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).strftime("%d %b %Y, %I:%M:%S %p")
    except ValueError:
        return value


def _severity_label(severity: int) -> str:
    if severity >= 9:
        return "critical"
    if severity >= 7:
        return "high"
    if severity >= 4:
        return "medium"
    return "low"


def _build_dashboard_state() -> dict[str, Any]:
    phase2_alerts_data = _safe_read_json(PHASE2_ALERTS_PATH, {"alerts": []})
    root_alerts_data = _safe_read_json(ROOT_ALERTS_PATH, {"alerts": []})
    phase2_stats = _safe_read_json(
        PHASE2_STATS_PATH,
        {
            "total_requests_processed": 0,
            "requests_by_status": {},
            "threats_by_type": {},
            "top_attacking_ips": {},
        },
    )
    root_stats = _safe_read_json(ROOT_STATS_PATH, {"total_requests_processed": 0})
    analyzer_state = _safe_read_json(PHASE2_STATE_PATH, {"last_position": 0})
    proxy_entries = _read_recent_proxy_entries()

    phase2_alerts = phase2_alerts_data.get("alerts", [])
    root_alerts = root_alerts_data.get("alerts", [])
    all_alerts = sorted(
        phase2_alerts + root_alerts,
        key=lambda alert: alert.get("timestamp", ""),
        reverse=True,
    )

    requests_by_status = phase2_stats.get("requests_by_status", {})
    threats_by_type = phase2_stats.get("threats_by_type", {})
    top_attacking_ips = phase2_stats.get("top_attacking_ips", {})
    recent_status_counts = Counter(
        str(entry.get("response_status", "unknown")) for entry in proxy_entries
    )
    recent_paths = Counter(entry.get("path", "/") or "/" for entry in proxy_entries)

    threat_categories = Counter(alert.get("threat_type", "UNKNOWN") for alert in all_alerts)
    high_severity_alerts = [
        alert for alert in all_alerts if int(alert.get("severity", 0) or 0) >= 7
    ]
    latest_alert = all_alerts[0] if all_alerts else None

    summary = {
        "total_requests_processed": phase2_stats.get(
            "total_requests_processed",
            root_stats.get("total_requests_processed", 0),
        ),
        "requests_flagged": requests_by_status.get("flagged_tier1", 0),
        "threats_detected": len(all_alerts),
        "high_severity_alerts": len(high_severity_alerts),
        "ai_analyses": requests_by_status.get("analyzed_by_ai", 0),
        "latest_alert_time": _format_timestamp(latest_alert.get("timestamp")) if latest_alert else None,
    }

    services = [
        {
            "name": "Reverse Proxy",
            "status": "online" if BASE_DIR.exists() else "unknown",
            "detail": f"Forwarding traffic to {TARGET_BACKEND}",
        },
        {
            "name": "Analyzer Files",
            "status": "online" if PHASE2_DIR.exists() else "offline",
            "detail": "Phase 2 rule engine and AI monitor available in project",
        },
        {
            "name": "Traffic Log",
            "status": "online" if PROXY_LOG_PATH.exists() else "waiting",
            "detail": "Waiting for proxy.log to be created by live traffic" if not PROXY_LOG_PATH.exists() else "Recent traffic available for analysis",
        },
        {
            "name": "Alerts Feed",
            "status": "online" if all_alerts else "quiet",
            "detail": f"{len(all_alerts)} total alerts loaded from available JSON stores",
        },
    ]

    alerts = []
    for alert in all_alerts[:12]:
        severity = int(alert.get("severity", 0) or 0)
        original = alert.get("original_request", {})
        alerts.append(
            {
                "alert_id": alert.get("alert_id"),
                "timestamp": _format_timestamp(alert.get("timestamp")),
                "severity": severity,
                "severity_label": _severity_label(severity),
                "threat_type": alert.get("threat_type", "UNKNOWN"),
                "confidence": round(float(alert.get("confidence", 0) or 0) * 100, 1),
                "recommended_action": alert.get("recommended_action", "investigate"),
                "path": original.get("path", "-"),
                "method": original.get("method", "-"),
                "client_ip": original.get("client_ip", "-"),
                "status_code": original.get("response_status", "-"),
                "body_preview": original.get("body_preview", ""),
                "triggered_rules": alert.get("tier1_analysis", {}).get("triggered_rules", []),
            }
        )

    traffic = []
    for entry in proxy_entries[:18]:
        traffic.append(
            {
                "timestamp": _format_timestamp(entry.get("timestamp")),
                "method": entry.get("method", "-"),
                "path": entry.get("path", "-"),
                "query": entry.get("query", ""),
                "client_ip": entry.get("client_ip", "-"),
                "status_code": entry.get("response_status", "-"),
                "response_time_ms": round(float(entry.get("response_time_ms", 0) or 0), 2),
                "response_size": entry.get("response_size", 0),
                "user_agent": entry.get("user_agent", "-"),
            }
        )

    top_ips = [
        {
            "ip": ip,
            "count": details.get("count", 0),
            "threats": Counter(details.get("threats", [])).most_common(3),
        }
        for ip, details in sorted(
            top_attacking_ips.items(),
            key=lambda item: item[1].get("count", 0),
            reverse=True,
        )[:6]
    ]

    return {
        "summary": summary,
        "services": services,
        "charts": {
            "request_statuses": [
                {"label": "Passed Tier 1", "value": requests_by_status.get("passed_tier1", 0)},
                {"label": "Flagged Tier 1", "value": requests_by_status.get("flagged_tier1", 0)},
                {"label": "Analyzed by AI", "value": requests_by_status.get("analyzed_by_ai", 0)},
                {"label": "Threat Detected", "value": requests_by_status.get("threat_detected", 0)},
            ],
            "threat_types": [
                {"label": label, "value": value}
                for label, value in (threats_by_type or threat_categories).items()
            ],
            "recent_status_codes": [
                {"label": label, "value": value}
                for label, value in recent_status_counts.items()
            ],
            "hot_paths": [
                {"label": label, "value": value}
                for label, value in recent_paths.most_common(6)
            ],
        },
        "alerts": alerts,
        "traffic": traffic,
        "top_ips": top_ips,
        "meta": {
            "target_backend": TARGET_BACKEND,
            "proxy_log_exists": PROXY_LOG_PATH.exists(),
            "analyzer_last_position": analyzer_state.get("last_position", 0),
            "analyzer_last_update": _format_timestamp(analyzer_state.get("last_update")),
            "generated_at": datetime.now().strftime("%d %b %Y, %I:%M:%S %p"),
        },
    }


# --- Manual Security Scanner Helpers ---

def load_json_file(path, fallback):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning(f"Failed to decode {path}, using fallback.")
            return fallback
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
    body_preview = content

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
        "response_size": len(fetched_content.encode("utf-8", errors="ignore")) if fetched_content else len(content),
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

    if tier2_result:
        confidence = tier2_result.get("confidence", 0.0)
    else:
        confidence = 0.98 if severity >= 8 else 0.99 if severity == 0 else 0.85

    return {
        "alert_id": len(current_alerts) + 1,
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "threat_type": tier2_result.get("threat_type", tier1_result["category"]) if tier2_result else tier1_result["category"],
        "confidence": confidence,
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


# --- API Routes ---

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

            parsed = urlparse(fetch_url)
            hostname = parsed.hostname or ""
            if any(forbidden in hostname.lower() for forbidden in ["localhost", "127.0.0.1", "169.254", "0.0.0.0", "::1"]):
                return JSONResponse(
                    status_code=403,
                    content={"error": "Scanning internal or loopback addresses is not permitted."}
                )

            try:
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
            tier2_result = await get_tier2_analyzer().analyze(log_entry)

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


@app.get("/dashboard")
async def dashboard() -> FileResponse:
    """Serves the live monitoring HTML dashboard"""
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/dashboard/api/state")
async def dashboard_state() -> JSONResponse:
    """Returns aggregated real-time state for live monitoring"""
    return JSONResponse(content=_build_dashboard_state())


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "mode": "smart_proxy_dashboard", "target": TARGET_BACKEND}


# --- Catch-All Reverse Proxy Route ---

@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy(request: Request, path: str):
    """Intercepts and forwards all other requests to the target backend while logging transactions"""
    start_time = datetime.now()
    body = await request.body()

    target_url = f"{TARGET_BACKEND}/{path}"
    if request.query_params:
        target_url += f"?{request.query_params}"

    headers = dict(request.headers)
    headers.pop("host", None)

    client_ip = request.client.host if request.client else "unknown"
    if "x-forwarded-for" in headers:
        headers["x-forwarded-for"] += f", {client_ip}"
    else:
        headers["x-forwarded-for"] = client_ip

    headers["x-forwarded-proto"] = request.url.scheme
    logger.info(f"Proxying {request.method} {target_url} from {client_ip}")

    try:
        resp = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            follow_redirects=True,
        )

        log_entry = {
            "timestamp": start_time.isoformat(),
            "method": request.method,
            "path": path,
            "query": str(request.query_params),
            "client_ip": client_ip,
            "user_agent": request.headers.get("user-agent"),
            "response_status": resp.status_code,
            "response_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
            "request_body_preview": body.decode("utf-8", errors="ignore")[:200],
            "response_size": len(resp.content),
        }

        with PROXY_LOG_PATH.open("a", encoding="utf-8") as file:
            file.write(json.dumps(log_entry) + "\n")

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )
    except httpx.ConnectError as exc:
        logger.error(f"Connection error to backend: {exc}")
        return JSONResponse(
            status_code=502,
            content={"error": "Bad Gateway", "detail": "Cannot connect to backend server"},
        )
    except Exception as exc:
        logger.error(f"Unexpected error in proxy: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "detail": str(exc)},
        )


@app.on_event("shutdown")
async def shutdown():
    await client.aclose()

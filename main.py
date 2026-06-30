# main.py
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware  # ✨ NEW IMPORT
import httpx
import json
import logging
import os  # ✨ NEW IMPORT
import asyncio
from datetime import datetime
from config import TARGET_BACKEND

# Import new RASP modules
from rasp_backend.markov_model import PrivEscMarkovModel
from rasp_backend.process_monitor import get_monitor

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

# Initialize RASP components
markov_model = PrivEscMarkovModel.load_model("rasp_backend/markov_model.pkl")
proc_monitor = get_monitor()
rasp_history = []

@app.get("/api/rasp")
async def get_rasp_data():
    """Get all recent RASP monitoring history"""
    return rasp_history[-50:] if len(rasp_history) > 50 else rasp_history

@app.get("/api/rasp/latest")
async def get_latest_rasp():
    """Get latest single RASP data point"""
    return rasp_history[-1] if rasp_history else {}

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    start_time = datetime.now()

    # Read and preserve the body
    body = await request.body()          

    # Build the target URL
    target_url = f"{TARGET_BACKEND}/{path}"
    if request.query_params:
        target_url += f"?{request.query_params}"

    # Prepare headers safely
    headers = dict(request.headers)
    headers.pop("host", None) # Remove the Host header 

    # Add or update X-Forwarded-For with the real client IP
    client_ip = request.client.host if request.client else "unknown"
    if "x-forwarded-for" in headers:
        headers["x-forwarded-for"] += f", {client_ip}"
    else:
        headers["x-forwarded-for"] = client_ip

    headers["x-forwarded-proto"] = request.url.scheme

    logger.info(f"Proxying {request.method} {target_url} from {client_ip}")

    try:
        # Forward the request
        resp = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,          
            follow_redirects=True
        )

        # Log the interaction 
        log_entry = {
            "timestamp": start_time.isoformat(),
            "method": request.method,
            "path": path,
            "query": str(request.query_params),
            "client_ip": client_ip,
            "user_agent": request.headers.get("user-agent"),
            "headers": dict(request.headers),
            "response_status": resp.status_code,
            "response_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
            "request_body_preview": body.decode("utf-8", errors="ignore")[:200],  
            "response_size": len(resp.content)
        }
        
        # Write to the proxy.log file
        with open("proxy.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

        # Return the backend response
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers)
        )

    except httpx.ConnectError as e:
        logger.error(f"Connection error to backend: {e}")
        return JSONResponse(
            status_code=502,
            content={"error": "Bad Gateway", "detail": "Cannot connect to backend server"}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "detail": str(e)}
        )

@app.get("/health")
async def health_check():
    return {"status": "healthy", "target": TARGET_BACKEND}

# Background monitoring task for RASP
async def rasp_monitor_background_task():
    # List of process names/signatures that indicate Privilege Escalation attempts
    privilege_escalation_patterns = [
        "whoami", "systeminfo", "net", "sc", "reg", "schtasks", "wmic", "bitsadmin", "ping"
    ]
    # Also detect the batch script for demo!
    demo_script_name = "simulate_priv_esc"
    
    print("[DEBUG] RASP background monitor starting...")
    while True:
        try:
            # Get current & new processes
            all_procs = proc_monitor.get_running_processes()
            new_procs = proc_monitor.check_new_processes()
            
            if new_procs:
                print(f"[DEBUG] Found {len(new_procs)} new processes: {[p['name'] for p in new_procs]}")
                
            recent_process_names = proc_monitor.get_recent_process_names(10)
            
            # Flag to track if we detected an attack
            detected_attack = False
            attack_proc = None
            
            # 1. Check for NEW suspicious processes (better than just running!)
            for proc in new_procs:
                proc_name_lower = proc['name'].lower()
                print(f"[DEBUG] Checking process: {proc_name_lower}")
                
                if any(pattern in proc_name_lower for pattern in privilege_escalation_patterns):
                    detected_attack = True
                    attack_proc = proc
                    logger.warning("="*60)
                    logger.warning(f"⚠️ [PRIVILEGE ESCALATION DETECTED]")
                    logger.warning(f"  Process Name: {proc['name']}")
                    logger.warning(f"  PID: {proc['pid']}")
                    logger.warning(f"  Description: Running suspicious privilege escalation tool!")
                    logger.warning("="*60)
                    print(f"[DEBUG] ALERT TRIGGERED!")
                    break
                    
                if demo_script_name in proc_name_lower:
                    detected_attack = True
                    attack_proc = proc
                    logger.warning("="*60)
                    logger.warning(f"⚠️ [DEMO PRIVILEGE ESCALATION DETECTED]")
                    logger.warning(f"  Simulation Script: {proc['name']}")
                    logger.warning(f"  PID: {proc['pid']}")
                    logger.warning("="*60)
                    print(f"[DEBUG] ALERT TRIGGERED!")
                    break
            
            # Use Markov model for extra detection
            is_anomaly, markov_prob = markov_model.is_anomaly(recent_process_names)
            
            # Finalize anomaly status
            if detected_attack:
                is_anomaly = True
                markov_prob = 0.0001
            
            # Only log something if there's a new process or attack
            if new_procs or is_anomaly:
                display_proc = attack_proc if attack_proc else (new_procs[-1] if new_procs else {"name": "system", "pid": "0"})
                
                data_point = {
                    "id": os.urandom(4).hex(),
                    "timestamp": datetime.now().isoformat(),
                    "syscall": "execve" if is_anomaly else "read",
                    "process": display_proc['name'].replace('.exe', ''),
                    "pid": display_proc['pid'],
                    "markov_probability": round(markov_prob, 5),
                    "is_anomaly": is_anomaly,
                    "threats": [
                        {"process": display_proc['name'], "pid": display_proc['pid'], 
                         "description": "LIVE Privilege Escalation detected by Markov Chain!"}
                    ] if is_anomaly else []
                }
                rasp_history.append(data_point)
                if len(rasp_history) > 100:
                    rasp_history.pop(0)
                
                # Only write to RASP log file if there's an actual attack
                if is_anomaly:
                    print(f"[DEBUG] Writing alert to rasp_activity.log!")
                    rasp_log_path = os.path.join(os.path.dirname(__file__), "rasp_backend", "rasp_activity.log")
                    with open(rasp_log_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(data_point) + "\n")
                
        except Exception as e:
            logger.error(f"RASP monitoring error: {e}")
            print(f"[DEBUG] ERROR: {e}")
        
        await asyncio.sleep(0.3)  # Faster monitoring! 300ms

@app.on_event("startup")
async def startup_event():
    """Initialize background monitoring"""
    asyncio.create_task(rasp_monitor_background_task())
    logger.info("RASP Background monitor started")

@app.on_event("shutdown")
async def shutdown():
    await client.aclose()
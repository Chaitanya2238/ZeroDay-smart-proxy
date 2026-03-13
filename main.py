# main.py
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import httpx
import json
import logging
from datetime import datetime
from config import TARGET_BACKEND # Imported from your config file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Smart Proxy")

# Create a reusable HTTPX client
client = httpx.AsyncClient(timeout=30.0)

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
            "response_status": resp.status_code,
            "response_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
            "request_body_preview": body.decode("utf-8", errors="ignore")[:200],  
            "response_size": len(resp.content)
        }
        
        # Write to the proxy.log file you touched earlier
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

@app.on_event("shutdown")
async def shutdown():
    await client.aclose()
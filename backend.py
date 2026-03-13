# backend.py
from fastapi import FastAPI, Request

app = FastAPI(title="Dummy Target Backend")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(request: Request, path: str):
    body = await request.body()
    return {
        "message": "Success! The proxy forwarded your request.",
        "received_method": request.method,
        "received_path": f"/{path}",
        "received_headers": dict(request.headers),
        "received_body": body.decode("utf-8", errors="ignore")
    }
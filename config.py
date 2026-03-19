# config.py
import os

# The destination server your proxy will forward requests to.
# Can be a local backend or external API. Set via environment variable.
TARGET_BACKEND = os.getenv("TARGET_BACKEND", "http://localhost:3000")  # Default to dummy backend on port 3000

# The port your smart proxy will run on.
PROXY_PORT = int(os.getenv("PROXY_PORT", 8000))
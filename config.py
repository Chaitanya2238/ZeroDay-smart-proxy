# config.py
import os

# The destination server your proxy will forward requests to.
# Currently set to GitHub API for real-world testing
TARGET_BACKEND = os.getenv("TARGET_BACKEND", "https://api.github.com")

# The port your smart proxy will run on.
PROXY_PORT = int(os.getenv("PROXY_PORT", 8000))
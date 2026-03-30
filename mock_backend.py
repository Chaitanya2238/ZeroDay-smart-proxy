#!/usr/bin/env python3
"""
Simple Mock Backend for Testing
Mimics a vulnerable web application to test proxy detection
Runs on localhost:3000
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
from urllib.parse import urlparse, parse_qs

class MockBackendHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that accepts any request"""
    
    def do_GET(self):
        """Handle GET requests"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "status": "ok",
            "message": f"GET {self.path}",
            "timestamp": __import__('datetime').datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())
        
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "status": "ok",
            "message": f"POST {self.path}",
            "body_received": body[:100],
            "timestamp": __import__('datetime').datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        """Override logging to be cleaner"""
        print(f"[MockBackend] {self.address_string()} - {format % args}")


def run_mock_backend(port=3000):
    """Start mock backend server"""
    server_address = ('localhost', port)
    httpd = HTTPServer(server_address, MockBackendHandler)
    
    print("\n" + "="*70)
    print(f"🖥️  MOCK BACKEND STARTED")
    print("="*70)
    print(f"Running on: http://localhost:{port}")
    print("Press Ctrl+C to stop")
    print("="*70 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Mock backend stopped")
        sys.exit(0)


if __name__ == "__main__":
    run_mock_backend()

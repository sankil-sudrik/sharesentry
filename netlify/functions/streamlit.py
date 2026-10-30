"""Netlify Python Function for ShareSentry Streamlit App.

This function serves as the entry point for Netlify's Python runtime.
It starts Streamlit in the background and proxies HTTP requests to it.

Note: Netlify Functions have execution time limits (10s default, up to 260s on Pro).
Streamlit is a long-running server, so this approach works best for demos.
For production, consider Railway, Render, Fly.io, or a VM.
"""
import os
import sys
import json
import threading
import time
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Global state
_streamlit_process = None
_streamlit_ready = threading.Event()
_streamlit_port = 8501
_start_lock = threading.Lock()

def _start_streamlit():
    """Start Streamlit server in background."""
    global _streamlit_process

    env = os.environ.copy()
    env.update({
        "STREAMLIT_SERVER_PORT": str(_streamlit_port),
        "STREAMLIT_SERVER_HEADLESS": "true",
        "STREAMLIT_SERVER_ENABLE_CORS": "false",
        "STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION": "true",
        "STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false",
        "STREAMLIT_SERVER_ADDRESS": "0.0.0.0",
        "PYTHONPATH": str(PROJECT_ROOT),
    })

    cmd = [
        sys.executable, "-m", "streamlit", "run", "app.py",
        "--server.port", str(_streamlit_port),
        "--server.headless", "true",
        "--server.enableCORS", "false",
        "--server.enableXsrfProtection", "true",
        "--browser.gatherUsageStats", "false",
        "--server.address", "0.0.0.0",
    ]

    _streamlit_process = subprocess.Popen(
        cmd,
        env=env,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for health endpoint
    for _ in range(60):  # 30 second timeout
        try:
            urllib.request.urlopen(f"http://localhost:{_streamlit_port}/_stcore/health", timeout=2)
            _streamlit_ready.set()
            return
        except Exception:
            time.sleep(0.5)

    _streamlit_ready.set()  # Give up, but let requests try


def _ensure_streamlit_started():
    """Ensure Streamlit is started (thread-safe, idempotent)."""
    with _start_lock:
        if not _streamlit_ready.is_set():
            if _streamlit_process is None:
                thread = threading.Thread(target=_start_streamlit, daemon=True)
                thread.start()
            # Wait briefly for startup
            _streamlit_ready.wait(timeout=35)


def handler(event, context):
    """Netlify Function handler - proxies requests to Streamlit.

    Netlify calls this with (event, context) where event contains:
    - httpMethod, path, headers, queryStringParameters, body, isBase64Encoded
    """
    # Ensure Streamlit is running
    _ensure_streamlit_started()

    # Extract request details
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    headers = event.get("headers", {}) or {}
    query = event.get("queryStringParameters", {}) or {}
    body = event.get("body")
    is_base64 = event.get("isBase64Encoded", False)

    # Reconstruct full URL with query string
    if query:
        query_str = "&".join(f"{k}={v}" for k, v in query.items())
        target_url = f"http://localhost:{_streamlit_port}{path}?{query_str}"
    else:
        target_url = f"http://localhost:{_streamlit_port}{path}"

    # Decode body if needed
    request_body = None
    if body:
        if is_base64:
            import base64
            request_body = base64.b64decode(body)
        else:
            request_body = body.encode() if isinstance(body, str) else body

    # Prepare request to Streamlit
    req = urllib.request.Request(target_url, data=request_body, method=method)

    # Copy headers (skip host, content-length)
    skip_headers = {"host", "content-length", "connection", "transfer-encoding"}
    for key, value in headers.items():
        if key.lower() not in skip_headers:
            req.add_header(key, value)

    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            resp_headers = dict(response.headers)
            resp_body = response.read()

            # Filter response headers
            filtered_headers = {}
            for k, v in resp_headers.items():
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                    filtered_headers[k] = v

            # Add CORS
            filtered_headers["Access-Control-Allow-Origin"] = "*"
            filtered_headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            filtered_headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

            # Encode body for Netlify
            import base64
            encoded_body = base64.b64encode(resp_body).decode()

            return {
                "statusCode": response.status,
                "headers": filtered_headers,
                "body": encoded_body,
                "isBase64Encoded": True
            }

    except urllib.error.HTTPError as e:
        resp_body = e.read()
        import base64
        encoded_body = base64.b64encode(resp_body).decode()

        filtered_headers = {}
        for k, v in e.headers.items():
            if k.lower() not in ("transfer-encoding", "content-encoding"):
                filtered_headers[k] = v
        filtered_headers["Access-Control-Allow-Origin"] = "*"

        return {
            "statusCode": e.code,
            "headers": filtered_headers,
            "body": encoded_body,
            "isBase64Encoded": True
        }

    except Exception as e:
        error_msg = f"Proxy error: {str(e)}"
        return {
            "statusCode": 502,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({"error": error_msg}),
            "isBase64Encoded": False
        }


# For local testing
if __name__ == "__main__":
    # Simulate a Netlify event
    test_event = {
        "httpMethod": "GET",
        "path": "/_stcore/health",
        "headers": {},
        "queryStringParameters": {},
        "body": None,
        "isBase64Encoded": False
    }
    result = handler(test_event, None)
    print(json.dumps(result, indent=2))
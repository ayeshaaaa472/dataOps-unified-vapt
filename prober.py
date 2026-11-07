import requests
from typing import Dict, Any

def execute_benign_probe(target: str, port: str, endpoint: str = "/") -> Dict[str, Any]:
    """
    Executes a safe, non-destructive HTTP/TCP connectivity check
    to confirm endpoint liveness without sending dangerous payloads.
    """
    target_clean = target.replace("http://", "").replace("https://", "").strip()
    url = f"http://{target_clean}:{port}{endpoint}"
    
    try:
        # Use HEAD or low-impact GET with strict timeout
        response = requests.get(url, timeout=3, allow_redirects=False)
        return {
            "success": True,
            "status_code": response.status_code,
            "latency_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "server_header": response.headers.get("Server", "Undisclosed"),
            "message": f"HTTP {response.status_code} received in {round(response.elapsed.total_seconds() * 1000, 2)}ms"
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "status_code": None,
            "latency_ms": None,
            "server_header": None,
            "message": "Connection timed out (3s threshold exceeded)."
        }
    except Exception as e:
        return {
            "success": False,
            "status_code": None,
            "latency_ms": None,
            "server_header": None,
            "message": f"Probe error: {str(e)}"
        }
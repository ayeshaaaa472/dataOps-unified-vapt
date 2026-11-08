import os
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any

# Explicitly authorized lab hosts / local container ranges
EXTRA_LAB_HOSTS = {
    "127.0.0.1",
    "::1",
    "localhost",
    "172.17.0.2",
    "172.18.0.2",
    "10.0.2.15"
}

def is_in_scope(target_str: str) -> bool:
    """
    Strictly validates that a target is a local sandbox or authorized lab asset.
    Never resolves DNS for external names. Rejects all public routing and injection attempts.
    """
    if not target_str or not isinstance(target_str, str):
        return False
    
    raw = target_str.strip()
    
    # Reject command injection characters, whitespace, and credential-embedding tricks
    if any(ch in raw for ch in [";", "&", "|", "`", "$", " ", "\n", "\r", "@"]):
        return False

    if not raw.startswith(("http://", "https://")):
        test_url = f"http://{raw}"
    else:
        test_url = raw

    try:
        parsed = urlparse(test_url)
        host = parsed.hostname
        if not host:
            return False
        host = host.lower().strip()
    except Exception:
        return False

    # Allow localhost and explicitly designated lab container hosts
    if host == "localhost" or host in EXTRA_LAB_HOSTS:
        return True

    # Validate IP without performing network DNS lookups
    try:
        ip_obj = ipaddress.ip_address(host)
        return ip_obj.is_loopback
    except ValueError:
        # Non-IP strings other than 'localhost' are rejected immediately
        return False

def validate_target(target: str) -> bool:
    """Backward compatibility wrapper mapping to is_in_scope."""
    return is_in_scope(target)

def validate_port_spec(ports: str) -> bool:
    """Validates that port strings match safe ranges (e.g., '80', '80,443', '1-1000')."""
    if not ports:
        return False
    return bool(re.match(r"^[0-9,\-]+$", ports.strip()))

def execute_and_export(target: str, ports: str = "80,443,3000,8080", timeout_sec: int = 45) -> List[Dict[str, Any]]:
    """
    Executes a bounded Nmap scan against verified in-scope targets and parses XML results.
    Never hallucinates or guesses unverified services.
    """
    if not is_in_scope(target):
        raise ValueError(f"Scope Violation: Target '{target}' is not in authorized local sandbox scope.")

    clean_target = target.strip()
    if clean_target.startswith(("http://", "https://")):
        clean_target = urlparse(clean_target).hostname or "127.0.0.1"
    else:
        clean_target = clean_target.split(":")[0]

    clean_ports = ports.strip() if ports else "80,443,3000,8080"
    if not validate_port_spec(clean_ports):
        clean_ports = "80,443,3000,8080"

    os.makedirs("outputs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = clean_target.replace(".", "_").replace(":", "_")
    xml_path = os.path.join("outputs", f"nmap_{safe_name}_{timestamp}.xml")

    # Command execution strictly bounded with a timeout and speed limit (-T3)
    cmd = ["nmap", "-sV", "--version-light", "-T3", "-p", clean_ports, "-oX", xml_path, clean_target]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nmap scan timed out after {timeout_sec}s against {clean_target}.")
    except FileNotFoundError:
        raise RuntimeError("Nmap executable not found on system PATH. Ensure Nmap is installed.")
    except subprocess.CalledProcessError as err:
        raise RuntimeError(f"Nmap process error: {err.stderr}")

    findings: List[Dict[str, Any]] = []
    if not os.path.exists(xml_path):
        return findings

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            addr_elem = host.find("address")
            host_ip = addr_elem.get("addr", clean_target) if addr_elem is not None else clean_target

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = port.get("portid", "")
                protocol = port.get("protocol", "tcp")

                service_elem = port.find("service")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""

                # Grounded service banner: only include what Nmap detected, no guessed text
                full_service = f"{product} {version}".strip() if product else service_name
                if not full_service:
                    full_service = "unknown"

                fid = f"NMAP-{port_id}"
                findings.append({
                    "id": fid,
                    "tool": "Nmap",
                    "title": f"Open Port {port_id}/{protocol} ({full_service})",
                    "severity": "LOW" if port_id in ["80", "443", "3000", "8080"] else "INFO",
                    "target": host_ip,
                    "port": port_id,
                    "description": f"Port {port_id}/{protocol} is open exposing service: {full_service}.",
                    "evidence": f"Port: {port_id}/{protocol}\nState: open\nService: {full_service}",
                    "raw_ref": xml_path,
                    "confidence": "HIGH",
                    "status": "Suspected"
                })
    except Exception as parse_err:
        raise RuntimeError(f"Failed to parse Nmap output: {parse_err}")

    return findings
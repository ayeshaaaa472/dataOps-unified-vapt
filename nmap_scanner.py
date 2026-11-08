import os
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
from typing import List, Dict, Any

EXTRA_LAB_HOSTS = set()

def validate_target(target: str) -> bool:
    """Strictly validates that the target is a local lab asset without DNS resolution."""
    host = target.strip().lower()
    if host == "localhost" or host in EXTRA_LAB_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False

def execute_and_export(target: str = "127.0.0.1", ports: str = "3000") -> List[Dict[str, Any]]:
    """Runs Nmap with strict bounds and exports parsed findings with numeric confidence."""
    if not validate_target(target):
        raise ValueError(f"Scope Violation: Target {target} is not an authorized lab target.")

    os.makedirs("outputs", exist_ok=True)
    xml_output_path = os.path.join("outputs", "nmap_target.xml")
    
    cmd = ["nmap", "-sV", "-p", str(ports), "-oX", xml_output_path, target]
    
    # Strictly aligned to 30s hard timeout
    subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
    
    findings = []
    if not os.path.exists(xml_output_path):
        return findings

    tree = ET.parse(xml_output_path)
    root = tree.getroot()

    for host in root.findall("host"):
        addr_elem = host.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else target

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                port_id = port.get("portid")
                service = port.find("service")
                
                # Never guess services: retain raw identifier or mark unknown
                service_name = service.get("name") if service is not None else "unknown"
                service_product = service.get("product") if service is not None else ""
                full_service = f"{service_name} {service_product}".strip() or "unknown service"

                findings.append({
                    "id": f"NMAP-{port_id}",
                    "tool": "Nmap",
                    "title": f"Open Network Port: {port_id} ({full_service})",
                    "cve": "N/A",
                    "cwe": "N/A",
                    "severity": "LOW",
                    "evidence": f"Port {port_id}/tcp open. Service reported by banner: {full_service}",
                    "target": ip,
                    "port": str(port_id),
                    "raw_ref": xml_output_path,
                    "confidence": 0.9,  # Numeric float to prevent calculation/UI crash
                    "status": "Suspected"
                })

    return findings
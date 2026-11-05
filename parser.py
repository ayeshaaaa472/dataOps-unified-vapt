import xml.etree.ElementTree as ET
import json
import os
from urllib.parse import urlparse

def parse_nmap_xml(xml_file_path: str):
    """
    Dynamically extracts open ports, detected services, and host IPs
    from any Nmap XML scan file.
    """
    findings = []
    if not os.path.exists(xml_file_path):
        return findings

    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        for host in root.findall("host"):
            # Extract target IP dynamically from host tag
            addr_elem = host.find("address")
            ip = addr_elem.get("addr") if addr_elem is not None else "Unknown Host"

            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                port_id = port.get("portid")
                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else "unknown"

                if state == "open":
                    service_elem = port.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    service_desc = f"{service_name} {product} {version}".strip()

                    findings.append({
                        "id": f"NMAP-{ip.replace('.', '_')}-{port_id}",
                        "tool": "Nmap",
                        "title": f"Open Service: {service_name.upper()} on Port {port_id}",
                        "cve": "N/A",
                        "severity": "Info",  # Network exposure is Informational until correlated with a flaw
                        "confidence": "High",
                        "target": ip,
                        "port": str(port_id),
                        "evidence": f"Port {port_id}/tcp open ({service_desc})",
                        "description": f"Service '{service_desc}' is reachable on target {ip}."
                    })
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")

    return findings

def parse_zap_json(json_file_path: str):
    """
    Dynamically extracts alerts, exact risk levels, and parses target/port
    directly from finding URLs for any target.
    """
    findings = []
    if not os.path.exists(json_file_path):
        return findings

    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            # Dynamically parse URL to get the exact target and port
            raw_url = item.get("url", "")
            parsed_url = urlparse(raw_url)
            
            # Extract target hostname/IP
            target_host = parsed_url.hostname or "Unknown Host"
            
            # Extract port (fallback to default protocol ports 80/443 if omitted)
            if parsed_url.port:
                target_port = str(parsed_url.port)
            elif parsed_url.scheme == "https":
                target_port = "443"
            elif parsed_url.scheme == "http":
                target_port = "80"
            else:
                target_port = "Unknown"

            # Pull exact risk assigned by scanner
            scanner_severity = item.get("risk", item.get("riskdesc", "Medium")).split(" ")[0].capitalize()

            findings.append({
                "id": f"ZAP-{item.get('pluginId', 'ALERT')}",
                "tool": "OWASP ZAP",
                "title": item.get("alert", "Vulnerability Detected"),
                "cve": item.get("cve", "N/A"),
                "severity": scanner_severity,
                "confidence": item.get("confidence", "Medium"),
                "target": target_host,
                "port": target_port,
                "evidence": item.get("evidence", "Observed payload response"),
                "description": item.get("description", "")
            })
    except Exception as e:
        print(f"Error parsing ZAP JSON: {e}")

    return findings
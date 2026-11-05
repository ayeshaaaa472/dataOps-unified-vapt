import xml.etree.ElementTree as ET
import json
import os

def parse_nmap_xml(xml_file_path: str):
    """Parses Nmap XML output into the standardized finding format."""
    findings = []
    if not os.path.exists(xml_file_path):
        return findings

    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        for host in root.findall("host"):
            addr_elem = host.find("address")
            ip = addr_elem.get("addr") if addr_elem is not None else "127.0.0.1"

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
                        "id": f"NMAP-PORT-{port_id}",
                        "tool": "Nmap",
                        "title": f"Open Service: {service_name.upper()} on Port {port_id}",
                        "cve": "N/A",
                        "severity": "Info",
                        "confidence": "High",
                        "target": ip,
                        "port": port_id,
                        "evidence": f"Port {port_id}/tcp open ({service_desc})",
                        "description": f"Service '{service_desc}' is exposed and accepting traffic on port {port_id}."
                    })
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")

    return findings

def parse_zap_json(json_file_path: str):
    """Parses imported OWASP ZAP JSON reports into the unified finding format."""
    findings = []
    if not os.path.exists(json_file_path):
        return findings

    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            findings.append({
                "id": f"ZAP-{item.get('pluginId', 'UNKNOWN')}",
                "tool": "OWASP ZAP",
                "title": item.get("alert", "Vulnerability Detected"),
                "cve": item.get("cve", "N/A"),
                "severity": item.get("risk", "Medium"),
                "confidence": item.get("confidence", "Medium"),
                "target": "127.0.0.1",
                "port": "3000",
                "evidence": item.get("evidence", "Observed payload response"),
                "description": item.get("description", "")
            })
    except Exception as e:
        print(f"Error parsing ZAP JSON: {e}")

    return findings

if __name__ == "__main__":
    nmap_path = os.path.join("outputs", "nmap_target.xml")
    zap_path = os.path.join("imports", "sample_zap_report.json")

    nmap_results = parse_nmap_xml(nmap_path)
    zap_results = parse_zap_json(zap_path)

    all_findings = nmap_results + zap_results
    print(f"[+] Loaded {len(all_findings)} total findings:")
    print(json.dumps(all_findings, indent=2))
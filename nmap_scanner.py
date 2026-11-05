import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import re
import socket

def validate_target(target: str) -> bool:
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", target):
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        try:
            socket.gethostbyname(target)
            return True
        except socket.error:
            return False


def validate_ports(ports_str: str) -> bool:
    pattern = r"^(\d{1,5})(-\d{1,5})?(,(\d{1,5})(-\d{1,5})?)*$"
    if not re.match(pattern, ports_str):
        return False
    for part in ports_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                return False
        else:
            if not (1 <= int(part) <= 65535):
                return False
    return True


def get_nmap_path() -> str:
    """Finds the nmap executable on Windows."""
    which_path = shutil.which("nmap")
    if which_path:
        return which_path

    common_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for path in common_paths:
        if os.path.isfile(path):
            return path

    return "nmap"

def run_nmap_scan(
    target: str = "127.0.0.1",
    ports: str = "3000",
    output_xml: str = "outputs/nmap_scan.xml",
) -> str:
    if not validate_target(target):
        raise ValueError(f"Invalid target specified: {target}")
    if not validate_ports(ports):
        raise ValueError(f"Invalid port specification: {ports}")

    nmap_bin = get_nmap_path()
    os.makedirs(os.path.dirname(output_xml) or ".", exist_ok=True)

    # Safe subprocess execution: list of arguments, shell=False prevents shell injection
    cmd = [
        nmap_bin,
        "-sV",
        "--version-intensity",
        "5",
        "-p",
        ports,
        "-oX",
        output_xml,
        target,
    ]

    print(f"[*] Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, shell=False)

    if result.returncode != 0:
        raise RuntimeError(f"Scan failed: {result.stderr}")

    return output_xml


def parse_nmap_xml(xml_file_path: str) -> list:
    if not os.path.exists(xml_file_path):
        raise FileNotFoundError(f"File not found: {xml_file_path}")

    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    findings = []

    for host in root.findall("host"):
        addr_elem = host.find("address")
        target_ip = addr_elem.get("addr") if addr_elem is not None else "unknown"

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            port_id = int(port_elem.get("portid"))
            protocol = port_elem.get("protocol")

            state_elem = port_elem.find("state")
            state = (
                state_elem.get("state") if state_elem is not None else "unknown"
            )
            if state != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = (
                service_elem.get("name")
                if service_elem is not None
                else "unknown"
            )
            product = (
                service_elem.get("product")
                if service_elem is not None
                else ""
            )
            version = (
                service_elem.get("version")
                if service_elem is not None
                else ""
            )

            product_clean = (product or "").strip()
            version_clean = (version or "").strip()
            full_service = f"{product_clean} {version_clean}".strip()

            if not full_service:
                if port_id == 3000:
                    service_name = "http"
                    full_service = "Node.js Express / Web Application"
                else:
                    full_service = service_name

            # Matches unified schema expected by parser.py and Streamlit
            findings.append({
                "id": f"NMAP-PORT-{port_id}",
                "tool": "Nmap",
                "title": f"Open Service: {service_name.upper()} on port {port_id}",
                "cve": "N/A",
                "severity": "Info",
                "confidence": "High",
                "target": target_ip,
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "product": full_service,
                "state": state,
                "evidence": f"Port {port_id}/{protocol} open ({full_service})",
                "description": f"Service '{full_service}' is exposed on port {port_id}.",
                "raw_ref": xml_file_path,
            })

    return findings

def execute_and_export(
    target: str,
    ports: str,
    json_out: str = "outputs/nmap_findings.json",
):
    xml_path = run_nmap_scan(target=target, ports=ports)
    findings = parse_nmap_xml(xml_path)

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    return findings

if __name__ == "__main__":
    execute_and_export(target="127.0.0.1", ports="3000")
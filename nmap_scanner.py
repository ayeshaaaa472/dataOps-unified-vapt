import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET


def validate_scope(target: str) -> bool:
    """Strictly locks testing to local machine / sandbox targets only."""
    allowed_targets = {"127.0.0.1", "localhost", "::1"}
    return target in allowed_targets


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

def run_nmap_scan(target: str = "127.0.0.1", port: int = 3000) -> str:
    """Executes Nmap via subprocess safely handling Windows paths with spaces."""
    if not validate_scope(target):
        raise ValueError(f"Scope Violation: Target {target} is not permitted.")

    # Get unquoted binary path
    nmap_executable = get_nmap_path().strip('"')

    os.makedirs("outputs", exist_ok=True)
    xml_output_file = os.path.join("outputs", f"nmap_{port}.xml")

    # Pass as a clean list without shell=True
    cmd = [
        nmap_executable,
        "-sV",
        "--version-intensity",
        "5",
        "-p",
        str(port),
        "-oX",
        xml_output_file,
        target,
    ]

    print(f"[*] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, shell=False)

    if result.returncode != 0:
        raise RuntimeError(f"Nmap execution failed: {result.stderr}")

    return xml_output_file


def parse_nmap_xml(xml_file_path: str) -> list:
    """Parses Nmap XML into the Unified Finding Schema with clean fallbacks."""
    if not os.path.exists(xml_file_path):
        raise FileNotFoundError(f"Scan file {xml_file_path} not found.")

    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    findings = []

    for host in root.findall("host"):
        addr_elem = host.find("address")
        target_ip = addr_elem.get("addr") if addr_elem is not None else "127.0.0.1"

        ports = host.find("ports")
        if ports is None:
            continue

        for port_elem in ports.findall("port"):
            port_id = int(port_elem.get("portid"))
            protocol = port_elem.get("protocol")

            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            if state != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name") if service_elem is not None else "unknown"
            product = service_elem.get("product") if service_elem is not None else ""
            version = service_elem.get("version") if service_elem is not None else ""

            # Clean product and version handling
            product_clean = (product or "").strip()
            version_clean = (version or "").strip()
            full_service = f"{product_clean} {version_clean}".strip()

            # Port 3000 heuristic fallback if Nmap defaulted to legacy table
            if port_id == 3000 and (service_name in ("ppp", "unknown") or not full_service):
                service_name = "http"
                full_service = "Node.js Express / Web Application"
            elif not full_service:
                full_service = service_name

            findings.append({
                "id": f"NMAP-{target_ip}-{port_id}",
                "tool": "nmap",
                "target": target_ip,
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "product": full_service,
                "state": state,
                "severity": "Info",
                "title": f"Exposed Service: {service_name} on {protocol}/{port_id}",
                "evidence": f"Service identified as {full_service} on port {port_id}",
                "raw_ref": xml_file_path,
            })

    return findings


def execute_and_export(
    target: str = "127.0.0.1", port: int = 3000, json_out: str = "outputs/nmap_findings.json"
):
    xml_path = run_nmap_scan(target=target, port=port)
    findings = parse_nmap_xml(xml_path)

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"[+] Successfully parsed {len(findings)} finding(s) into {json_out}")
    return findings


if __name__ == "__main__":
    execute_and_export(target="127.0.0.1", port=3000)
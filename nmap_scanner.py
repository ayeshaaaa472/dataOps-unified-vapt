import json
import os
import subprocess
import xml.etree.ElementTree as ET


def validate_scope(target: str) -> bool:
    """Strictly locks testing to local machine / sandbox targets only."""
    allowed_targets = {"127.0.0.1", "localhost", "::1"}
    return target in allowed_targets


def run_nmap_scan(target: str = "127.0.0.1", port: int = 3000) -> str:
    """Executes Nmap via subprocess with XML output on a confirmed local target."""
    if not validate_scope(target):
        raise ValueError(
            f"Scope Violation: Target {target} is not permitted. Only localhost is allowed."
        )

    # Ensure output folder exists
    os.makedirs("outputs", exist_ok=True)
    xml_output_file = os.path.join("outputs", f"nmap_{port}.xml")

    # Command line: nmap -sV -p <port> -oX <xml_output_file> <target>
    cmd = ["nmap", "-sV", "-p", str(port), "-oX", xml_output_file, target]

    print(f"[*] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Nmap execution failed: {result.stderr}")

    return xml_output_file


def parse_nmap_xml(xml_file_path: str) -> list:
    """Parses standard Nmap XML into the project's Unified Finding Schema."""
    if not os.path.exists(xml_file_path):
        raise FileNotFoundError(f"Scan file {xml_file_path} not found.")

    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    findings = []

    # Iterate over all hosts in the XML
    for host in root.findall("host"):
        # Extract IP address
        addr_elem = host.find("address")
        target_ip = (
            addr_elem.get("addr") if addr_elem is not None else "127.0.0.1"
        )

        ports = host.find("ports")
        if ports is None:
            continue

        for port_elem in ports.findall("port"):
            port_id = port_elem.get("portid")
            protocol = port_elem.get("protocol")

            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            # We only record open ports as active findings
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
                else "unknown"
            )
            version = (
                service_elem.get("version")
                if service_elem is not None
                else ""
            )

            full_service = (
                f"{product} {version}".strip()
                if product != "unknown"
                else service_name
            )

            # Construct the unified finding object
            finding = {
                "id": f"NMAP-{target_ip}-{port_id}",
                "tool": "nmap",
                "target": target_ip,
                "port": int(port_id),
                "protocol": protocol,
                "service": service_name,
                "product": full_service,
                "state": state,
                "severity": "Info",
                "title": f"Exposed Service: {service_name} on {protocol}/{port_id}",
                "evidence": f"Service detected as {full_service} on port {port_id}",
                "raw_ref": xml_file_path,
            }
            findings.append(finding)

    return findings


def execute_and_export(
    target: str = "127.0.0.1", port: int = 3000, json_out: str = "outputs/nmap_findings.json"
):
    """Executes scan, parses XML, and writes normalized output to JSON."""
    xml_path = run_nmap_scan(target=target, port=port)
    findings = parse_nmap_xml(xml_path)

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(
        f"[+] Successfully parsed {len(findings)} finding(s) into {json_out}"
    )
    return findings


if __name__ == "__main__":
    # Test execution against the local Juice Shop container port
    execute_and_export(target="127.0.0.1", port=3000)
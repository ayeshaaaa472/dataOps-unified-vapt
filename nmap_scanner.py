import ipaddress
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

# Strict lab allowlist: loopback addresses and Docker default subnets
EXTRA_LAB_HOSTS = {"127.0.0.1", "localhost", "::1", "172.17.0.2"}


def validate_target(target: str) -> bool:
  """Validates that a target is strictly a local sandbox or loopback host."""
  if not target or not isinstance(target, str):
    return False

  target = target.strip().lower()

  # Block shell metacharacters and tricky formatting
  if any(char in target for char in [";", "&", "|", "`", "$", " ", "@"]):
    return False

  if target == "localhost" or target in EXTRA_LAB_HOSTS:
    return True

  try:
    ip = ipaddress.ip_address(target)
    return ip.is_loopback or str(ip) in EXTRA_LAB_HOSTS
  except ValueError:
    return False


def execute_and_export(
    target: str = "127.0.0.1", ports: str = "3000"
) -> List[Dict[str, Any]]:
  """Runs Nmap against an in-scope target with a hard execution timeout."""
  # Enforce scope check inside the execution function itself
  if not validate_target(target):
    raise ValueError(f"Target '{target}' is outside the authorized lab scope.")

  output_dir = "outputs"
  os.makedirs(output_dir, exist_ok=True)
  xml_path = os.path.join(output_dir, "nmap_target.xml")

  # Clean port string to accept only digits and commas
  clean_ports = "".join(c for c in ports if c.isdigit() or c == ",")
  if not clean_ports:
    clean_ports = "3000"

  cmd = ["nmap", "-sV", "-p", clean_ports, "-oX", xml_path, target]

  # Hard 30-second subprocess limit to prevent infinite hangs
  subprocess.run(cmd, check=True, timeout=30)

  return parse_nmap_xml(xml_path, target)


def parse_nmap_xml(xml_file: str, target_ip: str) -> List[Dict[str, Any]]:
  findings = []
  if not os.path.exists(xml_file):
    return findings

  tree = ET.parse(xml_file)
  root = tree.getroot()

  for host in root.findall("host"):
    ports_elem = host.find("ports")
    if ports_elem is None:
      continue

    for port_elem in ports_elem.findall("port"):
      state_elem = port_elem.find("state")
      if state_elem is not None and state_elem.get("state") == "open":
        port_id = port_elem.get("portid", "unknown")
        service_elem = port_elem.find("service")

        service_name = "unknown"
        product = ""
        if service_elem is not None:
          service_name = service_elem.get("name", "unknown")
          product = service_elem.get("product", "")

        # Report actual detected service without fabricated guesses
        reported_svc = (
            f"{product} ({service_name})" if product else service_name
        )

        findings.append({
            "id": f"NMAP-{port_id}",
            "tool": "Nmap",
            "title": f"Open Network Port {port_id}/{reported_svc}",
            "cve": "N/A",
            "cwe": "CWE-200",
            "severity": "LOW",
            "evidence": (
                f"State: open | Service: {reported_svc} on port {port_id}"
            ),
            "target": target_ip,
            "port": str(port_id),
            "raw_ref": xml_file,
            "confidence": 1.0,
            "status": "Suspected",
        })

  return findings
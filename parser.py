import os
import json
from urllib.parse import urlparse
from typing import List, Dict, Any

def parse_zap_json(file_path: str) -> List[Dict[str, Any]]:
    """Parses standard, legacy, and flat ZAP exports handling pluginId/pluginid."""
    findings = []
    if not os.path.exists(file_path):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return findings

    severity_map = {
        "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO",
        "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO"
    }

    sites = []
    if isinstance(data, list):
        sites = data
    elif isinstance(data, dict):
        if "site" in data:
            sites = data["site"] if isinstance(data["site"], list) else [data["site"]]
        elif "Report" in data and isinstance(data["Report"], dict):
            raw_sites = data["Report"].get("sites", data["Report"].get("site", []))
            sites = raw_sites if isinstance(raw_sites, list) else [raw_sites]
        elif "sites" in data:
            sites = data["sites"] if isinstance(data["sites"], list) else [data["sites"]]
        elif "alerts" in data:
            sites = [{"@host": "127.0.0.1", "@port": "3000", "alerts": data["alerts"]}]

    for site in sites:
        if not isinstance(site, dict):
            continue

        alerts = site.get("alerts", [])
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            raw_risk = str(alert.get("riskcode", alert.get("riskdesc", "1"))).split()[0]
            severity = severity_map.get(raw_risk.upper(), "LOW")

            instances = alert.get("instances", [])
            if isinstance(instances, dict):
                instances = [instances]

            uri_str = instances[0].get("uri", "") if instances else ""
            evidence_val = instances[0].get("evidence", "") if instances else ""

            parsed_uri = urlparse(uri_str)
            host = parsed_uri.hostname or site.get("@host", site.get("@name", "127.0.0.1"))
            port = str(parsed_uri.port or site.get("@port", "3000"))

            # Handle both pluginId and lowercase pluginid
            plugin_id = alert.get("pluginId") or alert.get("pluginid") or "ALERT"

            cwe_id = alert.get("cweid") or alert.get("cweId")
            cwe_tag = f"CWE-{cwe_id}" if cwe_id and str(cwe_id) not in ["-1", "0"] else "N/A"

            findings.append({
                "id": f"ZAP-{plugin_id}",
                "tool": "OWASP ZAP",
                "title": alert.get("alert", "Application Vulnerability"),
                "cve": "N/A",
                "cwe": cwe_tag,
                "severity": severity,
                "evidence": evidence_val or alert.get("desc", "Identified by ZAP rule.")[:200],
                "target": host,
                "port": port,
                "raw_ref": file_path,
                "confidence": 0.8 if str(alert.get("confidence", "2")) in ["2", "Medium"] else 0.9,
                "status": "Suspected"
            })

    return findings


def parse_nikto_json(file_path: str) -> List[Dict[str, Any]]:
    """Parses Nikto JSON reports whether formatted as a root dict or raw item list."""
    findings = []
    if not os.path.exists(file_path):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return findings

    items = []
    host = "127.0.0.1"
    port = "3000"

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        host = data.get("host", data.get("ip", "127.0.0.1"))
        port = str(data.get("port", "3000"))
        items = data.get("vulnerabilities", data.get("items", []))

    for item in items:
        if not isinstance(item, dict):
            continue
        msg = item.get("msg", item.get("description", "Server configuration issue identified."))
        nikto_id = item.get("id", item.get("OSVDB", item.get("nikto_id", "ALERT")))
        item_port = str(item.get("port", port))

        findings.append({
            "id": f"NIKTO-{nikto_id}",
            "tool": "Nikto (Import)",
            "title": msg[:80],
            "cve": "N/A",
            "cwe": "N/A",
            "severity": "LOW",
            "evidence": msg,
            "target": host,
            "port": item_port,
            "raw_ref": file_path,
            "confidence": 0.7,
            "status": "Suspected"
        })

    return findings
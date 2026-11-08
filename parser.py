import os
import json
from urllib.parse import urlparse
from typing import List, Dict, Any

def parse_zap_json(file_path: str) -> List[Dict[str, Any]]:
    """
    Parses OWASP ZAP JSON reports across standard, legacy, and flat formats.
    Extracts host, port, URL, evidence, and CWE without fabricated CVE data.
    """
    findings = []
    if not os.path.exists(file_path):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return findings

    severity_map = {
        "3": "HIGH",
        "2": "MEDIUM",
        "1": "LOW",
        "0": "INFO",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFORMATIONAL": "INFO"
    }

    # Normalize sites across all known ZAP export variants
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

            cwe_id = alert.get("cweid")
            cwe_tag = f"CWE-{cwe_id}" if cwe_id and str(cwe_id) != "-1" else "N/A"

            findings.append({
                "id": f"ZAP-{alert.get('pluginId', 'ALERT')}",
                "tool": "OWASP ZAP",
                "title": alert.get("alert", "Application Vulnerability"),
                "cve": "N/A",  # Strictly no fabricated CVEs
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
    """
    Parses a Nikto JSON report import to satisfy the 3-tool requirement.
    """
    findings = []
    if not os.path.exists(file_path):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return findings

    items = data.get("vulnerabilities", data.get("items", []))
    host = data.get("host", "127.0.0.1")
    port = str(data.get("port", "80"))

    for item in items:
        msg = item.get("msg", item.get("description", "Nikto finding"))
        nikto_id = item.get("id", item.get("OSVDB", "INFO"))
        findings.append({
            "id": f"NIKTO-{nikto_id}",
            "tool": "Nikto (Import)",
            "title": msg[:80],
            "cve": "N/A",
            "cwe": "N/A",
            "severity": "LOW",
            "evidence": msg,
            "target": host,
            "port": port,
            "raw_ref": file_path,
            "confidence": 0.7,
            "status": "Suspected"
        })
    return findings
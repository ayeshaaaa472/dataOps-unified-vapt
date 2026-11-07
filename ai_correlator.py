import os
import json
from typing import List, Dict, Any
from google import genai
from google.genai import types
from groq import Groq

def correlate_and_deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups findings by target and issue, merges duplicates across tools,
    and cross-correlates web findings against verified open Nmap ports.
    """
    deduped = {}
    open_ports = {
        str(f.get("port")) for f in findings 
        if f.get("tool") == "Nmap" and str(f.get("port")) not in ["unknown", "None", ""]
    }

    for f in findings:
        key = f"{f.get('target')}:{f.get('port')}:{f.get('title')}"
        if key in deduped:
            existing = deduped[key]
            if "merged_sources" not in existing:
                existing["merged_sources"] = [existing["tool"]]
            existing["merged_sources"].append(f["tool"])
            continue

        f_copy = dict(f)
        port_str = str(f.get("port"))
        
        # Cross-tool verification logic
        if f.get("tool") != "Nmap" and port_str in open_ports:
            f_copy["trust_reason"] = f"Verified: Nmap independently confirmed port {port_str} is open and accessible."
            f_copy["confidence"] = min(1.0, round(float(f_copy.get("confidence", 0.7)) + 0.15, 2))
        elif f.get("tool") == "Nmap":
            f_copy["trust_reason"] = "Direct network enumeration: Raw SYN/service response received."
        else:
            f_copy["trust_reason"] = "Single source reporting; no cross-tool network confirmation."

        deduped[key] = f_copy

    return list(deduped.values())


def calculate_formulaic_score(findings: List[Dict[str, Any]]) -> str:
    """
    Calculates an auditable risk score based on severity weights and confidence.
    """
    weight_map = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
        "INFO": 0
    }
    total_score = 0.0
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        conf = float(f.get("confidence", 0.7))
        total_score += weight_map.get(sev, 1) * conf

    if total_score >= 12:
        return "HIGH"
    elif total_score >= 5:
        return "MEDIUM"
    return "LOW"


def run_ai_correlation(findings: List[Dict[str, Any]], api_key: str = None) -> Dict[str, Any]:
    """
    Executes grounded AI analysis across correlated findings with Gemini -> Groq -> Deterministic fallback.
    """
    if not findings:
        return {
            "overall_risk_score": "LOW",
            "executive_summary": "No vulnerabilities identified in current scope.",
            "attack_path_analysis": "No attack vectors identified across assessed assets.",
            "prioritized_actions": [],
            "provider_used": "Deterministic Core"
        }

    processed_findings = correlate_and_deduplicate(findings)
    calculated_score = calculate_formulaic_score(processed_findings)

    system_prompt = (
        "You are a Senior VAPT Security Assessor. Analyze the findings strictly using the provided evidence.\n"
        "STRICT RULES:\n"
        "1. Use ONLY the findings provided. NEVER invent CVE IDs, exploits, or scores.\n"
        "2. If an asset service or CVE is unknown, state 'N/A' or 'Unknown'.\n"
        "3. Return ONLY valid JSON matching the requested schema."
    )

    user_prompt = f"""Target Assessment Findings:
{json.dumps(processed_findings, indent=2)}

Computed Formulaic Risk: {calculated_score}

Return a valid JSON object with EXACTLY this structure:
{{
  "overall_risk_score": "{calculated_score}",
  "executive_summary": "Factual 2-sentence summary grounded strictly in the findings.",
  "attack_path_analysis": "Step-by-step vector synthesis using only the confirmed open ports and alerts.",
  "prioritized_actions": [
    {{
      "priority": 1,
      "finding_id": "Exact ID from findings",
      "action": "Specific remediation step",
      "owner": "DevOps / Backend / SecOps"
    }}
  ]
}}"""

    effective_gemini_key = (api_key or os.getenv("GEMINI_API_KEY", "")).strip()

    # Tier 1: Google Gemini
    if effective_gemini_key:
        for model_name in ["gemini-2.5-flash", "gemini-flash-lite-latest", "gemini-1.5-flash"]:
            try:
                client = genai.Client(api_key=effective_gemini_key)
                response = client.models.generate_content(
                    model=model_name,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        response_mime_type="application/json",
                        temperature=0.1
                    )
                )
                data = json.loads(response.text)
                data["provider_used"] = f"Google Gemini ({model_name})"
                data["overall_risk_score"] = calculated_score
                return data
            except Exception:
                continue

    # Tier 2: Groq Fallback
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    if groq_key:
        try:
            client = Groq(api_key=groq_key)
            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            data = json.loads(chat_completion.choices[0].message.content)
            data["provider_used"] = "Groq (llama-3.3-70b-versatile)"
            data["overall_risk_score"] = calculated_score
            return data
        except Exception:
            pass

    # Tier 3: Deterministic Fallback
    return {
        "overall_risk_score": calculated_score,
        "executive_summary": f"Assessment identified {len(processed_findings)} total findings. Evaluated posture: {calculated_score}.",
        "attack_path_analysis": "Automated attack path synthesis unavailable (AI offline). Review open ports and high severity web alerts directly.",
        "prioritized_actions": [
            {
                "priority": idx + 1,
                "finding_id": f.get("id"),
                "action": f"Remediate {f.get('title')} on port {f.get('port')}",
                "owner": "Security Team"
            }
            for idx, f in enumerate(processed_findings[:3])
        ],
        "provider_used": "Deterministic Rules (Offline Fallback)"
    }
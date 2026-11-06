import json
import os
import time
from typing import Any, Dict, List
from dotenv import load_dotenv
from google import genai
from google.genai import types
from groq import Groq

# Load environment keys from .env
load_dotenv()


def build_correlation_prompt(findings: List[Dict[str, Any]]) -> str:
    findings_summary = []
    for item in findings:
        findings_summary.append(
            {
                "id": item.get("id"),
                "tool": item.get("tool"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "port": item.get("port"),
                "target": item.get("target"),
                "evidence": item.get("evidence"),
                "description": item.get("description"),
            }
        )

    prompt = f"""
You are an expert Application Security and DevSecOps Risk Assessor.
Analyze the following security assessment findings collected from network scanning (Nmap) and dynamic web scanning (OWASP ZAP).

### Normalized Tool Findings:
{json.dumps(findings_summary, indent=2)}

### Objectives:
1. Perform contextual correlation: How do open ports/services amplify or mitigate the identified web vulnerabilities?
2. Produce an overall contextual risk rating: CRITICAL, HIGH, MEDIUM, or LOW.
3. Highlight potential attack vectors or chains an adversary could leverage.
4. Provide a prioritized defensive remediation plan.

Respond strictly in valid JSON matching this exact structure:
{{
  "overall_risk_score": "CRITICAL | HIGH | MEDIUM | LOW",
  "executive_summary": "Concise high-level summary of security posture",
  "attack_path_analysis": "Explanation of potential exploitation vectors combining network and application findings",
  "prioritized_actions": [
    {{
      "priority": 1,
      "finding_id": "Finding ID or Tool reference",
      "action": "Immediate technical remediation step",
      "owner": "DevOps | Security | Backend Team"
    }}
  ]
}}
"""
    return prompt.strip()


def _call_groq_fallback(prompt: str) -> Dict[str, Any]:
    """Fallback handler using Groq if Gemini fails."""
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        raise ValueError("GROQ_API_KEY missing from environment.")

    client = Groq(api_key=groq_key)
    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
    )
    result = json.loads(completion.choices[0].message.content)
    result["provider_used"] = "Groq (Fallback)"
    return result


def run_ai_correlation(
    findings: List[Dict[str, Any]],
    api_key: str = None,
    candidate_models: List[str] = None,
) -> Dict[str, Any]:
    """Sends findings to Gemini with automatic model fallback on 503/404, then Groq."""
    if not findings:
        return {
            "overall_risk_score": "LOW",
            "executive_summary": "No open findings or services provided for correlation.",
            "attack_path_analysis": "None",
            "prioritized_actions": [],
        }

    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        raise ValueError("Gemini API Key missing.")

    client = genai.Client(api_key=key)
    prompt = build_correlation_prompt(findings)

    # Sequence of models to try if the primary one is busy or unavailable
    if candidate_models is None:
        candidate_models = [
            "gemini-flash-latest",
            "gemini-flash-lite-latest",
            "gemini-pro-latest",
            "gemini-2.5-flash-lite",
            "gemini-3.5-flash-lite",
            "gemini-3.5-flash",
            "gemini-3.6-flash",
            "gemini-3.7-flash",
        ]

    last_error = None
    for model_name in candidate_models:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            result = json.loads(response.text)
            result["provider_used"] = f"Google Gemini ({model_name})"
            return result
        except Exception as err:
            err_str = str(err)
            # If rate-limited or busy, try the next model in the pool
            if "503" in err_str or "404" in err_str:
                last_error = err
                time.sleep(1)
                continue
            last_error = err

    # If all Gemini models fail, fail over to Groq:
    print("[*] Gemini models exhausted. Failing over to Groq...")
    try:
        return _call_groq_fallback(prompt)
    except Exception as groq_err:
        raise RuntimeError(
            f"All candidate models failed. Last Gemini error: {last_error} | Groq error: {groq_err}"
        )


if __name__ == "__main__":
    print("[*] Starting AI correlation test...")

    from parser import parse_nmap_xml, parse_zap_json

    nmap_path = os.path.join("outputs", "nmap_target.xml")
    zap_path = os.path.join("imports", "sample_zap_report.json")

    nmap_findings = parse_nmap_xml(nmap_path) if os.path.exists(nmap_path) else []
    zap_findings = parse_zap_json(zap_path) if os.path.exists(zap_path) else []
    test_findings = nmap_findings + zap_findings

    if not test_findings:
        print("[!] No scan files found in outputs/ or imports/. Using synthetic findings...")
        test_findings = [
            {
                "id": "NMAP-127_0_0_1-3000",
                "tool": "Nmap",
                "title": "Open Service: HTTP on Port 3000",
                "severity": "Info",
                "target": "127.0.0.1",
                "port": "3000",
                "evidence": "Port 3000/tcp open (Node.js Express)",
                "description": "Port 3000 exposed on local loopback.",
            },
            {
                "id": "ZAP-40012",
                "tool": "OWASP ZAP",
                "title": "Cross Site Scripting (Reflected)",
                "severity": "High",
                "target": "127.0.0.1",
                "port": "3000",
                "evidence": "<script>alert(1)</script>",
                "description": "Reflected XSS on user profile search query.",
            },
        ]

    output = run_ai_correlation(test_findings)
    print("\n--- Correlation Result ---")
    print(json.dumps(output, indent=2))
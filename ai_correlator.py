import json
import os
import time
from typing import Any, Dict, List
from google import genai
from google.genai import types


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


def run_ai_correlation(
    findings: List[Dict[str, Any]],
    api_key: str = None,
    candidate_models: List[str] = None,
) -> Dict[str, Any]:
    """Sends findings to Gemini with automatic model fallback on 503/404."""
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
            return json.loads(response.text)
        except Exception as err:
            err_str = str(err)
            # If rate-limited or busy, try the next model in the pool
            if "503" in err_str or "404" in err_str:
                last_error = err
                time.sleep(1)
                continue
            raise err

    raise RuntimeError(
        f"All candidate models failed under high demand. Last error: {last_error}"
    )
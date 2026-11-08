================================================================================
                    AI VAPT TRIAGE & PRIORITIZATION COPILOT
                              System Architecture
================================================================================

+------------------------------------------------------------------------------+
|                           1. INPUT & SCOPE GATE                              |
|  - Target Validation: Strict RFC 1918 / 127.0.0.1 scope enforcement (prober) |
|  - Execution Plan: Human analyst approves scope and planned tasks            |
+------------------------------------------------------------------------------+
                                       │
                                       ▼
+------------------------------------------------------------------------------+
|                         2. INGESTION & DISCOVERY                             |
|  - Active Service Enumeration: Live Nmap subprocess discovery (XML output)   |
|  - Web Vulnerability Data: OWASP ZAP (JSON) parser                           |
|  - Web Server Security: Nikto (JSON) parser                                  |
+------------------------------------------------------------------------------+
                                       │
                                       ▼
+------------------------------------------------------------------------------+
|                     3. CORRELATION & TRUST REASONING                         |
|  - Deduplication: Normalized key grouping (target:port:title)                |
|  - Port Verification: Elevates confidence (+15%) if Nmap confirms open port  |
|  - Formulaic Baseline: Deterministic weighted risk score (Critical to Info)  |
+------------------------------------------------------------------------------+
                                       │
                                       ▼
+------------------------------------------------------------------------------+
|                       4. CONTEXTUAL RISK SYNTHESIS                           |
|  - Primary: Google Gemini (`gemini-3.8-flash`) structured JSON output         |
|  - Grounding Guardrails: Temperature 0.1, strict rule against hallucinated CVEs|
|  - Deterministic Fallback: Offline rule-based engine if external API fails   |
+------------------------------------------------------------------------------+
                                       │
                                       ▼
+------------------------------------------------------------------------------+
|                   5. HUMAN-IN-THE-LOOP & GOVERNANCE UI                       |
|  - Analyst Actions: Safe HTTP probe reachability test / Reject false positive |
|  - Dynamic Roadmap: Rejected findings automatically filtered from actions    |
|  - Append-Only Audit Log: Every approval, probe, and rejection recorded      |
+------------------------------------------------------------------------------+
                                       │
                                       ▼
+------------------------------------------------------------------------------+
|                           6. REPORT GENERATOR                                |
|  - Output: Controlled audit-ready PDF report (FPDF2)                         |
|  - Sections: Scope, Tools Matrix, Severity Stats, Remediation Roadmap, Log   |
+------------------------------------------------------------------------------+
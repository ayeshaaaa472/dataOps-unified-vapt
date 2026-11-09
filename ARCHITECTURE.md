# Architecture Overview
 
AI VAPT Triage Copilot
Team: 
- Ayesha Tabassum (GitHub: ayeshaaaa472) - https://github.com/ayeshaaaa472
- Shaik Abdul Aziz (GitHub: shaikabdulaziz23) - https://github.com/shaikabdulaziz23
 
This document covers: AI models, orchestration, tool adapters, data flow, state and memory, and security boundaries.
 
## 1. The big picture
 
The flow runs top to bottom. Every step writes to the audit log (sidebar on screen and audit_log.jsonl on disk).
 
```
+------------------------------------------------------------------------------+
| 1. INPUT & SCOPE GATE                                                        |
|                                                                              |
| - Scope lock: only localhost and loopback addresses (127.x.x.x, ::1)         |
| - Checked 3 times: plan approval, Nmap runner, and before every probe        |
| - Execution plan with reasons: analyst approves before anything runs         |
+------------------------------------------------------------------------------+
                                       |
                                       v
+------------------------------------------------------------------------------+
| 2. INGESTION & DISCOVERY                                                     |
|                                                                              |
| - Nmap (live): service detection on 1 port, 30 s limit, XML output           |
| - OWASP ZAP (import-only): JSON parser                                       |
| - Nikto (import-only): JSON parser                                           |
+------------------------------------------------------------------------------+
                                       |
                                       v
+------------------------------------------------------------------------------+
| 3. CORRELATION & TRUST REASONING                                             |
|                                                                              |
| - Common finding format: one record per finding                              |
| - Merge: same target, port and title become one finding                      |
| - Confidence +0.15 (max 1.0) when Nmap confirms the same port is open        |
| - Weighted risk score: severity x confidence (HIGH >= 12, MEDIUM >= 5)       |
+------------------------------------------------------------------------------+
                                       |
                                       v
+------------------------------------------------------------------------------+
| 4. CONTEXTUAL RISK SYNTHESIS (AI)                                            |
|                                                                              |
| - Gemini (gemini-3.8-flash, then other flash models)                         |
| - Groq (gpt-oss-120b, then qwen3.6-27b) if Gemini is unavailable             |
| - Rule-based fallback if no AI is reachable                                  |
| - Guardrails: temperature 0.1, only the given findings, never invent CVEs    |
+------------------------------------------------------------------------------+
                                       |
                                       v
+------------------------------------------------------------------------------+
| 5. HUMAN REVIEW & GOVERNANCE                                                 |
|                                                                              |
| - Approve Safe Probe: 1 plain GET, 3 s limit, no payloads                    |
| - Reject Finding: removed from the remediation roadmap                       |
| - Audit log: every approval, block, rejection and failure is saved           |
+------------------------------------------------------------------------------+
                                       |
                                       v
+------------------------------------------------------------------------------+
| 6. REPORT GENERATOR                                                          |
|                                                                              |
| - PDF (FPDF2): scope, tools, severity, summary, roadmap, evidence, log       |
| - Each finding shows its Raw Source for traceability                         |
+------------------------------------------------------------------------------+
```
 
## 2. AI models
 
The AI only writes the summary, the attack-path story and the fix recommendations. It does not scan, run commands or decide what is in scope.
 
- First choice: Google Gemini, model gemini-3.8-flash.
- If that fails: other Gemini "flash" models that the API key can use.
- If Gemini is unavailable: Groq, models openai/gpt-oss-120b and then qwen/qwen3.6-27b.
- If no AI is reachable: a rule-based summary built from the findings. The screen shows why the AI was unavailable.
The report always names the engine that wrote the narrative. The prompt tells the model to use only the findings provided and never invent CVE IDs, evidence or scores.
 
## 3. Orchestration
 
app.py controls the whole flow in a fixed, human-approved order:
 
1. Read the target and request.
2. Check the scope.
3. Show the plan and wait for approval.
4. Run the scan and imports.
5. Cross-check findings and calculate the risk score.
6. Ask the AI for the summary.
7. Show each finding for review.
8. Build the PDF on request.
The tool order is fixed by the plan, but the content of the plan, the trust reasons and the summary depend on what was actually found.
 
## 4. Tool adapters
 
- Nmap (live): nmap_scanner.py runs a service-detection scan on one port and saves the raw XML to outputs/nmap_target.xml.
- OWASP ZAP (import-only): parser.py reads a ZAP JSON report.
- Nikto (import-only): parser.py reads a Nikto JSON report.
- Safe probe: prober.py sends one plain HTTP GET request with a 3-second timeout, only after the analyst approves.
Not built: Nessus, OpenVAS / Greenbone, Burp Suite (planned) and Metasploit (unsupported on purpose).
 
## 5. Data flow
 
Every tool result is converted into one common finding record. The main fields are:
 
- id and tool (where it came from)
- title and severity
- target and port (what is affected)
- evidence (what the tool actually reported)
- raw_ref (path to the original file, so the finding can be traced)
- confidence (a number from 0 to 1)
- status (for example Suspected, Reachable, Rejected by Analyst)
- cwe (when the tool provides it)
- trust_reason (why the finding is trusted or doubted)
Cross-checking: findings with the same target, port and title are merged. If Nmap found the same port open, the other tools' findings get a higher confidence and a trust reason that says so.
 
Risk score: severity weight multiplied by confidence, added up across findings (HIGH at 12 or more, MEDIUM at 5 or more, otherwise LOW).
 
## 6. State and memory
 
- During an assessment, findings, review decisions and the log live in the Streamlit session.
- The audit log is also appended to audit_log.jsonl so it survives a page refresh.
- Raw Nmap output is kept in outputs/.
- There is no memory between assessments and no database.

## 7. Security boundaries
 
- Lab only: only localhost and loopback addresses are allowed. There is no DNS lookup in the check.
- The scope is checked at plan approval, inside the Nmap runner and before every probe (imported findings included).
- Nothing runs without approval: the scan needs plan approval, and each probe needs its own approval.
- Non-destructive: only a service-detection scan and one plain GET request. No exploit payloads, ever.
- Limits: one port per scan, 30-second scan limit, 3-second probe limit.
- The AI never runs commands. It only reads findings.
- Secrets: API keys come from a git-ignored .env file.
- Audit trail: every approval, block, rejection, failure and probe result is logged with a timestamp.

## 8. What is real and what is sample data
 
- Real: the Nmap scan of the local lab target.
- Sample: the ZAP and Nikto files in imports/ are hand-made demonstration data. Their findings are titled "Sample Data" and the report states that they are not live scans.
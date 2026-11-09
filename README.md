# AI VAPT Triage Copilot
 
A chat-style security assistant that plans an assessment on a safe lab target, combines results from different security tools, explains why it trusts or doubts each finding (with proof attached), and asks a human before doing anything risky.
 
Built for the DataOps Innovation Hackathon (HackTheCore) on Unstop.
Problem statement: AI Agent for Automated Penetration Testing.
 
## Team
 
Two people built this project together, and both worked on every part (planning, code, testing, report and pitch):
 
- Ayesha Tabassum (GitHub: ayeshaaaa472) - https://github.com/ayeshaaaa472
- Shaik Abdul Aziz (GitHub: shaikabdulaziz23) - https://github.com/shaikabdulaziz23
## The problem
 
Security testers use many tools. Each one produces its own long, messy report. Junior analysts and small IT teams without a security specialist then struggle to answer two questions: which results can I trust, and what should I fix first?
 
## Who it is for
 
Junior analysts and small IT teams who receive results from several tools and have no dedicated security expert to interpret them.
 
## What it does
 
1. You enter a lab target and a plain-language request.
2. The app shows a plan: which tools it will use and why. Nothing runs yet.
3. You click Approve Plan. Only then does the scan start.
4. It runs a live Nmap scan and imports ZAP and Nikto reports.
5. All results are converted into one common format and cross-checked against each other.
6. Each finding gets a confidence level and a plain-language "trust justification".
7. An AI model writes the summary, attack-path story and fix recommendations, using only the findings it was given.
8. For each finding you can Approve Safe Probe or Reject it. Every decision is logged.
9. You download a professional PDF report. Each finding in it points back to its raw source file.
## How it is different
 
- Autonomous AI pentest agents such as PentestGPT try to do the whole job on their own. This project keeps a human in charge of every active step.
- Result aggregators such as DefectDojo and Faraday merge findings but do not explain why a finding is trusted or doubted. This project explains each one and shows the evidence.
## Tools: what is live and what is not
 
Live (really runs):
- Nmap: service detection on one port, 30-second limit.
Import-only (reads saved output files):
- OWASP ZAP: JSON report.
- Nikto: JSON report.
Planned (not built): Nessus, OpenVAS / Greenbone, Burp Suite.
 
Unsupported: Metasploit. It is left out on purpose, because exploitation must never be automatic.
 
Important: the ZAP and Nikto files in the imports/ folder are hand-made demonstration data, not real scanner output. Their findings are titled "Sample Data" and the report says so. Only the Nmap results are live.
 
## Safety controls
 
- Lab only: targets must be localhost or a loopback address (127.x.x.x or ::1). Anything else is blocked. The check never does a DNS lookup, so tricky host names cannot slip through.
- The scope is checked three times: when the plan is approved, inside the Nmap runner, and before every probe (including findings that came from imported files).
- Human approval: the scan starts only after plan approval, and every probe needs its own approval.
- Non-destructive: the tool only runs a service-detection scan and one plain HTTP GET request. It never sends exploit payloads.
- Limits: one port per scan, 30-second scan limit, 3-second probe limit.
- The AI never runs commands. It only reads findings.
- Every approval, block, rejection, failure and probe result is written to an audit log with a timestamp (shown in the sidebar and saved to audit_log.jsonl).
- The AI is told to use only the findings provided and never invent CVE IDs, evidence or scores.
- API keys are read from a .env file, which is git-ignored.
## Setup and run
 
You need: Python 3.10 or newer, Nmap installed and on your PATH, Docker, and at least one AI key (Gemini or Groq). Without a key the app still runs with a rule-based summary.
 
```
git clone https://github.com/ayeshaaaa472/dataOps-unified-vapt.git
cd dataOps-unified-vapt
pip install -r requirements.txt
```
 
Create a file named .env in the project folder:
 
```
GEMINI_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
```
 
Start the practice target (it is only reachable from your own computer):
 
```
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```
 
Run the app:
 
```
python -m streamlit run app.py
```
 
Open the address Streamlit prints (usually http://localhost:8501).
 
## Demo walkthrough
 
1. Type 8.8.8.8 and approve. A red scope error appears and a BLOCKED line is logged.
2. Enter 127.0.0.1:3000. Read the plan and its reasons.
3. Approve the plan. Nmap runs live, ZAP and Nikto are imported.
4. Open the findings. Each shows confidence, status and a trust justification.
5. Use Approve Safe Probe on one finding and Reject on another. Check the audit log.
6. Download the PDF report and follow one finding to its Raw Source.
7. Stop Juice Shop and run again to see a safe failure. Compare with the tool list above, which states honestly what is live.
## How risk is calculated
 
Each finding gets a weight from its severity (Critical 10, High 7, Medium 4, Low 1, Info 0), multiplied by its confidence. The total sets the overall rating: 12 or more is HIGH, 5 or more is MEDIUM, anything lower is LOW.
 
Confidence starts at 0.9 for Nmap, 0.7 for Nikto and 0.8 or 0.9 for ZAP (taken from ZAP's own confidence). It goes up by 0.15 (maximum 1.0) when Nmap independently confirms that the same port is open.
 
## Sample output
 
sample_vapt_report.pdf is a report generated by this app from a real run against a local OWASP Juice Shop container.
 
Demo video: [ADD VIDEO LINK HERE]
 
More detail on how everything fits together: see ARCHITECTURE.md.
 
## Known limitations
 
- Only Nmap is live. The ZAP and Nikto data used by default are labelled samples.
- Duplicates are only merged when two findings have the same target, port and title. Cross-tool correlation mainly raises confidence when Nmap confirms an open port.
- The safe probe only checks that an endpoint answers. It does not prove that a vulnerability exists, and the status text says so.
- The AI summary is written before the analyst reviews the findings, so a rejected finding can still appear in the story. The report notes this.
- AI output can be wrong. A person should always review it.
- Tested only on Windows against a local OWASP Juice Shop container.
- No retesting, comparison or export formats other than PDF.
## Standards
 
CWE identifiers are shown when an imported ZAP report contains them. The project does not calculate CVSS scores and never generates CVE IDs; unknown values show as N/A. The standards named in the problem statement (NIST SP 800-115, OWASP Top 10, MITRE ATT&CK, NIST CSF 2.0) guided the workflow and the report layout only. Using them does not mean formal compliance.
 
## Licensing
 
This project uses the MIT License (see the LICENSE file). It does not bundle any third-party security tool. Nmap, OWASP ZAP, Nikto, OWASP Juice Shop and the Python libraries listed in requirements.txt are used or recommended separately, each under its own licence. Commercial tools such as Nessus are not included.
 
## Project files
 
```
app.py                   Streamlit app (screens, plan, approval, review, report download)
nmap_scanner.py          Scope check and live Nmap scan
parser.py                ZAP and Nikto JSON import
ai_correlator.py         Cross-checking, trust reasons, risk score, AI summary
prober.py                Safe HTTP probe
report_generator.py      PDF report
imports/                 Sample ZAP and Nikto files (demonstration data)
outputs/                 Raw Nmap output from the run used for the sample report
sample_vapt_report.pdf   Sample report generated by the app
ARCHITECTURE.md          Architecture overview
requirements.txt         Python dependencies
LICENSE                  MIT License
```
 
## Future work
 
Live ZAP and Nikto connections, Nessus and OpenVAS imports, multi-host scope management, retesting and change comparison, remediation tracking, and CVSS-based scoring.
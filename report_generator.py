import datetime
from typing import List, Dict, Any
from fpdf import FPDF

class VAPTReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(30, 41, 59)
        self.cell(0, 10, "Automated VAPT Assessment & Triage Report", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(203, 213, 225)
        self.line(10, 22, 200, 22)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Controlled Document", align="C")


def clean_text(text: Any) -> str:
    if text is None:
        return ""
    s = str(text)
    replacements = {
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2014": "-", "\u2013": "-", "\u2022": "*"
    }
    for orig, repl in replacements.items():
        s = s.replace(orig, repl)
    return s.encode("latin-1", "replace").decode("latin-1")


def generate_pdf_report(
    target: str,
    analysis_data: Dict[str, Any],
    findings: List[Dict[str, Any]],
    audit_log: List[Dict[str, Any]],
    zap_is_sample: bool = True,
    nikto_is_sample: bool = True
) -> bytes:
    pdf = VAPTReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # 1. Scope & Rules of Engagement
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 6, "1. Engagement Scope & Rules of Engagement", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Authorized Target Scope: {clean_text(target)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"Execution Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(10)
    pdf.multi_cell(190, 5, "Rules of Engagement: Non-destructive local sandbox testing restricted strictly to authorized loopback assets.")
    pdf.ln(3)

    # 2. Tools Matrix
    zap_label = "Import (Sample Data)" if zap_is_sample else "Import (Custom Ingestion)"
    nikto_label = "Import (Sample Data)" if nikto_is_sample else "Import (Custom Ingestion)"
    engine_used = clean_text(analysis_data.get("provider_used", "Deterministic Rules (Offline Fallback)"))

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "2. Tools & Ingestion Sources", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, "- Nmap Network Mapper: Live Subprocess Discovery", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"- OWASP ZAP (Web Application Scan): {zap_label}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"- Nikto (Server Configuration): {nikto_label}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"- Correlation & Prioritization Engine: {engine_used}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # 3. Posture & Severity Distribution
    score = analysis_data.get("overall_risk_score", "LOW").upper()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "3. Risk Posture & Severity Distribution", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 5, f"Overall Posture Rating: {score}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Severity Counts: Critical: {counts['CRITICAL']} | High: {counts['HIGH']} | Medium: {counts['MEDIUM']} | Low: {counts['LOW']}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # 4. Executive Summary
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "4. Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(10)
    pdf.multi_cell(190, 5, clean_text(analysis_data.get("executive_summary", "No summary provided.")))
    pdf.ln(3)

    # 5. Attack Path Analysis
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "5. Attack Path Synthesis", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(10)
    pdf.multi_cell(190, 5, clean_text(analysis_data.get("attack_path_analysis", "No attack vectors identified.")))
    pdf.ln(3)

    # 6. Prioritized Actions
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "6. Remediation Roadmap", new_x="LMARGIN", new_y="NEXT")
    actions = analysis_data.get("prioritized_actions", [])
    if actions:
        for act in actions:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, f"Priority {act.get('priority')} | ID: {clean_text(act.get('finding_id'))} | Owner: {clean_text(act.get('owner'))}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_x(10)
            pdf.multi_cell(190, 4, f"Action: {clean_text(act.get('action'))}")
            pdf.ln(1)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 5, "No prioritized actions found.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # 7. Unified Findings Breakdown
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, f"7. Finding Evidence & Provenance ({len(findings)})", new_x="LMARGIN", new_y="NEXT")
    for f in findings:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, f"[{f.get('severity', 'INFO').upper()}] {clean_text(f.get('title'))} (Tool: {clean_text(f.get('tool'))})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        conf_pct = int(float(f.get('confidence', 0.8)) * 100)
        pdf.cell(0, 4, f"Target: {clean_text(f.get('target'))}:{clean_text(f.get('port'))} | Confidence: {conf_pct}% | Status: {clean_text(f.get('status', 'Suspected'))}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(10)
        pdf.multi_cell(190, 4, f"Trust Justification: {clean_text(f.get('trust_reason', 'Single tool report'))}")
        pdf.set_x(10)
        pdf.multi_cell(190, 4, f"Evidence: {clean_text(f.get('evidence', 'No raw snippet'))}")
        pdf.ln(2)
    pdf.ln(2)

    # 8. Limitations & Audit Log
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "8. Limitations & Audit Trail", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_x(10)
    pdf.multi_cell(190, 4, "Limitations: Testing was strictly non-destructive and scoped solely to approved target ports. Safe HTTP probes evaluate endpoint reachability without verifying payload execution.")
    pdf.ln(2)
    for entry in audit_log:
        ts = clean_text(entry.get("timestamp"))
        act = clean_text(entry.get("action"))
        stat = clean_text(entry.get("status"))
        pdf.set_x(10)
        pdf.multi_cell(190, 4, f"[{ts}] [{stat}] {act}")

    return bytes(pdf.output())
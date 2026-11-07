import datetime
from typing import Any, Dict, List
from fpdf import FPDF


class VAPTReportPDF(FPDF):

  def header(self):
    self.set_font("Helvetica", "B", 15)
    self.set_text_color(30, 41, 59)
    self.cell(0, 10, "AI VAPT Triage & Assessment Report", ln=True, align="L")
    self.set_draw_color(203, 213, 225)
    self.line(10, 22, 200, 22)
    self.ln(5)

  def footer(self):
    self.set_y(-15)
    self.set_font("Helvetica", "I", 8)
    self.set_text_color(148, 163, 184)
    self.cell(
        0, 10, f"Page {self.page_no()}/{{nb}} | Confidential", align="C"
    )


def clean_text(text: Any) -> str:
  """Sanitizes text to prevent Latin-1 encoding errors in basic PDF fonts."""
  if text is None:
    return ""
  s = str(text)
  replacements = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2014": "-",
    "\u2013": "-",
    "\u2022": "*",
  }
  for orig, repl in replacements.items():
    s = s.replace(orig, repl)
  return s.encode("latin-1", "replace").decode("latin-1")


def generate_pdf_report(
    target: str,
    analysis_data: Dict[str, Any],
    findings: List[Dict[str, Any]],
    audit_log: List[Dict[str, Any]],
) -> bytes:
  """Generates a binary PDF buffer containing executive summary, attack analysis,

  findings, and audit history.
  """
  pdf = VAPTReportPDF()
  pdf.alias_nb_pages()
  pdf.add_page()
  pdf.set_auto_page_break(auto=True, margin=15)

  # Metadata block
  pdf.set_font("Helvetica", "", 10)
  pdf.set_text_color(71, 85, 105)
  gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  pdf.cell(0, 6, f"Target Scope: {clean_text(target)}", ln=True)
  pdf.cell(0, 6, f"Generated On: {gen_time}", ln=True)

  # Posture rating
  score = analysis_data.get("overall_risk_score", "UNKNOWN").upper()
  pdf.ln(3)
  pdf.set_font("Helvetica", "B", 12)
  if score == "CRITICAL":
    pdf.set_text_color(220, 38, 38)
  elif score == "HIGH":
    pdf.set_text_color(234, 88, 12)
  elif score == "MEDIUM":
    pdf.set_text_color(202, 138, 4)
  else:
    pdf.set_text_color(22, 163, 74)

  pdf.cell(0, 8, f"Contextual Risk Posture: {score}", ln=True)
  pdf.set_text_color(30, 41, 59)
  pdf.ln(2)

  # Executive Summary
  pdf.set_font("Helvetica", "B", 11)
  pdf.cell(0, 6, "1. Executive Summary", ln=True)
  pdf.set_font("Helvetica", "", 9)
  exec_summary = analysis_data.get("executive_summary", "No summary provided.")
  pdf.multi_cell(0, 5, clean_text(exec_summary))
  pdf.ln(3)

  # Attack Path Analysis
  pdf.set_font("Helvetica", "B", 11)
  pdf.cell(0, 6, "2. Attack Path & Vector Synthesis", ln=True)
  pdf.set_font("Helvetica", "", 9)
  attack_path = analysis_data.get(
      "attack_path_analysis", "No attack path identified."
  )
  pdf.multi_cell(0, 5, clean_text(attack_path))
  pdf.ln(3)

  # Remediation Roadmap
  pdf.set_font("Helvetica", "B", 11)
  pdf.cell(0, 6, "3. Prioritized Remediation Roadmap", ln=True)
  actions = analysis_data.get("prioritized_actions", [])
  if actions:
    for act in actions:
      pdf.set_font("Helvetica", "B", 9)
      pdf.cell(
          0,
          5,
          f"Priority {act.get('priority')} | ID: {clean_text(act.get('finding_id'))} | Owner: {clean_text(act.get('owner'))}",
          ln=True,
      )
      pdf.set_font("Helvetica", "", 8)
      pdf.multi_cell(0, 4, f"Action: {clean_text(act.get('action'))}")
      pdf.ln(1)
  else:
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 5, "No prioritized actions found.", ln=True)
  pdf.ln(3)

  # Tool Findings Breakdown
  pdf.set_font("Helvetica", "B", 11)
  pdf.cell(0, 6, f"4. Unified Tool Findings ({len(findings)})", ln=True)
  for idx, f in enumerate(findings, 1):
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(
        0,
        5,
        f"[{f.get('severity', 'INFO').upper()}] {clean_text(f.get('title', 'Unknown'))} ({clean_text(f.get('tool', 'Tool'))})",
        ln=True,
    )
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(
        0,
        4,
        f"Target: {clean_text(f.get('target', 'N/A'))}:{clean_text(f.get('port', 'N/A'))}",
        ln=True,
    )
    evidence = clean_text(f.get("evidence", "N/A"))
    if evidence and evidence != "N/A":
      pdf.multi_cell(0, 4, f"Evidence: {evidence}")
    pdf.ln(1)
  pdf.ln(3)

  # Activity Audit Log
  pdf.set_font("Helvetica", "B", 11)
  pdf.cell(0, 6, f"5. Activity Audit Log ({len(audit_log)} entries)", ln=True)
  pdf.set_font("Courier", "", 8)
  for entry in audit_log:
    ts = clean_text(entry.get("timestamp"))
    act = clean_text(entry.get("action"))
    stat = clean_text(entry.get("status"))
    pdf.cell(0, 4, f"[{ts}] [{stat}] {act}", ln=True)

  return bytes(pdf.output())
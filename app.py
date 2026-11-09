import os
import json
import datetime
import base64
from PIL import Image
from urllib.parse import urlparse
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from nmap_scanner import execute_and_export, validate_target
from parser import parse_zap_json, parse_nikto_json
from ai_correlator import correlate_and_deduplicate, run_ai_correlation
from prober import execute_benign_probe
from report_generator import generate_pdf_report

load_dotenv()

# 1. Page title and icon
icon_target = ".streamlit/shield_icon.png" if os.path.exists(".streamlit/shield_icon.png") else ".streamlit\\shield_icon.png"
st.set_page_config(
    page_title="VAPT Copilot",
    page_icon=icon_target if os.path.exists(icon_target) else "🛡️",
    layout="wide"
)

# Function to load background directly from .streamlit folder
def set_global_background(filename="bg_pattern.jpg"):
    abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".streamlit", filename)
    if os.path.exists(abs_path):
        with open(abs_path, "rb") as img_file:
            encoded_str = base64.b64encode(img_file.read()).decode()
        
        st.markdown(f"""
        <style>
        /* Global Background across all tabs & sessions */
        .stApp {{
            background: linear-gradient(rgba(11, 18, 32, 0.88), rgba(11, 18, 32, 0.88)), 
                        url("data:image/jpeg;base64,{encoded_str}") !important;
            background-size: cover !important;
            background-position: center !important;
            background-repeat: no-repeat !important;
            background-attachment: fixed !important;
        }}

        /* Keep tabs transparent to show background depth */
        div[data-testid="stTabs"] > div {{
            background-color: transparent !important;
        }}
        
        /* Sidebar glassmorphism */
        section[data-testid="stSidebar"] {{
            background-color: rgba(17, 28, 44, 0.85) !important;
            backdrop-filter: blur(10px) !important;
        }}
        </style>
        """, unsafe_allow_html=True)

# Apply immediately
set_global_background("bg_pattern.jpg")

# Custom UI Polish matching the steel blue theme
st.markdown(r"""
<style>
    /* Metric Cards */
    .metric-card {
        background: #172438;
        border: 1px solid #23354E;
        border-radius: 8px;
        padding: 14px 16px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        transition: border-color 0.2s ease-in-out;
    }
    .metric-card:hover {
        border-color: #5B8DBD;
    }
    .metric-title {
        color: #8CA3C3;
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 4px;
    }
    .metric-val {
        color: #F0F4FA;
        font-size: 1.3rem;
        font-weight: 700;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .metric-sub {
        color: #7085A0;
        font-size: 0.75rem;
        margin-top: 3px;
    }

    /* Expander card header refinement */
    .streamlit-expanderHeader {
        background-color: #172438 !important;
        border: 1px solid #23354E !important;
        border-radius: 6px !important;
    }

    /* Terminal Console Font for Execution Status Box */
    div[data-testid="stStatusWidget"],
    div[data-testid="stStatusWidget"] * {
        font-family: "Cascadia Code", "Consolas", "Courier New", "Fira Code", monospace !important;
    }

    div[data-testid="stStatusWidget"] div[data-testid="stMarkdownContainer"] p,
    div[data-testid="stStatusWidget"] div[data-testid="stMarkdownContainer"] blockquote,
    div[data-testid="stStatusWidget"] div[data-testid="stMarkdownContainer"] {
        font-family: "Cascadia Code", "Consolas", "Courier New", "Fira Code", monospace !important;
        font-size: 0.84rem !important;
        color: #38bdf8 !important;
        letter-spacing: 0.02em !important;
        line-height: 1.6 !important;
        border-left-color: #0284c7 !important;
    }

    div[data-testid="stStatusWidget"] {
        background-color: #0A0F18 !important;
        border: 1px solid #1E2D42 !important;
        border-radius: 8px !important;
    }
</style>
""", unsafe_allow_html=True)

AUDIT_LOG_FILE = "audit_log.jsonl"

def add_audit_entry(action: str, status: str):
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "status": status
    }
    if "audit_log" not in st.session_state:
        st.session_state["audit_log"] = []
    st.session_state["audit_log"].append(entry)
    
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

if "audit_log" not in st.session_state:
    st.session_state["audit_log"] = []
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        st.session_state["audit_log"].append(json.loads(line.strip()))
        except Exception:
            pass

# Sidebar: Honest 7-Tool Benchmark Status and Audit Log
st.sidebar.title("🛠️ Integration Status")
integration_data = {
    "Tool": ["Nmap", "OWASP ZAP", "Nikto", "Burp Suite", "OpenVAS", "Nessus", "Metasploit"],
    "Type": ["Network", "Web App", "Web Server", "Proxy/DAST", "Infra Vuln", "Compliance", "Exploitation"],
    "Status": [
        "Live Subprocess",
        "Import (JSON)",
        "Import (JSON)",
        "Planned (Import)",
        "Planned (XML)",
        "Planned (.nessus)",
        "Unsupported"
    ],
}
st.sidebar.table(pd.DataFrame(integration_data))

st.sidebar.markdown("---")
st.sidebar.title("Activity Audit Log")
if st.session_state["audit_log"]:
    for entry in reversed(st.session_state["audit_log"][-8:]):
        st.sidebar.text(f"[{entry['timestamp']}]\n{entry['action']}\nStatus: {entry['status']}\n-------------------------")
else:
    st.sidebar.caption("No activities recorded yet.")

# Main Interface
header_col1, header_col2 = st.columns([0.06, 0.94], vertical_alignment="center")

with header_col1:
    if os.path.exists(".streamlit/shield_icon.png"):
        st.image(".streamlit/shield_icon.png", width=56)
    elif os.path.exists(".streamlit\\shield_icon.png"):
        st.image(".streamlit\\shield_icon.png", width=56)
    else:
        st.markdown("## 🛡️")

with header_col2:
    st.title("VAPT Copilot")

st.caption("Human-in-the-Loop Security Assessment, Verification & Contextual Risk Prioritization")

target_input = st.text_input("Target Scope (Lab IP):", "127.0.0.1:3000")

col_upload1, col_upload2 = st.columns(2)
with col_upload1:
    uploaded_zap = st.file_uploader("Upload OWASP ZAP Report (JSON)", type=["json"])
with col_upload2:
    uploaded_nikto = st.file_uploader("Upload Nikto Report (Optional JSON)", type=["json"])

clean_target = target_input.strip()
if not clean_target.startswith(("http://", "https://")):
    clean_target = "http://" + clean_target
parsed = urlparse(clean_target)
target_host = parsed.hostname or "127.0.0.1"
target_port = str(parsed.port or "3000")

if "request_intent" not in st.session_state:
    st.session_state["request_intent"] = ""

chat_text = st.chat_input("Tell the assistant what to assess (for example: Check the web app on port 3000 for exposure)")
if chat_text:
    st.session_state["request_intent"] = chat_text.strip()

request_intent = st.session_state["request_intent"]
if not request_intent:
    with st.chat_message("assistant"):
        st.markdown("Hi! I am your security assessment assistant. Enter your lab target above, then tell me in the chat box what you'd like me to look into. I will prepare an approval plan before touching anything.")
    st.stop()

# Conversational Execution Plan Card
st.subheader("Assessment Plan")
with st.chat_message("user"):
    st.markdown(f"**Assessment request:** {request_intent}")
    st.caption(f"Target: `{target_host}:{target_port}`")

with st.chat_message("assistant"):
    st.markdown(f"""Understood. Before I run anything, here is my plan for `{target_host}:{target_port}`:

1. `[Network]` **Nmap Service Discovery** (Timeout: 30s) — *Reason: Identify active listening ports to validate web vulnerability exposure.*
2. `[Web]` **OWASP ZAP Ingestion** ({'Custom Upload' if uploaded_zap else 'Sample Dataset'}) — *Reason: Ingest application-layer findings (SQLi, missing security headers).*
3. `[Server]` **Nikto Ingestion** ({'Custom Upload' if uploaded_nikto else 'Sample Dataset'}) — *Reason: Discover web server configuration flaws and information disclosures.*
4. `[Correlation]` **Deterministic Python Cross-Referencing & Multi-Tier AI Synthesis** — *Reason: Deduplicate findings and elevate confidence on open network ports.*

**[Requires Approval]** Nothing runs until you approve this plan with the button below.""")

if st.button(" Approve Plan & Execute Assessment", type="primary"):
    if not validate_target(target_host):
        st.error(f"🚫 I can't scan `{target_host}`. It is outside the authorized lab boundary, and I only test local safe targets on your own machine.")
        add_audit_entry(f"Scope violation blocked for target: {target_host}", "BLOCKED")
    else:
        add_audit_entry(f"Plan approved by analyst for {target_host}:{target_port}", "AUTHORIZED")

        with st.status("Executing assessment according to approved plan...", expanded=True) as status:
            st.code("[1/5] Validating target boundary and RFC 1918 scope...", language="bash")
            
            # 1. Live Nmap
            st.code(f"[2/5] Running Nmap active service discovery on port {target_port}...", language="bash")
            try:
                network_findings = execute_and_export(target=target_host, ports=target_port)
                add_audit_entry(f"Nmap scan completed: {len(network_findings)} port(s) detected", "OK")
            except Exception as err:
                network_findings = []
                add_audit_entry(f"Nmap execution failed/empty: {err}", "FAILED")

            # 2. ZAP Ingestion
            st.code("[3/5] Ingesting OWASP ZAP application vulnerability records...", language="bash")
            zap_is_sample = uploaded_zap is None
            zap_path = os.path.join("imports", "sample_zap_report.json")
            if uploaded_zap is not None:
                zap_path = os.path.join("imports", "uploaded_temp_zap.json")
                os.makedirs("imports", exist_ok=True)
                with open(zap_path, "wb") as f:
                    f.write(uploaded_zap.getbuffer())
                add_audit_entry("Loaded custom OWASP ZAP JSON export", "OK")
            
            try:
                web_findings = parse_zap_json(zap_path)
            except Exception as zap_err:
                web_findings = []
                add_audit_entry(f"ZAP parsing failed: {zap_err}", "FAILED")

            # 3. Nikto Ingestion
            st.code("[4/5] Ingesting Nikto web server configuration findings...", language="bash")
            nikto_is_sample = uploaded_nikto is None
            nikto_path = os.path.join("imports", "sample_nikto_report.json")
            if uploaded_nikto is not None:
                nikto_path = os.path.join("imports", "uploaded_temp_nikto.json")
                os.makedirs("imports", exist_ok=True)
                with open(nikto_path, "wb") as f:
                    f.write(uploaded_nikto.getbuffer())
                add_audit_entry("Loaded custom Nikto JSON export", "OK")
            
            try:
                nikto_findings = parse_nikto_json(nikto_path)
            except Exception as nikto_err:
                nikto_findings = []
                add_audit_entry(f"Nikto parsing failed: {nikto_err}", "FAILED")

            # Correlation
            st.code("[*] Correlating network service reachability with application findings...", language="bash")
            raw_findings = (network_findings or []) + (web_findings or []) + (nikto_findings or [])
            
            try:
                st.session_state["current_findings"] = correlate_and_deduplicate(raw_findings)
            except Exception as corr_err:
                st.session_state["current_findings"] = raw_findings
                add_audit_entry(f"Correlation fallback engaged: {corr_err}", "FALLBACK")

            st.session_state["zap_is_sample"] = zap_is_sample
            st.session_state["nikto_is_sample"] = nikto_is_sample

            # 4. Multi-tier AI
            st.code("[5/5] Synthesizing contextual risk analysis with AI engine...", language="bash")
            try:
                triage_analysis = run_ai_correlation(st.session_state["current_findings"])
            except Exception as ai_err:
                triage_analysis = {
                    "overall_risk_score": "MEDIUM",
                    "provider_used": "Deterministic Rule Fallback",
                    "executive_summary": f"Context correlation performed under fallback mode: {ai_err}",
                    "attack_path_analysis": "Automated path analysis engaged via heuristic fallback.",
                    "prioritized_actions": []
                }
            
            st.session_state["triage_report"] = triage_analysis
            add_audit_entry(f"Correlation completed via {triage_analysis.get('provider_used')}", "OK")

            status.update(label="✔ Assessment complete", state="complete", expanded=False)
            st.rerun()

# Results Section
if st.session_state.get("current_findings"):
    st.markdown("---")
    
    # Top Summary Metric Cards
    report = st.session_state.get("triage_report", {})
    findings = st.session_state.get("current_findings", [])
    
    # Calculate high severity count for the card badge
    high_count = sum(1 for f in findings if str(f.get("severity", "")).upper() in ["HIGH", "CRITICAL"])
    posture = report.get("overall_risk_score", "MEDIUM")
    engine = report.get("provider_used", "Fallback")

    # Clean up any slashes and stray parentheses for a neat card label
    engine_display = engine.split("/")[-1].rstrip(")") if "/" in engine else engine

    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Total Findings</div>
            <div class="metric-val">{len(findings)} <span style="font-size:0.85rem; color:#F87171;">({high_count} High)</span></div>
            <div class="metric-sub">Deduplicated from 3 tools</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m2:
        posture_color = "#F87171" if posture in ["CRITICAL", "HIGH"] else ("#FBBF24" if posture == "MEDIUM" else "#34D399")
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Risk Posture</div>
            <div class="metric-val" style="color: {posture_color};">{posture}</div>
            <div class="metric-sub">Contextual Exposure Assessment</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Active AI Engine</div>
            <div class="metric-val" title="{engine}">{engine_display}</div>
            <div class="metric-sub">Multi-tier fallback ready</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Data Pipeline</div>
            <div class="metric-val">Nmap + ZAP + Nikto</div>
            <div class="metric-sub">Live Subprocess + JSON Ingest</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    # Tabs Layout
    tab_findings, tab_report, tab_plan, tab_audit = st.tabs([
        "Correlated Findings",
        "AI Synthesis & PDF Export",
        "Original Plan",
        "Full Audit Trail"
    ])

    with tab_findings:
        st.subheader(f"Ingested & Correlated Findings ({len(findings)})")
        
        # Colored severity markers
        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🔴",
            "MEDIUM": "🟠",
            "LOW": "🟡",
            "INFO": "🔵"
        }

        for idx, finding in enumerate(findings):
            sev = str(finding.get("severity", "INFO")).upper()
            icon = severity_icons.get(sev, "⚪")
            tool = finding.get("tool", "Scanner")
            title = finding.get("title", "Unknown Finding")
            
            # Crisp header title separating tool from vulnerability name
            expander_title = f"{icon} [{sev}] {title} — [{tool}]"
            
            with st.expander(expander_title):
                col_f1, col_f2 = st.columns([1.2, 0.8])
                with col_f1:
                    st.markdown(f"**Asset:** `{finding.get('target')}:{finding.get('port')}` &nbsp;|&nbsp; **Status:** `{finding.get('status')}`")
                    conf = int(float(finding.get("confidence", 0.8)) * 100)
                    st.markdown(f"**Confidence Rating:** `{conf}%`")
                    st.info(f"**🛡️ Trust Justification:** {finding.get('trust_reason', 'Single tool report.')}")
                    if finding.get("cwe") and finding.get("cwe") != "N/A":
                        st.caption(f"Classification / CWE: {finding.get('cwe')}")
                with col_f2:
                    st.markdown("**Raw Ingested Evidence:**")
                    st.code(finding.get("evidence", "No raw snippet available"), language="text")
                    st.caption(f"Source Reference: `{finding.get('raw_ref', 'N/A')}`")

                st.markdown("---")
                col_btn1, col_btn2, _ = st.columns([1.5, 1.5, 4])
                with col_btn1:
                    if st.button("⚡ Approve Safe Probe", key=f"probe_{idx}", type="primary"):
                        target_to_probe = str(finding.get("target") or "127.0.0.1")
                        port_to_probe = str(finding.get("port") or target_port)
                        if not validate_target(target_to_probe):
                            finding["status"] = "Probe blocked: target outside authorized lab scope"
                            add_audit_entry(f"Probe blocked on {finding.get('id')}: {target_to_probe}", "BLOCKED")
                        else:
                            try:
                                probe_result = execute_benign_probe(target_to_probe, port_to_probe)
                                sc = int(probe_result.get("status_code", 0) or 0)
                                if sc > 0:
                                    finding["status"] = f"Reachable (HTTP {sc}); vulnerability not confirmed"
                                else:
                                    finding["status"] = "Probe Unreachable (Connection Refused)"
                                add_audit_entry(f"Benign probe on {finding.get('id')} -> {finding['status']}", "VERIFIED")
                            except Exception as probe_err:
                                finding["status"] = "Probe Failed"
                                add_audit_entry(f"Probe failed on {finding.get('id')}: {probe_err}", "ERROR")
                        st.session_state["current_findings"][idx] = finding
                        st.rerun()
                        
                with col_btn2:
                    if st.button("❌ Reject Finding", key=f"rej_{idx}"):
                        finding["status"] = "Rejected by Analyst"
                        add_audit_entry(f"Finding {finding.get('id')} rejected by analyst", "REJECTED")
                        st.session_state["current_findings"][idx] = finding
                        st.rerun()

    with tab_report:
        if report:
            with st.chat_message("assistant"):
                st.markdown(f"### Executive Triage Summary\n{report.get('executive_summary')}")
                st.markdown(f"**Attack Path Synthesis:**\n{report.get('attack_path_analysis')}")

            if report.get("fallback_reason"):
                st.info(f"ℹEngine Note: Deterministic local rules engaged ({report.get('fallback_reason')})")

            rejected_ids = {str(f.get("id")) for f in findings if f.get("status") == "Rejected by Analyst"}
            active_actions = [a for a in report.get("prioritized_actions", []) if str(a.get("finding_id")) not in rejected_ids]
            if active_actions:
                st.write("### Prioritized Remediation Roadmap")
                st.table(pd.DataFrame(active_actions))

            st.markdown("---")
            st.subheader("Export Assessment Report")
            try:
                pdf_bytes = generate_pdf_report(
                    target=target_input,
                    analysis_data=report,
                    findings=findings,
                    audit_log=st.session_state.get("audit_log", []),
                    zap_is_sample=st.session_state.get("zap_is_sample", True),
                    nikto_is_sample=st.session_state.get("nikto_is_sample", True)
                )
                st.download_button(
                    label="📥 Download Full VAPT Audit Report (PDF)",
                    data=pdf_bytes,
                    file_name=f"VAPT_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error(f"Error generating PDF report: {e}")

    with tab_plan:
        st.info(f"**Target:** `{target_host}:{target_port}`")
        st.write(f"**Intent:** {request_intent}")
        st.markdown("""
        * Scope verified against RFC 1918 loopback boundaries.
        * Live Nmap service identification executed on target port.
        * Web and server vulnerability imports correlated against open network services.
        * Human oversight required before any probe execution.
        """)

    with tab_audit:
        st.subheader("Immutable Audit Trail")
        if st.session_state.get("audit_log"):
            st.dataframe(pd.DataFrame(st.session_state["audit_log"]), use_container_width=True)
        else:
            st.caption("No audit entries recorded.")
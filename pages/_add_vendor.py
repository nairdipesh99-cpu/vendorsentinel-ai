import streamlit as st
import time
from utils.scanner import run_full_scan

FRAMEWORKS = ["ISO 27001", "SOC 2", "DORA", "NIS2", "NIST CSF", "PCI DSS", "HIPAA", "CMMC 2.0"]
DATA_TYPES  = [
    "Employee PII", "Payroll / banking data", "Customer PII",
    "Financial records", "Source code", "Health records",
    "Authentication credentials", "General business data",
]

def render():
    st.markdown("""
    <div class="page-header">
        <div>
            <div class="page-title">Add Vendor</div>
            <div class="page-sub">Onboard a new vendor for continuous threat monitoring</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_form, col_info = st.columns([3, 2])

    with col_form:
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-card-title">Vendor Details</div>', unsafe_allow_html=True)

        company_name = st.text_input("Company Name", placeholder="e.g. PayCo Ltd")
        domain       = st.text_input("Domain", placeholder="e.g. payco.com")
        data_access  = st.multiselect("Data this vendor can access", DATA_TYPES, default=["General business data"])
        frameworks   = st.multiselect("Compliance frameworks to check", FRAMEWORKS, default=["ISO 27001", "SOC 2", "NIST CSF"])
        notes        = st.text_area("Notes (optional)", placeholder="e.g. Payroll processor — quarterly review required", height=80)

        st.markdown("</div>", unsafe_allow_html=True)

        can_submit = bool(company_name and domain)
        if not can_submit:
            st.markdown('<div style="font-size:12px;color:#475569;margin-top:8px">Fill in company name and domain to run scan.</div>', unsafe_allow_html=True)

        run_scan = st.button(
            "🔍 Run Full Scan",
            disabled=not can_submit,
            use_container_width=True,
        )

    with col_info:
        st.markdown("""
        <div class="section-card">
            <div class="section-card-title">What We Check</div>
            <div style="display:flex;flex-direction:column;gap:10px;margin-top:4px">
        """, unsafe_allow_html=True)

        checks = [
            ("🔐", "SSL / TLS",         "Certificate validity, expiry, cipher suites"),
            ("📧", "DNS & Email",        "SPF, DMARC, DKIM — phishing exposure"),
            ("🔭", "Attack Surface",     "Shodan — exposed ports and services"),
            ("💥", "Breach History",     "Have I Been Pwned — credential leaks"),
            ("📰", "Adverse Media",      "News — breaches, fines, incidents"),
            ("🚨", "Threat Intel",       "CISA KEV, NVD, AlienVault OTX"),
            ("🧠", "AI Analysis",        "Claude — attack chain construction"),
        ]
        for icon, name, desc in checks:
            st.markdown(f"""
            <div style="display:flex;gap:10px;align-items:flex-start">
                <span style="font-size:16px">{icon}</span>
                <div>
                    <div style="font-size:12px;font-weight:600;color:#E2E8F0">{name}</div>
                    <div style="font-size:11px;color:#64748B">{desc}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
            </div>
            <div style="margin-top:16px;padding-top:12px;border-top:1px solid #334155;font-size:11px;color:#475569">
                All data collected from public sources only. No internal system access required.
            </div>
        </div>
        """, unsafe_allow_html=True)

    if run_scan and can_submit:
        clean_domain = domain.lower().strip().replace("https://", "").replace("http://", "").rstrip("/")
        data_access_str = ", ".join(data_access) if data_access else "General business data"

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-card"><div class="section-card-title">Live Scan Log</div>', unsafe_allow_html=True)
        log_placeholder = st.empty()
        st.markdown("</div>", unsafe_allow_html=True)

        log_lines = []
        result_placeholder = st.empty()

        def progress_cb(step, status, finding=None):
            if status == "running":
                log_lines.append(f'<span class="log-info">→ {step}...</span>')
            elif status in ("ok", "done"):
                if finding:
                    sev = finding.get("severity", "Low")
                    cls = {"Critical":"log-bad","High":"log-bad","Medium":"log-warn","Low":"log-dim","Info":"log-dim"}.get(sev,"log-dim")
                    log_lines.append(f'<span class="{cls}">  [{sev}] {finding.get("title","")}</span>')
                else:
                    log_lines.append(f'<span class="log-ok">✓ {step} complete</span>')
            elif status in ("error","timeout"):
                log_lines.append(f'<span class="log-warn">⚠ {step} — {status}</span>')
            elif finding:
                sev = finding.get("severity","Low")
                cls = {"Critical":"log-bad","High":"log-bad","Medium":"log-warn"}.get(sev,"log-dim")
                log_lines.append(f'<span class="{cls}">  [{sev}] {finding.get("title","")}</span>')

            log_placeholder.markdown(
                f'<div class="scan-log">{"<br>".join(log_lines[-20:])}</div>',
                unsafe_allow_html=True,
            )

        try:
            secrets = dict(st.secrets)
        except Exception:
            secrets = {}

        log_lines.append(f'<span class="log-info">Starting full scan of {clean_domain}...</span>')
        log_placeholder.markdown(
            f'<div class="scan-log">{"<br>".join(log_lines)}</div>',
            unsafe_allow_html=True,
        )

        with st.spinner(""):
            vendor_data = run_full_scan(
                domain       = clean_domain,
                company_name = company_name,
                data_access  = data_access_str,
                frameworks   = frameworks,
                secrets      = secrets,
                progress_cb  = progress_cb,
            )

        score = vendor_data.get("risk_score", 0)
        tier  = vendor_data.get("risk_tier", "Unknown")
        color_map = {"Critical":"#EF4444","High":"#F97316","Medium":"#F59E0B","Low":"#10B981","Minimal":"#3B82F6"}
        color = color_map.get(tier, "#64748B")

        log_lines.append(f'<span class="log-ok">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>')
        log_lines.append(f'<span class="log-ok">✓ Scan complete — Risk score: {score}/100 ({tier})</span>')
        log_placeholder.markdown(
            f'<div class="scan-log">{"<br>".join(log_lines[-25:])}</div>',
            unsafe_allow_html=True,
        )

        result_placeholder.markdown(f"""
        <div class="section-card" style="border-color:{color};text-align:center;margin-top:16px">
            <div style="font-size:12px;color:#64748B;margin-bottom:8px">SCAN COMPLETE — {company_name.upper()}</div>
            <div style="font-size:48px;font-weight:800;color:{color};line-height:1">{score}</div>
            <div style="font-size:16px;color:{color};font-weight:600;margin-top:4px">{tier} Risk</div>
            <div style="font-size:12px;color:#64748B;margin-top:8px">{len(vendor_data.get('findings',[]))} findings · {sum(1 for f in vendor_data.get('findings',[]) if f.get('severity')=='Critical')} critical</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("View Full Report →", use_container_width=False):
            st.session_state.selected_vendor = clean_domain
            st.session_state.page = "dashboard"
            st.rerun()

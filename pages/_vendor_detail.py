import streamlit as st
import plotly.graph_objects as go
from utils.storage import get_vendor, load_evidence
from utils.helpers import score_to_class, tier_to_color, format_dt, time_ago
from utils.scanner import run_full_scan

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

def render(domain):
    vendor = get_vendor(domain)
    if not vendor:
        st.error("Vendor not found.")
        if st.button("← Back to Dashboard"):
            st.session_state.selected_vendor = None
            st.rerun()
        return

    name     = vendor.get("name", domain)
    score    = vendor.get("risk_score", 0)
    tier     = vendor.get("risk_tier", "Unknown")
    analysis = vendor.get("analysis", {})
    findings = sorted(
        vendor.get("findings", []),
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 99)
    )

    # Header
    h1, h2 = st.columns([5, 1])
    with h1:
        st.markdown(f"""
        <div style="margin-bottom:6px">
            <span style="font-size:13px;color:#475569;cursor:pointer" onclick="void(0)">← Dashboard</span>
        </div>
        <div class="page-title">{name}</div>
        <div style="font-size:13px;color:#64748B;margin-top:4px">{domain} · Last scanned {time_ago(vendor.get('last_scanned'))}</div>
        """, unsafe_allow_html=True)
    with h2:
        if st.button("← Dashboard", use_container_width=True):
            st.session_state.selected_vendor = None
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Score + AI status + rescan
    sc1, sc2, sc3, sc4 = st.columns([1, 1, 1, 1])

    sc = score_to_class(score)
    color = tier_to_color(tier)
    with sc1:
        st.markdown(f"""
        <div class="section-card" style="text-align:center;border-color:{color}40">
            <div class="section-card-title">Risk Score</div>
            <div class="score-ring-num" style="color:{color}">{score}</div>
            <div class="score-ring-den">/100</div>
            <div class="score-ring-tier" style="color:{color}">{tier}</div>
        </div>""", unsafe_allow_html=True)

    with sc2:
        ai_powered = analysis.get("ai_powered", False)
        effort = analysis.get("threat_actor_effort", "Unknown")
        confidence = analysis.get("confidence", "Unknown")
        st.markdown(f"""
        <div class="section-card">
            <div class="section-card-title">Assessment</div>
            <div style="font-size:12px;color:#64748B;margin-bottom:8px">AI Powered</div>
            <div style="font-size:15px;color:{'#10B981' if ai_powered else '#F59E0B'};font-weight:600">
                {'✓ Claude AI' if ai_powered else '◎ Rule-based'}
            </div>
            <div style="font-size:12px;color:#64748B;margin-top:12px">Attacker effort</div>
            <div style="font-size:14px;color:{'#EF4444' if effort=='Low' else '#F97316' if effort=='Medium' else '#10B981'};font-weight:600">{effort}</div>
        </div>""", unsafe_allow_html=True)

    with sc3:
        critical = sum(1 for f in findings if f.get("severity") == "Critical")
        high     = sum(1 for f in findings if f.get("severity") == "High")
        medium   = sum(1 for f in findings if f.get("severity") == "Medium")
        st.markdown(f"""
        <div class="section-card">
            <div class="section-card-title">Findings</div>
            <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px">
                <div style="display:flex;justify-content:space-between">
                    <span style="font-size:12px;color:#64748B">Critical</span>
                    <span style="font-size:13px;font-weight:700;color:#EF4444">{critical}</span>
                </div>
                <div style="display:flex;justify-content:space-between">
                    <span style="font-size:12px;color:#64748B">High</span>
                    <span style="font-size:13px;font-weight:700;color:#F97316">{high}</span>
                </div>
                <div style="display:flex;justify-content:space-between">
                    <span style="font-size:12px;color:#64748B">Medium</span>
                    <span style="font-size:13px;font-weight:700;color:#F59E0B">{medium}</span>
                </div>
            </div>
        </div>""", unsafe_allow_html=True)

    with sc4:
        fw_gaps = analysis.get("compliance_gaps", {})
        fw_fails = sum(1 for fw, d in fw_gaps.items() if isinstance(d, dict) and d.get("status") == "Fail")
        fw_total = len(fw_gaps)
        st.markdown(f"""
        <div class="section-card">
            <div class="section-card-title">Compliance</div>
            <div style="font-size:28px;font-weight:700;color:{'#EF4444' if fw_fails > 3 else '#F97316' if fw_fails > 0 else '#10B981'};line-height:1">{fw_fails}/{fw_total}</div>
            <div style="font-size:12px;color:#64748B;margin-top:4px">Frameworks failing</div>
            <div style="margin-top:10px">
                {''.join(f'<span class="tier-badge tier-Critical" style="font-size:10px;margin:2px">{fw}</span>' for fw, d in fw_gaps.items() if isinstance(d, dict) and d.get('status')=='Fail')}
            </div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🧠 Attack Analysis", "🔍 Findings", "📊 Risk Trend", "📋 Compliance Map"])

    with tab1:
        narrative = analysis.get("attack_path_narrative", "No analysis available.")
        st.markdown(f"""
        <div class="narrative-box">
            <div class="narrative-header">⚡ AI Attack Path Narrative</div>
            <div class="narrative-text">{narrative}</div>
        </div>
        """, unsafe_allow_html=True)

        steps = analysis.get("key_attack_steps", [])
        if steps:
            st.markdown('<div class="section-card"><div class="section-card-title">Attack Chain Steps</div>', unsafe_allow_html=True)
            for i, step in enumerate(steps, 1):
                st.markdown(f"""
                <div style="display:flex;gap:12px;align-items:flex-start;margin-bottom:12px">
                    <div style="min-width:28px;height:28px;background:#EF444420;border:1px solid #EF4444;border-radius:50%;
                         display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#EF4444">{i}</div>
                    <div style="font-size:13px;color:#CBD5E1;line-height:1.6;padding-top:4px">{step}</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        recs = analysis.get("top_recommendations", [])
        if recs:
            st.markdown('<div class="section-card"><div class="section-card-title">Top Recommendations</div>', unsafe_allow_html=True)
            for rec in recs:
                st.markdown(f"""
                <div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:10px">
                    <span style="color:#10B981;font-size:16px;margin-top:1px">→</span>
                    <span style="font-size:13px;color:#94A3B8;line-height:1.6">{rec}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        if not findings:
            st.info("No findings yet. Run a scan first.")
        else:
            sev_filter = st.multiselect(
                "Filter by severity",
                ["Critical", "High", "Medium", "Low", "Info"],
                default=["Critical", "High", "Medium"],
                label_visibility="collapsed",
            )
            filtered_findings = [f for f in findings if f.get("severity","Info") in sev_filter]
            for f in filtered_findings:
                sev = f.get("severity", "Low").lower()
                controls_html = "".join(
                    f'<span class="finding-tag">{c}</span>' for c in f.get("controls", [])
                )
                st.markdown(f"""
                <div class="finding-card {sev}">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                        <div class="finding-title">{f.get('title','')}</div>
                        <span class="tier-badge tier-{f.get('severity','Low')}">{f.get('severity','Low')}</span>
                    </div>
                    <div style="font-size:11px;color:#475569;margin-bottom:6px">Source: {f.get('source','Unknown')}</div>
                    <div class="finding-desc">{f.get('detail','')}</div>
                    <div class="finding-meta">{controls_html}</div>
                </div>
                """, unsafe_allow_html=True)

    with tab3:
        history = vendor.get("risk_history", [])
        if len(history) < 2:
            st.info("Risk trend data will appear after multiple scans. Run another scan to start tracking changes.")
            # Show current score as single point
            if history:
                st.markdown(f"""
                <div style="text-align:center;padding:40px">
                    <div style="font-size:48px;font-weight:800;color:{tier_to_color(tier)}">{score}</div>
                    <div style="font-size:14px;color:#64748B;margin-top:8px">Current risk score</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            dates  = [h.get("date","") for h in history]
            scores = [h.get("score", 0) for h in history]
            color_line = tier_to_color(tier)

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=dates, y=scores,
                mode="lines+markers",
                line=dict(color=color_line, width=2),
                marker=dict(color=color_line, size=8),
                fill="tozeroy",
                fillcolor=f"rgba({int(color_line[1:3],16)},{int(color_line[3:5],16)},{int(color_line[5:7],16)},0.1)",
                name="Risk Score",
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#0F172A",
                font=dict(color="#94A3B8"),
                xaxis=dict(gridcolor="#1E293B", linecolor="#334155"),
                yaxis=dict(gridcolor="#1E293B", linecolor="#334155", range=[0,105]),
                margin=dict(t=20, b=20, l=20, r=20),
                height=300,
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with tab4:
        fw_gaps = analysis.get("compliance_gaps", {})
        if not fw_gaps:
            st.info("Compliance mapping will appear after running a scan.")
        else:
            st.markdown('<div class="fw-grid">', unsafe_allow_html=True)
            for fw, data in fw_gaps.items():
                if not isinstance(data, dict):
                    continue
                status = data.get("status", "Unknown")
                detail = data.get("detail", "")
                controls = data.get("controls", [])
                cls = "fw-pass" if status == "Pass" else "fw-fail"
                icon = "✓" if status == "Pass" else "✗"
                controls_str = " · ".join(controls[:3]) if controls else ""
                st.markdown(f"""
                <div class="section-card" style="margin-bottom:12px">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                        <span style="font-size:14px;font-weight:600;color:#F1F5F9">{fw}</span>
                        <span class="fw-badge {cls}">{icon} {status}</span>
                    </div>
                    <div style="font-size:12px;color:#64748B;margin-bottom:6px">{detail}</div>
                    {f'<div style="font-size:11px;color:#475569">{controls_str}</div>' if controls_str else ''}
                </div>
                """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)


    # Delete vendor
    st.markdown("<br>", unsafe_allow_html=True)
    col_del, col_confirm = st.columns([1, 3])
    with col_del:
        delete_clicked = st.button(f"🗑️ Delete {name}", use_container_width=True)
    with col_confirm:
        if delete_clicked:
            confirm = st.checkbox("Tick to confirm deletion")
            if confirm:
                from utils.storage import load_vendors, save_vendors, load_evidence, EVIDENCE_FILE
                import json
                vendors = load_vendors()
                vendors = [v for v in vendors if v["domain"] != domain]
                save_vendors(vendors)
                evidence = json.loads(EVIDENCE_FILE.read_text())
                evidence = [e for e in evidence if e.get("domain") != domain]
                EVIDENCE_FILE.write_text(json.dumps(evidence, indent=2))
                st.success(f"{name} deleted successfully.")
                st.session_state.selected_vendor = None
                st.session_state.page = "dashboard"
                st.rerun()
    # Rescan button
    if st.button(f"🔄 Rescan {name}", use_container_width=False):
        try:
            secrets = dict(st.secrets)
        except Exception:
            secrets = {}
        with st.spinner("Running full scan..."):
            updated = run_full_scan(
                domain=domain,
                company_name=vendor.get("name", domain),
                data_access=vendor.get("data_access", ""),
                frameworks=vendor.get("frameworks", []),
                secrets=secrets,
            )
        st.success(f"Scan complete. New risk score: {updated['risk_score']}/100")
        st.rerun()


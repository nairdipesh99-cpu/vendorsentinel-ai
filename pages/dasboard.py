import streamlit as st
import plotly.graph_objects as go
from utils.storage import load_vendors
from utils.helpers import score_to_class, tier_to_color, time_ago

def render():
    vendors = load_vendors()

    st.markdown("""
    <div class="page-header">
        <div>
            <div class="page-title">Vendor Risk Dashboard</div>
            <div class="page-sub">Continuous threat intelligence monitoring across your vendor ecosystem</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Metrics
    total    = len(vendors)
    critical = sum(1 for v in vendors if v.get("risk_tier") == "Critical")
    high     = sum(1 for v in vendors if v.get("risk_tier") == "High")
    medium   = sum(1 for v in vendors if v.get("risk_tier") == "Medium")
    avg_score = round(sum(v.get("risk_score", 0) for v in vendors) / total, 1) if total else 0

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Vendors</div>
            <div class="metric-value blue">{total}</div>
            <div class="metric-sub">Actively monitored</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Critical Risk</div>
            <div class="metric-value red">{critical}</div>
            <div class="metric-sub">Immediate action required</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">High Risk</div>
            <div class="metric-value orange">{high}</div>
            <div class="metric-sub">Review within 7 days</div>
        </div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Avg Risk Score</div>
            <div class="metric-value {'red' if avg_score >= 75 else 'amber' if avg_score >= 55 else 'green'}">{avg_score}</div>
            <div class="metric-sub">Portfolio average /100</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if not vendors:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-state-icon">🛡️</div>
            <div class="empty-state-title">No vendors monitored yet</div>
            <div class="empty-state-sub">Add your first vendor to start continuous threat monitoring</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("+ Add First Vendor", use_container_width=False):
            st.session_state.page = "add_vendor"
            st.rerun()
        return

    col_main, col_side = st.columns([3, 1])

    with col_main:
        # Filters
        fc1, fc2, fc3 = st.columns([2, 1, 1])
        with fc1:
            search = st.text_input("🔍 Search vendors", placeholder="Search by name or domain...", label_visibility="collapsed")
        with fc2:
            tier_filter = st.selectbox("Risk tier", ["All tiers", "Critical", "High", "Medium", "Low", "Minimal"], label_visibility="collapsed")
        with fc3:
            sort_by = st.selectbox("Sort by", ["Risk score ↑", "Risk score ↓", "Name A-Z", "Recently scanned"], label_visibility="collapsed")

        filtered = vendors
        if search:
            s = search.lower()
            filtered = [v for v in filtered if s in v.get("name","").lower() or s in v.get("domain","").lower()]
        if tier_filter != "All tiers":
            filtered = [v for v in filtered if v.get("risk_tier") == tier_filter]

        if sort_by == "Risk score ↑":
            filtered = sorted(filtered, key=lambda v: v.get("risk_score", 0), reverse=True)
        elif sort_by == "Risk score ↓":
            filtered = sorted(filtered, key=lambda v: v.get("risk_score", 0))
        elif sort_by == "Name A-Z":
            filtered = sorted(filtered, key=lambda v: v.get("name", "").lower())
        else:
            filtered = sorted(filtered, key=lambda v: v.get("last_scanned", ""), reverse=True)

        st.markdown(f"""
        <div class="vendor-table-wrap">
            <div class="table-header">
                <span class="table-title">Vendor Portfolio</span>
                <span style="font-size:12px;color:#475569">{len(filtered)} of {total} vendors</span>
            </div>
            <div class="vendor-row" style="background:#0F172A;cursor:default">
                <div class="col-head">Vendor</div>
                <div class="col-head">Risk Score</div>
                <div class="col-head">Risk Tier</div>
                <div class="col-head">Findings</div>
                <div class="col-head">Top Finding</div>
                <div class="col-head">Last Scanned</div>
                <div></div>
            </div>
        """, unsafe_allow_html=True)

        for v in filtered:
            score     = v.get("risk_score", 0)
            tier      = v.get("risk_tier",  "Unknown")
            findings  = v.get("findings", [])
            crit_count= sum(1 for f in findings if f.get("severity") == "Critical")
            high_count= sum(1 for f in findings if f.get("severity") == "High")
            top_finding = next(
                (f["title"] for f in findings if f.get("severity") == "Critical"),
                next((f["title"] for f in findings if f.get("severity") == "High"),
                "No significant findings")
            )[:55]
            sc = score_to_class(score)

            st.markdown(f"""
            <div class="vendor-row" onclick="void(0)">
                <div>
                    <div class="vendor-name">{v.get('name','Unknown')}</div>
                    <div class="vendor-domain">{v.get('domain','')}</div>
                </div>
                <div><span class="score-badge score-{sc}">{score}</span></div>
                <div><span class="tier-badge tier-{tier}">{tier}</span></div>
                <div style="font-size:12px;color:#94A3B8">
                    {f'<span style="color:#EF4444">{crit_count} crit</span> · ' if crit_count else ''}
                    {f'<span style="color:#F97316">{high_count} high</span>' if high_count else ''}
                    {f'<span style="color:#64748B">{len(findings)} total</span>' if not crit_count and not high_count else f' · {len(findings)} total'}
                </div>
                <div style="font-size:12px;color:#94A3B8">{top_finding}{'...' if len(top_finding) >= 55 else ''}</div>
                <div style="font-size:12px;color:#64748B">{time_ago(v.get('last_scanned'))}</div>
                <div></div>
            </div>
            """, unsafe_allow_html=True)

            if st.button("View →", key=f"view_{v['domain']}", use_container_width=True):
                st.session_state.selected_vendor = v["domain"]
                st.session_state.page = "dashboard"
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

    with col_side:
        # Risk distribution chart
        tier_counts = {}
        for v in vendors:
            t = v.get("risk_tier", "Unknown")
            tier_counts[t] = tier_counts.get(t, 0) + 1

        if tier_counts:
            labels = list(tier_counts.keys())
            values = list(tier_counts.values())
            colors = [tier_to_color(t) for t in labels]

            fig = go.Figure(data=[go.Pie(
                labels=labels, values=values,
                marker=dict(colors=colors, line=dict(color="#0D1B2A", width=2)),
                hole=0.55, textinfo="value",
                textfont=dict(size=13, color="white"),
            )])
            fig.update_layout(
                showlegend=True,
                legend=dict(font=dict(color="#94A3B8", size=11), bgcolor="rgba(0,0,0,0)"),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=10, b=10, l=10, r=10),
                height=220,
            )
            st.markdown('<div class="section-card"><div class="section-card-title">Risk Distribution</div>', unsafe_allow_html=True)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            st.markdown("</div>", unsafe_allow_html=True)

        # Frameworks at risk
        fw_failures = {}
        for v in vendors:
            gaps = v.get("analysis", {}).get("compliance_gaps", {})
            for fw, data in gaps.items():
                if isinstance(data, dict) and data.get("status") == "Fail":
                    fw_failures[fw] = fw_failures.get(fw, 0) + 1

        if fw_failures:
            st.markdown('<div class="section-card"><div class="section-card-title">Framework Failures</div>', unsafe_allow_html=True)
            for fw, count in sorted(fw_failures.items(), key=lambda x: -x[1]):
                pct = int(count / total * 100) if total else 0
                st.markdown(f"""
                <div style="margin-bottom:10px">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                        <span style="font-size:12px;color:#94A3B8">{fw}</span>
                        <span style="font-size:12px;color:#EF4444">{count} vendor{'s' if count > 1 else ''}</span>
                    </div>
                    <div style="height:4px;background:#1E293B;border-radius:2px">
                        <div style="height:100%;width:{pct}%;background:#EF4444;border-radius:2px"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)


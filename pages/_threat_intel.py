import streamlit as st
from intelligence.cisa_feed import fetch_cisa_kev
from intelligence.nvd_feed  import fetch_recent_cves
from intelligence.otx_feed  import fetch_otx_pulses
from utils.storage import load_vendors, load_threat_intel

def render():
    st.markdown("""
    <div class="page-header">
        <div>
            <div class="page-title">Threat Intelligence Feed</div>
            <div class="page-sub">Live global threat intelligence from CISA KEV, NVD, and AlienVault OTX</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_refresh, col_filter = st.columns([1, 3])
    with col_refresh:
        refresh = st.button("🔄 Refresh Feeds", use_container_width=True)
    with col_filter:
        sev_filter = st.multiselect(
            "Severity filter",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High"],
            label_visibility="collapsed",
        )

    if refresh or "intel_cache" not in st.session_state:
        with st.spinner("Fetching live threat intelligence..."):
            try:
                secrets = dict(st.secrets)
            except Exception:
                secrets = {}

            otx_key = secrets.get("OTX_API_KEY")
            kev_data = fetch_cisa_kev()
            nvd_data = fetch_recent_cves(days_back=7, severity_filter="CRITICAL")
            otx_data = fetch_otx_pulses(api_key=otx_key, days_back=7)

            st.session_state.intel_cache = {
                "kev": kev_data.get("entries", []),
                "nvd": nvd_data.get("entries", []),
                "otx": otx_data.get("entries", []),
                "kev_status": kev_data.get("status"),
                "nvd_status": nvd_data.get("status"),
                "otx_status": otx_data.get("status"),
            }

    cache = st.session_state.intel_cache
    kev_entries = cache.get("kev", [])
    nvd_entries = cache.get("nvd", [])
    otx_entries = cache.get("otx", [])

    # Summary metrics
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">CISA KEV Entries</div>
            <div class="metric-value red">{len(kev_entries)}</div>
            <div class="metric-sub">Actively exploited CVEs</div>
        </div>""", unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">New Critical CVEs</div>
            <div class="metric-value orange">{len(nvd_entries)}</div>
            <div class="metric-sub">Last 7 days (CVSS 9+)</div>
        </div>""", unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">OTX Threat Pulses</div>
            <div class="metric-value amber">{len(otx_entries)}</div>
            <div class="metric-sub">Community intelligence</div>
        </div>""", unsafe_allow_html=True)
    with m4:
        vendors = load_vendors()
        at_risk = sum(1 for v in vendors if v.get("risk_score", 0) >= 55)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Vendors at Risk</div>
            <div class="metric-value {'red' if at_risk > 0 else 'green'}">{at_risk}</div>
            <div class="metric-sub">Score ≥ 55 (High+)</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["🚨 CISA KEV", "🔍 NVD Critical CVEs", "📡 AlienVault OTX"])

    with tab1:
        status = cache.get("kev_status")
        if status == "error":
            st.warning("Could not reach CISA KEV feed. Showing cached data.")
        if status == "timeout":
            st.warning("CISA KEV request timed out.")

        search_kev = st.text_input("Search KEV", placeholder="Search by CVE, vendor or product...", key="kev_search", label_visibility="collapsed")

        filtered_kev = kev_entries
        if search_kev:
            s = search_kev.lower()
            filtered_kev = [e for e in filtered_kev if
                s in e.get("cve_id","").lower() or
                s in e.get("vendor_name","").lower() or
                s in e.get("product","").lower() or
                s in e.get("title","").lower()
            ]
        if "Critical" not in sev_filter:
            filtered_kev = []

        st.markdown(f'<div style="font-size:12px;color:#475569;margin-bottom:12px">Showing {len(filtered_kev)} entries</div>', unsafe_allow_html=True)

        for e in filtered_kev[:30]:
            st.markdown(f"""
            <div class="threat-card critical">
                <div class="threat-cve">{e.get('cve_id','')} · CISA KEV</div>
                <div class="threat-title">{e.get('title','')}</div>
                <div class="threat-meta">
                    {e.get('vendor_name','')} — {e.get('product','')} · 
                    Added: {e.get('date_added','')} · 
                    Due: {e.get('due_date','')}
                </div>
                {f'<div style="font-size:11px;color:#94A3B8;margin-top:6px">{e.get("description","")[:180]}</div>' if e.get("description") else ''}
            </div>
            """, unsafe_allow_html=True)

    with tab2:
        status = cache.get("nvd_status")
        if status != "ok":
            st.info(f"NVD feed status: {status}")

        search_nvd = st.text_input("Search CVEs", placeholder="Search CVEs...", key="nvd_search", label_visibility="collapsed")
        filtered_nvd = [e for e in nvd_entries if e.get("severity","") in sev_filter]
        if search_nvd:
            s = search_nvd.lower()
            filtered_nvd = [e for e in filtered_nvd if s in e.get("cve_id","").lower() or s in e.get("title","").lower()]

        st.markdown(f'<div style="font-size:12px;color:#475569;margin-bottom:12px">Showing {len(filtered_nvd)} entries</div>', unsafe_allow_html=True)

        for e in filtered_nvd[:30]:
            sev = e.get("severity","Medium")
            cls = "critical" if sev=="Critical" else "high" if sev=="High" else "medium"
            cvss = e.get("cvss_score",0)
            av = e.get("attack_vector","")
            st.markdown(f"""
            <div class="threat-card {cls}">
                <div class="threat-cve">{e.get('cve_id','')} · CVSS {cvss} · {sev}</div>
                <div class="threat-title">{e.get('title','')[:140]}</div>
                <div class="threat-meta">
                    Published: {e.get('published','')} · Attack vector: {av}
                </div>
            </div>
            """, unsafe_allow_html=True)

    with tab3:
        status = cache.get("otx_status")
        if status != "ok":
            st.info(f"OTX feed status: {status}")

        filtered_otx = [e for e in otx_entries if e.get("severity","") in sev_filter]
        st.markdown(f'<div style="font-size:12px;color:#475569;margin-bottom:12px">Showing {len(filtered_otx)} pulses</div>', unsafe_allow_html=True)

        for e in filtered_otx[:20]:
            sev = e.get("severity","Medium")
            cls = "critical" if sev=="Critical" else "high" if sev=="High" else "medium"
            tags = e.get("tags",[])
            tags_html = " ".join(f'<span class="finding-tag">{t}</span>' for t in tags[:6])
            st.markdown(f"""
            <div class="threat-card {cls}">
                <div class="threat-cve">AlienVault OTX · {sev} · {e.get('indicators',0)} indicators</div>
                <div class="threat-title">{e.get('title','')}</div>
                <div class="threat-meta">Author: {e.get('author','')} · Published: {e.get('published','')} · TLP: {e.get('tlp','').upper()}</div>
                {f'<div style="margin-top:8px">{tags_html}</div>' if tags_html else ''}
                {f'<div style="font-size:11px;color:#64748B;margin-top:6px">{e.get("description","")[:160]}</div>' if e.get("description") else ''}
            </div>
            """, unsafe_allow_html=True)


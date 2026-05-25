import streamlit as st
from pages import dashboard, vendor_detail, add_vendor, threat_intel, reports
from utils.storage import init_storage
from utils.styles import load_css

st.set_page_config(
    page_title="VendorSentinel AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

load_css()
init_storage()

PAGES = {
    "dashboard":     {"label": "Dashboard",           "icon": "grid"},
    "add_vendor":    {"label": "Add Vendor",           "icon": "plus-circle"},
    "threat_intel":  {"label": "Threat Intelligence",  "icon": "shield-alert"},
    "reports":       {"label": "Reports",              "icon": "file-text"},
}

def sidebar():
    with st.sidebar:
        st.markdown("""
        <div class="sidebar-logo">
            <span class="logo-icon">⚡</span>
            <div>
                <div class="logo-title">VendorSentinel</div>
                <div class="logo-sub">AI Threat Intelligence</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sidebar-nav-label">NAVIGATION</div>', unsafe_allow_html=True)

        if "page" not in st.session_state:
            st.session_state.page = "dashboard"
        if "selected_vendor" not in st.session_state:
            st.session_state.selected_vendor = None

        for key, meta in PAGES.items():
            active = "nav-active" if st.session_state.page == key else ""
            if st.button(
                f"{meta['label']}",
                key=f"nav_{key}",
                use_container_width=True,
            ):
                st.session_state.page = key
                st.session_state.selected_vendor = None
                st.rerun()

        st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)

        from utils.storage import load_vendors
        vendors = load_vendors()
        critical = sum(1 for v in vendors if v.get("risk_tier") == "Critical")
        high     = sum(1 for v in vendors if v.get("risk_tier") == "High")

        st.markdown(f"""
        <div class="sidebar-stats">
            <div class="sidebar-stat">
                <div class="stat-num">{len(vendors)}</div>
                <div class="stat-lbl">Vendors</div>
            </div>
            <div class="sidebar-stat">
                <div class="stat-num red">{critical}</div>
                <div class="stat-lbl">Critical</div>
            </div>
            <div class="sidebar-stat">
                <div class="stat-num amber">{high}</div>
                <div class="stat-lbl">High</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sidebar-footer">VendorSentinel AI v1.0<br>Open Source TPRM Platform</div>', unsafe_allow_html=True)

def main():
    sidebar()

    page = st.session_state.get("page", "dashboard")
    selected = st.session_state.get("selected_vendor")

    if page == "dashboard" and selected:
        vendor_detail.render(selected)
    elif page == "dashboard":
        dashboard.render()
    elif page == "add_vendor":
        add_vendor.render()
    elif page == "threat_intel":
        threat_intel.render()
    elif page == "reports":
        reports.render()

if __name__ == "__main__":
    main()


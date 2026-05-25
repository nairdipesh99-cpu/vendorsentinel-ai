def load_css():
    import streamlit as st
    st.markdown("""
<style>
/* â”€â”€ GLOBAL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}
.stApp {
    background: #0D1B2A !important;
}
.block-container {
    padding: 2.5rem 2rem 2rem 2rem !important;
    max-width: 100% !important;
}
section[data-testid="stSidebar"] {
    background: #0A1628 !important;
    border-right: 1px solid #1E293B !important;
    width: 260px !important;
    min-width: 260px !important;
}
section[data-testid="stSidebar"] > div {
    padding: 0 !important;
}

/* â”€â”€ SIDEBAR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.sidebar-logo {
    display: flex; align-items: center; gap: 12px;
    padding: 20px 16px 16px;
    border-bottom: 1px solid #1E293B;
    margin-bottom: 8px;
}
.logo-icon { font-size: 28px; }
.logo-title { font-size: 15px; font-weight: 700; color: #F1F5F9; line-height: 1; }
.logo-sub   { font-size: 11px; color: #475569; margin-top: 2px; }
.sidebar-nav-label {
    font-size: 10px; font-weight: 600; color: #475569;
    letter-spacing: .08em; padding: 8px 16px 4px;
}
.sidebar-divider {
    height: 1px; background: #1E293B; margin: 12px 16px;
}
.sidebar-stats {
    display: flex; justify-content: space-around;
    padding: 12px 8px; margin: 0 8px;
    background: #1E293B; border-radius: 8px;
}
.sidebar-stat { text-align: center; }
.stat-num { font-size: 20px; font-weight: 700; color: #F1F5F9; line-height: 1; }
.stat-num.red   { color: #EF4444; }
.stat-num.amber { color: #F97316; }
.stat-lbl { font-size: 10px; color: #64748B; margin-top: 2px; }
.sidebar-footer {
    font-size: 10px; color: #334155; text-align: center;
    padding: 16px; line-height: 1.6;
}

/* Streamlit sidebar buttons â†’ nav items */
section[data-testid="stSidebar"] .stButton button {
    background: transparent !important;
    border: none !important;
    color: #94A3B8 !important;
    text-align: left !important;
    padding: 9px 16px !important;
    border-radius: 6px !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    width: 100% !important;
    margin: 1px 0 !important;
    transition: all .15s !important;
}
section[data-testid="stSidebar"] .stButton button:hover {
    background: #1E293B !important;
    color: #F1F5F9 !important;
}

/* â”€â”€ PAGE HEADER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.page-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 24px; padding-bottom: 16px;
    border-bottom: 1px solid #1E293B;
}
.page-title { font-size: 22px; font-weight: 700; color: #F1F5F9; margin: 0; }
.page-sub   { font-size: 13px; color: #64748B; margin-top: 2px; }

/* â”€â”€ METRIC CARDS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.metric-row {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 16px; margin-bottom: 24px;
}
.metric-card {
    background: #1E293B; border: 1px solid #334155;
    border-radius: 10px; padding: 16px 20px;
}
.metric-label { font-size: 11px; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: .07em; margin-bottom: 8px; }
.metric-value { font-size: 28px; font-weight: 700; color: #F1F5F9; line-height: 1; }
.metric-value.red    { color: #EF4444; }
.metric-value.orange { color: #F97316; }
.metric-value.amber  { color: #F59E0B; }
.metric-value.green  { color: #10B981; }
.metric-value.blue   { color: #3B82F6; }
.metric-sub { font-size: 11px; color: #475569; margin-top: 6px; }
.metric-trend-up   { color: #EF4444; font-size: 11px; margin-top: 4px; }
.metric-trend-down { color: #10B981; font-size: 11px; margin-top: 4px; }

/* â”€â”€ VENDOR TABLE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.vendor-table-wrap {
    background: #1E293B; border: 1px solid #334155;
    border-radius: 10px; overflow: hidden;
}
.table-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 20px; border-bottom: 1px solid #334155;
}
.table-title { font-size: 14px; font-weight: 600; color: #F1F5F9; }
.vendor-row {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr 2fr 1fr 80px;
    gap: 12px; align-items: center;
    padding: 12px 20px;
    border-bottom: 1px solid #1E3A5F22;
    transition: background .15s;
}
.vendor-row:hover { background: #263548; cursor: pointer; }
.vendor-row:last-child { border-bottom: none; }
.col-head {
    font-size: 10px; font-weight: 600; color: #475569;
    text-transform: uppercase; letter-spacing: .07em;
}
.vendor-name { font-size: 13px; font-weight: 600; color: #F1F5F9; }
.vendor-domain { font-size: 11px; color: #64748B; margin-top: 2px; }
.score-badge {
    display: inline-flex; align-items: center; justify-content: center;
    width: 48px; height: 48px; border-radius: 50%;
    font-size: 15px; font-weight: 700; border: 2px solid;
}
.score-critical { color: #EF4444; border-color: #EF4444; background: #7F1D1D22; }
.score-high     { color: #F97316; border-color: #F97316; background: #7C2D1222; }
.score-medium   { color: #F59E0B; border-color: #F59E0B; background: #78350F22; }
.score-low      { color: #10B981; border-color: #10B981; background: #14532D22; }

/* â”€â”€ RISK TIER BADGE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.tier-badge {
    display: inline-block; font-size: 11px; font-weight: 600;
    padding: 3px 10px; border-radius: 999px;
}
.tier-Critical { background: #7F1D1D; color: #FCA5A5; }
.tier-High     { background: #7C2D12; color: #FDBA74; }
.tier-Medium   { background: #78350F; color: #FCD34D; }
.tier-Low      { background: #14532D; color: #6EE7B7; }
.tier-Minimal  { background: #1E3A5F; color: #93C5FD; }

/* â”€â”€ FINDING CARD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.finding-card {
    background: #0F172A; border: 1px solid #1E293B;
    border-radius: 8px; padding: 14px 16px; margin-bottom: 10px;
}
.finding-card.critical { border-left: 3px solid #EF4444; }
.finding-card.high     { border-left: 3px solid #F97316; }
.finding-card.medium   { border-left: 3px solid #F59E0B; }
.finding-card.low      { border-left: 3px solid #10B981; }
.finding-title { font-size: 13px; font-weight: 600; color: #F1F5F9; margin-bottom: 4px; }
.finding-desc  { font-size: 12px; color: #94A3B8; line-height: 1.6; }
.finding-meta  { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.finding-tag   {
    font-size: 10px; padding: 2px 8px; border-radius: 4px;
    background: #1E293B; color: #64748B; border: 1px solid #334155;
}

/* â”€â”€ ATTACK NARRATIVE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.narrative-box {
    background: linear-gradient(135deg, #1E1B4B, #1E293B);
    border: 1px solid #4338CA; border-radius: 10px; padding: 20px;
    margin-bottom: 20px;
}
.narrative-header {
    display: flex; align-items: center; gap: 8px;
    font-size: 11px; font-weight: 600; color: #818CF8;
    text-transform: uppercase; letter-spacing: .08em; margin-bottom: 12px;
}
.narrative-text { font-size: 13px; color: #C7D2FE; line-height: 1.8; }

/* â”€â”€ FRAMEWORK BADGE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.fw-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.fw-badge {
    display: flex; align-items: center; gap: 6px;
    font-size: 11px; font-weight: 600; padding: 5px 10px;
    border-radius: 6px; border: 1px solid;
}
.fw-pass { background: #14532D22; border-color: #10B981; color: #6EE7B7; }
.fw-fail { background: #7F1D1D22; border-color: #EF4444; color: #FCA5A5; }

/* â”€â”€ SCAN LOG â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.scan-log {
    background: #0A0F1C; border: 1px solid #1E293B;
    border-radius: 8px; padding: 16px; font-family: monospace;
    font-size: 12px; line-height: 2; max-height: 320px; overflow-y: auto;
}
.log-ok   { color: #10B981; }
.log-warn { color: #F59E0B; }
.log-bad  { color: #EF4444; }
.log-info { color: #60A5FA; }
.log-dim  { color: #475569; }

/* â”€â”€ THREAT CARD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.threat-card {
    background: #1E293B; border: 1px solid #334155;
    border-radius: 8px; padding: 14px; margin-bottom: 10px;
}
.threat-card.critical { border-left: 3px solid #EF4444; }
.threat-card.high     { border-left: 3px solid #F97316; }
.threat-card.medium   { border-left: 3px solid #F59E0B; }
.threat-cve   { font-size: 12px; font-weight: 700; color: #F87171; margin-bottom: 4px; }
.threat-title { font-size: 13px; font-weight: 500; color: #E2E8F0; margin-bottom: 6px; }
.threat-meta  { font-size: 11px; color: #64748B; }

/* â”€â”€ SCORE RING â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.score-ring-wrap {
    display: flex; flex-direction: column; align-items: center;
    justify-content: center; padding: 20px 0;
}
.score-ring-num { font-size: 48px; font-weight: 800; line-height: 1; }
.score-ring-den { font-size: 16px; color: #475569; margin-top: 2px; }
.score-ring-tier { font-size: 14px; font-weight: 600; margin-top: 8px; }

/* â”€â”€ SECTION CARD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.section-card {
    background: #1E293B; border: 1px solid #334155;
    border-radius: 10px; padding: 20px; margin-bottom: 16px;
}
.section-card-title {
    font-size: 13px; font-weight: 600; color: #94A3B8;
    text-transform: uppercase; letter-spacing: .07em;
    margin-bottom: 16px; padding-bottom: 10px;
    border-bottom: 1px solid #334155;
}

/* â”€â”€ BUTTONS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.stButton button {
    background: #1D4ED8 !important; color: white !important;
    border: none !important; border-radius: 8px !important;
    font-size: 13px !important; font-weight: 600 !important;
    padding: 8px 20px !important; transition: all .15s !important;
}
.stButton button:hover {
    background: #2563EB !important; transform: translateY(-1px) !important;
}

/* â”€â”€ INPUTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
.stTextInput input, .stSelectbox select, .stTextArea textarea {
    background: #0F172A !important; color: #F1F5F9 !important;
    border: 1px solid #334155 !important; border-radius: 8px !important;
    font-size: 13px !important;
}
.stTextInput label, .stSelectbox label, .stTextArea label,
.stMultiSelect label, .stCheckbox label {
    color: #94A3B8 !important; font-size: 12px !important; font-weight: 600 !important;
}

/* â”€â”€ MISC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
div[data-testid="stMetric"] {
    background: #1E293B; border: 1px solid #334155;
    border-radius: 10px; padding: 16px 20px;
}
div[data-testid="stMetric"] label { color: #64748B !important; font-size: 11px !important; }
div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
    color: #F1F5F9 !important; font-size: 28px !important; font-weight: 700 !important;
}
.stAlert { border-radius: 8px !important; }
hr { border-color: #1E293B !important; }
.stTabs [data-baseweb="tab-list"] { background: #1E293B !important; border-radius: 8px 8px 0 0; }
.stTabs [data-baseweb="tab"] { color: #64748B !important; font-size: 13px !important; }
.stTabs [aria-selected="true"] { color: #F1F5F9 !important; }
.stDataFrame { border: 1px solid #334155 !important; border-radius: 8px !important; }
[data-testid="stExpander"] {
    background: #1E293B !important; border: 1px solid #334155 !important;
    border-radius: 8px !important;
}
.empty-state {
    text-align: center; padding: 60px 20px; color: #475569;
}
.empty-state-icon { font-size: 48px; margin-bottom: 16px; }
.empty-state-title { font-size: 18px; font-weight: 600; color: #94A3B8; margin-bottom: 8px; }
.empty-state-sub { font-size: 13px; color: #475569; }
</style>
""", unsafe_allow_html=True)


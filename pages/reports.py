import streamlit as st
import json
from datetime import datetime
from utils.storage import load_vendors, get_vendor, load_evidence
from utils.helpers import format_dt, tier_to_color

def render():
    st.markdown("""
    <div class="page-header">
        <div>
            <div class="page-title">Reports & Evidence</div>
            <div class="page-sub">Generate audit-ready reports with timestamped evidence</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    vendors = load_vendors()
    if not vendors:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-state-icon">📋</div>
            <div class="empty-state-title">No vendors to report on</div>
            <div class="empty-state-sub">Add and scan vendors first to generate reports</div>
        </div>
        """, unsafe_allow_html=True)
        return

    col_form, col_preview = st.columns([1, 2])

    with col_form:
        st.markdown('<div class="section-card"><div class="section-card-title">Report Configuration</div>', unsafe_allow_html=True)

        vendor_options = {v["name"]: v["domain"] for v in vendors}
        selected_name  = st.selectbox("Select vendor", list(vendor_options.keys()))
        selected_domain= vendor_options[selected_name]

        report_type = st.selectbox("Report type", [
            "Full Vendor Risk Report",
            "Executive Summary",
            "Compliance Gap Analysis",
            "Evidence Package",
        ])

        frameworks = st.multiselect(
            "Include frameworks",
            ["ISO 27001", "SOC 2", "DORA", "NIS2", "NIST CSF", "PCI DSS"],
            default=["ISO 27001", "SOC 2", "DORA"],
        )

        include_evidence = st.checkbox("Include raw evidence appendix", value=True)
        include_narrative= st.checkbox("Include AI attack narrative",    value=True)

        st.markdown("</div>", unsafe_allow_html=True)

        gen = st.button("📄 Generate Report", use_container_width=True)

    with col_preview:
        vendor = get_vendor(selected_domain)
        if not vendor:
            st.info("Select a vendor to preview report details.")
        else:
            score    = vendor.get("risk_score", 0)
            tier     = vendor.get("risk_tier", "Unknown")
            analysis = vendor.get("analysis", {})
            findings = vendor.get("findings", [])
            color    = tier_to_color(tier)

            st.markdown(f"""
            <div class="section-card" style="border-color:{color}40">
                <div class="section-card-title">Report Preview</div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
                    <div>
                        <div style="font-size:11px;color:#64748B">Vendor</div>
                        <div style="font-size:14px;font-weight:600;color:#F1F5F9">{vendor.get('name','')}</div>
                    </div>
                    <div>
                        <div style="font-size:11px;color:#64748B">Risk Score</div>
                        <div style="font-size:14px;font-weight:700;color:{color}">{score}/100 — {tier}</div>
                    </div>
                    <div>
                        <div style="font-size:11px;color:#64748B">Total Findings</div>
                        <div style="font-size:14px;font-weight:600;color:#F1F5F9">{len(findings)}</div>
                    </div>
                    <div>
                        <div style="font-size:11px;color:#64748B">Last Scanned</div>
                        <div style="font-size:14px;font-weight:600;color:#F1F5F9">{format_dt(vendor.get('last_scanned'))}</div>
                    </div>
                </div>
                <div style="padding-top:12px;border-top:1px solid #334155">
                    <div style="font-size:11px;color:#64748B;margin-bottom:8px">Report will include</div>
                    {'<div style="font-size:12px;color:#94A3B8">• Executive risk summary</div>' if True else ''}
                    {'<div style="font-size:12px;color:#94A3B8">• AI attack path narrative</div>' if include_narrative else ''}
                    <div style="font-size:12px;color:#94A3B8">• {len(findings)} findings with severity ratings</div>
                    <div style="font-size:12px;color:#94A3B8">• Compliance gap analysis: {', '.join(frameworks)}</div>
                    <div style="font-size:12px;color:#94A3B8">• Remediation recommendations</div>
                    {'<div style="font-size:12px;color:#94A3B8">• Timestamped evidence appendix</div>' if include_evidence else ''}
                </div>
            </div>
            """, unsafe_allow_html=True)

    if gen and vendor:
        report_content = _build_report_text(
            vendor=vendor,
            report_type=report_type,
            frameworks=frameworks,
            include_evidence=include_evidence,
            include_narrative=include_narrative,
        )

        st.markdown("<br>", unsafe_allow_html=True)

        # Display report
        st.markdown(f"""
        <div class="section-card">
            <div class="section-card-title">{report_type} — {vendor.get('name','')} — {datetime.now().strftime('%d %b %Y')}</div>
        """, unsafe_allow_html=True)

        st.markdown(report_content, unsafe_allow_html=False)
        st.markdown("</div>", unsafe_allow_html=True)

        # Download buttons
        dl1, dl2 = st.columns(2)
        with dl1:
            st.download_button(
                label="⬇ Download as Markdown",
                data=report_content,
                file_name=f"vendorsentinel_{selected_domain}_{datetime.now().strftime('%Y%m%d')}.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with dl2:
            evidence_json = json.dumps(load_evidence(selected_domain), indent=2, default=str)
            st.download_button(
                label="⬇ Download Evidence (JSON)",
                data=evidence_json,
                file_name=f"evidence_{selected_domain}_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True,
            )


def _build_report_text(vendor, report_type, frameworks, include_evidence, include_narrative):
    name      = vendor.get("name","Unknown")
    domain    = vendor.get("domain","")
    score     = vendor.get("risk_score", 0)
    tier      = vendor.get("risk_tier","Unknown")
    analysis  = vendor.get("analysis", {})
    findings  = vendor.get("findings", [])
    generated = datetime.now().strftime("%d %B %Y, %H:%M UTC")

    lines = [
        f"# VendorSentinel AI — {report_type}",
        f"## {name} ({domain})",
        f"**Generated:** {generated}  ",
        f"**Platform:** VendorSentinel AI v1.0  ",
        f"**Classification:** Confidential  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"**Vendor:** {name}  ",
        f"**Domain:** {domain}  ",
        f"**Risk Score:** {score}/100  ",
        f"**Risk Tier:** {tier}  ",
        f"**Total Findings:** {len(findings)}  ",
        f"**Critical:** {sum(1 for f in findings if f.get('severity')=='Critical')}  ",
        f"**High:** {sum(1 for f in findings if f.get('severity')=='High')}  ",
        "",
    ]

    if include_narrative:
        narrative = analysis.get("attack_path_narrative","Not available.")
        lines += [
            "## AI Attack Path Analysis",
            "",
            narrative,
            "",
            "### Key Attack Steps",
            "",
        ]
        for i, step in enumerate(analysis.get("key_attack_steps",[]), 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    # Findings
    lines += ["## Findings Detail", ""]
    for sev in ["Critical","High","Medium","Low"]:
        sev_findings = [f for f in findings if f.get("severity")==sev]
        if sev_findings:
            lines += [f"### {sev} Severity ({len(sev_findings)} findings)", ""]
            for f in sev_findings:
                lines += [
                    f"**{f.get('title','')}**  ",
                    f"Source: {f.get('source','')}  ",
                    f.get("detail",""),
                    f"Controls: {', '.join(f.get('controls',[]))}  " if f.get("controls") else "",
                    "",
                ]

    # Compliance
    if frameworks:
        lines += ["## Compliance Gap Analysis", ""]
        fw_gaps = analysis.get("compliance_gaps", {})
        for fw in frameworks:
            data = fw_gaps.get(fw, {})
            if isinstance(data, dict):
                status  = data.get("status","Unknown")
                detail  = data.get("detail","")
                controls= data.get("controls",[])
                status_icon = "✅" if status == "Pass" else "❌"
                lines += [
                    f"### {fw} — {status_icon} {status}",
                    detail,
                    f"Controls: {', '.join(controls)}" if controls else "",
                    "",
                ]

    # Recommendations
    recs = analysis.get("top_recommendations", [])
    if recs:
        lines += ["## Remediation Recommendations", ""]
        for i, rec in enumerate(recs, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    # Evidence
    if include_evidence:
        evidence = load_evidence(domain)
        lines += [
            "## Evidence Appendix",
            "",
            f"Total evidence items collected: {len(evidence)}  ",
            "",
        ]
        for e in evidence[:10]:
            lines += [
                f"**Source:** {e.get('source','')} — **Type:** {e.get('finding_type','')} — **Collected:** {e.get('collected_at','')[:19]}",
                "",
            ]

    lines += [
        "---",
        f"*Generated by VendorSentinel AI — Open Source TPRM Platform — {generated}*",
    ]
    return "\n".join(lines)


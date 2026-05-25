from collectors.ssl_check   import check_ssl
from collectors.dns_check   import check_dns
from collectors.shodan_check import check_shodan
from collectors.hibp_check  import check_hibp
from collectors.news_check  import check_news
from intelligence.cisa_feed import fetch_cisa_kev
from intelligence.nvd_feed  import fetch_recent_cves
from ai.attack_chain        import run_attack_chain_analysis
from utils.storage          import upsert_vendor, save_evidence, load_threat_intel, save_threat_intel
from datetime import datetime


def run_full_scan(domain, company_name, data_access, frameworks, secrets, progress_cb=None):
    """
    Orchestrates a full vendor scan.
    progress_cb: callable(step_name, status, finding) for live UI updates
    """
    def log(step, status, finding=None):
        if progress_cb:
            progress_cb(step, status, finding)

    all_results = []
    log("SSL / TLS certificate health", "running")
    ssl_result = check_ssl(domain)
    all_results.append(ssl_result)
    for f in ssl_result["findings"]:
        if f["severity"] != "Info":
            log("SSL / TLS certificate health", ssl_result["status"], f)
    save_evidence(domain, "ssl", ssl_result["raw"], "ssl")
    log("SSL / TLS certificate health", "done")

    log("DNS & email security", "running")
    dns_result = check_dns(domain)
    all_results.append(dns_result)
    for f in dns_result["findings"]:
        if f["severity"] != "Info":
            log("DNS & email security", dns_result["status"], f)
    save_evidence(domain, "dns", dns_result["raw"], "dns")
    log("DNS & email security", "done")

    log("Attack surface (Shodan)", "running")
    shodan_key = secrets.get("SHODAN_API_KEY")
    shodan_result = check_shodan(domain, api_key=shodan_key)
    all_results.append(shodan_result)
    for f in shodan_result["findings"]:
        if f["severity"] not in ("Info", "Low"):
            log("Attack surface (Shodan)", shodan_result["status"], f)
    save_evidence(domain, "shodan", shodan_result["raw"], "exposure")
    log("Attack surface (Shodan)", "done")

    log("Breach database (HIBP)", "running")
    hibp_key = secrets.get("HIBP_API_KEY")
    hibp_result = check_hibp(domain, api_key=hibp_key)
    all_results.append(hibp_result)
    for f in hibp_result["findings"]:
        if f["severity"] != "Info":
            log("Breach database (HIBP)", hibp_result["status"], f)
    save_evidence(domain, "hibp", hibp_result["raw"], "breach")
    log("Breach database (HIBP)", "done")

    log("Adverse media & news", "running")
    news_key = secrets.get("NEWS_API_KEY")
    news_result = check_news(domain, company_name=company_name, api_key=news_key)
    all_results.append(news_result)
    for f in news_result["findings"]:
        if f["severity"] not in ("Info",):
            log("Adverse media & news", news_result["status"], f)
    save_evidence(domain, "news", {"articles": news_result["raw"].get("articles", [])[:5]}, "media")
    log("Adverse media & news", "done")

    log("CISA KEV threat intelligence", "running")
    kev_data = fetch_cisa_kev()
    kev_entries = kev_data.get("entries", [])
    log("CISA KEV threat intelligence", kev_data["status"])

    log("NVD vulnerability database", "running")
    nvd_data = fetch_recent_cves(days_back=14, severity_filter="CRITICAL")
    nvd_entries = nvd_data.get("entries", [])
    log("NVD vulnerability database", nvd_data["status"])

    # Save threat intel
    existing = load_threat_intel()
    new_intel = kev_entries[:20] + nvd_entries[:20]
    merged = {e["cve_id"]: e for e in existing + new_intel if e.get("cve_id")}.values()
    save_threat_intel(list(merged)[:200])

    log("AI attack chain analysis", "running")
    anthropic_key = secrets.get("ANTHROPIC_API_KEY")
    analysis = run_attack_chain_analysis(
        domain           = domain,
        data_access      = data_access,
        collector_results= all_results,
        kev_entries      = kev_entries,
        nvd_entries      = nvd_entries,
        api_key          = anthropic_key,
    )
    log("AI attack chain analysis", "done")

    # Aggregate all findings
    all_findings = []
    for r in all_results:
        for f in r.get("findings", []):
            f["source"] = r["source"]
            all_findings.append(f)

    # Build risk history entry
    vendor_data = {
        "domain":      domain,
        "name":        company_name,
        "data_access": data_access,
        "frameworks":  frameworks,
        "risk_score":  analysis["risk_score"],
        "risk_tier":   analysis["risk_tier"],
        "analysis":    analysis,
        "findings":    all_findings,
        "last_scanned": datetime.now().isoformat(),
    }

    # Preserve history
    from utils.storage import get_vendor
    existing_vendor = get_vendor(domain)
    history = existing_vendor.get("risk_history", []) if existing_vendor else []
    history.append({
        "score": analysis["risk_score"],
        "tier":  analysis["risk_tier"],
        "date":  datetime.now().isoformat()[:10],
    })
    vendor_data["risk_history"] = history[-30:]  # keep 30 data points

    upsert_vendor(vendor_data)
    return vendor_data


import anthropic
import json
from utils.helpers import score_to_tier

SYSTEM_PROMPT = """You are a senior threat analyst at a cybersecurity firm specialising in Third Party Risk Management (TPRM). You think like both an attacker and a defender.

You will be given:
- Raw signals collected from public sources about a vendor
- Live threat intelligence from CISA KEV, NVD, and other feeds
- The data types that Organisation A shares with this vendor

Your job is to:
1. Construct the most plausible attack chain an attacker would use against this vendor to reach Organisation A's data
2. Calculate a risk score from 0-100 (higher = more dangerous)
3. Map findings to compliance frameworks
4. Write a clear, professional threat narrative

You MUST respond with valid JSON only. No markdown. No explanation outside the JSON."""

ATTACK_CHAIN_PROMPT = """Analyse this vendor's security posture and produce a threat assessment.

VENDOR: {domain}
DATA ACCESS: {data_access}

SIGNALS COLLECTED:
{signals_summary}

THREAT INTELLIGENCE CONTEXT:
{threat_context}

Respond ONLY with this JSON structure:
{{
  "risk_score": <integer 0-100>,
  "risk_tier": "<Critical|High|Medium|Low|Minimal>",
  "attack_path_narrative": "<3-5 sentence plain English description of the most likely attack chain from public internet to Organisation A's data. Be specific about which signals combine to create the path. Name the exact vulnerability types.>",
  "key_attack_steps": [
    "<step 1>",
    "<step 2>",
    "<step 3>"
  ],
  "compliance_gaps": {{
    "ISO 27001": {{"status": "<Pass|Fail>", "controls": ["<control ref>"], "detail": "<one line>"}},
    "SOC 2":     {{"status": "<Pass|Fail>", "controls": ["<control ref>"], "detail": "<one line>"}},
    "DORA":      {{"status": "<Pass|Fail>", "controls": ["<article ref>"], "detail": "<one line>"}},
    "NIS2":      {{"status": "<Pass|Fail>", "controls": ["<article ref>"], "detail": "<one line>"}},
    "NIST CSF":  {{"status": "<Pass|Fail>", "controls": ["<subcategory>"], "detail": "<one line>"}},
    "PCI DSS":   {{"status": "<Pass|Fail>", "controls": ["<req ref>"],    "detail": "<one line>"}}
  }},
  "top_recommendations": [
    "<most impactful remediation action>",
    "<second action>",
    "<third action>"
  ],
  "confidence": "<High|Medium|Low>",
  "threat_actor_effort": "<Low|Medium|High>"
}}"""


def build_signals_summary(collector_results):
    lines = []
    for r in collector_results:
        source = r.get("source", "Unknown")
        findings = r.get("findings", [])
        for f in findings:
            sev = f.get("severity", "Info")
            if sev == "Info":
                continue
            lines.append(
                f"[{sev.upper()}] {source}: {f.get('title', '')} "
                f"— {f.get('detail', '')[:150]}"
            )
    return "\n".join(lines) if lines else "No significant findings."


def build_threat_context(kev_entries, nvd_entries):
    lines = []
    for e in (kev_entries or [])[:5]:
        lines.append(
            f"CISA KEV: {e.get('cve_id', '')} — {e.get('title', '')} "
            f"(affects {e.get('product', 'unknown')})"
        )
    for e in (nvd_entries or [])[:5]:
        if e.get("severity") in ("Critical", "High"):
            lines.append(
                f"NVD CVE: {e.get('cve_id', '')} CVSS {e.get('cvss_score', '')} "
                f"— {e.get('title', '')[:100]}"
            )
    return "\n".join(lines) if lines else "No specific threat intelligence matches."


def run_attack_chain_analysis(
    domain,
    data_access,
    collector_results,
    kev_entries=None,
    nvd_entries=None,
    api_key=None,
):
    if not api_key:
        return _fallback_analysis(domain, collector_results)

    signals_summary = build_signals_summary(collector_results)
    threat_context  = build_threat_context(kev_entries or [], nvd_entries or [])

    prompt = ATTACK_CHAIN_PROMPT.format(
        domain          = domain,
        data_access     = data_access or "General business data",
        signals_summary = signals_summary,
        threat_context  = threat_context,
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model      = "claude-sonnet-4-20250514",
            max_tokens = 1500,
            system     = SYSTEM_PROMPT,
            messages   = [{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()

        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        analysis = json.loads(raw)
        analysis["ai_powered"] = True
        analysis["domain"]     = domain
        return analysis

    except json.JSONDecodeError:
        return _fallback_analysis(domain, collector_results)
    except Exception as e:
        return _fallback_analysis(domain, collector_results, error=str(e))


# ── RECOMMENDATION ENGINE ──────────────────────────────────────────────────────

def _build_recommendations(critical_findings, high_findings):
    """
    Build proper actionable recommendations based on what was actually found.
    Never returns article titles — always returns real remediation actions.
    """
    recs = []
    all_findings = critical_findings + high_findings
    sources = set(f.get("source", "") for f in all_findings)
    titles  = " ".join(f.get("title", "").lower() for f in all_findings)

    if "SSL/TLS" in sources or "ssl" in titles:
        if "expir" in titles:
            recs.append(
                "Renew the SSL/TLS certificate immediately and implement automated "
                "renewal to prevent future expiry and service disruption"
            )
        else:
            recs.append(
                "Review SSL/TLS configuration — ensure certificates use trusted CAs, "
                "strong cipher suites, and TLS 1.2 or higher only"
            )

    if "DNS & Email Security" in sources or "dmarc" in titles or "spf" in titles:
        recs.append(
            "Implement DMARC policy set to p=reject and configure SPF with -all "
            "to prevent domain spoofing and phishing attacks using this vendor's domain"
        )

    if "Shodan (Attack Surface)" in sources or "rdp" in titles or "port" in titles:
        recs.append(
            "Remove all publicly exposed management ports — especially RDP (3389), "
            "Telnet (23), and database ports — restrict access behind a VPN or firewall"
        )

    if "HIBP (Breach Database)" in sources or "breach" in titles or "credential" in titles:
        recs.append(
            "Request written confirmation of credential rotation and MFA enforcement "
            "following identified historical breach — obtain their formal incident report"
        )

    if "Adverse Media" in sources:
        recs.append(
            "Request vendor's most recent third-party penetration test report (within 12 months) "
            "and their formal written response to any regulatory or media incidents"
        )

    if "cve" in titles or "vulnerabilit" in titles:
        recs.append(
            "Request evidence of patch management process and confirm all critical "
            "CVEs identified in this assessment have been remediated with timelines"
        )

    if not recs:
        recs = [
            "Request vendor's latest ISO 27001 certificate or SOC 2 Type II report "
            "as evidence of their security programme maturity",
            "Review data processing agreement and ensure breach notification obligations "
            "are contractually defined with a maximum 72-hour notification window",
            "Schedule a formal vendor security review within 30 days and add this "
            "vendor to your continuous monitoring programme",
        ]

    return recs[:3]


# ── SCORE ENGINE ───────────────────────────────────────────────────────────────

def _calculate_score(collector_results):
    """
    Context-aware scoring — news findings weighted lower than
    technical findings because they are indirect unverified evidence.
    """
    source_weights = {
        "SSL/TLS":                  {"Critical": 25, "High": 15, "Medium": 8,  "Low": 3,  "Info": 0},
        "DNS & Email Security":     {"Critical": 20, "High": 12, "Medium": 6,  "Low": 2,  "Info": 0},
        "Shodan (Attack Surface)":  {"Critical": 25, "High": 15, "Medium": 8,  "Low": 3,  "Info": 0},
        "HIBP (Breach Database)":   {"Critical": 20, "High": 12, "Medium": 6,  "Low": 2,  "Info": 0},
        "Adverse Media":            {"Critical": 10, "High": 6,  "Medium": 3,  "Low": 1,  "Info": 0},
    }
    default_weights = {"Critical": 20, "High": 12, "Medium": 6, "Low": 2, "Info": 0}

    total = 0
    for r in collector_results:
        source  = r.get("source", "")
        weights = source_weights.get(source, default_weights)
        for f in r.get("findings", []):
            sev    = f.get("severity", "Info")
            total += weights.get(sev, 0)

    return min(total, 100)


# ── NARRATIVE ENGINE ───────────────────────────────────────────────────────────

def _build_narrative(domain, risk_tier, critical_findings, high_findings, all_results):
    """
    Contextual narrative based on actual technical findings only.
    Never mentions news article titles.
    """
    technical_issues = []
    for r in all_results:
        source = r.get("source", "")
        if source == "Adverse Media":
            continue
        for f in r.get("findings", []):
            if f.get("severity") in ("Critical", "High"):
                technical_issues.append((source, f.get("title", ""), f.get("severity")))

    if not technical_issues and not critical_findings and not high_findings:
        return (
            f"{domain} presents a {risk_tier.lower()} risk profile based on passive analysis. "
            "No significant technical vulnerabilities were detected across SSL certificate health, "
            "DNS email security, attack surface analysis, or breach databases. "
            "Continue monitoring for changes in this vendor's security posture. "
            "Consider requesting their latest security assessment for a complete picture."
        )

    if technical_issues:
        issue_descriptions = [
            f"{title.lower()} via {source}"
            for source, title, sev in technical_issues[:2]
        ]
        issues_str = "; ".join(issue_descriptions)
        return (
            f"{domain} presents a {risk_tier.lower()} risk profile based on technical signals. "
            f"Key findings include: {issues_str}. "
            "An attacker could chain these signals to reach data shared by your organisation "
            "with this vendor, reducing the effort and time required for a successful breach. "
            "Prioritise the remediation actions below before extending this vendor relationship."
        )

    return (
        f"{domain} presents a {risk_tier.lower()} risk profile. "
        "Technical infrastructure checks did not identify direct exploitable vulnerabilities. "
        "However, adverse media signals indicate reputational and governance risks "
        "that warrant further investigation before renewing or extending this vendor relationship. "
        "Request the vendor's latest penetration test report and formal security certifications."
    )


# ── COMPLIANCE ENGINE ──────────────────────────────────────────────────────────

def _build_compliance(collector_results, risk_score):
    """
    Framework-specific compliance assessment based on actual findings.
    Not just pass/fail based on score — maps to specific signals.
    """
    has_ssl_issue    = False
    has_email_issue  = False
    has_exposure     = False
    has_breach       = False
    has_media        = False

    for r in collector_results:
        source = r.get("source", "")
        has_critical_or_high = any(
            f.get("severity") in ("Critical", "High")
            for f in r.get("findings", [])
        )
        if source == "SSL/TLS" and has_critical_or_high:
            has_ssl_issue = True
        if source == "DNS & Email Security" and has_critical_or_high:
            has_email_issue = True
        if source == "Shodan (Attack Surface)" and has_critical_or_high:
            has_exposure = True
        if source == "HIBP (Breach Database)" and has_critical_or_high:
            has_breach = True
        if source == "Adverse Media" and has_critical_or_high:
            has_media = True

    frameworks = {
        "ISO 27001": {
            "fail": has_ssl_issue or has_email_issue or has_exposure or has_breach,
            "controls": ["A.8.20", "A.8.23", "A.8.24", "A.5.7"],
            "pass_detail": "No critical technical findings — manual assessment recommended to confirm",
            "fail_detail": "SSL, DNS, or breach findings indicate control gaps in Annex A supplier security",
        },
        "SOC 2": {
            "fail": has_exposure or has_breach or has_ssl_issue,
            "controls": ["CC6.1", "CC6.6", "CC7.2", "CC9.2"],
            "pass_detail": "No findings mapping to Trust Service Criteria failures",
            "fail_detail": "Exposed services or breach history indicate CC6/CC7 control failures",
        },
        "DORA": {
            "fail": has_exposure or has_breach,
            "controls": ["Art.28", "Art.30", "Art.9"],
            "pass_detail": "No DORA ICT third-party risk signals detected",
            "fail_detail": "Exposed infrastructure or breach history triggers DORA Art.28 ICT risk obligations",
        },
        "NIS2": {
            "fail": has_exposure or has_email_issue,
            "controls": ["Art.21", "Art.23"],
            "pass_detail": "No NIS2 supply chain security risk signals detected",
            "fail_detail": "Supply chain security obligations under NIS2 Art.21 may not be satisfied",
        },
        "NIST CSF": {
            "fail": has_email_issue or has_exposure or has_breach,
            "controls": ["GV.SC-06", "PR.AC-05", "DE.CM-01"],
            "pass_detail": "No NIST CSF supply chain subcategory failures detected",
            "fail_detail": "GV.SC supply chain risk management subcategories not fully addressed",
        },
        "PCI DSS": {
            "fail": has_exposure or has_breach,
            "controls": ["Req 12.8", "Req 6.3"],
            "pass_detail": "No PCI DSS third-party service provider risk signals detected",
            "fail_detail": "Req 12.8 third-party security programme requirements may not be met",
        },
    }

    result = {}
    for fw, config in frameworks.items():
        status = "Fail" if config["fail"] else "Pass"
        detail = config["fail_detail"] if config["fail"] else config["pass_detail"]
        result[fw] = {
            "status":   status,
            "controls": config["controls"] if config["fail"] else [],
            "detail":   detail,
        }
    return result


# ── FALLBACK ANALYSIS ──────────────────────────────────────────────────────────

def _fallback_analysis(domain, collector_results, error=None):
    """
    Rule-based fallback when Claude API is not available.
    Produces accurate context-aware scoring and proper recommendations.
    """
    risk_score = _calculate_score(collector_results)
    risk_tier  = score_to_tier(risk_score)

    critical_findings = [
        f for r in collector_results
        for f in r.get("findings", [])
        if f.get("severity") == "Critical"
    ]
    high_findings = [
        f for r in collector_results
        for f in r.get("findings", [])
        if f.get("severity") == "High"
    ]

    narrative       = _build_narrative(domain, risk_tier, critical_findings, high_findings, collector_results)
    compliance_gaps = _build_compliance(collector_results, risk_score)
    recommendations = _build_recommendations(critical_findings, high_findings)

    # Attack steps — technical only, never article titles
    technical_steps = [
        f["title"]
        for r in collector_results
        for f in r.get("findings", [])
        if f.get("severity") in ("Critical", "High")
        and r.get("source") != "Adverse Media"
    ][:3]

    if not technical_steps:
        technical_steps = [
            "No direct technical attack vectors identified in passive analysis",
            "Monitor vendor infrastructure continuously for new exposures",
            "Request vendor security documentation to complete the assessment",
        ]

    effort = "Low" if risk_score >= 75 else "Medium" if risk_score >= 40 else "High"

    return {
        "risk_score":            risk_score,
        "risk_tier":             risk_tier,
        "attack_path_narrative": narrative,
        "key_attack_steps":      technical_steps,
        "compliance_gaps":       compliance_gaps,
        "top_recommendations":   recommendations,
        "confidence":            "Medium",
        "threat_actor_effort":   effort,
        "ai_powered":            False,
        "domain":                domain,
        "error":                 error,
    }

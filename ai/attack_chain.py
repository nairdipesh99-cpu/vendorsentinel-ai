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
            lines.append(f"[{sev.upper()}] {source}: {f.get('title', '')} — {f.get('detail', '')[:150]}")
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
                f"NVD CVE: {e.get('cve_id', '')} CVSS {e.get('cvss_score', '')} — "
                f"{e.get('title', '')[:100]}"
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
        domain         = domain,
        data_access    = data_access or "General business data",
        signals_summary= signals_summary,
        threat_context = threat_context,
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

        # Strip markdown fences if present
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


def _fallback_analysis(domain, collector_results, error=None):
    """Rule-based fallback when Claude API is not available."""
    total_score = 0
    all_controls = []

    severity_weights = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}
    for r in collector_results:
        for f in r.get("findings", []):
            total_score += severity_weights.get(f.get("severity", "Info"), 0)
            all_controls.extend(f.get("controls", []))

    risk_score = min(total_score, 100)
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

    if critical_findings:
        narrative = (
            f"{domain} presents a {risk_tier.lower()} risk profile. "
            f"Critical findings include: {'; '.join(f['title'] for f in critical_findings[:2])}. "
            "These represent direct attack vectors that could be exploited to access data "
            "shared by your organisation with this vendor. "
            "Immediate remediation is required to prevent potential data exposure."
        )
    elif high_findings:
        narrative = (
            f"{domain} presents a {risk_tier.lower()} risk profile. "
            f"High severity findings: {'; '.join(f['title'] for f in high_findings[:2])}. "
            "These findings, combined, create exploitable paths through the vendor's infrastructure. "
            "Remediation should be prioritised within 30 days."
        )
    else:
        narrative = (
            f"{domain} presents a {risk_tier.lower()} risk profile based on passive analysis. "
            "No critical or high severity findings were detected. "
            "Continue monitoring for changes in the vendor's security posture."
        )

    fw_status = "Fail" if risk_score >= 55 else "Pass"
    note = f"Risk score {risk_score}/100 — review findings for details."

    return {
        "risk_score":            risk_score,
        "risk_tier":             risk_tier,
        "attack_path_narrative": narrative,
        "key_attack_steps":      [f["title"] for f in (critical_findings + high_findings)[:3]],
        "compliance_gaps": {
            fw: {"status": fw_status, "controls": [], "detail": note}
            for fw in ["ISO 27001", "SOC 2", "DORA", "NIS2", "NIST CSF", "PCI DSS"]
        },
        "top_recommendations": [
            f["title"] for f in (critical_findings + high_findings)[:3]
        ] or ["No critical actions required at this time."],
        "confidence":           "Medium",
        "threat_actor_effort":  "Low" if risk_score >= 75 else "Medium",
        "ai_powered":           False,
        "domain":               domain,
        "error":                error,
    }


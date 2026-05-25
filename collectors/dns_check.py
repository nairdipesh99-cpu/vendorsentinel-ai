import dns.resolver
import dns.exception

def check_dns(domain):
    result = {
        "source":   "DNS & Email Security",
        "domain":   domain,
        "findings": [],
        "raw":      {},
        "status":   "ok",
    }
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 8
    resolver.lifetime = 8

    # SPF
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = [r.to_text() for r in answers if "v=spf1" in r.to_text()]
        result["raw"]["spf"] = spf_records
        if not spf_records:
            result["findings"].append({
                "title":    "No SPF record found",
                "severity": "High",
                "detail":   f"No SPF record on {domain}. Attackers can spoof emails from this domain.",
                "controls": ["ISO 27001 A.8.23", "SOC 2 CC6.7", "NIST CSF PR.AC-5"],
            })
        elif len(spf_records) > 1:
            result["findings"].append({
                "title":    "Multiple SPF records detected",
                "severity": "Medium",
                "detail":   "Having more than one SPF record is invalid and can break email authentication.",
                "controls": ["ISO 27001 A.8.23"],
            })
        else:
            spf = spf_records[0]
            if "+all" in spf:
                result["findings"].append({
                    "title":    "SPF record uses +all (permits any sender)",
                    "severity": "Critical",
                    "detail":   "The +all mechanism allows any IP to send email on behalf of this domain.",
                    "controls": ["ISO 27001 A.8.23", "DORA Art.9", "NIS2 Art.21"],
                })
            elif "~all" in spf:
                result["findings"].append({
                    "title":    "SPF uses ~all (soft-fail — not enforced)",
                    "severity": "Low",
                    "detail":   "Soft-fail mode does not reject spoofed emails, only marks them.",
                    "controls": ["ISO 27001 A.8.23"],
                })
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result["findings"].append({
            "title":    "No SPF record found",
            "severity": "High",
            "detail":   "No TXT records found. Domain cannot authenticate email senders.",
            "controls": ["ISO 27001 A.8.23", "SOC 2 CC6.7"],
        })
    except Exception as e:
        result["findings"].append({
            "title": "SPF check error", "severity": "Low",
            "detail": str(e), "controls": [],
        })

    # DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        dmarc_records = [r.to_text() for r in answers if "v=DMARC1" in r.to_text()]
        result["raw"]["dmarc"] = dmarc_records
        if not dmarc_records:
            result["findings"].append({
                "title":    "No DMARC record found",
                "severity": "High",
                "detail":   "Without DMARC, there is no policy for handling spoofed emails from this domain.",
                "controls": ["ISO 27001 A.8.23", "SOC 2 CC6.7", "NIST CSF PR.AC-5", "DORA Art.9"],
            })
        else:
            dmarc = dmarc_records[0]
            if "p=none" in dmarc:
                result["findings"].append({
                    "title":    "DMARC policy set to none (monitoring only)",
                    "severity": "Medium",
                    "detail":   "DMARC exists but does not reject or quarantine spoofed emails.",
                    "controls": ["ISO 27001 A.8.23", "SOC 2 CC6.7"],
                })
            result["raw"]["dmarc_policy"] = dmarc
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result["findings"].append({
            "title":    "No DMARC record found",
            "severity": "High",
            "detail":   "No DMARC policy in DNS. Phishing using this domain cannot be blocked.",
            "controls": ["ISO 27001 A.8.23", "SOC 2 CC6.7", "DORA Art.9"],
        })
    except Exception as e:
        result["findings"].append({
            "title": "DMARC check error", "severity": "Low",
            "detail": str(e), "controls": [],
        })

    # MX records
    try:
        mx_answers = resolver.resolve(domain, "MX")
        mx_list = [str(r.exchange) for r in mx_answers]
        result["raw"]["mx"] = mx_list
        if not mx_list:
            result["findings"].append({
                "title":    "No MX records found",
                "severity": "Low",
                "detail":   "Domain does not appear to receive email.",
                "controls": [],
            })
    except Exception:
        result["raw"]["mx"] = []

    if not result["findings"]:
        result["findings"].append({
            "title":    "DNS and email security configuration is healthy",
            "severity": "Info",
            "detail":   "SPF and DMARC records are present and correctly configured.",
            "controls": [],
        })

    result["score_contribution"] = sum(
        {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}.get(f["severity"], 0)
        for f in result["findings"]
    )
    return result


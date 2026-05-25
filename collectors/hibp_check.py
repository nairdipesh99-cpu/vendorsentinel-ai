import requests
from datetime import datetime

def check_hibp(domain, api_key=None):
    result = {
        "source":   "HIBP (Breach Database)",
        "domain":   domain,
        "findings": [],
        "raw":      {},
        "status":   "ok",
    }

    headers = {"User-Agent": "VendorSentinel-AI-TPRM/1.0"}
    if api_key:
        headers["hibp-api-key"] = api_key

    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers=headers,
            timeout=10,
        )

        if resp.status_code == 401:
            # Try public endpoint without key
            resp2 = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                headers=headers,
                timeout=10,
            )
            if resp2.status_code == 200:
                breaches = resp2.json()
            else:
                result["findings"].append({
                    "title":    "HIBP API key required for full breach data",
                    "severity": "Info",
                    "detail":   "Add HIBP_API_KEY to secrets.toml for detailed breach analysis.",
                    "controls": [],
                })
                result["score_contribution"] = 0
                return result
        elif resp.status_code == 404:
            result["raw"]["breaches"] = []
            result["findings"].append({
                "title":    f"No breaches found for {domain}",
                "severity": "Info",
                "detail":   "Domain does not appear in any known breach database.",
                "controls": [],
            })
            result["score_contribution"] = 0
            return result
        elif resp.status_code == 200:
            breaches = resp.json() if resp.text else []
        else:
            breaches = []

        result["raw"]["breach_count"] = len(breaches)
        result["raw"]["breaches"] = breaches

        if not breaches:
            result["findings"].append({
                "title":    f"No breaches found for {domain}",
                "severity": "Info",
                "detail":   "Domain does not appear in any known breach database.",
                "controls": [],
            })
        else:
            # Sort by date, most recent first
            sorted_breaches = sorted(
                breaches,
                key=lambda b: b.get("BreachDate", b.get("breach_date", "1900-01-01")),
                reverse=True,
            )

            # Most recent breach
            recent = sorted_breaches[0]
            breach_date = recent.get("BreachDate") or recent.get("breach_date", "Unknown")
            breach_name = recent.get("Name") or recent.get("name", "Unknown")
            data_classes = recent.get("DataClasses") or recent.get("data_classes", [])
            pwn_count    = recent.get("PwnCount") or recent.get("pwn_count", 0)

            # Calculate how old the breach is
            try:
                breach_dt = datetime.strptime(breach_date, "%Y-%m-%d")
                days_since = (datetime.now() - breach_dt).days
                age_str = f"{days_since} days ago"
            except Exception:
                age_str = breach_date

            severity = "Critical" if days_since < 365 else "High" if days_since < 730 else "Medium"
            sensitive_types = ["Passwords", "Credit card numbers", "Bank account numbers", "Social security numbers"]
            has_sensitive = any(dt in data_classes for dt in sensitive_types)
            if has_sensitive:
                severity = "Critical"

            controls = {
                "Critical": ["ISO 27001 A.5.7", "SOC 2 CC7.2", "DORA Art.28", "NIS2 Art.21", "NIST CSF RS.AN-2"],
                "High":     ["ISO 27001 A.5.7", "SOC 2 CC7.2", "NIST CSF RS.AN-2"],
                "Medium":   ["ISO 27001 A.5.7", "SOC 2 CC7.2"],
            }.get(severity, [])

            data_str = ", ".join(data_classes[:6]) if data_classes else "Unknown"
            result["findings"].append({
                "title":    f"Data breach found: {breach_name} ({age_str})",
                "severity": severity,
                "detail":   (
                    f"Breach occurred {age_str}. "
                    f"{f'{pwn_count:,} records' if pwn_count else 'Unknown records'} exposed. "
                    f"Data types: {data_str}."
                ),
                "controls": controls,
            })

            # Additional breaches
            if len(sorted_breaches) > 1:
                additional = len(sorted_breaches) - 1
                result["findings"].append({
                    "title":    f"{additional} additional historical breach(es) found",
                    "severity": "Medium",
                    "detail":   f"This domain has appeared in {len(sorted_breaches)} total breach datasets.",
                    "controls": ["ISO 27001 A.5.7"],
                })

    except requests.Timeout:
        result["status"] = "timeout"
        result["findings"].append({
            "title": "HIBP check timed out", "severity": "Low",
            "detail": "Request timed out after 10 seconds.", "controls": [],
        })
    except Exception as e:
        result["status"] = "error"
        result["findings"].append({
            "title": "HIBP check error", "severity": "Low",
            "detail": str(e), "controls": [],
        })

    result["score_contribution"] = sum(
        {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}.get(f["severity"], 0)
        for f in result["findings"]
    )
    return result


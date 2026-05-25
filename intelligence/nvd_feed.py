import requests
from datetime import datetime, timedelta

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_recent_cves(days_back=7, severity_filter=None):
    try:
        end   = datetime.utcnow()
        start = end - timedelta(days=days_back)

        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 50,
        }
        if severity_filter:
            params["cvssV3Severity"] = severity_filter.upper()

        resp = requests.get(NVD_BASE, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        entries = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description.")

            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                or {}
            )
            cvss_score    = cvss_data.get("baseScore", 0)
            base_severity = cvss_data.get("baseSeverity", "UNKNOWN")
            attack_vector = cvss_data.get("attackVector", "UNKNOWN")

            severity = {
                "CRITICAL": "Critical",
                "HIGH":     "High",
                "MEDIUM":   "Medium",
                "LOW":      "Low",
            }.get(base_severity, "Medium")

            references = cve.get("references", [])
            ref_urls = [r.get("url", "") for r in references[:3]]

            entries.append({
                "source":         "NVD",
                "cve_id":         cve_id,
                "title":          desc[:120] + ("..." if len(desc) > 120 else ""),
                "description":    desc,
                "cvss_score":     cvss_score,
                "severity":       severity,
                "attack_vector":  attack_vector,
                "published":      cve.get("published", "")[:10],
                "references":     ref_urls,
                "type":           "nvd_cve",
                "fetched_at":     datetime.now().isoformat(),
            })

        return {
            "status":  "ok",
            "entries": entries,
            "total":   data.get("totalResults", len(entries)),
        }

    except requests.Timeout:
        return {"status": "timeout", "entries": [], "total": 0}
    except Exception as e:
        return {"status": "error", "entries": [], "total": 0, "error": str(e)}


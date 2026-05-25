import requests
from datetime import datetime

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": "Mozilla/5.0 VendorSentinel-TPRM/1.0", "Accept": "application/json"}

def fetch_cisa_kev():
    try:
        resp = requests.get(CISA_KEV_URL, timeout=15, headers=HEADERS)
        if resp.status_code != 200:
            return {"status": "unavailable", "entries": _sample_kev(), "total": len(_sample_kev())}
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        sorted_vulns = sorted(vulns, key=lambda v: v.get("dateAdded", "1900-01-01"), reverse=True)
        processed = []
        for v in sorted_vulns[:100]:
            processed.append({
                "source":      "CISA KEV",
                "cve_id":      v.get("cveID", ""),
                "vendor_name": v.get("vendorProject", ""),
                "product":     v.get("product", ""),
                "title":       v.get("vulnerabilityName", ""),
                "description": v.get("shortDescription", ""),
                "date_added":  v.get("dateAdded", ""),
                "due_date":    v.get("dueDate", ""),
                "action":      v.get("requiredAction", ""),
                "severity":    "Critical",
                "type":        "cisa_kev",
                "fetched_at":  datetime.now().isoformat(),
            })
        return {"status": "ok", "entries": processed, "total": len(vulns)}
    except requests.Timeout:
        return {"status": "timeout", "entries": _sample_kev(), "total": 0}
    except Exception as e:
        return {"status": "error", "entries": _sample_kev(), "total": 0, "error": str(e)}


def _sample_kev():
    """Fallback sample data when CISA feed is unreachable."""
    return [
        {"source":"CISA KEV","cve_id":"CVE-2024-40711","vendor_name":"Veeam","product":"Backup & Replication",
         "title":"Veeam Backup & Replication Deserialization Vulnerability","description":"Veeam Backup & Replication contains a deserialization vulnerability that allows unauthenticated remote code execution.",
         "date_added":"2024-09-09","due_date":"2024-09-30","severity":"Critical","type":"cisa_kev","fetched_at":datetime.now().isoformat()},
        {"source":"CISA KEV","cve_id":"CVE-2024-38112","vendor_name":"Microsoft","product":"Windows",
         "title":"Microsoft Windows MSHTML Platform Spoofing Vulnerability","description":"Microsoft Windows MSHTML Platform contains a spoofing vulnerability.",
         "date_added":"2024-07-09","due_date":"2024-07-30","severity":"Critical","type":"cisa_kev","fetched_at":datetime.now().isoformat()},
        {"source":"CISA KEV","cve_id":"CVE-2024-3400","vendor_name":"Palo Alto Networks","product":"PAN-OS",
         "title":"Palo Alto Networks PAN-OS Command Injection Vulnerability","description":"Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability.",
         "date_added":"2024-04-12","due_date":"2024-04-19","severity":"Critical","type":"cisa_kev","fetched_at":datetime.now().isoformat()},
        {"source":"CISA KEV","cve_id":"CVE-2023-46604","vendor_name":"Apache","product":"ActiveMQ",
         "title":"Apache ActiveMQ Deserialization of Untrusted Data Vulnerability","description":"Apache ActiveMQ contains a deserialization of untrusted data vulnerability allowing RCE.",
         "date_added":"2023-11-02","due_date":"2023-11-23","severity":"Critical","type":"cisa_kev","fetched_at":datetime.now().isoformat()},
    ]


def match_vendor_to_kev(kev_entries, vendor_raw_data):
    matches = []
    candidate_terms = set()
    shodan = vendor_raw_data.get("shodan", {})
    for item in shodan.get("data", []):
        product = item.get("product", "")
        if product:
            candidate_terms.add(product.lower())
    os_info = shodan.get("os", "")
    if os_info:
        candidate_terms.add(os_info.lower())
    for entry in kev_entries:
        vendor_product = (entry.get("vendor_name","") + " " + entry.get("product","")).lower()
        for term in candidate_terms:
            if term and (term in vendor_product or vendor_product in term):
                matches.append(entry)
                break
    return matches


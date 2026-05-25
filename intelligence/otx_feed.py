import requests
from datetime import datetime, timedelta

OTX_BASE = "https://otx.alienvault.com/api/v1"

def fetch_otx_pulses(api_key=None, days_back=7, limit=20):
    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        since = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S")
        resp = requests.get(
            f"{OTX_BASE}/pulses/subscribed",
            headers=headers,
            params={"limit": limit, "modified_since": since},
            timeout=12,
        )

        if resp.status_code in (401, 403):
            return _public_pulses(days_back, limit)

        resp.raise_for_status()
        data = resp.json()
        return _process_pulses(data.get("results", []))

    except Exception:
        return _public_pulses(days_back, limit)


def _public_pulses(days_back, limit):
    """Fallback to public OTX feed (no key required)."""
    try:
        resp = requests.get(
            f"{OTX_BASE}/pulses/activity",
            params={"limit": limit},
            timeout=12,
        )
        resp.raise_for_status()
        data = resp.json()
        return _process_pulses(data.get("results", []))
    except Exception as e:
        return {"status": "error", "entries": [], "total": 0, "error": str(e)}


def _process_pulses(pulses):
    entries = []
    for p in pulses:
        tags = p.get("tags", [])
        tlp  = p.get("tlp", "white")

        severity = "High"
        tag_lower = " ".join(tags).lower()
        if any(kw in tag_lower for kw in ["ransomware", "apt", "critical", "exploit"]):
            severity = "Critical"
        elif any(kw in tag_lower for kw in ["phishing", "malware", "trojan"]):
            severity = "High"
        else:
            severity = "Medium"

        entries.append({
            "source":       "AlienVault OTX",
            "title":        p.get("name", "Unknown pulse"),
            "description":  p.get("description", "")[:200],
            "severity":     severity,
            "tags":         tags[:8],
            "indicators":   p.get("indicators_count", 0),
            "tlp":          tlp,
            "author":       p.get("author", {}).get("username", "Unknown"),
            "published":    p.get("created", "")[:10],
            "type":         "otx_pulse",
            "fetched_at":   datetime.now().isoformat(),
        })

    return {"status": "ok", "entries": entries, "total": len(entries)}


import requests
import urllib.parse
from datetime import datetime, timedelta

RISK_KEYWORDS = [
    "breach", "hack", "ransomware", "cyberattack", "data leak", "fine",
    "penalty", "lawsuit", "regulatory", "ICO", "GDPR", "insolvency",
    "bankruptcy", "fraud", "phishing", "vulnerability", "exploit",
    "malware", "investigation", "sanction", "shutdown",
]

# Words that indicate the company is reporting on others, not being breached
OBSERVER_WORDS = [
    "warns", "warning", "advises", "reports on", "discovers",
    "finds", "reveals", "uncovers", "alerts", "detects", "announces",
    "launches", "releases", "introduces", "updates", "improves",
]


def check_news(domain, company_name=None, api_key=None):
    result = {
        "source":   "Adverse Media",
        "domain":   domain,
        "findings": [],
        "raw":      {},
        "status":   "ok",
    }

    if not company_name:
        company_name = domain.split(".")[0].title()

    search_query = f'"{company_name}" AND ({" OR ".join(RISK_KEYWORDS[:8])})'
    from_date = (datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d")

    articles = []

    if api_key:
        try:
            resp = requests.get(
                "https://newsapi.org/v2/everything",
                params={
                    "q":        search_query,
                    "from":     from_date,
                    "sortBy":   "publishedAt",
                    "language": "en",
                    "pageSize": 10,
                    "apiKey":   api_key,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                articles = data.get("articles", [])
                result["raw"]["total_results"] = data.get("totalResults", 0)
        except Exception as e:
            result["raw"]["news_error"] = str(e)

    if not articles:
        try:
            query = urllib.parse.quote(f"{company_name} cybersecurity breach")
            rss_url = f"https://news.google.com/rss/search?q={query}&hl=en-GB&gl=GB&ceid=GB:en"
            resp = requests.get(
                rss_url,
                timeout=10,
                headers={"User-Agent": "VendorSentinel/1.0"},
            )
            if resp.status_code == 200:
                import re
                items = re.findall(r"<item>(.*?)</item>", resp.text, re.DOTALL)
                for item in items[:5]:
                    title_m = re.search(r"<title>(.*?)</title>", item)
                    link_m  = re.search(r"<link>(.*?)</link>",   item)
                    date_m  = re.search(r"<pubDate>(.*?)</pubDate>", item)
                    if title_m:
                        articles.append({
                            "title":       title_m.group(1),
                            "url":         link_m.group(1) if link_m else "",
                            "publishedAt": date_m.group(1) if date_m else "",
                            "source":      {"name": "Google News"},
                        })
        except Exception:
            pass

    result["raw"]["articles"] = articles

    risk_articles = []
    for a in articles:
        title = a.get("title", "").lower()
        if any(kw in title for kw in RISK_KEYWORDS):
            risk_articles.append(a)

    if not risk_articles and not articles:
        result["findings"].append({
            "title":    f"No adverse media found for {company_name}",
            "severity": "Info",
            "detail":   "No negative news articles detected in the past 12 months.",
            "controls": [],
        })
    elif not risk_articles:
        result["findings"].append({
            "title":    f"No risk-relevant news found for {company_name}",
            "severity": "Info",
            "detail":   f"{len(articles)} news articles found, none flagged as adverse.",
            "controls": [],
        })
    else:
        for a in risk_articles[:3]:
            title       = a.get("title", "Unknown")
            published   = a.get("publishedAt", "")[:10] if a.get("publishedAt") else "Unknown date"
            source_name = a.get("source", {}).get("name", "Unknown source")
            title_lower = title.lower()

            # Check if vendor is observer (reporting on others) not the victim
            is_observer = any(w in title_lower for w in OBSERVER_WORDS)

            if is_observer:
                severity = "Low"
            elif any(kw in title_lower for kw in ["ransomware", "breach", "hack", "cyberattack", "leak"]):
                severity = "High"
            elif any(kw in title_lower for kw in ["fine", "penalty", "regulatory", "lawsuit", "fraud"]):
                severity = "High"
            else:
                severity = "Medium"

            result["findings"].append({
                "title":    f"Adverse media: {title[:80]}{'...' if len(title) > 80 else ''}",
                "severity": severity,
                "detail":   f"Source: {source_name}. Published: {published}.",
                "controls": ["ISO 27001 A.5.7", "DORA Art.28", "NIS2 Art.21"],
                "url":      a.get("url", ""),
            })

    # News findings use lower weights — indirect unverified evidence
    result["score_contribution"] = sum(
        {"Critical": 10, "High": 6, "Medium": 3, "Low": 1, "Info": 0}.get(
            f["severity"], 0
        )
        for f in result["findings"]
    )
    return result

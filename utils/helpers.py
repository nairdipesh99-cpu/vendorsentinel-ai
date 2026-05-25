
from datetime import datetime, timezone

def score_to_tier(score):
    if score >= 75: return "Critical"
    if score >= 55: return "High"
    if score >= 35: return "Medium"
    if score >= 15: return "Low"
    return "Minimal"

def score_to_class(score):
    if score >= 75: return "critical"
    if score >= 55: return "high"
    if score >= 35: return "medium"
    return "low"

def tier_to_color(tier):
    return {
        "Critical": "#EF4444",
        "High":     "#F97316",
        "Medium":   "#F59E0B",
        "Low":      "#10B981",
        "Minimal":  "#3B82F6",
    }.get(tier, "#64748B")

def severity_to_class(severity):
    return severity.lower() if severity else "low"

def format_dt(iso_string):
    if not iso_string:
        return "Never"
    try:
        dt = datetime.fromisoformat(iso_string)
        return dt.strftime("%d %b %Y, %H:%M")
    except Exception:
        return iso_string

def time_ago(iso_string):
    if not iso_string:
        return "Never"
    try:
        dt = datetime.fromisoformat(iso_string)
        now = datetime.now()
        diff = now - dt
        if diff.days > 0:
            return f"{diff.days}d ago"
        hours = diff.seconds // 3600
        if hours > 0:
            return f"{hours}h ago"
        mins = diff.seconds // 60
        return f"{mins}m ago"
    except Exception:
        return iso_string

def safe_get(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


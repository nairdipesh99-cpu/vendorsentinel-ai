import requests
import socket

DANGEROUS_PORTS = {
    21:    ("FTP",            "High",     "Unencrypted file transfer — credential exposure risk."),
    23:    ("Telnet",         "Critical", "Unencrypted remote access — plaintext credentials."),
    445:   ("SMB",            "Critical", "Common ransomware propagation vector (EternalBlue)."),
    3306:  ("MySQL",          "Critical", "Database exposed to internet — direct data access risk."),
    3389:  ("RDP",            "Critical", "Remote Desktop exposed — primary ransomware entry vector."),
    5432:  ("PostgreSQL",     "Critical", "Database exposed to internet."),
    5900:  ("VNC",            "High",     "Remote desktop without encryption."),
    6379:  ("Redis",          "Critical", "Redis exposed — no authentication by default."),
    8080:  ("HTTP Alt",       "Medium",   "Alternative HTTP port exposed — may serve admin panels."),
    8443:  ("HTTPS Alt",      "Low",      "Alternative HTTPS port exposed."),
    27017: ("MongoDB",        "Critical", "MongoDB exposed — historically targeted with no auth."),
    9200:  ("Elasticsearch",  "Critical", "Elasticsearch exposed — no auth, direct data access."),
    2375:  ("Docker API",     "Critical", "Docker daemon exposed — full container control."),
    22:    ("SSH",            "Medium",   "SSH exposed to internet — brute force target."),
    25:    ("SMTP",           "Medium",   "Mail server exposed — potential spam relay."),
}

def check_shodan(domain, api_key=None):
    result = {
        "source":   "Shodan (Attack Surface)",
        "domain":   domain,
        "findings": [],
        "raw":      {},
        "status":   "ok",
    }

    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(domain)
        result["raw"]["ip"] = ip
    except Exception as e:
        result["findings"].append({
            "title": "Could not resolve domain to IP",
            "severity": "Low", "detail": str(e), "controls": [],
        })
        result["score_contribution"] = 0
        return result

    if not api_key:
        # Passive fallback — check open ports via headers
        result["findings"].append({
            "title":    "Shodan API key not configured",
            "severity": "Info",
            "detail":   "Add SHODAN_API_KEY to secrets.toml for full attack surface analysis.",
            "controls": [],
        })
        result["raw"]["note"] = "No API key — limited analysis"
        result["score_contribution"] = 0
        return result

    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=12,
        )
        if resp.status_code == 404:
            result["findings"].append({
                "title":    "No Shodan data for this IP",
                "severity": "Info",
                "detail":   "This host has not been indexed by Shodan recently.",
                "controls": [],
            })
            result["score_contribution"] = 0
            return result

        if resp.status_code == 401:
            result["findings"].append({
                "title": "Invalid Shodan API key", "severity": "Info",
                "detail": "Check your SHODAN_API_KEY in secrets.toml.", "controls": [],
            })
            result["score_contribution"] = 0
            return result

        data = resp.json()
        result["raw"]["shodan"] = data

        open_ports = data.get("ports", [])
        result["raw"]["open_ports"] = open_ports

        for port in open_ports:
            if port in DANGEROUS_PORTS:
                service, severity, detail = DANGEROUS_PORTS[port]
                controls = {
                    "Critical": ["ISO 27001 A.8.20", "SOC 2 CC6.6", "DORA Art.9", "NIS2 Art.21", "NIST CSF PR.AC-5"],
                    "High":     ["ISO 27001 A.8.20", "SOC 2 CC6.6", "NIST CSF PR.AC-5"],
                    "Medium":   ["ISO 27001 A.8.20", "NIST CSF PR.AC-5"],
                    "Low":      ["ISO 27001 A.8.20"],
                }.get(severity, [])
                result["findings"].append({
                    "title":    f"Port {port} ({service}) open on public internet",
                    "severity": severity,
                    "detail":   detail,
                    "controls": controls,
                })

        # Vulnerabilities
        vulns = data.get("vulns", {})
        if vulns:
            for cve, vuln_data in list(vulns.items())[:5]:
                cvss = vuln_data.get("cvss", 0)
                severity = "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium"
                result["findings"].append({
                    "title":    f"Known vulnerability: {cve} (CVSS {cvss})",
                    "severity": severity,
                    "detail":   vuln_data.get("summary", "No description available."),
                    "controls": ["ISO 27001 A.8.8", "SOC 2 CC7.1", "NIST CSF ID.RA-1"],
                })

        # OS info
        os_info = data.get("os")
        if os_info:
            result["raw"]["os"] = os_info

        if not result["findings"]:
            result["findings"].append({
                "title":    f"No dangerous exposed services found on {ip}",
                "severity": "Info",
                "detail":   f"Open ports: {open_ports}",
                "controls": [],
            })

    except requests.Timeout:
        result["status"] = "timeout"
        result["findings"].append({
            "title": "Shodan API timeout", "severity": "Low",
            "detail": "Request timed out.", "controls": [],
        })
    except Exception as e:
        result["status"] = "error"
        result["findings"].append({
            "title": "Shodan check error", "severity": "Low",
            "detail": str(e), "controls": [],
        })

    result["score_contribution"] = sum(
        {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}.get(f["severity"], 0)
        for f in result["findings"]
    )
    return result


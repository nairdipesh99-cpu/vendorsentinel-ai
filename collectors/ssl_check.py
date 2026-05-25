import ssl
import socket
from datetime import datetime, timezone
import requests

def check_ssl(domain):
    result = {
        "source":    "SSL/TLS",
        "domain":    domain,
        "findings":  [],
        "raw":       {},
        "status":    "ok",
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(socket.AF_INET), server_hostname=domain
        ) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            result["raw"] = cert

            # Expiry
            not_after = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days
            result["raw"]["days_until_expiry"] = days_left

            if days_left < 0:
                result["findings"].append({
                    "title":    "SSL certificate has expired",
                    "severity": "Critical",
                    "detail":   f"Certificate expired {abs(days_left)} days ago.",
                    "controls": ["ISO 27001 A.8.24", "SOC 2 CC9.1", "NIST CSF PR.AC-7"],
                })
            elif days_left < 14:
                result["findings"].append({
                    "title":    f"SSL certificate expires in {days_left} days",
                    "severity": "High",
                    "detail":   f"Certificate will expire on {not_after.strftime('%d %b %Y')}. Immediate renewal required.",
                    "controls": ["ISO 27001 A.8.24", "SOC 2 CC9.1"],
                })
            elif days_left < 30:
                result["findings"].append({
                    "title":    f"SSL certificate expiring soon ({days_left} days)",
                    "severity": "Medium",
                    "detail":   f"Certificate will expire on {not_after.strftime('%d %b %Y')}.",
                    "controls": ["ISO 27001 A.8.24"],
                })

            # Issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            org = issuer.get("organizationName", "Unknown")
            result["raw"]["issuer_org"] = org

            trusted_cas = [
                "DigiCert", "Let's Encrypt", "Sectigo", "GlobalSign",
                "Comodo", "Amazon", "Google Trust Services", "Entrust",
                "IdenTrust",
            ]
            if not any(ca.lower() in org.lower() for ca in trusted_cas):
                result["findings"].append({
                    "title":    f"SSL issued by unknown CA: {org}",
                    "severity": "Medium",
                    "detail":   "Certificate issuer is not a recognised Certificate Authority.",
                    "controls": ["ISO 27001 A.8.24", "DORA Art.9"],
                })

            if not result["findings"]:
                result["findings"].append({
                    "title":    f"SSL certificate valid ({days_left} days remaining)",
                    "severity": "Info",
                    "detail":   f"Issued by {org}. Expires {not_after.strftime('%d %b %Y')}.",
                    "controls": [],
                })

    except ssl.SSLCertVerificationError as e:
        result["status"] = "error"
        result["findings"].append({
            "title":    "SSL certificate verification failed",
            "severity": "Critical",
            "detail":   str(e),
            "controls": ["ISO 27001 A.8.24", "SOC 2 CC9.1", "DORA Art.9", "NIS2 Art.21"],
        })
    except socket.timeout:
        result["status"] = "timeout"
        result["findings"].append({
            "title":    "SSL check timed out",
            "severity": "Medium",
            "detail":   "Could not connect to port 443 within 10 seconds.",
            "controls": [],
        })
    except Exception as e:
        result["status"] = "error"
        result["findings"].append({
            "title":    "SSL check failed",
            "severity": "Medium",
            "detail":   str(e),
            "controls": [],
        })

    result["score_contribution"] = sum(
        {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}.get(f["severity"], 0)
        for f in result["findings"]
    )
    return result


import json
import os
from datetime import datetime
from pathlib import Path

DATA_DIR = Path("data")
VENDORS_FILE  = DATA_DIR / "vendors.json"
EVIDENCE_FILE = DATA_DIR / "evidence.json"
INTEL_FILE    = DATA_DIR / "threat_intel.json"

def init_storage():
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / "frameworks").mkdir(exist_ok=True)
    for f in [VENDORS_FILE, EVIDENCE_FILE, INTEL_FILE]:
        if not f.exists():
            f.write_text(json.dumps([]))

def load_vendors():
    try:
        return json.loads(VENDORS_FILE.read_text())
    except Exception:
        return []

def save_vendors(vendors):
    VENDORS_FILE.write_text(json.dumps(vendors, indent=2, default=str))

def get_vendor(domain):
    vendors = load_vendors()
    return next((v for v in vendors if v["domain"] == domain), None)

def upsert_vendor(vendor_data):
    vendors = load_vendors()
    idx = next((i for i, v in enumerate(vendors) if v["domain"] == vendor_data["domain"]), None)
    vendor_data["updated_at"] = datetime.now().isoformat()
    if idx is not None:
        vendors[idx] = vendor_data
    else:
        vendor_data["created_at"] = datetime.now().isoformat()
        vendors.append(vendor_data)
    save_vendors(vendors)

def load_evidence(domain=None):
    try:
        evidence = json.loads(EVIDENCE_FILE.read_text())
        if domain:
            return [e for e in evidence if e.get("domain") == domain]
        return evidence
    except Exception:
        return []

def save_evidence(domain, source, payload, finding_type):
    evidence = load_evidence()
    entry = {
        "domain":       domain,
        "source":       source,
        "finding_type": finding_type,
        "payload":      payload,
        "collected_at": datetime.now().isoformat(),
    }
    evidence.append(entry)
    EVIDENCE_FILE.write_text(json.dumps(evidence, indent=2, default=str))
    return entry

def load_threat_intel():
    try:
        return json.loads(INTEL_FILE.read_text())
    except Exception:
        return []

def save_threat_intel(entries):
    INTEL_FILE.write_text(json.dumps(entries, indent=2, default=str))

def get_risk_history(domain):
    vendors = load_vendors()
    v = next((v for v in vendors if v["domain"] == domain), None)
    return v.get("risk_history", []) if v else []


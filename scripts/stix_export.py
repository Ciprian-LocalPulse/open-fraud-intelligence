#!/usr/bin/env python3
"""
OFI → STIX 2.1 Export
======================
Convertește intrările din dataset în obiecte STIX 2.1 valide,
compatibile cu OpenCTI, MISP și orice platformă threat intelligence.

Utilizare:
    python3 stix_export.py --input ../../datasets/scams_v2.json
    python3 stix_export.py --input ../../datasets/scams_v2.json --output bundle.json
    python3 stix_export.py --id olx-0001 --output olx-0001.stix.json
"""

import json
import uuid
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path


STIX_SPEC_VERSION = "2.1"
OFI_IDENTITY_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


def now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def deterministic_uuid(namespace: str, name: str) -> str:
    """UUID determinist bazat pe namespace + name (reproducibil)."""
    ns = uuid.UUID("00000000-0000-0000-0000-000000000000")
    return str(uuid.uuid5(ns, f"{namespace}:{name}"))


def make_identity() -> dict:
    return {
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": f"identity--{OFI_IDENTITY_UUID}",
        "created": "2025-01-01T00:00:00.000Z",
        "modified": now_stix(),
        "name": "Open Fraud Intelligence",
        "description": "Open-source fraud intelligence database for Romania and Eastern Europe",
        "identity_class": "organization",
        "sectors": ["technology", "financial-services"],
        "contact_information": "https://github.com/open-fraud-intelligence"
    }


def severity_to_stix(severity: str) -> str:
    mapping = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Informational": "informational"
    }
    return mapping.get(severity, "unknown")


def entry_to_stix_objects(entry: dict) -> list:
    """Convertește o intrare OFI în lista de obiecte STIX 2.1."""
    objects = []
    entry_uuid = entry.get("uuid", deterministic_uuid("ofi", entry.get("id", "")))
    ts = now_stix()

    # ── 1. Report (obiectul principal) ──────────────────────────────────────
    ref_ids = []

    # ── 2. Indicator pentru fiecare mesaj AI ──────────────────────────────
    ai = entry.get("ai_dataset", {})
    if ai.get("label") == "scam" and ai.get("message"):
        indicator_id = f"indicator--{deterministic_uuid('indicator', entry.get('id',''))}"
        indicator = {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": indicator_id,
            "created_by_ref": f"identity--{OFI_IDENTITY_UUID}",
            "created": entry.get("created_at", ts),
            "modified": entry.get("last_updated", ts),
            "name": entry.get("title", "Unknown Scam"),
            "description": entry.get("scenario", ""),
            "pattern": f"[email-message:body MATCHES '{ai['message'][:100].replace(chr(39), chr(34))}']",
            "pattern_type": "stix",
            "valid_from": entry.get("created_at", ts),
            "indicator_types": ["malicious-activity", "compromised"],
            "confidence": int(ai.get("confidence", 0.9) * 100),
            "labels": entry.get("tags", []),
            "external_references": [
                {
                    "source_name": "Open Fraud Intelligence",
                    "external_id": entry.get("id", ""),
                    "url": f"https://github.com/open-fraud-intelligence/blob/main/scams/{entry.get('platform','unknown')}/{entry.get('id','')}.md"
                }
            ]
        }
        objects.append(indicator)
        ref_ids.append(indicator_id)

    # ── 3. IOC Domain indicators ──────────────────────────────────────────
    ioc = entry.get("ioc", {})
    for domain in ioc.get("domains", []):
        dom_id = f"domain-name--{deterministic_uuid('domain', domain)}"
        objects.append({
            "type": "domain-name",
            "spec_version": STIX_SPEC_VERSION,
            "id": dom_id,
            "value": domain
        })
        ref_ids.append(dom_id)

        # Indicator pentru domeniu
        ind_id = f"indicator--{deterministic_uuid('domain-indicator', domain)}"
        objects.append({
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": ind_id,
            "created_by_ref": f"identity--{OFI_IDENTITY_UUID}",
            "created": ts,
            "modified": ts,
            "name": f"Phishing domain: {domain}",
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": ts,
            "indicator_types": ["malicious-activity"],
            "labels": ["phishing-domain"]
        })
        ref_ids.append(ind_id)

    # ── 4. URL indicators ────────────────────────────────────────────────
    for url in ioc.get("urls", []):
        url_id = f"url--{deterministic_uuid('url', url)}"
        objects.append({
            "type": "url",
            "spec_version": STIX_SPEC_VERSION,
            "id": url_id,
            "value": url
        })
        ref_ids.append(url_id)

    # ── 5. Attack Pattern (MITRE ATT&CK) ─────────────────────────────────
    for mitre in entry.get("mitre_attack", []):
        ap_id = f"attack-pattern--{deterministic_uuid('mitre', mitre['technique_id'])}"
        ap = {
            "type": "attack-pattern",
            "spec_version": STIX_SPEC_VERSION,
            "id": ap_id,
            "created": ts,
            "modified": ts,
            "name": mitre.get("technique_name", ""),
            "description": f"MITRE ATT&CK {mitre['technique_id']}: {mitre.get('technique_name', '')}",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": mitre["technique_id"],
                    "url": mitre.get("url", f"https://attack.mitre.org/techniques/{mitre['technique_id']}/")
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": mitre.get("tactic", "unknown").lower().replace(" ", "-")
                }
            ]
        }
        objects.append(ap)
        ref_ids.append(ap_id)

    # ── 6. Course of Action (prevenție) ──────────────────────────────────
    prevention = entry.get("prevention", [])
    if prevention:
        coa_id = f"course-of-action--{deterministic_uuid('coa', entry.get('id',''))}"
        coa = {
            "type": "course-of-action",
            "spec_version": STIX_SPEC_VERSION,
            "id": coa_id,
            "created_by_ref": f"identity--{OFI_IDENTITY_UUID}",
            "created": ts,
            "modified": ts,
            "name": f"Prevention: {entry.get('title', 'Unknown')}",
            "description": "\n".join(f"- {p}" for p in prevention)
        }
        objects.append(coa)
        ref_ids.append(coa_id)

    # ── 7. Report (container pentru toate obiectele de mai sus) ───────────
    report = {
        "type": "report",
        "spec_version": STIX_SPEC_VERSION,
        "id": f"report--{entry_uuid}",
        "created_by_ref": f"identity--{OFI_IDENTITY_UUID}",
        "created": entry.get("created_at", ts),
        "modified": entry.get("last_updated", ts),
        "name": entry.get("title", "Unknown Scam"),
        "description": entry.get("scenario", ""),
        "report_types": ["threat-report", "indicator"],
        "published": entry.get("created_at", ts),
        "object_refs": ref_ids,
        "confidence": int(entry.get("confidence", {}).get("score", 0.9) * 100),
        "labels": entry.get("tags", []),
        "external_references": [
            {
                "source_name": "Open Fraud Intelligence",
                "external_id": entry.get("id", ""),
                "url": f"https://github.com/open-fraud-intelligence"
            }
        ],
        "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]
    }
    objects.insert(0, report)

    return objects


def build_bundle(entries: list) -> dict:
    """Construiește un STIX Bundle din lista de intrări OFI."""
    bundle_id = f"bundle--{str(uuid.uuid4())}"
    all_objects = [make_identity()]

    # TLP:WHITE marking definition
    all_objects.append({
        "type": "marking-definition",
        "spec_version": STIX_SPEC_VERSION,
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "white"}
    })

    seen_ids = set()
    for entry in entries:
        for obj in entry_to_stix_objects(entry):
            if obj["id"] not in seen_ids:
                all_objects.append(obj)
                seen_ids.add(obj["id"])

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": STIX_SPEC_VERSION,
        "objects": all_objects
    }


def main():
    parser = argparse.ArgumentParser(description="OFI → STIX 2.1 Export")
    parser.add_argument("--input",  default="../../datasets/scams_v2.json")
    parser.add_argument("--output", default="bundle.stix.json")
    parser.add_argument("--id",     help="Exportă doar o singură intrare după ID")
    parser.add_argument("--pretty", action="store_true", default=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"❌ Fișierul nu există: {input_path}")
        return

    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    if args.id:
        data = [e for e in data if e.get("id") == args.id]
        if not data:
            print(f"❌ ID-ul '{args.id}' nu a fost găsit")
            return

    bundle = build_bundle(data)
    output_path = Path(args.output)
    indent = 2 if args.pretty else None

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=indent)

    print(f"✅ STIX Bundle exportat: {output_path}")
    print(f"   Obiecte: {len(bundle['objects'])}")
    print(f"   Intrări procesate: {len(data)}")


if __name__ == "__main__":
    main()

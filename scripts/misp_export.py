#!/usr/bin/env python3
"""
OFI → MISP Export
==================
Generează un eveniment MISP compatibil din intrările OFI.
Poate fi importat direct în orice instanță MISP.

Utilizare:
    python3 misp_export.py --input ../../datasets/scams_v2.json
    python3 misp_export.py --input ../../datasets/scams_v2.json --output misp_event.json
"""

import json
import uuid
import argparse
from datetime import datetime, timezone
from pathlib import Path


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def misp_attribute(category: str, attr_type: str, value: str,
                   comment: str = "", to_ids: bool = True) -> dict:
    return {
        "uuid":       str(uuid.uuid4()),
        "category":   category,
        "type":       attr_type,
        "value":      value,
        "comment":    comment,
        "to_ids":     to_ids,
        "distribution": 1,
        "timestamp":  now_epoch()
    }


def entry_to_misp_event(entry: dict) -> dict:
    """Convertește o intrare OFI într-un eveniment MISP."""
    attributes = []
    objects = []
    tags = []

    # ── Tags din severitate ───────────────────────────────────────────────
    sev = entry.get("severity", "Medium")
    tags.append({
        "name": f"tlp:white",
        "colour": "#ffffff"
    })
    sev_colors = {
        "Critical": "#7c0000",
        "High": "#cc0000",
        "Medium": "#ff6600",
        "Low": "#ffcc00",
        "Informational": "#cccccc"
    }
    tags.append({
        "name": f"ofi:severity=\"{sev}\"",
        "colour": sev_colors.get(sev, "#888888")
    })
    tags.append({
        "name": f"ofi:platform=\"{entry.get('platform', 'unknown')}\"",
        "colour": "#0066cc"
    })
    for tag in entry.get("tags", []):
        tags.append({"name": f"ofi:{tag}", "colour": "#006688"})

    # MITRE ATT&CK tags
    for mitre in entry.get("mitre_attack", []):
        tags.append({
            "name": f"misp-galaxy:mitre-attack-pattern=\"{mitre['technique_name']} - {mitre['technique_id']}\"",
            "colour": "#2c3e50"
        })

    # ── IOC Attributes ────────────────────────────────────────────────────
    ioc = entry.get("ioc", {})

    for domain in ioc.get("domains", []):
        attributes.append(misp_attribute(
            "Network activity", "domain", domain,
            comment=f"Phishing domain — {entry.get('id', '')}"
        ))

    for url in ioc.get("urls", []):
        attributes.append(misp_attribute(
            "Network activity", "url", url,
            comment=f"Phishing URL — {entry.get('id', '')}"
        ))

    for phone in ioc.get("phones", []):
        attributes.append(misp_attribute(
            "Person", "phone-number", phone,
            comment=f"Scammer phone — {entry.get('id', '')}",
            to_ids=False
        ))

    for email in ioc.get("emails", []):
        attributes.append(misp_attribute(
            "Payload delivery", "email-src", email,
            comment=f"Scammer email — {entry.get('id', '')}"
        ))

    for wallet in ioc.get("wallets", []):
        attributes.append(misp_attribute(
            "Financial fraud", "btc", wallet,
            comment=f"Crypto wallet — {entry.get('id', '')}"
        ))

    for ip in ioc.get("ipv4", []):
        attributes.append(misp_attribute(
            "Network activity", "ip-src", ip,
            comment=f"Scam infrastructure IP — {entry.get('id', '')}"
        ))

    # ── AI Message ca pattern ────────────────────────────────────────────
    ai = entry.get("ai_dataset", {})
    if ai.get("message") and ai.get("label") == "scam":
        attributes.append(misp_attribute(
            "Payload content", "text", ai["message"],
            comment=f"Scam message pattern [conf={ai.get('confidence', 0)}]",
            to_ids=False
        ))

    # ── Obiect MISP pentru scenario ──────────────────────────────────────
    red_flags_text = "\n".join(f"- {rf}" for rf in entry.get("red_flags", []))
    prevention_text = "\n".join(f"- {p}" for p in entry.get("prevention", []))
    attributes.append(misp_attribute(
        "External analysis", "comment",
        f"SCENARIO:\n{entry.get('scenario', '')}\n\n"
        f"RED FLAGS:\n{red_flags_text}\n\n"
        f"PREVENTION:\n{prevention_text}",
        comment="OFI Analysis",
        to_ids=False
    ))

    event_uuid = entry.get("uuid", str(uuid.uuid4()))
    return {
        "Event": {
            "uuid":            event_uuid,
            "info":            entry.get("title", "Unknown Scam"),
            "date":            entry.get("created_at", now_ts())[:10],
            "timestamp":       now_epoch(),
            "published":       True,
            "distribution":    1,
            "threat_level_id": {"Critical": "1", "High": "2", "Medium": "3", "Low": "4"}.get(sev, "3"),
            "analysis":        "2",
            "org":             {"name": "Open Fraud Intelligence"},
            "orgc":            {"name": "Open Fraud Intelligence"},
            "Attribute":       attributes,
            "Object":          objects,
            "Tag":             tags,
            "Galaxy":          [],
            "RelatedEvent":    []
        }
    }


def build_misp_package(entries: list) -> dict:
    """Construiește un pachet MISP cu toate evenimentele."""
    events = []
    for entry in entries:
        if entry.get("ai_dataset", {}).get("label") == "scam":
            events.append(entry_to_misp_event(entry))
    return {"response": events}


def main():
    parser = argparse.ArgumentParser(description="OFI → MISP Export")
    parser.add_argument("--input",  default="../../datasets/scams_v2.json")
    parser.add_argument("--output", default="misp_events.json")
    parser.add_argument("--single", action="store_true",
                        help="Exportă ca eveniment MISP singular (toate intrările combinate)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"❌ Fișierul nu există: {input_path}")
        return

    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    package = build_misp_package(data)
    output_path = Path(args.output)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(package, f, ensure_ascii=False, indent=2)

    print(f"✅ MISP Package exportat: {output_path}")
    print(f"   Evenimente: {len(package['response'])}")


if __name__ == "__main__":
    main()

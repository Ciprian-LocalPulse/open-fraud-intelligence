#!/usr/bin/env python3
"""
OFI — RAG Dataset Export
===========================
Spune dataset-ul OFI într-un format pregătit pentru pipeline-uri RAG
(retrieval-augmented generation): chunk-uri de text scurte, autonome
semantic, fiecare cu metadate suficiente pentru filtrare la retrieval
și pentru citare înapoi la sursă.

Strategie de chunking: NU împărțim arbitrar pe N caractere — fiecare
intrare OFI generează 1 chunk per secțiune semantică distinctă
(scenariu, semnale de alarmă, prevenție, tehnică/DNA), pentru că
acestea răspund la întrebări diferite și ar trebui recuperate
independent ("cum recunosc o fraudă pe OLX?" -> chunk red_flags;
"ce fac dacă am pățit-o?" -> chunk prevention).

Output: rag/chunks.jsonl — un JSON pe linie, schema:
    {
      "chunk_id": "olx-0001#scenario",
      "entry_id": "olx-0001",
      "section": "scenario",
      "text": "...",
      "metadata": { platform, severity, tags, campaign_id, verified, language }
    }

Utilizare:
    python3 rag_export.py --input scams.json --output rag/chunks.jsonl
"""

import json
import argparse
from pathlib import Path


def base_metadata(entry: dict) -> dict:
    camp = entry.get("campaign") or {}
    return {
        "entry_id": entry.get("id"),
        "title": entry.get("title"),
        "platform": entry.get("platform"),
        "vector": entry.get("vector", []),
        "severity": entry.get("severity"),
        "severity_score": entry.get("severity_score"),
        "tags": entry.get("tags", []),
        "campaign_id": camp.get("campaign_id"),
        "verified": (entry.get("verification") or {}).get("status") == "verified",
        "language": (entry.get("ai_dataset") or {}).get("language", "ro"),
        "year": entry.get("year"),
    }


def make_chunk(entry: dict, section: str, text: str) -> dict | None:
    text = (text or "").strip()
    if not text:
        return None
    return {
        "chunk_id": f"{entry.get('id')}#{section}",
        "entry_id": entry.get("id"),
        "section": section,
        "text": text,
        "metadata": base_metadata(entry),
    }


def entry_to_chunks(entry: dict) -> list:
    chunks = []

    # 1. Scenariu — descrierea narativă a fraudei
    chunks.append(make_chunk(
        entry, "scenario",
        f"{entry.get('title', '')}. {entry.get('scenario', '')}"
    ))

    # 2. Pași — secvența operațională (utilă pentru "cum funcționează")
    steps = entry.get("steps", [])
    if steps:
        text = "Pașii fraudei:\n" + "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        chunks.append(make_chunk(entry, "steps", text))

    # 3. Semnale de alarmă — răspunde la "cum recunosc"
    red_flags = entry.get("red_flags", [])
    if red_flags:
        text = f"Semnale de alarmă pentru '{entry.get('title', '')}':\n" + "\n".join(f"- {r}" for r in red_flags)
        chunks.append(make_chunk(entry, "red_flags", text))

    # 4. Prevenție — răspunde la "ce fac"
    prevention = entry.get("prevention", [])
    if prevention:
        text = f"Cum te protejezi de '{entry.get('title', '')}':\n" + "\n".join(f"- {p}" for p in prevention)
        chunks.append(make_chunk(entry, "prevention", text))

    # 5. Tehnică / Scam DNA — pentru întrebări analitice ("ce tactici psihologice")
    dna = entry.get("scam_dna", {})
    if dna:
        parts = [f"Tehnică: {dna.get('technique', '')}."]
        if dna.get("psychology"):
            parts.append(f"Tactici psihologice folosite: {', '.join(dna['psychology'])}.")
        if dna.get("payment_methods"):
            parts.append(f"Metode de plată vizate: {', '.join(dna['payment_methods'])}.")
        if dna.get("brand_abuse"):
            parts.append(f"Branduri impersonate: {', '.join(dna['brand_abuse'])}.")
        loss = dna.get("typical_loss_ron") or {}
        if loss:
            parts.append(f"Pierdere tipică: între {loss.get('min')} și {loss.get('max')} RON (mediană {loss.get('median')} RON).")
        chunks.append(make_chunk(entry, "technique", " ".join(parts)))

    # 6. Verificare/sursă oficială — pentru întrebări de credibilitate
    verif = entry.get("verification") or {}
    if verif.get("status") == "verified":
        text = (
            f"Această fraudă a fost verificată oficial de {verif.get('verified_by', 'necunoscut')}. "
            f"Sursă: {verif.get('official_source') or 'raportări comunitate'}. "
            f"Evidențe colectate: {verif.get('evidence_count', 0)}, raportori: {verif.get('reporter_count', 0)}."
        )
        chunks.append(make_chunk(entry, "verification", text))

    return [c for c in chunks if c]


def main():
    parser = argparse.ArgumentParser(description="OFI RAG Dataset Export")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="chunks.jsonl")
    args = parser.parse_args()

    entries = json.loads(Path(args.input).read_text(encoding="utf-8"))

    all_chunks = []
    for entry in entries:
        all_chunks.extend(entry_to_chunks(entry))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    sections = {}
    for c in all_chunks:
        sections[c["section"]] = sections.get(c["section"], 0) + 1

    print(f"✅ {len(all_chunks)} chunk-uri din {len(entries)} intrări → {output_path}")
    for s, n in sections.items():
        print(f"   {s}: {n}")


if __name__ == "__main__":
    main()

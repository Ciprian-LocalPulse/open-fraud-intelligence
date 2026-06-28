#!/usr/bin/env python3
"""
OFI — Campaign Clustering / Duplicate Detector
==================================================
Diferența față de un simplu `similarity(a, b)`: aici construim un graf
de similaritate ponderat pe TOATE perechile de intrări, combinăm mai
multe semnale independente, și extragem CLUSTERE (variante ale aceleiași
campanii), nu doar un scor punctual între două ID-uri.

Semnale combinate (fiecare normalizat 0-1, apoi mediat ponderat):
    - text_similarity      (40%) — TF-IDF cosine pe scenario + steps
    - psychology_overlap   (15%) — Jaccard pe scam_dna.psychology
    - payment_overlap      (15%) — Jaccard pe scam_dna.payment_methods
    - brand_overlap        (15%) — Jaccard pe scam_dna.brand_abuse
    - infrastructure_overlap (15%) — domenii/IP-uri/wallet-uri partajate
      (semnal forte: același domeniu fals pe 2 intrări diferite = aproape
      sigur aceeași campanie, indiferent de cât de diferit e textul)

Două intrări devin muchie în graf dacă scorul combinat >= --threshold.
Clusterele sunt componentele conexe ale acestui graf (algoritm transparent,
nu o cutie neagră — poți inspecta exact de ce 2 intrări au fost unite).

Utilizare:
    python3 cluster_campaigns.py --input scams.json --threshold 0.35 --output clusters.json
"""

import json
import argparse
from pathlib import Path
from itertools import combinations

import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


WEIGHTS = {
    "text_similarity": 0.40,
    "psychology_overlap": 0.15,
    "payment_overlap": 0.15,
    "brand_overlap": 0.15,
    "infrastructure_overlap": 0.15,
}


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def entry_text(entry: dict) -> str:
    parts = [entry.get("scenario", "")]
    parts.extend(entry.get("steps", []))
    parts.extend(entry.get("red_flags", []))
    return " ".join(parts)


def entry_infrastructure(entry: dict) -> set:
    ioc = entry.get("ioc", {})
    items = set()
    for kind in ("domains", "urls", "phones", "emails", "wallets", "ipv4", "ipv6"):
        for v in ioc.get(kind, []):
            items.add(f"{kind}:{v.lower()}")
    return items


def compute_text_similarity_matrix(entries: list) -> list:
    texts = [entry_text(e) for e in entries]
    if not any(texts):
        return [[0.0] * len(entries) for _ in entries]
    vectorizer = TfidfVectorizer(
        lowercase=True, ngram_range=(1, 2), min_df=1,
        token_pattern=r"(?u)\b\w\w+\b",
    )
    tfidf = vectorizer.fit_transform(texts)
    sim = cosine_similarity(tfidf)
    return sim.tolist()


def pair_score(e1: dict, e2: dict, text_sim: float) -> dict:
    dna1, dna2 = e1.get("scam_dna", {}), e2.get("scam_dna", {})

    psych_overlap = jaccard(set(dna1.get("psychology", [])), set(dna2.get("psychology", [])))
    payment_overlap = jaccard(set(dna1.get("payment_methods", [])), set(dna2.get("payment_methods", [])))
    brand_overlap = jaccard(set(dna1.get("brand_abuse", [])), set(dna2.get("brand_abuse", [])))
    infra_overlap = jaccard(entry_infrastructure(e1), entry_infrastructure(e2))

    components = {
        "text_similarity": text_sim,
        "psychology_overlap": psych_overlap,
        "payment_overlap": payment_overlap,
        "brand_overlap": brand_overlap,
        "infrastructure_overlap": infra_overlap,
    }
    combined = sum(components[k] * WEIGHTS[k] for k in WEIGHTS)
    return {"combined_score": round(combined, 4), "components": {k: round(v, 4) for k, v in components.items()}}


def build_similarity_graph(entries: list, threshold: float) -> tuple:
    ids = [e.get("id") for e in entries]
    text_sim_matrix = compute_text_similarity_matrix(entries)

    g = nx.Graph()
    for eid in ids:
        g.add_node(eid)

    edge_details = []
    for i, j in combinations(range(len(entries)), 2):
        score_info = pair_score(entries[i], entries[j], text_sim_matrix[i][j])
        if score_info["combined_score"] >= threshold:
            g.add_edge(ids[i], ids[j], **score_info)
        edge_details.append({"a": ids[i], "b": ids[j], **score_info})

    return g, edge_details


def main():
    parser = argparse.ArgumentParser(description="OFI Campaign Clustering / Duplicate Detector")
    parser.add_argument("--input", required=True)
    parser.add_argument("--threshold", type=float, default=0.35,
                         help="Scor minim combinat pentru a uni 2 intrări (0-1)")
    parser.add_argument("--output", default="campaign_clusters.json")
    parser.add_argument("--report", default=None, help="Opțional: scrie și un raport markdown")
    args = parser.parse_args()

    entries = json.loads(Path(args.input).read_text(encoding="utf-8"))
    by_id = {e.get("id"): e for e in entries}

    g, edge_details = build_similarity_graph(entries, args.threshold)
    components = list(nx.connected_components(g))

    clusters = []
    for comp in components:
        members = sorted(comp)
        if len(members) == 1:
            continue  # nu raportăm "clustere" de o singură intrare — nimic de unit
        declared_campaigns = {by_id[m].get("campaign", {}).get("campaign_id") for m in members if by_id[m].get("campaign", {}).get("campaign_id")}
        internal_edges = [e for e in edge_details if e["a"] in members and e["b"] in members and e["combined_score"] >= args.threshold]
        clusters.append({
            "cluster_id": f"cluster-{len(clusters)+1:03d}",
            "members": members,
            "size": len(members),
            "declared_campaign_ids": sorted(declared_campaigns),
            "agrees_with_declared_campaign": len(declared_campaigns) <= 1,
            "evidence": sorted(internal_edges, key=lambda e: -e["combined_score"]),
        })

    singletons = [e["id"] for e in entries if e["id"] is not None and all(e["id"] not in c["members"] for c in clusters)]

    output = {
        "threshold": args.threshold,
        "total_entries": len(entries),
        "clusters_found": len(clusters),
        "entries_in_clusters": sum(c["size"] for c in clusters),
        "singleton_entries": singletons,
        "clusters": clusters,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"✅ {len(clusters)} clustere găsite din {len(entries)} intrări (threshold={args.threshold})")
    for c in clusters:
        flag = "✅ confirmă campania declarată" if c["agrees_with_declared_campaign"] else "⚠️ campanii declarate diferite — verifică manual"
        print(f"   {c['cluster_id']}: {c['members']} — {flag}")
    if singletons:
        print(f"   {len(singletons)} intrări fără pereche peste threshold: {singletons}")

    if args.report:
        write_markdown_report(output, Path(args.report))
        print(f"✅ Raport: {args.report}")


def write_markdown_report(output: dict, path: Path):
    lines = [
        "# Raport de clustering campanii — Open Fraud Intelligence",
        "",
        f"- Prag combinat folosit: **{output['threshold']}**",
        f"- Intrări analizate: **{output['total_entries']}**",
        f"- Clustere găsite: **{output['clusters_found']}**",
        "",
        "## Metodologie",
        "",
        "Scorul combinat dintre 2 intrări este o medie ponderată a 5 semnale "
        "independente: similaritate text (TF-IDF cosine, 40%), suprapunere "
        "tactici psihologice (Jaccard, 15%), suprapunere metode de plată "
        "(Jaccard, 15%), suprapunere branduri impersonate (Jaccard, 15%), "
        "suprapunere infrastructură IOC — domenii/wallet-uri/telefoane partajate "
        "(Jaccard, 15%). Două intrări devin parte din același cluster dacă scorul "
        "combinat trece de prag; clusterele sunt componentele conexe ale grafului "
        "de similaritate rezultat.",
        "",
        "## Clustere",
        "",
    ]
    for c in output["clusters"]:
        lines.append(f"### {c['cluster_id']} — {', '.join(c['members'])}")
        lines.append(f"- Campanie(i) declarată(e) în dataset: {c['declared_campaign_ids'] or '(niciuna)'}")
        lines.append(f"- {'✅ Confirmă gruparea manuală existentă' if c['agrees_with_declared_campaign'] else '⚠️ Algoritmul a unit intrări cu campanii declarate diferite — verifică manual, poate fi fals pozitiv sau o relație nedocumentată'}")
        lines.append("")
        for ev in c["evidence"]:
            lines.append(f"  - `{ev['a']}` ↔ `{ev['b']}`: scor={ev['combined_score']} "
                         f"(text={ev['components']['text_similarity']}, "
                         f"psihologie={ev['components']['psychology_overlap']}, "
                         f"plată={ev['components']['payment_overlap']}, "
                         f"brand={ev['components']['brand_overlap']}, "
                         f"infrastructură={ev['components']['infrastructure_overlap']})")
        lines.append("")
    if output["singleton_entries"]:
        lines.append("## Intrări izolate (fără pereche peste prag)")
        lines.append("")
        for s in output["singleton_entries"]:
            lines.append(f"- `{s}`")

    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()

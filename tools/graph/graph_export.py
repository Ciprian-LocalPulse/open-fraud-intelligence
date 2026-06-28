#!/usr/bin/env python3
"""
OFI — Graph Export
===================
Construiește graful relațiilor dintre fraude: lanțul de propagare
(Platformă → Vector → Tehnică → Plată) și graful de campanie
(intrare → intrări înrudite din campaign.related_ids).

Exportă în 3 formate, fiecare cu un scop diferit:
    - DOT      (Graphviz)        — pentru randare manuală / Gephi
    - SVG                        — vizual, randat direct cu `dot`
    - JSON node-link (D3 / Cytoscape.js) — pentru dashboard-uri web interactive

Utilizare:
    python3 graph_export.py --input scams.json --mode chain   --output chain
    python3 graph_export.py --input scams.json --mode campaign --output campaign
    python3 graph_export.py --input scams.json --mode all      --output graph
"""

import json
import argparse
import subprocess
import shutil
from pathlib import Path

import networkx as nx
from networkx.readwrite import json_graph


# ─── Culori pe tip de nod (folosite în DOT/SVG) ─────────────────────────────
NODE_STYLE = {
    "platform":  {"color": "#1d4ed8", "shape": "box",      "fontcolor": "white", "style": "filled"},
    "vector":    {"color": "#0891b2", "shape": "box",      "fontcolor": "white", "style": "filled"},
    "technique": {"color": "#b91c1c", "shape": "ellipse",  "fontcolor": "white", "style": "filled"},
    "payment":   {"color": "#15803d", "shape": "diamond",  "fontcolor": "white", "style": "filled"},
    "entry":     {"color": "#7c3aed", "shape": "ellipse",  "fontcolor": "white", "style": "filled"},
    "campaign":  {"color": "#92400e", "shape": "hexagon",  "fontcolor": "white", "style": "filled"},
}


def load_entries(path: Path) -> list:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def node_id(kind: str, value: str) -> str:
    """ID stabil pentru un nod, prefixat cu tipul (evită coliziuni de nume)."""
    return f"{kind}:{value}"


def add_node(g: nx.DiGraph, kind: str, value: str, **extra):
    nid = node_id(kind, value)
    if nid not in g:
        g.add_node(nid, kind=kind, label=value, **NODE_STYLE.get(kind, {}), **extra)
    return nid


# ─── Modul 1: Graf de lanț (Scam Evolution / Attack Chain) ──────────────────
def build_chain_graph(entries: list) -> nx.DiGraph:
    """
    Pentru fiecare intrare: Platform -> Vector(i) -> Tehnică(DNA) -> Metode de plată.
    Muchiile sunt agregate pe tot dataset-ul (un domeniu fals folosit pe mai
    multe intrări produce o muchie mai 'groasă' — atribut `weight`).
    """
    g = nx.DiGraph()
    for e in entries:
        platform_node = add_node(g, "platform", e.get("platform", "unknown"))
        technique = e.get("scam_dna", {}).get("technique") or e.get("title", e.get("id", "unknown"))
        technique_node = add_node(g, "technique", technique, entry_ids=[])
        g.nodes[technique_node]["entry_ids"] = list(set(g.nodes[technique_node].get("entry_ids", []) + [e.get("id")]))

        vectors = e.get("vector", []) or ["—"]
        for v in vectors:
            vector_node = add_node(g, "vector", v)
            _add_or_increment_edge(g, platform_node, vector_node)
            _add_or_increment_edge(g, vector_node, technique_node)

        if not vectors:
            _add_or_increment_edge(g, platform_node, technique_node)

        for pm in e.get("scam_dna", {}).get("payment_methods", []):
            payment_node = add_node(g, "payment", pm)
            _add_or_increment_edge(g, technique_node, payment_node)

    return g


def _add_or_increment_edge(g: nx.DiGraph, a: str, b: str):
    if g.has_edge(a, b):
        g[a][b]["weight"] += 1
    else:
        g.add_edge(a, b, weight=1)


# ─── Modul 2: Graf de campanie (entry <-> related_ids, prin campaign_id) ────
def build_campaign_graph(entries: list) -> nx.Graph:
    """
    Graf nedirecționat: o muchie între două intrări dacă au același
    campaign_id SAU dacă una apare în campaign.related_ids a celeilalte.
    Util pentru a vizualiza 'familia' de variante ale unei campanii.
    """
    g = nx.Graph()
    by_id = {e["id"]: e for e in entries if e.get("id")}

    for e in entries:
        eid = e.get("id")
        if not eid:
            continue
        entry_node = add_node(g, "entry", eid, title=e.get("title", ""), severity=e.get("severity", ""))

        campaign = e.get("campaign") or {}
        cid = campaign.get("campaign_id")
        if cid:
            camp_node = add_node(g, "campaign", cid, name=campaign.get("campaign_name", cid))
            g.add_edge(entry_node, camp_node, relation="member_of")

        for rel_id in campaign.get("related_ids", []):
            if rel_id in by_id:
                rel_node = add_node(g, "entry", rel_id, title=by_id[rel_id].get("title", ""))
                g.add_edge(entry_node, rel_node, relation="related")

    return g


# ─── Export DOT / SVG ────────────────────────────────────────────────────────
def to_dot(g) -> str:
    lines = ["digraph OFI {" if g.is_directed() else "graph OFI {"]
    lines.append('  rankdir=LR; bgcolor="transparent"; fontname="Helvetica";')
    lines.append('  node [fontname="Helvetica", fontsize=11];')
    lines.append('  edge [fontname="Helvetica", fontsize=9, color="#94a3b8"];')

    for nid, attrs in g.nodes(data=True):
        label = attrs.get("label", nid).replace('"', "'")
        style_attrs = []
        for k in ("color", "shape", "fontcolor", "style"):
            if k in attrs:
                style_attrs.append(f'{k}="{attrs[k]}"')
        style_str = ", ".join(style_attrs)
        lines.append(f'  "{nid}" [label="{label}", {style_str}];')

    conn = "->" if g.is_directed() else "--"
    for a, b, attrs in g.edges(data=True):
        w = attrs.get("weight", 1)
        penwidth = 1 + min(w, 5)
        label = f' [label="{w}x", penwidth={penwidth}]' if w > 1 else f" [penwidth={penwidth}]"
        lines.append(f'  "{a}" {conn} "{b}"{label};')

    lines.append("}")
    return "\n".join(lines)


def render_svg(dot_path: Path, svg_path: Path) -> bool:
    if not shutil.which("dot"):
        return False
    subprocess.run(["dot", "-Tsvg", str(dot_path), "-o", str(svg_path)], check=True)
    return True


# ─── Export JSON node-link (D3.js / Cytoscape.js) ───────────────────────────
def to_node_link_json(g) -> dict:
    data = json_graph.node_link_data(g, edges="links")
    return data


def main():
    parser = argparse.ArgumentParser(description="OFI Graph Export")
    parser.add_argument("--input", required=True, help="Fișier JSON cu intrări OFI")
    parser.add_argument("--mode", choices=["chain", "campaign", "all"], default="all")
    parser.add_argument("--output", default="graph", help="Prefix pentru fișierele de output")
    parser.add_argument("--outdir", default=".")
    args = parser.parse_args()

    entries = load_entries(Path(args.input))
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    targets = []
    if args.mode in ("chain", "all"):
        targets.append(("chain", build_chain_graph(entries)))
    if args.mode in ("campaign", "all"):
        targets.append(("campaign", build_campaign_graph(entries)))

    for name, g in targets:
        prefix = outdir / f"{args.output}_{name}"
        dot_path = prefix.with_suffix(".dot")
        svg_path = prefix.with_suffix(".svg")
        json_path = prefix.with_suffix(".json")

        dot_path.write_text(to_dot(g), encoding="utf-8")
        json_path.write_text(json.dumps(to_node_link_json(g), indent=2, ensure_ascii=False), encoding="utf-8")

        rendered = render_svg(dot_path, svg_path)
        print(f"✅ [{name}] {len(g.nodes)} noduri, {len(g.edges)} muchii")
        print(f"   DOT:  {dot_path}")
        print(f"   JSON: {json_path}")
        if rendered:
            print(f"   SVG:  {svg_path}")
        else:
            print("   SVG:  nerandat (binarul 'dot' din Graphviz nu e instalat)")


if __name__ == "__main__":
    main()

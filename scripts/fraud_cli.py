#!/usr/bin/env python3
"""
OFI CLI — Open Fraud Intelligence Command Line Interface
=========================================================

Comenzi disponibile:
    fraud validate  -- Validează dataset-ul
    fraud stats     -- Afișează statistici
    fraud search    -- Caută fraude
    fraud export    -- Exportă date
    fraud convert   -- Convertește formate
    fraud dna       -- Calculează Scam DNA
    fraud similar   -- Găsește fraude similare
    fraud quality   -- Scor calitate intrare

Utilizare:
    python3 fraud_cli.py stats
    python3 fraud_cli.py search --platform olx --severity High
    python3 fraud_cli.py export --format stix --output bundle.json
    python3 fraud_cli.py dna olx-0001
    python3 fraud_cli.py similar olx-0001 --threshold 0.5
"""

import json
import sys
import argparse
from pathlib import Path

# Adaugă SDK-ul în path
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk" / "python"))
from ofi_sdk import OFIClient, ScamDNAEngine

# ─── Culori ──────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

DEFAULT_DATASET = Path(__file__).parent.parent / "datasets" / "scams_v2.json"

SEV_COLORS = {
    "Critical":      C.RED,
    "High":          C.YELLOW,
    "Medium":        C.CYAN,
    "Low":           C.GREEN,
    "Informational": C.RESET
}


def header():
    print(f"\n{C.BOLD}{C.BLUE}  🛡️  Open Fraud Intelligence CLI v2.0{C.RESET}\n")


def cmd_stats(args, client: OFIClient):
    """fraud stats — Statistici dataset."""
    stats = client.statistics()

    print(f"\n{C.BOLD}  📊 Statistici Dataset{C.RESET}")
    print(f"  {'─'*50}")
    print(f"  Total intrări:      {stats['total']}")
    print(f"  Scam:               {stats['scam_count']}")
    print(f"  Legitimate:         {stats['legitimate_count']}")
    print(f"  Verificate:         {stats['verified_count']}")
    print(f"  Cu IOC:             {stats['with_ioc']}")
    print(f"  Cu MITRE ATT&CK:    {stats['with_mitre']}")
    print(f"  Calitate medie:     {stats['average_quality']:.2%}")

    print(f"\n  {C.BOLD}Top platforme:{C.RESET}")
    for platform, count in list(stats["platform_distribution"].items())[:8]:
        bar = "█" * count
        print(f"    {platform:<20} {count:>3}  {bar}")

    print(f"\n  {C.BOLD}Severitate (fraude):{C.RESET}")
    for sev, count in stats["severity_distribution"].items():
        color = SEV_COLORS.get(sev, C.RESET)
        print(f"    {color}{sev:<14}{C.RESET} {count}")

    if args.json:
        with open("stats.json", "w") as f:
            json.dump(stats, f, indent=2)
        print(f"\n  ✅ Salvat în stats.json")


def cmd_search(args, client: OFIClient):
    """fraud search — Caută fraude."""
    results = client.search(
        platform=args.platform,
        severity=args.severity,
        label=args.label,
        tag=args.tag,
        year=args.year,
        query=args.query,
        limit=args.limit
    )

    print(f"\n  {C.BOLD}🔍 Rezultate: {len(results)}{C.RESET}")
    print(f"  {'─'*70}")

    if not results:
        print(f"  {C.YELLOW}Nicio intrare găsită.{C.RESET}")
        return

    for e in results:
        sev   = e.get("severity", "?")
        color = SEV_COLORS.get(sev, C.RESET)
        label = e.get("ai_dataset", {}).get("label", "?")
        l_color = C.RED if label == "scam" else C.GREEN

        print(f"  {C.BOLD}[{e.get('id', '?')}]{C.RESET} {e.get('title', '')}")
        print(f"    Platform: {e.get('platform'):<12} "
              f"Severity: {color}{sev:<10}{C.RESET} "
              f"Label: {l_color}{label}{C.RESET}")

        if args.verbose:
            print(f"    Scenario: {e.get('scenario', '')[:100]}...")
            print(f"    Tags: {', '.join(e.get('tags', [])[:5])}")
        print()

    if args.json:
        with open("search_results.json", "w") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"  ✅ Salvat în search_results.json")


def cmd_export(args, client: OFIClient):
    """fraud export — Exportă dataset în diferite formate."""
    fmt = args.format.lower()
    output = args.output or f"ofi_export.{fmt}.json"

    if fmt == "ai":
        data = client.export_ai_dataset(
            language=args.language or "ro",
            label=args.label
        )
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  ✅ AI Dataset exportat: {output} ({len(data)} mesaje)")

    elif fmt == "stix":
        stix_path = Path(__file__).parent.parent / "exports" / "stix" / "stix_export.py"
        if stix_path.exists():
            import subprocess
            subprocess.run([sys.executable, str(stix_path),
                          "--input", str(args.dataset or DEFAULT_DATASET),
                          "--output", output])
        else:
            print(f"  {C.RED}❌ Modulul STIX nu a fost găsit.{C.RESET}")

    elif fmt == "misp":
        misp_path = Path(__file__).parent.parent / "exports" / "misp" / "misp_export.py"
        if misp_path.exists():
            import subprocess
            subprocess.run([sys.executable, str(misp_path),
                          "--input", str(args.dataset or DEFAULT_DATASET),
                          "--output", output])
        else:
            print(f"  {C.RED}❌ Modulul MISP nu a fost găsit.{C.RESET}")

    elif fmt == "csv":
        import csv
        data = client._data
        if not data:
            print(f"  {C.RED}❌ Dataset gol.{C.RESET}")
            return
        keys = ["id", "title", "platform", "severity", "country", "year"]
        with open(output, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys + ["ai_label", "ai_confidence"])
            w.writeheader()
            for e in data:
                row = {k: e.get(k, "") for k in keys}
                row["ai_label"]      = e.get("ai_dataset", {}).get("label", "")
                row["ai_confidence"] = e.get("ai_dataset", {}).get("confidence", "")
                w.writerow(row)
        print(f"  ✅ CSV exportat: {output} ({len(data)} rânduri)")

    else:
        print(f"  {C.RED}❌ Format necunoscut: {fmt}. Valori valide: ai, stix, misp, csv{C.RESET}")


def cmd_dna(args, client: OFIClient):
    """fraud dna <id> — Calculează și afișează Scam DNA."""
    try:
        dna = client.get_dna(args.id)
    except Exception as e:
        print(f"  {C.RED}❌ {e}{C.RESET}")
        return

    entry = client.get(args.id)
    print(f"\n  {C.BOLD}🧬 Scam DNA: {args.id}{C.RESET}")
    print(f"  Titlu: {entry.get('title', '')}")
    print(f"  {'─'*60}")
    print(f"  Psychology:      {', '.join(dna['psychology']) or '—'}")
    print(f"  Payment Methods: {', '.join(dna['payment_methods']) or '—'}")
    print(f"  Brand Abuse:     {', '.join(dna['brand_abuse']) or '—'}")
    print(f"  Urgency Level:   {'⚠️ ' * dna['urgency_level']} ({dna['urgency_level']}/5)")
    print(f"  Lang Markers:    {', '.join(dna['language_markers'][:5]) or '—'}")
    print(f"  Fingerprint:     {dna['fingerprint'][:32]}...")

    if args.json:
        print(f"\n  JSON:\n{json.dumps(dna, ensure_ascii=False, indent=4)}")


def cmd_similar(args, client: OFIClient):
    """fraud similar <id> — Găsește fraude similare."""
    try:
        results = client.find_similar(args.id, threshold=args.threshold, limit=args.limit)
    except Exception as e:
        print(f"  {C.RED}❌ {e}{C.RESET}")
        return

    entry = client.get(args.id)
    print(f"\n  {C.BOLD}🔗 Fraude similare cu {args.id}{C.RESET}")
    print(f"  Referință: {entry.get('title', '')}")
    print(f"  Prag similaritate: {args.threshold}")
    print(f"  {'─'*70}")

    if not results:
        print(f"  {C.YELLOW}Nicio fraudă similară găsită la prag {args.threshold}.{C.RESET}")
        return

    for r in results:
        sim    = r["similarity"]
        color  = C.RED if sim >= 0.8 else C.YELLOW if sim >= 0.6 else C.CYAN
        print(f"  {color}[{r['id2']}]{C.RESET} {r.get('title', '')}")
        print(f"    Similaritate: {color}{sim:.4f}{C.RESET} — {r['interpretation']}")
        if r["shared_psychology"]:
            print(f"    Psihologie comună: {', '.join(r['shared_psychology'])}")
        if r["shared_payments"]:
            print(f"    Plăți comune: {', '.join(r['shared_payments'])}")
        print()


def cmd_quality(args, client: OFIClient):
    """fraud quality <id> — Scor calitate intrare."""
    try:
        score = client.score_quality(args.id)
        entry = client.get(args.id)
    except Exception as e:
        print(f"  {C.RED}❌ {e}{C.RESET}")
        return

    print(f"\n  {C.BOLD}⭐ Calitate: {args.id}{C.RESET}")
    print(f"  {entry.get('title', '')}")
    print(f"  {'─'*50}")

    for dim, val in score.items():
        bar   = "█" * int(val * 20)
        color = C.GREEN if val >= 0.8 else C.YELLOW if val >= 0.5 else C.RED
        print(f"  {dim:<16} {color}{val:.2%}{C.RESET}  {bar}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="fraud",
        description="Open Fraud Intelligence CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--dataset", "-d", help="Cale spre dataset JSON")

    sub = parser.add_subparsers(dest="command")

    # stats
    p_stats = sub.add_parser("stats", help="Statistici dataset")
    p_stats.add_argument("--json", action="store_true")

    # search
    p_search = sub.add_parser("search", help="Caută fraude")
    p_search.add_argument("--platform",  "-p")
    p_search.add_argument("--severity",  "-s")
    p_search.add_argument("--label",     "-l")
    p_search.add_argument("--tag",       "-t")
    p_search.add_argument("--year",      "-y", type=int)
    p_search.add_argument("--query",     "-q")
    p_search.add_argument("--limit",     "-n", type=int, default=20)
    p_search.add_argument("--verbose",   "-v", action="store_true")
    p_search.add_argument("--json",      action="store_true")

    # export
    p_export = sub.add_parser("export", help="Exportă dataset")
    p_export.add_argument("--format",   "-f", default="ai",
                          choices=["ai", "stix", "misp", "csv"])
    p_export.add_argument("--output",   "-o")
    p_export.add_argument("--language", default="ro")
    p_export.add_argument("--label")

    # dna
    p_dna = sub.add_parser("dna", help="Scam DNA fingerprint")
    p_dna.add_argument("id")
    p_dna.add_argument("--json", action="store_true")

    # similar
    p_sim = sub.add_parser("similar", help="Fraude similare")
    p_sim.add_argument("id")
    p_sim.add_argument("--threshold", "-t", type=float, default=0.4)
    p_sim.add_argument("--limit",     "-n", type=int, default=10)

    # quality
    p_qual = sub.add_parser("quality", help="Scor calitate")
    p_qual.add_argument("id")

    args   = parser.parse_args()
    header()

    if not args.command:
        parser.print_help()
        return

    dataset_path = Path(args.dataset) if args.dataset else DEFAULT_DATASET
    if not dataset_path.exists():
        print(f"  {C.RED}❌ Dataset negăsit: {dataset_path}{C.RESET}")
        print(f"  Specifică cu --dataset sau asigură-te că {DEFAULT_DATASET} există.")
        sys.exit(1)

    client = OFIClient(dataset_path)

    commands = {
        "stats":   cmd_stats,
        "search":  cmd_search,
        "export":  cmd_export,
        "dna":     cmd_dna,
        "similar": cmd_similar,
        "quality": cmd_quality
    }

    commands[args.command](args, client)
    print()


if __name__ == "__main__":
    main()

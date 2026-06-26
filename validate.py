#!/usr/bin/env python3
"""
Open Fraud Intelligence — Script de Validare Avansat
=====================================================
Validează dataset-ul JSON și fișierele Markdown din repository.

Utilizare:
    python3 validate.py                        # validare completă
    python3 validate.py --json-only            # doar dataset JSON
    python3 validate.py --md-only              # doar fișiere Markdown
    python3 validate.py --stats                # statistici dataset
    python3 validate.py --fix-csv             # regenerează CSV din JSON
    python3 validate.py --file scams/olx/x.md # validează un singur fișier
"""

import json
import csv
import os
import sys
import re
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

# ─── Culori terminal ────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):   print(f"{C.GREEN}  ✅ {msg}{C.RESET}")
def err(msg):  print(f"{C.RED}  ❌ {msg}{C.RESET}")
def warn(msg): print(f"{C.YELLOW}  ⚠️  {msg}{C.RESET}")
def info(msg): print(f"{C.CYAN}  ℹ️  {msg}{C.RESET}")
def head(msg): print(f"\n{C.BOLD}{C.BLUE}{'─'*60}\n  {msg}\n{'─'*60}{C.RESET}")

# ─── Configurare ────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
DATASET_JSON = ROOT / "datasets" / "scams.json"
DATASET_CSV  = ROOT / "datasets" / "scams.csv"
SCAMS_DIR    = ROOT / "scams"
DOCS_DIR     = ROOT / "docs"
TEMPLATES_DIR = ROOT / "templates"

VALID_PLATFORMS = {
    "olx", "whatsapp", "facebook", "instagram", "telegram",
    "email", "sms", "crypto", "fake-jobs", "fake-shops",
    "telefon", "vinted", "web", "twitter", "linkedin",
    "fizic", "autovit", "storia"
}
VALID_SEVERITIES = {"high", "medium", "low", None}
VALID_LABELS     = {"scam", "legitimate", "suspicious"}

REQUIRED_FIELDS = [
    "id", "title", "platform", "severity", "country",
    "year", "active", "tags", "scenario", "red_flags",
    "prevention", "ai_dataset"
]
REQUIRED_AI_FIELDS = ["message", "label", "confidence"]

ID_PATTERN = re.compile(r"^[a-z0-9\-]+-\d{4}$")

SCAM_PLATFORMS_DIRS = [
    "olx", "whatsapp", "facebook", "instagram", "telegram",
    "email", "sms", "crypto", "fake-jobs", "fake-shops"
]

# ─── Validator JSON ──────────────────────────────────────────────────────────
class JSONValidator:
    def __init__(self, path: Path):
        self.path   = path
        self.errors = []
        self.warns  = []
        self.data   = []

    def load(self) -> bool:
        if not self.path.exists():
            self.errors.append(f"Fișierul nu există: {self.path}")
            return False
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data = json.load(f)
            return True
        except json.JSONDecodeError as e:
            self.errors.append(f"JSON invalid: {e}")
            return False

    def validate(self) -> bool:
        if not self.load():
            return False

        if not isinstance(self.data, list):
            self.errors.append("Fișierul trebuie să fie o listă JSON []")
            return False

        seen_ids   = {}
        seen_msgs  = {}
        all_ok     = True

        for i, entry in enumerate(self.data):
            entry_id = entry.get("id", f"index-{i}")
            prefix   = f"[{entry_id}]"

            # ── Câmpuri obligatorii ──
            for field in REQUIRED_FIELDS:
                if field not in entry:
                    self.errors.append(f"{prefix} Câmp lipsă: '{field}'")
                    all_ok = False

            # ── ID format ──
            if "id" in entry:
                if not ID_PATTERN.match(str(entry["id"])):
                    self.errors.append(
                        f"{prefix} ID invalid '{entry['id']}'. "
                        f"Format așteptat: platform-NNNN (ex: olx-0001)"
                    )
                    all_ok = False
                # duplicate
                if entry["id"] in seen_ids:
                    self.errors.append(
                        f"{prefix} ID duplicat! Apare și la index {seen_ids[entry['id']]}"
                    )
                    all_ok = False
                else:
                    seen_ids[entry["id"]] = i

            # ── Platformă ──
            if "platform" in entry and entry["platform"] not in VALID_PLATFORMS:
                self.warns.append(
                    f"{prefix} Platformă necunoscută: '{entry['platform']}'. "
                    f"Consideră adăugarea în VALID_PLATFORMS."
                )

            # ── Severitate ──
            if "severity" in entry and entry["severity"] not in VALID_SEVERITIES:
                self.errors.append(
                    f"{prefix} Severitate invalidă: '{entry['severity']}'. "
                    f"Valori valide: high, medium, low, null"
                )
                all_ok = False

            # ── An ──
            if "year" in entry and entry["year"] is not None:
                if not isinstance(entry["year"], int) or entry["year"] < 2020 or entry["year"] > datetime.now().year + 1:
                    self.errors.append(
                        f"{prefix} Anul '{entry['year']}' pare invalid."
                    )
                    all_ok = False

            # ── Tags ──
            if "tags" in entry:
                if not isinstance(entry["tags"], list):
                    self.errors.append(f"{prefix} 'tags' trebuie să fie o listă")
                    all_ok = False
                elif len(entry["tags"]) == 0:
                    self.warns.append(f"{prefix} Lista 'tags' este goală")

            # ── Red flags & prevention ──
            for list_field in ["red_flags", "prevention"]:
                if list_field in entry and not isinstance(entry[list_field], list):
                    self.errors.append(f"{prefix} '{list_field}' trebuie să fie o listă")
                    all_ok = False

            # ── AI Dataset ──
            if "ai_dataset" in entry:
                ai = entry["ai_dataset"]
                if not isinstance(ai, dict):
                    self.errors.append(f"{prefix} 'ai_dataset' trebuie să fie un obiect")
                    all_ok = False
                else:
                    for af in REQUIRED_AI_FIELDS:
                        if af not in ai:
                            self.errors.append(f"{prefix} ai_dataset.{af} lipsă")
                            all_ok = False

                    if "label" in ai and ai["label"] not in VALID_LABELS:
                        self.errors.append(
                            f"{prefix} ai_dataset.label invalid: '{ai['label']}'. "
                            f"Valori valide: {VALID_LABELS}"
                        )
                        all_ok = False

                    if "confidence" in ai:
                        c = ai["confidence"]
                        if not isinstance(c, (int, float)) or not (0.0 <= c <= 1.0):
                            self.errors.append(
                                f"{prefix} ai_dataset.confidence trebuie să fie între 0.0 și 1.0, nu '{c}'"
                            )
                            all_ok = False

                    # ── Mesaje duplicate ──
                    if "message" in ai:
                        msg_hash = hashlib.md5(ai["message"].strip().lower().encode()).hexdigest()
                        if msg_hash in seen_msgs:
                            self.warns.append(
                                f"{prefix} Mesaj posibil duplicat cu {seen_msgs[msg_hash]}"
                            )
                        else:
                            seen_msgs[msg_hash] = entry_id

                    # ── Mesaj prea scurt ──
                    if "message" in ai and len(ai.get("message", "")) < 10:
                        self.warns.append(f"{prefix} Mesajul AI e prea scurt (sub 10 caractere)")

            # ── Titlu ──
            if "title" in entry and len(entry["title"]) < 5:
                self.warns.append(f"{prefix} Titlul pare prea scurt")

            # ── Scenariu ──
            if "scenario" in entry and len(str(entry.get("scenario", ""))) < 20:
                self.warns.append(f"{prefix} Scenariul pare prea scurt")

        return all_ok

    def print_results(self):
        for e in self.errors:
            err(e)
        for w in self.warns:
            warn(w)


# ─── Validator Markdown ──────────────────────────────────────────────────────
class MarkdownValidator:
    REQUIRED_SECTIONS = [
        "Informații generale",
        "Semnale de avertizare",
        "Cum te protejezi",
    ]
    REQUIRED_TABLE_FIELDS = ["ID", "Platformă", "Severitate", "Țară"]
    SENSITIVE_PATTERNS = [
        (r"\b\d{10}\b", "număr de telefon posibil neanonimizat"),
        (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b", "IBAN posibil real"),
        (r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b", "număr de card posibil real"),
        (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", "adresă Bitcoin posibil reală"),
    ]

    def __init__(self, path: Path):
        self.path   = path
        self.errors = []
        self.warns  = []

    def validate(self) -> bool:
        if not self.path.exists():
            self.errors.append(f"Fișierul nu există: {self.path}")
            return False

        content = self.path.read_text(encoding="utf-8")
        all_ok  = True

        # ── Secțiuni obligatorii ──
        for section in self.REQUIRED_SECTIONS:
            if section not in content:
                self.warns.append(f"Secțiunea '{section}' lipsește")

        # ── Câmpuri din tabel ──
        for field in self.REQUIRED_TABLE_FIELDS:
            if field not in content:
                self.warns.append(f"Câmpul '{field}' lipsește din tabelul de informații")

        # ── Date sensibile posibil neanonimizate ──
        for pattern, desc in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                self.warns.append(
                    f"Posibil {desc} detectat — verifică anonimizarea: {matches[:2]}"
                )

        # ── Link-uri active spre phishing ──
        urls = re.findall(r'https?://[^\s\)\"\']+', content)
        safe_domains = {"github.com", "who.is", "cert.ro", "anaf.ro", "politiaromana.ro",
                        "diicot.ro", "anpc.ro", "asfromania.ro", "coinmarketcap.com",
                        "coingecko.com", "recom.onrc.ro", "glassdoor.com",
                        "bestjobs.eu", "europol.europa.eu", "ic3.gov",
                        "actionfraud.police.uk", "interpol.int"}
        for url in urls:
            domain = re.sub(r'^https?://(www\.)?', '', url).split('/')[0]
            if domain and domain not in safe_domains:
                self.warns.append(f"Link extern neverificat: {url[:80]}")

        # ── Lungime minimă ──
        if len(content) < 200:
            self.warns.append("Fișierul pare prea scurt (sub 200 caractere)")

        # ── Verifică că există bloc AI dataset ──
        if "ai_dataset" not in content and "Dataset AI" not in content:
            self.warns.append("Secțiunea 'Dataset AI' lipsește")

        return all_ok and len(self.errors) == 0

    def print_results(self):
        for e in self.errors:
            err(e)
        for w in self.warns:
            warn(w)


# ─── Statistici ──────────────────────────────────────────────────────────────
def print_stats(data: list):
    head("📊 Statistici Dataset")

    total      = len(data)
    scam_count = sum(1 for d in data if d.get("ai_dataset", {}).get("label") == "scam")
    legit_count= sum(1 for d in data if d.get("ai_dataset", {}).get("label") == "legitimate")
    susp_count = sum(1 for d in data if d.get("ai_dataset", {}).get("label") == "suspicious")

    print(f"\n  {C.BOLD}Total intrări:{C.RESET}    {total}")
    print(f"  {C.RED}Scam:{C.RESET}              {scam_count} ({scam_count/total*100:.1f}%)")
    print(f"  {C.GREEN}Legitimate:{C.RESET}        {legit_count} ({legit_count/total*100:.1f}%)")
    print(f"  {C.YELLOW}Suspicious:{C.RESET}        {susp_count}")

    # Per platformă
    print(f"\n  {C.BOLD}Distribuție per platformă:{C.RESET}")
    platform_counts = Counter(d.get("platform", "unknown") for d in data)
    for platform, count in platform_counts.most_common():
        bar = "█" * count
        print(f"    {platform:<20} {count:>3}  {bar}")

    # Per severitate
    print(f"\n  {C.BOLD}Distribuție per severitate:{C.RESET}")
    sev_counts = Counter(d.get("severity", "none") for d in data if d.get("ai_dataset", {}).get("label") == "scam")
    for sev, count in [("high", sev_counts.get("high", 0)),
                        ("medium", sev_counts.get("medium", 0)),
                        ("low", sev_counts.get("low", 0))]:
        color = C.RED if sev == "high" else C.YELLOW if sev == "medium" else C.GREEN
        print(f"    {color}{sev:<10}{C.RESET} {count}")

    # Top tags
    print(f"\n  {C.BOLD}Top 10 tag-uri:{C.RESET}")
    all_tags = []
    for d in data:
        all_tags.extend(d.get("tags", []))
    for tag, count in Counter(all_tags).most_common(10):
        print(f"    {tag:<30} {count}")

    # Confidence medie
    confidences = [d["ai_dataset"]["confidence"] for d in data if "ai_dataset" in d and "confidence" in d["ai_dataset"]]
    if confidences:
        avg_conf = sum(confidences) / len(confidences)
        print(f"\n  {C.BOLD}Confidence medie AI:{C.RESET} {avg_conf:.3f}")

    # Ani
    years = Counter(d.get("year") for d in data if d.get("year"))
    print(f"\n  {C.BOLD}Distribuție per an:{C.RESET}")
    for year, count in sorted(years.items()):
        print(f"    {year}: {count} intrări")


# ─── Regenerare CSV ───────────────────────────────────────────────────────────
def regenerate_csv(data: list, csv_path: Path):
    head("🔄 Regenerare CSV")
    fieldnames = ["id", "title", "platform", "severity", "country", "year",
                  "active", "tags", "ai_label", "ai_confidence", "ai_message_preview"]
    rows = []
    for d in data:
        ai = d.get("ai_dataset", {})
        rows.append({
            "id":                   d.get("id", ""),
            "title":                d.get("title", ""),
            "platform":             d.get("platform", ""),
            "severity":             d.get("severity", ""),
            "country":              d.get("country", ""),
            "year":                 d.get("year", ""),
            "active":               str(d.get("active", "")).lower(),
            "tags":                 ",".join(d.get("tags", [])),
            "ai_label":             ai.get("label", ""),
            "ai_confidence":        ai.get("confidence", ""),
            "ai_message_preview":   str(ai.get("message", ""))[:80],
        })

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    ok(f"CSV regenerat: {csv_path} ({len(rows)} rânduri)")


# ─── Extrage dataset AI plat ─────────────────────────────────────────────────
def export_ai_flat(data: list, out_path: Path):
    """Exportă doar mesajele și etichetele pentru antrenare ML."""
    ai_data = []
    for d in data:
        ai = d.get("ai_dataset", {})
        if ai.get("message") and ai.get("label"):
            ai_data.append({
                "id":         d.get("id"),
                "message":    ai["message"],
                "label":      ai["label"],
                "confidence": ai.get("confidence"),
                "platform":   d.get("platform"),
            })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(ai_data, f, ensure_ascii=False, indent=2)
    ok(f"Dataset AI exportat: {out_path} ({len(ai_data)} mesaje)")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Open Fraud Intelligence — Validator Avansat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--json-only",  action="store_true", help="Validează doar JSON")
    parser.add_argument("--md-only",    action="store_true", help="Validează doar Markdown")
    parser.add_argument("--stats",      action="store_true", help="Afișează statistici")
    parser.add_argument("--fix-csv",    action="store_true", help="Regenerează CSV din JSON")
    parser.add_argument("--export-ai",  action="store_true", help="Exportă dataset AI plat")
    parser.add_argument("--file",       type=str,            help="Validează un singur fișier .md")
    parser.add_argument("--dataset",    type=str, default=str(DATASET_JSON), help="Cale spre JSON")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)

    print(f"\n{C.BOLD}{C.CYAN}═══════════════════════════════════════════════════════════")
    print(f"  🛡️  Open Fraud Intelligence — Validator Avansat")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"═══════════════════════════════════════════════════════════{C.RESET}")

    total_errors = 0
    total_warns  = 0

    # ── Validare fișier MD unic ──
    if args.file:
        head(f"📄 Validare fișier: {args.file}")
        mv = MarkdownValidator(Path(args.file))
        mv.validate()
        mv.print_results()
        total_errors += len(mv.errors)
        total_warns  += len(mv.warns)
        if not mv.errors and not mv.warns:
            ok("Fișierul este valid!")
        sys.exit(0 if total_errors == 0 else 1)

    # ── Validare JSON ──
    data = []
    if not args.md_only:
        head(f"📋 Validare JSON: {dataset_path.name}")
        jv = JSONValidator(dataset_path)
        json_ok = jv.validate()
        jv.print_results()
        data = jv.data

        total_errors += len(jv.errors)
        total_warns  += len(jv.warns)

        if json_ok and not jv.warns:
            ok(f"JSON valid — {len(data)} intrări, fără probleme")
        elif json_ok:
            warn(f"JSON valid cu {len(jv.warns)} avertismente")
        else:
            err(f"JSON invalid — {len(jv.errors)} erori critice")

    # ── Statistici ──
    if args.stats and data:
        print_stats(data)

    # ── Regenerare CSV ──
    if args.fix_csv and data:
        regenerate_csv(data, DATASET_CSV)

    # ── Export AI ──
    if args.export_ai and data:
        head("🤖 Export Dataset AI")
        ai_path = dataset_path.parent / "ai_messages.json"
        export_ai_flat(data, ai_path)

    # ── Validare Markdown ──
    if not args.json_only:
        head("📝 Validare fișiere Markdown")

        md_files = list(SCAMS_DIR.rglob("*.md"))
        md_files += list(DOCS_DIR.glob("*.md")) if DOCS_DIR.exists() else []

        if not md_files:
            warn("Nu s-au găsit fișiere Markdown")
        else:
            md_errors_total = 0
            md_warns_total  = 0
            files_with_issues = []

            for md_file in sorted(md_files):
                rel = md_file.relative_to(ROOT)
                mv = MarkdownValidator(md_file)
                mv.validate()

                if mv.errors or mv.warns:
                    files_with_issues.append((rel, mv))
                    md_errors_total += len(mv.errors)
                    md_warns_total  += len(mv.warns)

            if files_with_issues:
                for rel, mv in files_with_issues:
                    print(f"\n  {C.BOLD}{rel}{C.RESET}")
                    mv.print_results()
            else:
                ok(f"Toate {len(md_files)} fișiere Markdown sunt valide!")

            if md_errors_total == 0 and md_warns_total > 0:
                warn(f"Total: {md_warns_total} avertismente în fișierele Markdown")
            elif md_errors_total > 0:
                err(f"Total: {md_errors_total} erori, {md_warns_total} avertismente în Markdown")
            else:
                ok(f"Total: {len(md_files)} fișiere Markdown verificate — OK")

            total_errors += md_errors_total
            total_warns  += md_warns_total

    # ── Verificare structură directoare ──
    if not args.json_only and not args.md_only:
        head("📁 Verificare structură repository")
        expected_dirs = [
            ROOT / "scams" / d for d in SCAM_PLATFORMS_DIRS
        ] + [
            ROOT / "datasets",
            ROOT / "docs",
            ROOT / "templates",
            ROOT / "screenshots",
        ]
        for d in expected_dirs:
            if d.exists():
                ok(f"Există: {d.relative_to(ROOT)}")
            else:
                warn(f"Directorul lipsește: {d.relative_to(ROOT)}")

        expected_files = [
            ROOT / "README.md",
            ROOT / "CONTRIBUTING.md",
            ROOT / "LICENSE",
            ROOT / ".gitignore",
            ROOT / "datasets" / "scams.json",
            ROOT / "datasets" / "scams.csv",
            ROOT / "docs" / "red-flags.md",
            ROOT / "docs" / "scam-taxonomy.md",
            ROOT / "docs" / "reporting-guide.md",
            ROOT / "templates" / "scam-template.md",
        ]
        print()
        for f in expected_files:
            if f.exists():
                size = f.stat().st_size
                ok(f"{f.relative_to(ROOT):<45} ({size:,} bytes)")
            else:
                warn(f"Fișier lipsă: {f.relative_to(ROOT)}")

    # ── Sumar final ──
    print(f"\n{C.BOLD}{'═'*60}")
    if total_errors == 0 and total_warns == 0:
        print(f"{C.GREEN}  ✅ Validare completă — fără probleme!{C.RESET}")
    elif total_errors == 0:
        print(f"{C.YELLOW}  ⚠️  Validare completă — {total_warns} avertismente (fără erori critice){C.RESET}")
    else:
        print(f"{C.RED}  ❌ Validare eșuată — {total_errors} erori, {total_warns} avertismente{C.RESET}")
    print(f"{C.BOLD}{'═'*60}{C.RESET}\n")

    sys.exit(0 if total_errors == 0 else 1)


if __name__ == "__main__":
    main()

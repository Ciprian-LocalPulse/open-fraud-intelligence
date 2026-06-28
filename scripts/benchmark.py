#!/usr/bin/env python3
"""
OFI — AI Benchmark Suite
=========================
Evaluează modele NLP pe task-urile principale:
  1. Clasificare scam/legitimate
  2. Extragere entități (platformă, severitate, tehnici)
  3. Detecție intenție
  4. Detecție spam

Utilizare:
    python3 benchmark.py --task classification --model baseline
    python3 benchmark.py --task all --dataset ../../datasets/scams_v2.json
    python3 benchmark.py --export-gold-standard
"""

import json
import re
import math
import argparse
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime


# ─── Utilitare ─────────────────────────────────────────────────────────────
def load_dataset(path: Path) -> list:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def extract_ai_samples(data: list) -> list:
    """Extrage perechile (message, label) din dataset."""
    samples = []
    for entry in data:
        ai = entry.get("ai_dataset", {})
        if ai.get("message") and ai.get("label"):
            samples.append({
                "id":         entry.get("id"),
                "message":    ai["message"],
                "label":      ai["label"],
                "confidence": ai.get("confidence", 1.0),
                "platform":   entry.get("platform"),
                "severity":   entry.get("severity"),
                "language":   ai.get("language", "ro")
            })
    return samples


# ─── Baseline Classifier (rule-based, fără ML) ─────────────────────────────
class BaselineScamClassifier:
    """
    Clasificator baseline bazat pe reguli pentru detectarea mesajelor scam.
    Scop: Gold standard pentru compararea cu modele ML/LLM.
    """

    HIGH_CONFIDENCE_SCAM_PATTERNS = [
        r"profit garantat",
        r"câștig garantat",
        r"câștigat\s+\d+\s*(?:eur|ron|usd)",
        r"investiție\s+fără\s+risc",
        r"accesați\s+(?:acest|link|linkul)",
        r"taxa\s+de\s+(?:formare|activare|confirmare|expediere|rezervare)",
        r"cod\s+de\s+verificare.*(?:trimite|dă|da)",
        r"am\s+plătit\s+deja",
        r"confirma(?:ți|re)\s+(?:plata|primirea)",
        r"contul\s+(?:dvs|tău).*(?:blocat|suspendat|restricționat)",
        r"(?:retrage|ridic)\s+fonduri.*taxă",
        r"(?:western\s+union|moneygram|paysafecard)",
        r"profit\s+de\s+\d+%\s+(?:zilnic|lunar|săptămânal)",
        r"bot(?:ul)?\s+(?:nostru|ai|automat).*profit",
        r"semnale?\s+(?:vip|crypto|trading)",
        r"(?:câștig|premiu|voucher).*(?:revendic|accesa|link)",
        r"(?:job|angaj).*taxă\s+de\s+(?:înscriere|activare|procesare)",
        r"felicitări.*(?:câștigat|câștigătorul|premiu)",
        r"(?:military|medic|inginer|offshore).*strainatate.*bani",
    ]

    LEGITIMATE_PATTERNS = [
        r"(?:bună\s+ziua|salut).*interesat.*produs",
        r"mai\s+este\s+disponibil",
        r"pot\s+veni\s+să.*(?:văd|testez)",
        r"coletul.*va\s+fi\s+livrat\s+astăzi",
        r"(?:awb|tracking).*(?:livra|urmărire)",
        r"tranzacție.*(?:mega\s+image|kaufland|lidl|emag\.ro)",
        r"(?:interviu|întâlnire).*(?:video|zoom|teams)",
    ]

    URGENCY_PATTERNS = [
        r"(?:urgent|urgentă|urgent!)",
        r"(?:azi|astăzi|acum|imediat)\s+trebuie",
        r"(?:expiră|expirat)\s+în\s+\d+\s*(?:ore|minute|zile)",
        r"(?:stoc|ofertă)\s+limitat",
        r"(?:nu\s+ratați|nu\s+pierde)",
    ]

    def __init__(self):
        self.scam_re   = [re.compile(p, re.IGNORECASE) for p in self.HIGH_CONFIDENCE_SCAM_PATTERNS]
        self.legit_re  = [re.compile(p, re.IGNORECASE) for p in self.LEGITIMATE_PATTERNS]
        self.urgent_re = [re.compile(p, re.IGNORECASE) for p in self.URGENCY_PATTERNS]

    def predict(self, message: str) -> dict:
        text = message.lower()

        scam_hits   = sum(1 for p in self.scam_re   if p.search(text))
        legit_hits  = sum(1 for p in self.legit_re  if p.search(text))
        urgency     = sum(1 for p in self.urgent_re if p.search(text))

        scam_score  = min(1.0, scam_hits * 0.3 + urgency * 0.1)
        legit_score = min(1.0, legit_hits * 0.4)

        if scam_score >= 0.3:
            label      = "scam"
            confidence = min(0.99, 0.6 + scam_score * 0.4)
        elif legit_score >= 0.4:
            label      = "legitimate"
            confidence = min(0.97, 0.6 + legit_score * 0.4)
        else:
            label      = "suspicious"
            confidence = 0.5

        return {
            "label":      label,
            "confidence": round(confidence, 3),
            "scam_hits":  scam_hits,
            "legit_hits": legit_hits,
            "urgency":    urgency
        }


# ─── Metrici de evaluare ────────────────────────────────────────────────────
def compute_metrics(predictions: list, ground_truth: list, label: str = "scam") -> dict:
    tp = fp = tn = fn = 0
    for pred, true in zip(predictions, ground_truth):
        p = (pred == label)
        t = (true == label)
        if p and t:   tp += 1
        elif p and not t: fp += 1
        elif not p and not t: tn += 1
        else: fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / len(predictions) if predictions else 0.0

    return {
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "support": len(predictions)
    }


def compute_confusion_matrix(predictions: list, ground_truth: list) -> dict:
    labels    = sorted(set(ground_truth) | set(predictions))
    matrix    = defaultdict(lambda: defaultdict(int))
    for pred, true in zip(predictions, ground_truth):
        matrix[true][pred] += 1
    return {"labels": labels, "matrix": {l: dict(matrix[l]) for l in labels}}


# ─── Benchmark Runner ───────────────────────────────────────────────────────
class BenchmarkRunner:
    def __init__(self, dataset_path: Path):
        self.data     = load_dataset(dataset_path)
        self.samples  = extract_ai_samples(self.data)
        self.clf      = BaselineScamClassifier()

    def run_classification(self, verbose: bool = True) -> dict:
        """Task 1: Clasificare binară scam vs. legitimate."""
        if verbose:
            print("\n" + "─"*60)
            print("  📊 TASK 1: Clasificare Scam / Legitimate")
            print("─"*60)

        predictions  = []
        ground_truth = []
        details      = []

        for sample in self.samples:
            if sample["label"] not in ("scam", "legitimate"):
                continue
            result = self.clf.predict(sample["message"])
            predictions.append(result["label"] if result["label"] != "suspicious" else "scam")
            ground_truth.append(sample["label"])
            details.append({
                "id":         sample["id"],
                "message":    sample["message"][:80],
                "true":       sample["label"],
                "pred":       result["label"],
                "confidence": result["confidence"],
                "correct":    result["label"] == sample["label"]
            })

        metrics = compute_metrics(predictions, ground_truth, "scam")
        cm      = compute_confusion_matrix(predictions, ground_truth)

        if verbose:
            print(f"\n  Samples: {len(predictions)}")
            print(f"  Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.1f}%)")
            print(f"  Precision: {metrics['precision']:.4f}")
            print(f"  Recall:    {metrics['recall']:.4f}")
            print(f"  F1-Score:  {metrics['f1']:.4f}")
            print(f"\n  Confusion Matrix:")
            for true_label in cm["labels"]:
                row = cm["matrix"].get(true_label, {})
                row_str = " | ".join(f"{row.get(p, 0):>4}" for p in cm["labels"])
                print(f"    {true_label:<12}: {row_str}")

            errors = [d for d in details if not d["correct"]]
            if errors and verbose:
                print(f"\n  ❌ Erori ({len(errors)}):")
                for e in errors[:5]:
                    print(f"    [{e['id']}] True={e['true']}, Pred={e['pred']}")
                    print(f"      Msg: {e['message'][:70]}...")

        return {"metrics": metrics, "confusion_matrix": cm, "details": details}

    def run_entity_extraction(self, verbose: bool = True) -> dict:
        """Task 2: Extragere entități (platformă, tehnici, IOC)."""
        if verbose:
            print("\n" + "─"*60)
            print("  🏷️  TASK 2: Extragere Entități")
            print("─"*60)

        platform_patterns = {
            "olx":       r"\bolx\b",
            "whatsapp":  r"\bwhatsapp\b",
            "facebook":  r"\bfacebook\b|\bfb\b",
            "instagram": r"\binstagram\b",
            "telegram":  r"\btelegram\b",
            "email":     r"\bemail\b|\bmail\b",
            "sms":       r"\bsms\b|\bmesaj text\b",
            "crypto":    r"\bcrypto\b|\bbitcoin\b|\bbtc\b|\busdt\b"
        }

        platform_re = {p: re.compile(pat, re.IGNORECASE) for p, pat in platform_patterns.items()}
        results = []

        for sample in self.samples:
            text       = sample["message"].lower()
            detected   = [p for p, r in platform_re.items() if r.search(text)]
            expected   = [sample.get("platform")]
            overlap    = set(detected) & set(expected)
            correct    = len(overlap) > 0 or (not detected and sample.get("platform") not in platform_patterns)
            results.append({"id": sample["id"], "expected": expected, "detected": detected, "correct": correct})

        accuracy = sum(1 for r in results if r["correct"]) / len(results) if results else 0.0
        if verbose:
            print(f"\n  Samples: {len(results)}")
            print(f"  Platform detection accuracy: {accuracy:.4f} ({accuracy*100:.1f}%)")
            print(f"  (Note: Baseline heuristic, un model NLP fin-tuned ar trebui să depășească 85%)")

        return {"accuracy": round(accuracy, 4), "details": results}

    def run_all(self) -> dict:
        print("\n" + "═"*60)
        print("  🛡️  OFI AI Benchmark Suite")
        print(f"  Dataset: {len(self.samples)} samples")
        print(f"  Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("═"*60)

        results = {
            "dataset_size": len(self.samples),
            "scam_count":   sum(1 for s in self.samples if s["label"] == "scam"),
            "legit_count":  sum(1 for s in self.samples if s["label"] == "legitimate"),
            "timestamp":    datetime.now().isoformat(),
            "classification":    self.run_classification(),
            "entity_extraction": self.run_entity_extraction()
        }

        print("\n" + "═"*60)
        print("  📋 SUMAR BENCHMARK")
        print("─"*60)
        print(f"  Classification F1:  {results['classification']['metrics']['f1']:.4f}")
        print(f"  Entity Extraction:  {results['entity_extraction']['accuracy']:.4f}")
        print("═"*60)

        return results

    def export_gold_standard(self, output_path: Path):
        """Exportă gold standard pentru antrenare/evaluare modele externe."""
        gold = [{
            "id":         s["id"],
            "message":    s["message"],
            "label":      s["label"],
            "confidence": s["confidence"],
            "platform":   s["platform"],
            "language":   s["language"]
        } for s in self.samples]

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(gold, f, ensure_ascii=False, indent=2)
        print(f"✅ Gold standard exportat: {output_path} ({len(gold)} samples)")


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="OFI AI Benchmark")
    parser.add_argument("--dataset", default="../../datasets/scams_v2.json")
    parser.add_argument("--task", choices=["classification", "entity", "all"], default="all")
    parser.add_argument("--output", default="benchmark_results.json")
    parser.add_argument("--export-gold-standard", action="store_true")
    args = parser.parse_args()

    runner = BenchmarkRunner(Path(args.dataset))

    if args.export_gold_standard:
        runner.export_gold_standard(Path("gold_standard.json"))
        return

    if args.task == "classification":
        results = {"classification": runner.run_classification()}
    elif args.task == "entity":
        results = {"entity_extraction": runner.run_entity_extraction()}
    else:
        results = runner.run_all()

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n✅ Rezultate salvate: {args.output}")


if __name__ == "__main__":
    main()

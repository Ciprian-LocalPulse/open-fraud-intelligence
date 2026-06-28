"""
Open Fraud Intelligence — Python SDK
=====================================
SDK oficial Python pentru interacțiunea cu baza de date OFI.

Instalare:
    pip install ofi-sdk  (viitor)
    
    SAU direct:
    from ofi_sdk import OFIClient

Utilizare rapidă:
    from ofi_sdk import OFIClient

    client = OFIClient("datasets/scams_v2.json")
    
    # Caută fraude după platformă
    results = client.search(platform="olx", severity="High")
    
    # Calculează similaritate între două fraude
    score = client.similarity("olx-0001", "olx-0002")
    
    # Exportă dataset AI
    dataset = client.export_ai_dataset(language="ro")
    
    # Calculează scor DNA
    dna = client.get_dna("olx-0001")
    
    # Clasifică un mesaj
    prediction = client.classify("Am plătit deja, accesați linkul.")
"""

import json
import re
import hashlib
import uuid as uuid_lib
from pathlib import Path
from datetime import datetime
from typing import Optional, Union
from collections import Counter


__version__ = "2.0.0"
__author__  = "Open Fraud Intelligence Community"
__license__ = "CC0-1.0"


# ─── Exceptions ──────────────────────────────────────────────────────────────
class OFIError(Exception):          pass
class OFINotFound(OFIError):        pass
class OFIValidationError(OFIError): pass


# ─── Scam DNA Fingerprinter ──────────────────────────────────────────────────
class ScamDNAEngine:
    """
    Calculează și compară amprenta unică (DNA) a fraudelor.
    Permite identificarea variantelor aceleiași campanii.
    """

    PSYCHOLOGY_KEYWORDS = {
        "urgency":      ["urgent", "acum", "imediat", "azi", "expiră", "rapid", "repede"],
        "authority":    ["bancă", "poliție", "anaf", "cert", "microsoft", "oficial"],
        "scarcity":     ["limitat", "ultimul", "sold out", "ofertă limitată", "puține"],
        "greed":        ["câștig", "profit", "bonus", "gratuit", "free", "bani"],
        "fear":         ["blocat", "suspendat", "amendat", "investigat", "dosar", "penale"],
        "social_proof": ["mii de oameni", "clienți mulțumiți", "recenzii", "testimoniale"],
        "empathy":      ["te rog", "ajutor", "urgență", "accident", "spital", "familie"]
    }

    PAYMENT_PATTERNS = {
        "card":           ["card", "cvv", "visa", "mastercard", "iban"],
        "transfer_bancar":["transfer", "cont bancar", "virament"],
        "crypto":         ["bitcoin", "btc", "crypto", "usdt", "ethereum", "eth", "wallet"],
        "revolut":        ["revolut"],
        "paypal":         ["paypal"],
        "voucher":        ["paysafe", "google play", "apple gift", "voucher"],
        "western_union":  ["western union", "moneygram", "money transfer"],
        "cash":           ["cash", "numerar", "bani gheață"]
    }

    BRAND_ABUSE_PATTERNS = [
        "fan courier", "dpd", "dhl", "cargus", "gls",
        "olx", "emag", "kaufland", "lidl", "metro", "carrefour",
        "bcr", "brd", "ing", "raiffeisen", "unicredit",
        "microsoft", "google", "apple", "amazon",
        "anaf", "politia", "cert-ro", "anpc"
    ]

    def compute(self, message: str, entry: dict = None) -> dict:
        """Calculează DNA-ul unui mesaj de fraudă."""
        text = message.lower()

        psychology = [
            psych for psych, keywords in self.PSYCHOLOGY_KEYWORDS.items()
            if any(kw in text for kw in keywords)
        ]

        payments = [
            method for method, patterns in self.PAYMENT_PATTERNS.items()
            if any(p in text for p in patterns)
        ]

        brands = [brand for brand in self.BRAND_ABUSE_PATTERNS if brand in text]

        urgency_count = sum(
            1 for kw in self.PSYCHOLOGY_KEYWORDS["urgency"] if kw in text
        )
        urgency_level = min(5, urgency_count + (1 if "!" in message else 0))

        language_markers = re.findall(
            r'\b(?:acces(?:ați|eze)|confirm(?:ați|are)|plătiți|urgent|imediat|link)\b',
            text
        )

        # Fingerprint determinist
        components = sorted(psychology) + sorted(payments) + sorted(brands)
        fingerprint = hashlib.sha256(
            ":".join(components).encode("utf-8")
        ).hexdigest()

        dna = {
            "psychology":       psychology,
            "payment_methods":  payments,
            "brand_abuse":      brands,
            "urgency_level":    urgency_level,
            "language_markers": list(set(language_markers)),
            "fingerprint":      fingerprint
        }

        if entry and "scam_dna" in entry:
            stored = entry["scam_dna"]
            dna["target_profile"]   = stored.get("target_profile", {})
            dna["typical_loss_ron"] = stored.get("typical_loss_ron", {})

        return dna

    def similarity(self, dna1: dict, dna2: dict) -> float:
        """
        Calculează similaritatea Jaccard între două DNA-uri.
        Returnează un scor între 0.0 (complet diferite) și 1.0 (identice).
        """
        def set_of(dna: dict) -> set:
            s = set()
            s.update(dna.get("psychology", []))
            s.update(dna.get("payment_methods", []))
            s.update(dna.get("brand_abuse", []))
            return s

        s1, s2   = set_of(dna1), set_of(dna2)
        union     = s1 | s2
        intersect = s1 & s2

        if not union:
            return 1.0

        jaccard = len(intersect) / len(union)

        # Bonus dacă fingerprint-urile sunt identice
        if dna1.get("fingerprint") == dna2.get("fingerprint"):
            jaccard = min(1.0, jaccard + 0.3)

        return round(jaccard, 4)


# ─── Quality Scorer ───────────────────────────────────────────────────────────
class QualityScorer:
    """Calculează scorul de calitate al unei intrări din dataset."""

    def score(self, entry: dict) -> dict:
        completeness  = self._completeness(entry)
        evidence      = self._evidence(entry)
        verification  = self._verification(entry)
        freshness     = self._freshness(entry)
        overall       = round(
            completeness * 0.30 +
            evidence     * 0.25 +
            verification * 0.30 +
            freshness    * 0.15, 4
        )
        return {
            "completeness":  completeness,
            "evidence":      evidence,
            "verification":  verification,
            "freshness":     freshness,
            "overall":       overall
        }

    def _completeness(self, e: dict) -> float:
        required = ["uuid","id","title","platform","severity","scenario",
                    "red_flags","prevention","ai_dataset","tags"]
        optional = ["ioc","mitre_attack","capec","scam_dna","timeline","references"]
        req_score = sum(1 for f in required if e.get(f)) / len(required)
        opt_score = sum(1 for f in optional if e.get(f)) / len(optional)
        return round(req_score * 0.7 + opt_score * 0.3, 4)

    def _evidence(self, e: dict) -> float:
        v         = e.get("verification", {})
        score     = 0.0
        score    += 0.3 if v.get("reporter_count", 0) > 0 else 0.0
        score    += min(0.3, v.get("reporter_count", 0) / 100 * 0.3)
        score    += 0.2 if v.get("evidence_count", 0) > 0 else 0.0
        score    += 0.2 if v.get("official_source") else 0.0
        ioc       = e.get("ioc", {})
        ioc_total = sum(len(v) for v in ioc.values() if isinstance(v, list))
        score    += min(0.1, ioc_total * 0.02)
        return round(min(1.0, score), 4)

    def _verification(self, e: dict) -> float:
        status = e.get("verification", {}).get("status", "pending")
        return {
            "official_source":  1.0,
            "verified":         0.9,
            "community_verified": 0.6,
            "pending":          0.3,
            "false_positive":   0.0
        }.get(status, 0.2)

    def _freshness(self, e: dict) -> float:
        last_upd = e.get("last_updated", e.get("created_at", ""))
        if not last_upd:
            return 0.3
        try:
            dt   = datetime.fromisoformat(last_upd.replace("Z", "+00:00"))
            days = (datetime.now(dt.tzinfo) - dt).days
            if days < 30:   return 1.0
            if days < 90:   return 0.8
            if days < 180:  return 0.6
            if days < 365:  return 0.4
            return 0.2
        except Exception:
            return 0.3


# ─── Main Client ──────────────────────────────────────────────────────────────
class OFIClient:
    """
    Client principal pentru Open Fraud Intelligence.
    
    Exemplu:
        client = OFIClient("datasets/scams_v2.json")
        results = client.search(platform="olx")
        for r in results:
            print(r["id"], r["title"])
    """

    def __init__(self, dataset_path: Union[str, Path] = None):
        self.dataset_path = Path(dataset_path) if dataset_path else None
        self._data: list  = []
        self._index: dict = {}
        self.dna_engine   = ScamDNAEngine()
        self.quality      = QualityScorer()

        if self.dataset_path and self.dataset_path.exists():
            self.load(self.dataset_path)

    def load(self, path: Union[str, Path]) -> "OFIClient":
        """Încarcă dataset-ul din fișier JSON."""
        path = Path(path)
        if not path.exists():
            raise OFIError(f"Fișierul nu există: {path}")
        with open(path, encoding="utf-8") as f:
            self._data = json.load(f)
        self._index = {e.get("id"): e for e in self._data if e.get("id")}
        return self

    def get(self, entry_id: str) -> dict:
        """Obține o intrare după ID."""
        if entry_id not in self._index:
            raise OFINotFound(f"ID-ul '{entry_id}' nu există în dataset")
        return self._index[entry_id]

    def search(self,
               platform: str = None,
               severity: str = None,
               label:    str = None,
               tag:      str = None,
               active:   bool = None,
               year:     int  = None,
               query:    str  = None,
               limit:    int  = None) -> list:
        """
        Caută intrări în dataset cu filtre multiple.
        
        Args:
            platform: Filtrează după platformă (ex: "olx", "whatsapp")
            severity: Filtrează după severitate (ex: "High", "Critical")
            label:    Filtrează după eticheta AI ("scam", "legitimate")
            tag:      Filtrează după tag
            active:   Filtrează fraude active / inactive
            year:     Filtrează după an
            query:    Caută în titlu și scenariu (text liber)
            limit:    Numărul maxim de rezultate
        
        Returns:
            Lista de intrări care corespund filtrelor
        """
        results = self._data

        if platform:
            results = [e for e in results if e.get("platform") == platform]
        if severity:
            results = [e for e in results if e.get("severity") == severity]
        if label:
            results = [e for e in results if e.get("ai_dataset", {}).get("label") == label]
        if tag:
            results = [e for e in results if tag in e.get("tags", [])]
        if active is not None:
            results = [e for e in results if e.get("active") == active]
        if year:
            results = [e for e in results if e.get("year") == year]
        if query:
            q = query.lower()
            results = [
                e for e in results
                if q in e.get("title", "").lower()
                or q in e.get("scenario", "").lower()
                or any(q in t for t in e.get("tags", []))
            ]
        if limit:
            results = results[:limit]

        return results

    def similarity(self, id1: str, id2: str) -> dict:
        """
        Calculează similaritatea dintre două fraude pe baza Scam DNA.
        
        Returns:
            dict cu scorul și detalii despre similaritate
        """
        e1 = self.get(id1)
        e2 = self.get(id2)

        ai1 = e1.get("ai_dataset", {}).get("message", "")
        ai2 = e2.get("ai_dataset", {}).get("message", "")

        dna1 = self.dna_engine.compute(ai1, e1)
        dna2 = self.dna_engine.compute(ai2, e2)

        score = self.dna_engine.similarity(dna1, dna2)

        return {
            "id1":             id1,
            "id2":             id2,
            "similarity":      score,
            "interpretation":  (
                "Identice / Aceeași campanie" if score >= 0.9 else
                "Foarte similare"             if score >= 0.7 else
                "Similare"                    if score >= 0.5 else
                "Parțial similare"            if score >= 0.3 else
                "Diferite"
            ),
            "shared_psychology":     list(set(dna1["psychology"]) & set(dna2["psychology"])),
            "shared_payments":       list(set(dna1["payment_methods"]) & set(dna2["payment_methods"])),
            "shared_brand_abuse":    list(set(dna1["brand_abuse"]) & set(dna2["brand_abuse"])),
            "dna1_fingerprint":      dna1["fingerprint"],
            "dna2_fingerprint":      dna2["fingerprint"]
        }

    def find_similar(self, entry_id: str, threshold: float = 0.5, limit: int = 10) -> list:
        """Găsește toate fraudele similare cu una dată."""
        results = []
        for e in self._data:
            if e.get("id") == entry_id:
                continue
            try:
                sim = self.similarity(entry_id, e["id"])
                if sim["similarity"] >= threshold:
                    results.append({**sim, "title": e.get("title", "")})
            except Exception:
                pass
        return sorted(results, key=lambda x: x["similarity"], reverse=True)[:limit]

    def get_dna(self, entry_id: str) -> dict:
        """Obține Scam DNA pentru o intrare."""
        entry = self.get(entry_id)
        msg   = entry.get("ai_dataset", {}).get("message", "")
        return self.dna_engine.compute(msg, entry)

    def score_quality(self, entry_id: str) -> dict:
        """Calculează scorul de calitate al unei intrări."""
        return self.quality.score(self.get(entry_id))

    def export_ai_dataset(self, language: str = "ro", label: str = None) -> list:
        """
        Exportă dataset-ul pentru antrenare modele AI.
        
        Args:
            language: Limba mesajelor ("ro", "en", "fr", etc.)
            label:    Filtrează după etichetă ("scam", "legitimate")
        """
        results = []
        for e in self._data:
            ai = e.get("ai_dataset", {})
            if not ai.get("message"):
                continue
            if label and ai.get("label") != label:
                continue

            msg = ai["message"]
            if language != "ro":
                translations = ai.get("translations", {})
                msg = translations.get(language, ai["message"])

            results.append({
                "id":         e.get("id"),
                "message":    msg,
                "label":      ai.get("label"),
                "confidence": ai.get("confidence"),
                "platform":   e.get("platform"),
                "language":   language
            })
        return results

    def statistics(self) -> dict:
        """Generează statistici complete ale dataset-ului."""
        scam_entries  = [e for e in self._data if e.get("ai_dataset", {}).get("label") == "scam"]
        legit_entries = [e for e in self._data if e.get("ai_dataset", {}).get("label") == "legitimate"]

        platform_dist = Counter(e.get("platform") for e in self._data)
        severity_dist = Counter(e.get("severity") for e in scam_entries)
        tag_dist      = Counter(tag for e in self._data for tag in e.get("tags", []))

        quality_scores = [self.quality.score(e)["overall"] for e in self._data]
        avg_quality    = sum(quality_scores) / len(quality_scores) if quality_scores else 0

        return {
            "total":             len(self._data),
            "scam_count":        len(scam_entries),
            "legitimate_count":  len(legit_entries),
            "platform_distribution": dict(platform_dist.most_common()),
            "severity_distribution": dict(severity_dist.most_common()),
            "top_tags":              dict(tag_dist.most_common(20)),
            "average_quality":       round(avg_quality, 4),
            "verified_count":        sum(
                1 for e in self._data
                if e.get("verification", {}).get("status") in ("verified", "official_source")
            ),
            "with_ioc":              sum(
                1 for e in self._data
                if any(e.get("ioc", {}).get(k) for k in ["domains", "urls", "phones", "emails", "wallets"])
            ),
            "with_mitre":            sum(1 for e in self._data if e.get("mitre_attack")),
            "with_dna":              sum(1 for e in self._data if e.get("scam_dna"))
        }

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"OFIClient(entries={len(self._data)}, path={self.dataset_path})"

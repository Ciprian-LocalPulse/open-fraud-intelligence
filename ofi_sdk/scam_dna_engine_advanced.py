#!/usr/bin/env python3
"""
OFI — Scam DNA Engine Avansat
==============================
Nivel 15 — Unic în lume.

Componente:
  1. ScamDNA       — Amprentă unică multidimensională
  2. SimilarityEngine — Detectare variante și campanii
  3. ScamTimeline  — Evoluția istorică a fraudelor
  4. EvolutionGraph — Graf de propagare inter-platforme

Utilizare:
    from scam_dna_engine import ScamDNAEngine, SimilarityEngine, EvolutionGraph
    
    engine = ScamDNAEngine()
    dna    = engine.compute_from_entry(entry)
    
    sim    = SimilarityEngine(dataset)
    graph  = sim.build_campaign_graph()
    
    timeline = ScamTimeline(entry)
    timeline.render()
"""

import json
import hashlib
import math
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional


# ─── Scam DNA — Amprenta multidimensională ───────────────────────────────────
class ScamDNA:
    """
    Amprenta unică a unei fraude pe 9 dimensiuni:
    Technique → Psychology → Platform → Payment → Urgency
    → Language → Target → Brand → Outcome
    """

    DIMENSIONS = [
        "technique", "psychology", "platform",
        "payment", "urgency", "language",
        "target", "brand", "outcome"
    ]

    PSYCHOLOGY_MAP = {
        "urgency":      ["urgent", "imediat", "acum", "expiră", "rapid", "azi", "grabă"],
        "authority":    ["bancă", "poliție", "anaf", "cert", "microsoft", "oficial", "inspector", "procuror"],
        "scarcity":     ["limitat", "ultimul", "sold out", "ofertă limitată", "puține locuri", "stoc mic"],
        "greed":        ["câștig", "profit", "bonus", "gratuit", "free", "bani", "avere", "îmbogățire"],
        "fear":         ["blocat", "suspendat", "amendat", "investigat", "dosar", "penale", "executare"],
        "social_proof": ["mii de oameni", "clienți mulțumiți", "alții au câștigat", "recenzii pozitive"],
        "reciprocity":  ["ți-am trimis deja", "am plătit", "am investit pentru tine", "îți datorez"],
        "empathy":      ["te rog", "ajutor", "urgență", "accident", "spital", "familie", "copil bolnav"],
        "romance":      ["dragostea mea", "te iubesc", "relație", "partener", "suflet pereche"]
    }

    PAYMENT_MAP = {
        "card":             ["card", "cvv", "visa", "mastercard", "nr card", "date card"],
        "transfer_bancar":  ["transfer", "cont bancar", "virament", "iban", "op"],
        "crypto_btc":       ["bitcoin", "btc", "crypto", "blockchain"],
        "crypto_usdt":      ["usdt", "tether", "stablecoin"],
        "crypto_eth":       ["ethereum", "eth"],
        "revolut":          ["revolut"],
        "paypal":           ["paypal"],
        "voucher_paysafe":  ["paysafecard", "paysafe"],
        "voucher_google":   ["google play", "google gift"],
        "western_union":    ["western union"],
        "moneygram":        ["moneygram"],
        "cash_meetup":      ["cash", "numerar", "bani gheață", "ne întâlnim"],
        "wire_international":["wire transfer", "swift", "international wire"]
    }

    LANGUAGE_MARKERS_MAP = {
        "imperative_access":    [r"accesați", r"accesează", r"intră pe"],
        "imperative_confirm":   [r"confirmați", r"confirmă", r"confirmare"],
        "imperative_pay":       [r"plătiți", r"achitați", r"virați"],
        "fake_official":        [r"departamentul de", r"serviciul de", r"direcția"],
        "pressure_time":        [r"în \d+ (ore|minute|zile)", r"până (la ora|mâine|astăzi)"],
        "winner_notification":  [r"ați câștigat", r"felicitări", r"câștigătorul"],
        "problem_notification": [r"am detectat", r"a fost detectat", r"problemă la"],
        "link_invitation":      [r"accesați linkul", r"click aici", r"urmați linkul"]
    }

    BRAND_LIST = [
        # Curieri
        "fan courier", "dpd", "dhl", "cargus", "gls", "sameday", "urgent cargus",
        # Marketplace
        "olx", "emag", "altex", "media galaxy", "flanco", "dedeman", "ikea",
        "facebook marketplace", "vinted", "autovit", "storia",
        # Retail
        "kaufland", "lidl", "penny", "metro", "carrefour", "auchan", "mega image",
        # Banking
        "bcr", "brd", "ing", "raiffeisen", "unicredit", "alpha bank", "cec", "banca transilvania",
        # Tech
        "microsoft", "google", "apple", "amazon", "netflix", "paypal",
        # Gov
        "anaf", "politia romana", "diicot", "cert-ro", "anpc", "dsv", "primaria",
        # Telecom
        "orange", "vodafone", "digi", "telekom"
    ]

    TARGET_PROFILES = {
        "seller_marketplace":   ["vânzător", "anunț", "produs de vânzare", "olx"],
        "buyer_marketplace":    ["cumpărător", "interesat de", "produs disponibil"],
        "elderly":              ["pensionar", "bătrân", "vârstnic"],
        "young_jobseeker":      ["job", "angajare", "muncă", "câștig rapid", "studente"],
        "investor":             ["investitor", "portofoliu", "randament", "dividende"],
        "romantic_target":      ["dragostea", "relație", "online dating", "singur"],
        "business_owner":       ["firma", "factură", "furnizor", "plată b2b"],
        "crypto_user":          ["wallet", "exchange", "defi", "nft", "token"]
    }

    OUTCOME_MAP = {
        "financial_loss":   ["pierdere", "furat", "transferat", "plătit", "golit"],
        "identity_theft":   ["date personale", "cnp", "buletin", "parolă furata"],
        "account_takeover": ["cont preluat", "blocat din cont", "parolă schimbată"],
        "malware":          ["virus", "ransomware", "trojan", "instalat aplicație"],
        "data_harvest":     ["date colectate", "formular completat", "phishing reușit"]
    }

    def __init__(self):
        import re
        self._re_lang = {
            k: [re.compile(p, re.IGNORECASE) for p in patterns]
            for k, patterns in self.LANGUAGE_MARKERS_MAP.items()
        }

    def compute(self, message: str, entry: dict = None) -> dict:
        """Calculează DNA complet al unui mesaj/intrări."""
        import re
        text = message.lower()

        # 1. Psihologie
        psychology = {
            psych: sum(1 for kw in kws if kw in text)
            for psych, kws in self.PSYCHOLOGY_MAP.items()
        }
        psychology_active = [k for k, v in psychology.items() if v > 0]

        # 2. Plăți
        payments = [m for m, kws in self.PAYMENT_MAP.items() if any(kw in text for kw in kws)]

        # 3. Markeri de limbaj
        lang_markers = {
            cat: [p.pattern for p in patterns if p.search(message)]
            for cat, patterns in self._re_lang.items()
        }
        lang_markers = {k: v for k, v in lang_markers.items() if v}

        # 4. Brand abuse
        brands = [b for b in self.BRAND_LIST if b in text]

        # 5. Target profil
        targets = [t for t, kws in self.TARGET_PROFILES.items() if any(kw in text for kw in kws)]

        # 6. Outcome prezis
        outcomes = [o for o, kws in self.OUTCOME_MAP.items() if any(kw in text for kw in kws)]

        # 7. Urgency score
        urgency_hits = sum(1 for kw in self.PSYCHOLOGY_MAP["urgency"] if kw in text)
        urgency_hits += message.count("!")
        urgency_level = min(5, urgency_hits)

        # 8. Technique (din entry dacă există)
        technique = ""
        if entry and entry.get("scam_dna", {}).get("technique"):
            technique = entry["scam_dna"]["technique"]

        # 9. Platform
        platform = entry.get("platform", "unknown") if entry else "unknown"

        # Fingerprint SHA-256 determinist
        components = (
            sorted(psychology_active) +
            sorted(payments) +
            sorted(brands) +
            sorted(targets) +
            [platform]
        )
        fingerprint = hashlib.sha256(
            ":".join(components).encode("utf-8")
        ).hexdigest()

        dna = {
            "technique":         technique or self._infer_technique(psychology_active, payments, brands),
            "psychology":        psychology_active,
            "psychology_scores": psychology,
            "platform":          platform,
            "payment_methods":   payments,
            "urgency_level":     urgency_level,
            "language_markers":  lang_markers,
            "target_profiles":   targets,
            "brand_abuse":       brands,
            "predicted_outcomes": outcomes,
            "fingerprint":       fingerprint,
            "dimensions_filled": sum([
                bool(technique), bool(psychology_active), bool(platform),
                bool(payments), bool(urgency_level), bool(lang_markers),
                bool(targets), bool(brands), bool(outcomes)
            ]),
            "computed_at":       datetime.now(timezone.utc).isoformat() + "Z"
        }

        if entry and entry.get("scam_dna", {}).get("typical_loss_ron"):
            dna["typical_loss_ron"] = entry["scam_dna"]["typical_loss_ron"]

        return dna

    def _infer_technique(self, psychology: list, payments: list, brands: list) -> str:
        """Inferează tehnica principală din componentele DNA."""
        if "authority" in psychology and any("banc" in b for b in brands):
            return "banking_impersonation_phishing"
        if "authority" in psychology and any(b in ["anaf", "politia romana"] for b in brands):
            return "government_impersonation_vishing"
        if "greed" in psychology and any("crypto" in p for p in payments):
            return "crypto_investment_fraud"
        if "romance" in psychology:
            return "romance_scam_advance_fee"
        if "urgency" in psychology and any(c in brands for c in ["fan courier", "dpd", "dhl"]):
            return "courier_smishing_phishing"
        if "scarcity" in psychology and payments:
            return "marketplace_advance_fee"
        return "social_engineering_fraud"


# ─── Similarity Engine ────────────────────────────────────────────────────────
class SimilarityEngine:
    """
    Calculează similaritatea între fraude și identifică campanii.
    Folosește combinație de Jaccard, cosinus și fingerprint matching.
    """

    def __init__(self, dataset: list):
        self.dataset = dataset
        self.dna_engine = ScamDNA()
        self._dnas = {}
        self._precompute()

    def _precompute(self):
        """Pre-calculează DNA pentru toate intrările."""
        for entry in self.dataset:
            eid = entry.get("id")
            if eid:
                msg = entry.get("ai_dataset", {}).get("message", "")
                self._dnas[eid] = self.dna_engine.compute(msg, entry)

    def similarity_score(self, id1: str, id2: str) -> dict:
        """Calculează similaritatea detaliată între două fraude."""
        if id1 not in self._dnas or id2 not in self._dnas:
            return {"error": "ID negăsit", "score": 0.0}

        d1, d2 = self._dnas[id1], self._dnas[id2]

        # Jaccard pe seturi
        def jaccard(s1: set, s2: set) -> float:
            u = s1 | s2
            return len(s1 & s2) / len(u) if u else 1.0

        psych_j  = jaccard(set(d1["psychology"]), set(d2["psychology"]))
        pay_j    = jaccard(set(d1["payment_methods"]), set(d2["payment_methods"]))
        brand_j  = jaccard(set(d1["brand_abuse"]), set(d2["brand_abuse"]))
        target_j = jaccard(set(d1["target_profiles"]), set(d2["target_profiles"]))
        platform_match = 1.0 if d1["platform"] == d2["platform"] else 0.0
        fingerprint_match = 1.0 if d1["fingerprint"] == d2["fingerprint"] else 0.0
        urgency_sim = 1.0 - abs(d1["urgency_level"] - d2["urgency_level"]) / 5.0

        # Score ponderat
        score = (
            psych_j        * 0.25 +
            pay_j          * 0.20 +
            brand_j        * 0.20 +
            target_j       * 0.10 +
            platform_match * 0.10 +
            urgency_sim    * 0.05 +
            fingerprint_match * 0.10
        )

        return {
            "id1": id1, "id2": id2,
            "score": round(score, 4),
            "interpretation": self._interpret(score),
            "components": {
                "psychology":  round(psych_j, 3),
                "payment":     round(pay_j, 3),
                "brand":       round(brand_j, 3),
                "target":      round(target_j, 3),
                "platform":    platform_match,
                "urgency":     round(urgency_sim, 3),
                "fingerprint": fingerprint_match
            },
            "shared": {
                "psychology":     list(set(d1["psychology"]) & set(d2["psychology"])),
                "payment_methods":list(set(d1["payment_methods"]) & set(d2["payment_methods"])),
                "brand_abuse":    list(set(d1["brand_abuse"]) & set(d2["brand_abuse"]))
            }
        }

    @staticmethod
    def _interpret(score: float) -> str:
        if score >= 0.90: return "🔴 Identice — aceeași campanie"
        if score >= 0.75: return "🟠 Foarte similare — variantă a aceleiași campanii"
        if score >= 0.55: return "🟡 Similare — tehnici comune"
        if score >= 0.35: return "🟢 Parțial similare"
        return "⚪ Diferite"

    def build_campaign_graph(self, threshold: float = 0.65) -> dict:
        """
        Construiește un graf de campanii pe baza similarității.
        Returnează noduri, muchii și grupuri de campanii detectate.
        """
        ids    = list(self._dnas.keys())
        edges  = []
        groups = defaultdict(set)

        for i, id1 in enumerate(ids):
            for id2 in ids[i+1:]:
                sim = self.similarity_score(id1, id2)
                if sim["score"] >= threshold:
                    edges.append({
                        "source": id1,
                        "target": id2,
                        "weight": sim["score"],
                        "label":  sim["interpretation"]
                    })

        # Componente conexe = campanii detectate
        parent = {i: i for i in ids}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        for e in edges:
            union(e["source"], e["target"])

        for eid in ids:
            groups[find(eid)].add(eid)

        campaigns = [
            {"campaign_id": f"AUTO-CAMP-{i+1:03d}", "members": sorted(list(members)), "size": len(members)}
            for i, (_, members) in enumerate(groups.items())
            if len(members) > 1
        ]

        nodes = []
        for entry in self.dataset:
            eid = entry.get("id")
            if eid and eid in self._dnas:
                dna = self._dnas[eid]
                nodes.append({
                    "id":       eid,
                    "title":    entry.get("title", ""),
                    "platform": entry.get("platform", ""),
                    "severity": entry.get("severity", ""),
                    "technique":dna.get("technique", ""),
                    "urgency":  dna["urgency_level"],
                    "brands":   dna["brand_abuse"][:3]
                })

        return {
            "nodes":              nodes,
            "edges":              edges,
            "detected_campaigns": campaigns,
            "total_edges":        len(edges),
            "threshold":          threshold,
            "generated_at":       datetime.now(timezone.utc).isoformat() + "Z"
        }

    def find_all_similar(self, entry_id: str, threshold: float = 0.4) -> list:
        """Returnează toate fraudele similare, sortate descrescător după scor."""
        results = []
        for eid in self._dnas:
            if eid == entry_id:
                continue
            sim = self.similarity_score(entry_id, eid)
            if sim["score"] >= threshold:
                results.append(sim)
        return sorted(results, key=lambda x: x["score"], reverse=True)


# ─── Scam Timeline ────────────────────────────────────────────────────────────
class ScamTimeline:
    """
    Reconstruiește și vizualizează evoluția istorică a unei fraude:
    - Prima apariție
    - Variante noi
    - Schimbări de tactică
    - Extinderea pe alte platforme
    """

    def __init__(self, entry: dict):
        self.entry   = entry
        self.timeline = self._build(entry)

    def _build(self, entry: dict) -> list:
        """Construiește timeline-ul din câmpurile intrării."""
        events = list(entry.get("timeline", []))

        # Adaugă eveniment creare dacă lipsește
        created = entry.get("created_at", "")
        if created and not any(e.get("event") == "Prima documentare" for e in events):
            events.insert(0, {
                "date":        created[:10],
                "event":       "Prima documentare",
                "description": f"Frauda '{entry.get('title', '')}' documentată pentru prima dată",
                "source":      None
            })

        # Adaugă ultima actualizare
        last_upd = entry.get("last_updated", "")
        if last_upd and last_upd[:10] != created[:10]:
            events.append({
                "date":        last_upd[:10],
                "event":       "Ultima actualizare",
                "description": "Intrarea a fost actualizată cu noi date",
                "source":      None
            })

        # Campaign events
        campaign = entry.get("campaign", {})
        if campaign.get("first_seen"):
            events.append({
                "date":        campaign["first_seen"],
                "event":       f"Prima activitate campanie: {campaign.get('campaign_name', '')}",
                "description": "Campania organizată detectată pentru prima dată",
                "source":      None
            })
        if campaign.get("last_seen"):
            events.append({
                "date":        campaign["last_seen"],
                "event":       "Ultima activitate campanie",
                "description": "Ultima activitate detectată a campaniei",
                "source":      None
            })

        return sorted(events, key=lambda x: x.get("date", ""))

    def render_text(self) -> str:
        """Redă timeline-ul în format text."""
        lines = [
            f"\n  🕐 TIMELINE: {self.entry.get('title', '')}",
            f"  {'─'*60}"
        ]
        for event in self.timeline:
            date   = event.get("date", "????-??-??")
            name   = event.get("event", "")
            desc   = event.get("description", "")
            source = event.get("source", "")
            lines.append(f"\n  📅 {date}")
            lines.append(f"     {name}")
            if desc:
                lines.append(f"     {desc[:80]}")
            if source:
                lines.append(f"     🔗 {source}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry.get("id"),
            "title":    self.entry.get("title"),
            "events":   self.timeline,
            "span_days": self._span_days()
        }

    def _span_days(self) -> int:
        try:
            dates = [datetime.fromisoformat(e["date"]) for e in self.timeline if e.get("date")]
            if len(dates) < 2:
                return 0
            return (max(dates) - min(dates)).days
        except Exception:
            return 0


# ─── Demo / Test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🧬 OFI Scam DNA Engine Demo\n")

    engine = ScamDNA()

    test_messages = [
        ("olx-0001", "Am plătit deja produsul. Accesați acest link Fan Courier pentru a confirma și a primi suma urgent."),
        ("sms-0001", "Coletul dvs nu a putut fi livrat. Achitați taxa de 2.99 RON: fan-curier-plata.ro"),
        ("crypto-0001", "Profit garantat 40% lunar! Investiție crypto fără risc. Contactează-mă pe WhatsApp acum!"),
        ("legit-0001", "Bună ziua, sunt interesat de produsul dvs. Mai este disponibil? Putem discuta prețul?"),
    ]

    dnas = {}
    for eid, msg in test_messages:
        dna = engine.compute(msg)
        dnas[eid] = dna
        print(f"[{eid}]")
        print(f"  Technique:    {dna['technique']}")
        print(f"  Psychology:   {', '.join(dna['psychology']) or '—'}")
        print(f"  Payments:     {', '.join(dna['payment_methods']) or '—'}")
        print(f"  Brands:       {', '.join(dna['brand_abuse']) or '—'}")
        print(f"  Urgency:      {'⚠' * dna['urgency_level']} ({dna['urgency_level']}/5)")
        print(f"  Fingerprint:  {dna['fingerprint'][:32]}...")
        print()

    # Similaritate OLX vs SMS
    sim_engine = SimilarityEngine([])
    sim_engine._dnas = dnas

    print("─"*60)
    print("📊 Similaritate olx-0001 vs sms-0001:")
    sim = sim_engine.similarity_score("olx-0001", "sms-0001")
    print(f"  Score: {sim['score']} — {sim['interpretation']}")
    print(f"  Psihologie comună: {sim['shared']['psychology']}")
    print(f"  Brand-uri comune:  {sim['shared']['brand_abuse']}")

    print("\n📊 Similaritate olx-0001 vs legit-0001:")
    sim2 = sim_engine.similarity_score("olx-0001", "legit-0001")
    print(f"  Score: {sim2['score']} — {sim2['interpretation']}")

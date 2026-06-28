#!/usr/bin/env python3
"""
OFI — Ontology Export (OWL / RDF / TTL)
==========================================
Convertește ontologia OFI din JSON (ofi-ontology.json) într-o ontologie OWL
reală, cu semantică formală (owl:Class, owl:DatatypeProperty,
owl:ObjectProperty) — nu doar un graf RDF generic.

Produce DOUĂ seturi de fișiere, cu scopuri diferite:
    1. TBox (schema ontologiei — clase și proprietăți):
         ofi-ontology.ttl   (Turtle — lizibil uman, pentru editare/review)
         ofi-ontology.owl   (RDF/XML — pentru import în Protégé / OpenCTI)
    2. ABox (instanțe — intrările reale din dataset, ca indivizi RDF):
         ofi-instances.rdf  (RDF/XML — fraudele concrete ca date legate)
         ofi-instances.ttl  (Turtle)

Utilizare:
    python3 ontology_export.py --ontology ofi-ontology.json --dataset scams.json --outdir exports/ontology
"""

import json
import argparse
import re
from pathlib import Path

from rdflib import Graph, Namespace, Literal, RDF, RDFS, OWL, XSD, URIRef
from rdflib.namespace import DCTERMS

OFI = Namespace("https://open-fraud-intelligence.github.io/ontology#")
OFI_DATA = Namespace("https://open-fraud-intelligence.github.io/data#")

# Tipul XSD potrivit per nume de proprietate (euristică simplă, dar corectă
# pentru câmpurile din ofi-ontology.json — extinde aici dacă apar tipuri noi).
XSD_TYPE_MAP = {
    "boolean": XSD.boolean,
    "number": XSD.double,
    "integer": XSD.integer,
    "string": XSD.string,
    "array": None,  # tratat separat (devine multi-valoare, nu un literal)
}


def slug_to_local_name(name: str) -> str:
    """ageGroup, lossAmountRon etc. — camelCase valid ca local name OWL."""
    parts = re.split(r"[^a-zA-Z0-9]+", name)
    parts = [p for p in parts if p]
    if not parts:
        return name
    return parts[0].lower() + "".join(p.capitalize() for p in parts[1:])


def build_tbox(ontology_json: dict) -> Graph:
    g = Graph()
    g.bind("ofi", OFI)
    g.bind("owl", OWL)
    g.bind("rdfs", RDFS)
    g.bind("dcterms", DCTERMS)

    ont_uri = URIRef(str(OFI).rstrip("#"))
    g.add((ont_uri, RDF.type, OWL.Ontology))
    g.add((ont_uri, RDFS.label, Literal("Open Fraud Intelligence Ontology", lang="en")))
    g.add((ont_uri, DCTERMS.description,
            Literal(ontology_json.get("description", ""), lang="ro")))
    g.add((ont_uri, OWL.versionInfo, Literal(ontology_json.get("version", "2.0.0"))))

    entities = ontology_json.get("entities", {})
    for entity_name, entity_def in entities.items():
        class_uri = OFI[entity_name]
        g.add((class_uri, RDF.type, OWL.Class))
        g.add((class_uri, RDFS.label, Literal(entity_name, lang="en")))
        if entity_def.get("description"):
            g.add((class_uri, RDFS.comment, Literal(entity_def["description"], lang="ro")))

        for prop_name, prop_def in entity_def.get("properties", {}).items():
            prop_local = slug_to_local_name(prop_name)
            prop_uri = OFI[f"{entity_name.lower()}_{prop_local}"]
            prop_type = prop_def.get("type", "string")
            if isinstance(prop_type, list):
                # Tip nullable, ex. ["string", "null"] — folosim primul tip non-null.
                prop_type = next((t for t in prop_type if t != "null"), "string")

            if prop_type == "array":
                # Proprietate multi-valoare -> owl:DatatypeProperty fără
                # restricție de cardinalitate (poate apărea de N ori).
                g.add((prop_uri, RDF.type, OWL.DatatypeProperty))
                items_type = (prop_def.get("items") or {}).get("type", "string")
                range_xsd = XSD_TYPE_MAP.get(items_type, XSD.string)
                if range_xsd:
                    g.add((prop_uri, RDFS.range, range_xsd))
            else:
                g.add((prop_uri, RDF.type, OWL.DatatypeProperty))
                range_xsd = XSD_TYPE_MAP.get(prop_type, XSD.string)
                if range_xsd:
                    g.add((prop_uri, RDFS.range, range_xsd))

            g.add((prop_uri, RDFS.domain, class_uri))
            g.add((prop_uri, RDFS.label, Literal(prop_name, lang="en")))
            if prop_def.get("enum"):
                g.add((prop_uri, RDFS.comment,
                        Literal(f"enum: {', '.join(map(str, prop_def['enum']))}", lang="en")))

    # Relații explicite (Actor exploatează Technique pe Platform, etc.)
    # Definite ca owl:ObjectProperty conectând clasele existente, dacă
    # ontologia JSON le declară separat sub "relationships".
    for rel in ontology_json.get("relationships", []):
        rel_uri = OFI[slug_to_local_name(rel.get("name", "relatedTo"))]
        g.add((rel_uri, RDF.type, OWL.ObjectProperty))
        if rel.get("domain"):
            g.add((rel_uri, RDFS.domain, OFI[rel["domain"]]))
        if rel.get("range"):
            g.add((rel_uri, RDFS.range, OFI[rel["range"]]))
        if rel.get("description"):
            g.add((rel_uri, RDFS.comment, Literal(rel["description"], lang="ro")))

    return g


# ─── ABox: instanțe reale din dataset, ca indivizi RDF ──────────────────────
def entry_to_rdf(g: Graph, entry: dict):
    entry_id = entry.get("id", entry.get("uuid"))
    subject = OFI_DATA[entry_id]

    g.add((subject, RDF.type, OFI.ScamReport))
    g.add((subject, RDFS.label, Literal(entry.get("title", ""), lang="ro")))
    g.add((subject, OFI["report_platform"], Literal(entry.get("platform", ""))))
    g.add((subject, OFI["report_severity"], Literal(entry.get("severity", ""))))
    g.add((subject, OFI["report_severityScore"], Literal(entry.get("severity_score", 0), datatype=XSD.double)))
    g.add((subject, OFI["report_country"], Literal(entry.get("country", ""))))
    g.add((subject, OFI["report_year"], Literal(entry.get("year", 0), datatype=XSD.integer)))
    g.add((subject, OFI["report_active"], Literal(entry.get("active", True), datatype=XSD.boolean)))
    g.add((subject, DCTERMS.description, Literal(entry.get("scenario", ""), lang="ro")))

    for tag in entry.get("tags", []):
        g.add((subject, OFI["report_tag"], Literal(tag)))

    # Tehnica -> instanță de clasă Technique, legată prin ObjectProperty
    dna = entry.get("scam_dna", {})
    if dna.get("technique"):
        tech_uri = OFI_DATA[f"technique-{entry_id}"]
        g.add((tech_uri, RDF.type, OFI.Technique))
        g.add((tech_uri, RDFS.label, Literal(dna["technique"], lang="en")))
        for mitre in entry.get("mitre_attack", []):
            g.add((tech_uri, OFI["technique_mitreAttackId"], Literal(mitre.get("technique_id", ""))))
        for capec in entry.get("capec", []):
            g.add((tech_uri, OFI["technique_capecId"], Literal(capec.get("capec_id", ""))))
        g.add((subject, OFI["exploitsTechnique"], tech_uri))

    # IOC-uri ca indivizi separați (utile pentru join-uri SPARQL pe domenii/wallet-uri)
    ioc = entry.get("ioc", {})
    for domain in ioc.get("domains", []):
        ioc_uri = OFI_DATA[f"domain-{domain}"]
        g.add((ioc_uri, RDF.type, OFI.Indicator))
        g.add((ioc_uri, OFI["indicator_kind"], Literal("domain")))
        g.add((ioc_uri, OFI["indicator_value"], Literal(domain)))
        g.add((subject, OFI["hasIndicator"], ioc_uri))
    for wallet in ioc.get("wallets", []):
        ioc_uri = OFI_DATA[f"wallet-{wallet}"]
        g.add((ioc_uri, RDF.type, OFI.Indicator))
        g.add((ioc_uri, OFI["indicator_kind"], Literal("wallet")))
        g.add((ioc_uri, OFI["indicator_value"], Literal(wallet)))
        g.add((subject, OFI["hasIndicator"], ioc_uri))

    # Campanie -> instanță de clasă Campaign, cu legătură memberOfCampaign
    camp = entry.get("campaign") or {}
    if camp.get("campaign_id"):
        camp_uri = OFI_DATA[camp["campaign_id"]]
        g.add((camp_uri, RDF.type, OFI.Campaign))
        g.add((camp_uri, RDFS.label, Literal(camp.get("campaign_name", ""), lang="ro")))
        g.add((subject, OFI["memberOfCampaign"], camp_uri))


def build_abox(entries: list) -> Graph:
    g = Graph()
    g.bind("ofi", OFI)
    g.bind("ofidata", OFI_DATA)
    g.bind("dcterms", DCTERMS)
    for entry in entries:
        entry_to_rdf(g, entry)
    return g


def main():
    parser = argparse.ArgumentParser(description="OFI Ontology Export (OWL/RDF/TTL)")
    parser.add_argument("--ontology", required=True, help="ofi-ontology.json")
    parser.add_argument("--dataset", required=True, help="scams.json (pentru ABox)")
    parser.add_argument("--outdir", default=".")
    args = parser.parse_args()

    ontology_json = json.loads(Path(args.ontology).read_text(encoding="utf-8"))
    entries = json.loads(Path(args.dataset).read_text(encoding="utf-8"))

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    tbox = build_tbox(ontology_json)
    abox = build_abox(entries)

    tbox.serialize(destination=outdir / "ofi-ontology.ttl", format="turtle")
    tbox.serialize(destination=outdir / "ofi-ontology.owl", format="xml")
    abox.serialize(destination=outdir / "ofi-instances.ttl", format="turtle")
    abox.serialize(destination=outdir / "ofi-instances.rdf", format="xml")

    print(f"✅ TBox (schemă): {len(tbox)} triple-uri")
    print(f"   → {outdir / 'ofi-ontology.ttl'}")
    print(f"   → {outdir / 'ofi-ontology.owl'}")
    print(f"✅ ABox (instanțe): {len(abox)} triple-uri, {len(entries)} intrări")
    print(f"   → {outdir / 'ofi-instances.ttl'}")
    print(f"   → {outdir / 'ofi-instances.rdf'}")


if __name__ == "__main__":
    main()

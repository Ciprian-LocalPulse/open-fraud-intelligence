# 🛡️ Open Fraud Intelligence (OFI)

**Bază de date deschisă și set de unelte pentru documentarea, analiza și prevenirea
fraudelor online care vizează utilizatorii din România.**

[![Schema](https://img.shields.io/badge/schema-v2.0.0-blue)]()
[![License: CC0-1.0](https://img.shields.io/badge/data-CC0--1.0-lightgrey)]()
[![Code: MIT](https://img.shields.io/badge/code-MIT-green)]()

---

## Ce este OFI

OFI documentează tipare de fraudă (nu victime individuale) într-un format
structurat, validabil automat, pregătit pentru:

- 🔎 **Căutare și filtrare** rapidă a fraudelor cunoscute (CLI, dashboard web)
- 🤖 **Antrenare/evaluare modele AI** de detectare a mesajelor scam (`ai_dataset`, RAG chunks)
- 🕸️ **Analiză de campanie** — grafuri de relații între fraude înrudite
- 🔗 **Interoperabilitate** cu unelte de threat intelligence (export STIX 2.1, MISP)
- 🧠 **Ontologie formală** (OWL/RDF/TTL) pentru integrare cu Protégé / OpenCTI

## Structura proiectului

```
ofi_sdk/              SDK Python (OFIClient, ScamDNAEngine)
schemas/               schema.json — schema JSON Schema a unei intrări
datasets/              scams_v2.json, multilingual_dataset.json, dataset_metadata.json
ontology/              ofi-ontology.json, severity-matrix.json (definiții sursă)
scripts/               fraud_cli.py, benchmark.py, misp_export.py, stix_export.py
tools/                 graph_export, dashboard_generator, ontology_export, rag_export, cluster_campaigns
exports/               output generat de tools/ (graf, dashboard, ontologie OWL, RAG, clustere)
test_data/             fixtures sintetice — NU fac parte din dataset-ul real
notebooks/             OFI_Analysis.ipynb — analiză exploratorie
web/                   index.html — dashboard static
.github/workflows/     ci.yml — validare schema + teste automate
```

## Instalare rapidă

```bash
git clone https://github.com/Ciprian-LocalPulse/open-fraud-intelligence.git
cd open-fraud-intelligence
pip install -r requirements.txt
export PYTHONPATH=.   # necesar ca scripts/ și tools/ să găsească pachetul ofi_sdk/
```

> ⚠️ Pachetul `ofi_sdk` **trebuie** să fie un director cu `__init__.py` la
> rădăcina repo-ului (nu un fișier `__init__.py` izolat) — altfel
> `from ofi_sdk import OFIClient` din `scripts/fraud_cli.py` nu va găsi modulul.

## Utilizare

```bash
# Statistici generale
python3 scripts/fraud_cli.py stats

# Caută fraude după platformă/severitate
python3 scripts/fraud_cli.py search --platform crypto --severity High

# Amprentă Scam DNA + fraude similare
python3 scripts/fraud_cli.py dna olx-0001
python3 scripts/fraud_cli.py similar olx-0001 --threshold 0.4

# Export interoperabil
python3 scripts/fraud_cli.py export --format stix --output bundle.json
python3 scripts/fraud_cli.py export --format misp --output misp.json
python3 scripts/fraud_cli.py export --format csv  --output datasets/scams.csv

# Unelte de analiză avansată
python3 tools/graph/graph_export.py        --input datasets/scams_v2.json --mode all --output exports/graph/ofi
python3 tools/dashboard/dashboard_generator.py --input datasets/scams_v2.json --outdir exports/dashboard
python3 tools/ontology/ontology_export.py  --ontology ontology/ofi-ontology.json --dataset datasets/scams_v2.json --outdir exports/ontology
python3 tools/rag/rag_export.py            --input datasets/scams_v2.json --output exports/rag/chunks.jsonl
python3 tools/clustering/cluster_campaigns.py --input datasets/scams_v2.json --threshold 0.35 --output exports/clustering/campaign_clusters.json
```

## Starea dataset-ului — transparență

Dataset-ul real (`datasets/scams_v2.json`) conține în prezent **7 intrări**
complet documentate, conforme schema v2. Acesta este în mod deliberat mic și
crește doar prin intrări verificabile — vezi `test_data/` pentru fixture-uri
sintetice folosite **doar** la testarea uneltelor, niciodată în dataset-ul
real. Pentru detalii despre sursele fiecărei intrări, vezi câmpul
`verification.official_source` din fiecare intrare.

**Contribuții cu fraude noi documentate, cu sursă oficială sau comunitară
verificabilă, sunt binevenite** — vezi [CONTRIBUTING.md](CONTRIBUTING.md).

## 💛 Susține proiectul

Open Fraud Intelligence este întreținut de un singur dezvoltator, pe cont
propriu, fără finanțare instituțională sau sponsorizare corporativă. Timpul
investit în documentarea fraudelor, întreținerea uneltelor și verificarea
surselor este, în prezent, susținut integral din resurse personale.

Dacă proiectul ți-a fost de folos — fie ca cercetător, jurnalist, dezvoltator
sau pur și simplu cineva interesat de protecția împotriva fraudelor online —
și vrei să contribui la continuarea lui, poți face o donație prin transfer
bancar (Wise), către titularul **Ciprian Stefan Plesca**:

<details>
<summary><strong>🇪🇺 Cont EUR</strong> (transfer SEPA local sau SWIFT internațional)</summary>

| | |
|---|---|
| Titular | Ciprian Stefan Plesca |
| IBAN | `BE83 9679 1975 8915` |
| SWIFT/BIC | `TRWIBEB1XXX` |
| Adresă bancă | Wise, Rue du Trône 100, 3rd floor, Brussels, 1050, Belgia |

</details>

<details>
<summary><strong>🇬🇧 Cont GBP</strong> (transfer local UK sau SWIFT internațional)</summary>

| | |
|---|---|
| Titular | Ciprian Stefan Plesca |
| Număr de cont | `92055372` |
| Sort code | `23-14-70` |
| IBAN | `GB68 TRWI 2314 7092 0553 72` |
| SWIFT/BIC | `TRWIGB2LXXX` |
| Adresă bancă | Wise Payments Limited, 1st Floor, Worship Square, 65 Clifton Street, London, EC2A 4JE, UK |

</details>

<details>
<summary><strong>🇺🇸 Cont USD</strong> (transfer local SUA sau SWIFT internațional)</summary>

| | |
|---|---|
| Titular | Ciprian Stefan Plesca |
| Tip cont | Checking |
| Număr de rutare (ACH/Wire) | `026073150` |
| Număr de cont | `8314225367` |
| SWIFT/BIC | `CMFGUS33` |
| Adresă bancă | Community Federal Savings Bank, 89-16 Jamaica Ave, Woodhaven, NY 11421, SUA |

</details>

<details>
<summary><strong>🇷🇴 Cont RON</strong> (transfer local din România)</summary>

| | |
|---|---|
| Titular | Ciprian Stefan Plesca |
| IBAN | `RO94 BREL 0005 6026 8420 0100` |

</details>

> 💡 Folosește contul din moneda în care trimiți, pentru a evita comisioane
> inutile de schimb valutar. Orice sumă contează și e folosită direct pentru
> timpul de cercetare, documentare și întreținere a acestui proiect.

## Licență

- **Date** (`datasets/`, `ontology/`): [CC0-1.0](LICENSE) — domeniu public.
- **Cod** (`ofi_sdk/`, `scripts/`, `tools/`): MIT — vezi [LICENSE](LICENSE).

## Documente conexe

- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — codul de conduită al comunității
- [GOVERNANCE.md](GOVERNANCE.md) — structura de guvernanță a proiectului
- [SECURITY.md](SECURITY.md) — politica de raportare a vulnerabilităților
- [LEGAL.md](LEGAL.md) — cadrul legal și politica de date
- [CONTRIBUTING.md](CONTRIBUTING.md) — cum contribui cu o intrare nouă

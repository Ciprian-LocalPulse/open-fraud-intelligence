# 🏛️ Guvernanță — Open Fraud Intelligence

## Structura proiectului

### Core Team (Maintainers)

Maintainer-ii sunt responsabili pentru:
- Revizuirea și aprobarea Pull Request-urilor
- Luarea deciziilor tehnice și editoriale
- Menținerea calității dataset-ului
- Moderarea comunității

**Devenirea maintainer:** Contribuitori activi timp de 6+ luni cu contribuții de calitate pot fi invitați de core team.

---

### Advisory Board

Consiliul consultativ include experți din:
- 🔐 **Cybersecurity** — cercetători CERT-RO, specialiști
- 🏛️ **Legal** — juriști specializați în GDPR și drept digital
- 📰 **Jurnalism** — jurnaliști de investigație specializați în fraude
- 🎓 **Cercetare academică** — universitari din domeniu
- 👮 **Law Enforcement** — reprezentanți DIICOT / Poliție (dacă acceptă)

---

### Community Contributors

Oricine poate contribui prin:
- Adăugarea de noi fraude documentate
- Raportarea duplicatelor sau intrărilor incorecte
- Îmbunătățirea documentației
- Traduceri
- Testarea SDK-ului și CLI-ului

---

## Procesul de decizie

### Decizii minore (un maintainer)
- Corecții typo, formatare
- Intrări noi care respectă complet schema
- Actualizări IOC

### Decizii majore (consens core team)
- Modificări de schemă
- Noi tipuri de export
- Parteneriate instituționale
- Politici ale proiectului

### Decizii critice (vot + Advisory Board)
- Schimbări de licență
- Retragerea unor intrări controversate
- Parteneri oficiali (CERT-RO, Poliție etc.)
- Modificări la politicile de date

---

## Politica de contribuții

### Ce acceptăm
✅ Fraude documentate cu minimum 2 surse verificabile  
✅ Variante noi ale fraudelor existente  
✅ Îmbunătățiri ale calității intrărilor existente  
✅ Traduceri verificate  
✅ Bugfix-uri în scripturi  

### Ce nu acceptăm
❌ Intrări fără sursă verificabilă  
❌ Date personale neanonimizate  
❌ Intrări despre evenimente disputate sau nesigure  
❌ Conținut care ar putea facilita fraude  
❌ Orice conținut care încalcă GDPR  

---

## ROADMAP 2025-2026

### Q3 2025 — Fundație
- [x] Schema v2 cu UUID și IOC
- [x] STIX 2.1 și MISP export
- [x] Python SDK și CLI
- [x] Ontologie Knowledge Graph
- [ ] Parteneriat CERT-RO (în negociere)
- [ ] 100+ intrări verificate

### Q4 2025 — Creștere
- [ ] Website GitHub Pages cu search și dashboard
- [ ] API REST public (read-only)
- [ ] Jupyter Notebook examples
- [ ] DOI pe Zenodo
- [ ] Articol academic (arxiv preprint)

### Q1 2026 — Maturitate
- [ ] 500+ intrări
- [ ] Multilingual dataset complet (7 limbi)
- [ ] Fine-tuning dataset dedicat
- [ ] Integrare OpenCTI
- [ ] SDK JavaScript și Go

### Q2 2026 — Extindere
- [ ] Extindere la nivel European (Bulgaria, Ungaria, Polonia)
- [ ] Knowledge Graph interactiv
- [ ] Scam Similarity Engine public
- [ ] Colaborare cu platforme (OLX, Facebook România)

---

## CHANGELOG

### v2.0.0 (2025-07-01)
- Schema completă cu toate cele 15 niveluri
- UUID, IOC, MITRE ATT&CK, CAPEC, STIX, MISP
- Scam DNA Fingerprinting
- Python SDK + CLI complet
- AI Benchmark Suite
- Ontologie / Knowledge Graph
- Multilingual dataset (7 limbi)

### v1.0.0 (2025-01-01)
- Lansare inițială
- 66 intrări documentate
- Structura de bază
- Validare JSON simplă

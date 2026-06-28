# Cum contribui la Open Fraud Intelligence

Mulțumim pentru interesul de a contribui! OFI crește doar prin intrări
**verificabile** — preferăm un dataset mic și corect unui dataset mare și
nesigur.

## 1. Adaugă o intrare nouă de fraudă

1. Verifică mai întâi în `datasets/scams_v2.json` că fraudă nu este deja
   documentată (caută după `platform`, `tags` sau termeni din `scenario`).
2. Copiază structura unei intrări existente și completează toate câmpurile
   obligatorii din `schemas/scam.schema.json`.
3. **Sursă obligatorie**: fiecare intrare nouă trebuie să aibă cel puțin una
   din următoarele:
   - un `verification.official_source` (alertă DNSC/CERT-RO, comunicat al
     Poliției Române, articol dintr-o sursă media credibilă care citează o
     instituție oficială), SAU
   - `verification.status: "community_verified"` cu o explicație în
     `confidence.source` despre cum a fost colectată și verificată dovada
     (capturi de ecran anonimizate, raportări multiple independente etc.)
4. **Nu inventa** numere precise (`evidence_count`, `reporter_count`) dacă
   nu provin dintr-o sursă reală — lasă câmpurile opționale necompletate
   în loc să pui o cifră plauzibilă, dar inventată.
5. Anonimizează complet orice victimă — fără nume, fără numere de telefon
   ale victimelor, fără capturi de ecran care identifică o persoană reală.
6. Validează local înainte de a trimite PR:
   ```bash
   python3 -c "
   import json, jsonschema
   schema = json.load(open('schemas/scam.schema.json'))
   data = json.load(open('datasets/scams_v2.json'))
   for e in data: jsonschema.validate(e, schema)
   print('OK')
   "
   ```

## 2. Adaugă o intrare în `test_data/` (fixture sintetică)

Dacă vrei să testezi o unealtă (clustering, graf) cu mai multe exemple
fictive, adaugă-le în `test_data/sample_scams_fixtures.json`, **niciodată**
în `datasets/scams_v2.json`. Documentează clar în PR că sunt sintetice.

## 3. Contribuții de cod

- `ofi_sdk/` — SDK-ul Python; păstrează compatibilitatea cu `scripts/fraud_cli.py`.
- `tools/` — unelte independente (graph, dashboard, ontology, rag, clustering);
  fiecare trebuie să ruleze standalone cu `--input`/`--output` ca argumente CLI.
- Rulează CI local înainte de PR (vezi `.github/workflows/ci.yml`).

## 4. Raportarea unei vulnerabilități de securitate

Nu folosi un issue public — vezi [SECURITY.md](SECURITY.md).

## 5. Codul de conduită

Toate contribuțiile trebuie să respecte [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

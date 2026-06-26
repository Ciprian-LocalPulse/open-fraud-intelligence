# 🤝 Ghid pentru Contribuitori

Mulțumim că vrei să contribui la **Open Fraud Intelligence**! Fiecare adăugare protejează un potențial utilizator de a pierde bani sau date personale.

---

## 📋 Reguli de bază

1. **Anonimizează** orice date personale (numere de telefon, nume reale, IBAN-uri)
2. **Nu include** link-uri active spre site-uri de phishing
3. **Verifică** că frauda nu e deja documentată (caută înainte de a adăuga)
4. **Fii obiectiv** — descrie ce s-a întâmplat, fără emoții
5. **Limba** — acceptăm intrări în română și engleză

---

## 🗂️ Cum adaugi o nouă fraudă

### Pasul 1 — Fork și clone

```bash
git clone https://github.com/yourusername/open-fraud-intelligence.git
cd open-fraud-intelligence
```

### Pasul 2 — Copiază template-ul

```bash
cp templates/scam-template.md scams/[platforma]/[nume-scurt-descriptiv].md
```

Exemplu:
```bash
cp templates/scam-template.md scams/olx/fals-cumparator-transport-olx.md
```

### Pasul 3 — Completează fișierul

Deschide fișierul și completează toate câmpurile din template.

### Pasul 4 — Adaugă în dataset

Adaugă și intrarea corespunzătoare în `datasets/scams.json`.

### Pasul 5 — Pull Request

```bash
git add .
git commit -m "feat: adaugă fals cumpărător OLX cu transport plătit"
git push origin main
```

Deschide un Pull Request cu titlul clar.

---

## 📸 Screenshot-uri

Dacă ai capturi de ecran:
- **Anonimizează** orice informație personală (blur / pixelate)
- Salvează în `/screenshots/[platforma]/`
- Format acceptat: `.png`, `.jpg`, `.webp`
- Maxim 5 MB per imagine

---

## ✅ Checklist înainte de Pull Request

- [ ] Datele personale sunt anonimizate
- [ ] Fișierul respectă structura din template
- [ ] Intrarea e adăugată și în `datasets/scams.json`
- [ ] Nu există duplicate
- [ ] Titlul PR-ului e descriptiv

---

## 🏷️ Convenții de denumire fișiere

Format: `[tip-frauda]-[detaliu-scurt].md`

Exemple:
- `fals-cumparator-transport.md`
- `phishing-bcr-2024.md`
- `job-remote-taxa-inscriere.md`
- `crypto-profit-garantat.md`

---

## 💬 Întrebări?

Deschide un **Issue** cu eticheta `question`.

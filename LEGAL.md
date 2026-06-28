# ⚖️ Cadrul Legal — Open Fraud Intelligence

## 1. Politica de Date (Data Policy)

### Ce date colectăm

Open Fraud Intelligence colectează **exclusiv** date despre tipare de fraudă, **nu date despre victime identificabile**. Specific:

| Tip date | Colectăm? | Condiții |
|----------|-----------|----------|
| Mesaje scam (anonimizate) | ✅ Da | Fără date personale ale victimei |
| IOC (domenii, URL-uri) | ✅ Da | Ale escrocilor, nu ale victimelor |
| Numere telefon escroci | ✅ Da | Raportate de victime, anonimizate |
| Capturi ecran | ✅ Da | Obligatoriu anonimizate |
| Date personale victime | ❌ Nu | Niciodată |
| IBAN sau date card reale | ❌ Nu | Niciodată |
| CNP sau serie buletin | ❌ Nu | Niciodată |
| Locație exactă victime | ❌ Nu | Niciodată |

### Cum procesăm datele

- Toate datele sunt **anonimizate** înainte de includere
- Datele se publică sub licență **CC0-1.0** (domeniu public)
- Nu stocăm metadate despre contribuitori dincolo de ce GitHub colectează
- Nu există baze de date cu utilizatori sau sisteme de tracking

---

## 2. Conformitate GDPR

Proiectul este proiectat pentru **conformitate GDPR by design**:

### Temeiul legal
Procesarea datelor se bazează pe **interes public legitim** (Art. 6(1)(f) GDPR) — protejarea cetățenilor împotriva fraudelor.

### Drepturi GDPR pentru contribuitori

| Drept | Implementare |
|-------|-------------|
| Dreptul la informare | Această politică |
| Dreptul de acces | Toate datele sunt publice |
| Dreptul la rectificare | Deschide un Issue sau PR |
| Dreptul la ștergere | Contact: privacy@ofi.example.org |
| Dreptul la portabilitate | Datele sunt în format JSON/CSV deschis |
| Dreptul la opoziție | Contact maintaineri |

### Responsabil cu protecția datelor (DPO)
*Rol în curs de desemnare — actualizează cu persoana reală*

---

## 3. Politica de Retenție a Datelor (Retention Policy)

| Tip date | Perioadă retenție | Motiv |
|----------|------------------|-------|
| Fraude active | Indefinit | Referință activă |
| Fraude inactive | 5 ani după ultima activitate | Referință istorică |
| False pozitive | Șterse imediat după confirmare | GDPR, acuratețe |
| IOC confirmate | 2 ani după ultima utilizare | Threat intelligence |
| Capturi ecran | Conform intrării asociate | Coerență |

---

## 4. Politica de False Pozitive (False Positive Policy)

Recunoaștem că un sistem de detecție a fraudelor poate identifica eronat entități legitime.

### Procesul de contestare

1. **Identificare** — O entitate crede că e documentată incorect ca fraudă
2. **Notificare** — Trimite email la `appeals@ofi.example.org` cu:
   - ID-ul intrării contestate
   - Dovezi că entitatea e legitimă
   - Contacte verificabile
3. **Investigație** — Core team investighează în maxim 14 zile
4. **Decizie** — Intrarea e corectată, etichetată `false_positive`, sau menținută cu explicație
5. **Notificare** — Contestatarul e informat despre decizie

### Garanții
- Nicio entitate nu e documentată pe baza unei singure raportări neconfirmate
- Toate intrările noi trec prin starea `pending` înainte de publicare
- Furnizorii de servicii legitimi au drept de răspuns

---

## 5. Etica Proiectului (Ethics Statement)

### Principii etice fundamentale

**1. Nu facilitez fraude**  
Datele din acest proiect nu trebuie folosite pentru a facilita sau îmbunătăți fraude. Orice utilizare în scopuri ilegale încalcă licența și va fi raportată autorităților.

**2. Protejarea victimelor**  
Victimele fraudelor sunt protejate prin anonimizarea strictă. Nu publicăm niciodată informații care ar putea identifica o victimă.

**3. Acuratețe și responsabilitate**  
Publicăm numai ce putem verifica rezonabil. Recunoaștem limitele cunoașterii noastre și marcăm clar intrările nesigure cu statusul `pending`.

**4. Accesibilitate**  
Datele sunt libere și deschise, pentru că frauda afectează disproportionat persoanele vulnerabile care nu au acces la resurse plătite de protecție.

**5. Colaborare, nu competiție**  
Colaborăm cu CERT-RO, Poliția Română, mass-media și alte proiecte similare din Europa. Securitatea colectivă e mai importantă decât recunoașterea individuală.

---

## 6. Politica de Moderare a Conținutului

### Criterii de respingere automată
- Intrări cu date personale neanonimizate
- Intrări duplicate fără valoare adăugată
- Intrări fără minimum 1 sursă verificabilă
- Conținut care insultă sau stigmatizează victimele

### Procesul de revizuire
1. PR deschis de contribuitor
2. Verificare automată (CI/CD)
3. Revizuire manuală maintainer (72 ore)
4. Aprobare sau feedback cu solicitare modificări
5. Merge sau respingere cu explicație

### Apeluri
Contribuitorii ale căror PR-uri sunt respinse pot apela la `governance@ofi.example.org`.

---

## 7. Clauza de exonerare de răspundere

Informațiile din **Open Fraud Intelligence** sunt furnizate **"as-is"** în scop educațional și de cercetare. Proiectul și contribuitorii săi:

- Nu garantează acuratețea completă a tuturor intrărilor
- Nu sunt răspunzători pentru decizii luate pe baza acestor date
- Recomandă verificarea independentă pentru utilizări cu miză ridicată
- Nu oferă servicii juridice sau de securitate profesionale

Utilizatorii sunt responsabili pentru conformitatea cu legile locale în utilizarea acestor date.

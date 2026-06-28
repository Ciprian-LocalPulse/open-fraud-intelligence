# 🔒 Politica de Securitate — Open Fraud Intelligence

## Versiuni suportate

| Versiune | Suport |
|----------|--------|
| 2.x      | ✅ Activ |
| 1.x      | ⚠️ Doar corecții critice |
| < 1.0    | ❌ Nesusținut |

---

## Raportarea vulnerabilităților

### Ce constituie o vulnerabilitate în contextul OFI

Deși suntem o bază de date, nu software executabil, vulnerabilitățile includ:

1. **Date personale neanonimizate** — dacă găsești numere de telefon reale, IBAN-uri, adrese sau alte date identificabile în dataset
2. **Intrări false pozitive** — fraude documentate incorect care ar putea afecta reputația unor entități legitime
3. **Script-uri cu probleme de securitate** — vulnerabilități în scripturile Python/CLI/SDK
4. **Injecție de date malițioase** — tentative de a introduce intrări care să faciliteze fraude reale
5. **Scurgeri de date despre victimele identificabile**

### Cum raportezi

**NU deschide un Issue public pentru vulnerabilități de securitate.**

În schimb:

1. **Email privat:** security@open-fraud-intelligence.org *(actualizează cu emailul real)*
2. **GitHub Security Advisories:** Folosește funcția "Report a vulnerability" din tab-ul Security al repo-ului
3. **PGP (opțional):** Cheie publică disponibilă la `/community/security.pgp`

### Ce să incluzi în raport

```
Tip vulnerabilitate: [date personale / script / date false / altele]
Locația: [fișier, linie, ID intrare]
Descriere: [ce ai găsit]
Impact potențial: [ce s-ar putea întâmpla]
Pași de reproducere: [cum ai găsit]
Sugestie de remediere: [opțional]
```

### Timeline de răspuns

| Etapă | Termen |
|-------|--------|
| Confirmare primire | 48 ore |
| Evaluare inițială | 7 zile |
| Plan de remediere | 14 zile |
| Remediere completă | 30 zile (sau mai rapid) |
| Publicare advisory | După remediere |

---

## Responsible Disclosure Policy

Îți mulțumim pentru că ne ajuți să menținem integritatea proiectului. Angajamentele noastre:

✅ Nu vom iniția acțiuni legale împotriva cercetătorilor care raportează în bună credință  
✅ Vom recunoaște public contribuția ta (dacă dorești) în Hall of Fame  
✅ Vom lucra cu tine pentru a înțelege și remedia problema rapid  
✅ Vom păstra confidențialitatea raportului până la remediere  

---

## Hall of Fame — Cercetători de securitate

*Mulțumim cercetătorilor care au contribuit la securitatea proiectului:*

| Cercetător | Tip contribuție | Data |
|------------|----------------|------|
| *(viitor)* | *(viitor)* | *(viitor)* |

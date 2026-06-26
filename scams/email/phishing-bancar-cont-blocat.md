# Phishing Bancar — Email Fals BCR / BRD / ING

> ⚠️ Toate datele personale din acest document sunt **fictive sau anonimizate**.

---

## 📋 Informații generale

| Câmp | Valoare |
|------|---------|
| **ID** | `email-0001` |
| **Platformă** | Email |
| **Severitate** | 🔴 Înalt |
| **Țară** | România |
| **Anul documentat** | 2022–2025 |
| **Activ** | Da |

---

## 📝 Descriere scurtă

Victima primește un email care imită banca sa. Este avertizată că contul va fi suspendat sau că există o activitate suspectă și e direcționată spre un site fals pentru „verificare".

---

## 🎭 Scenariul

Un email cu logo-ul băncii și design profesional anunță o problemă urgentă cu contul. Linkul din email duce la o pagină identică vizual cu internet banking-ul real, unde victima introduce credențialele și codul SMS.

---

## 📊 Pașii fraudei

1. **Email primit** — Design identic cu banca, ton urgent
2. **Pretextul** — „Activitate suspectă detectată" / „Contul va fi blocat în 24h"
3. **Link phishing** — Duce la o pagină clonă a băncii
4. **Furt credențiale** — Victima introduce user, parolă, PIN
5. **Furt cod SMS** — Pagina falsă cere și codul 2FA primit pe telefon
6. **Acces la cont** — Escrocii golesc contul în minute

---

## 🚩 Semnale de avertizare (Red Flags)

- [ ] Email-ul vine de pe un domeniu suspect (ex: `bcr-secure.ro`, `ing-romania.net`)
- [ ] URL-ul paginii nu e domeniul oficial al băncii
- [ ] Ton urgent: „Contul va fi blocat", „Acționați imediat"
- [ ] Ți se cere codul SMS primit — banca **niciodată** nu face asta prin email
- [ ] Certificatul SSL al site-ului arată un domeniu diferit

---

## 💬 Mesaje tipice

> *"Stimate client, am detectat o activitate neobișnuită pe contul dvs. Pentru a evita blocarea, vă rugăm să verificați identitatea în următoarele 24 de ore: [link fals]"*

> *"Contul dvs ING Home'Bank necesită reconfirmarea datelor. Accesați: [link fals]"*

---

## 🛡️ Cum te protejezi

1. **Nu accesa linkuri** din emailuri despre bănci — deschide site-ul direct în browser
2. Verifică adresa de email a expeditorului (nu doar numele afișat)
3. Băncile **nu cer niciodată** codul SMS prin email sau telefon
4. Activează **autentificarea în doi pași** oriunde e posibil
5. Sună banca direct la numărul de pe spatele cardului dacă ești nesigur
6. Raportează la CERT-RO și la bancă

---

## 🏷️ Tag-uri

`email` `phishing` `banking` `bcr` `brd` `ing` `raiffeisen` `credentiale`

---

## 🤖 Dataset AI

```json
{
  "id": "email-0001",
  "message": "Am detectat activitate neobișnuită pe contul dvs. Vă rugăm să accesați linkul de mai jos pentru a verifica și a evita blocarea contului.",
  "label": "scam",
  "platform": "email",
  "confidence": 0.98
}
```

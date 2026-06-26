# Fals Curier — SMS Phishing (Smishing)

> ⚠️ Toate datele personale din acest document sunt **fictive sau anonimizate**.

---

## 📋 Informații generale

| Câmp | Valoare |
|------|---------|
| **ID** | `sms-0001` |
| **Platformă** | SMS |
| **Severitate** | 🔴 Înalt |
| **Țară** | România |
| **Anul documentat** | 2023–2025 |
| **Activ** | Da |

---

## 📝 Descriere scurtă

Victima primește un SMS care imită un curier cunoscut (Fan Courier, DPD, DHL, Cargus) și e direcționată spre un site fals unde i se cer datele cardului pentru „taxa de livrare".

---

## 🎭 Scenariul

Un SMS sosește de la un număr necunoscut sau chiar de la un sender care pare a fi „FanCourier". Mesajul anunță că un colet nu a putut fi livrat și că victima trebuie să plătească o taxă mică (1–5 RON) pentru reprogramare. Link-ul din SMS duce la un site care imită perfect curierii reali.

---

## 📊 Pașii fraudei

1. **SMS primit** — *"Coletul dvs. nu a putut fi livrat. Plătiți 2 RON pentru reprogramare: [link]"*
2. **Site fals** — Designul imită Fan Courier / DHL / DPD cu logo și culori identice
3. **Formularul** — Victima introduce numărul cardului, data expirării, CVV
4. **Datele furate** — Sunt folosite imediat pentru tranzacții online frauduloase
5. **Cont golit** — Victima observă tranzacții neautorizate în aplicația bancară

---

## 🚩 Semnale de avertizare (Red Flags)

- [ ] Nu ai un colet așteptat
- [ ] URL-ul nu e domeniul oficial (ex: `fancourier-livrare.ro` în loc de `fancourier.ro`)
- [ ] Suma e mică (1–5 RON) — tactică de a părea nesemnificativă
- [ ] SMS vine de la număr obișnuit (+40xxx), nu de la un sender oficial
- [ ] Site-ul cere datele complete ale cardului pentru o taxă minimă

---

## 💬 Mesaje tipice

> *"FanCourier: Coletul dvs AWB#48291xx nu a putut fi livrat. Taxa de reprogramare: 2.49 RON. Accesati: [link fals]"*

> *"DPD Romania: Aveti un pachet in asteptare. Confirmati adresa si achitati 1.99 RON: [link fals]"*

---

## 🛡️ Cum te protejezi

1. **Nu accesa link-uri** din SMS-uri despre colete — du-te direct pe site-ul oficial
2. Verifică AWB-ul pe site-ul oficial al curierului
3. Curieri legitimi **nu cer date de card** prin SMS
4. Activează **notificările de tranzacție** pe aplicația băncii tale
5. Raportează SMS-ul la CERT-RO: [cert.ro](https://cert.ro)

---

## 🏷️ Tag-uri

`sms` `smishing` `phishing` `curier-fals` `card` `fancourier` `dpd` `dhl`

---

## 🤖 Dataset AI

```json
{
  "id": "sms-0001",
  "message": "Coletul dvs nu a putut fi livrat. Accesati linkul pentru a achita taxa de reprogramare de 2.99 RON.",
  "label": "scam",
  "platform": "sms",
  "confidence": 0.97
}
```

# Recuperare Cont WhatsApp — Cod de Verificare

> ⚠️ Toate datele personale din acest document sunt **fictive sau anonimizate**.

---

## 📋 Informații generale

| Câmp | Valoare |
|------|---------|
| **ID** | `whatsapp-0001` |
| **Platformă** | WhatsApp |
| **Severitate** | 🟠 Mediu |
| **Țară** | România |
| **Anul documentat** | 2023–2025 |
| **Activ** | Da |

---

## 📝 Descriere scurtă

Escrocul contactează victima pretinzând că e un prieten sau un cont compromis. Solicită un cod SMS primit „din greșeală" — codul este de fapt cel de autentificare WhatsApp al victimei.

---

## 🎭 Scenariul

Victima primește un SMS de la WhatsApp cu un cod de 6 cifre. Imediat după, un „prieten" de pe WhatsApp (cont deja compromis) o contactează și spune că i-a trimis din greșeală un cod pe numărul ei și are nevoie de el urgent.

---

## 📊 Pașii fraudei

1. **Escrocul inițiază** o sesiune nouă WhatsApp pe numărul victimei
2. **WhatsApp trimite** automat un SMS cu codul de verificare pe telefonul victimei
3. **Escrocul (din contul unui prieten compromis)** contactează victima: *"Mi-a venit un cod pe numărul tău, poți să mi-l dai?"*
4. **Victima, crezând că ajută un prieten**, trimite codul
5. **Escrocul preia** contul WhatsApp al victimei și repetă schema cu lista ei de contacte

---

## 🚩 Semnale de avertizare (Red Flags)

- [ ] Primești un SMS cu cod WhatsApp fără să fi cerut tu
- [ ] Imediat după, cineva îți cere acel cod
- [ ] Pretextul e că „a trimis din greșeală" codul pe numărul tău
- [ ] Urgență artificială: *"Am nevoie acum, repede"*
- [ ] Mesajele prietenului par ușor diferite ca stil față de normal

---

## 💬 Mesaje tipice

> *"Salut, îmi pare rău să te deranjez, dar mi-a venit din greșeală un cod SMS pe numărul tău. Poți să mi-l dai? E urgent."*

> *"E codul meu de WhatsApp, l-am trecut greșit. Ajutor!"*

---

## 🛡️ Cum te protejezi

1. **Nu da niciodată** coduri SMS primite de la WhatsApp, indiferent cine le cere
2. Sună prietenul pe telefon direct pentru a confirma dacă e el cu adevărat
3. Activează **verificarea în doi pași** în WhatsApp (Setări → Cont → Verificare în doi pași)
4. Dacă ți-ai pierdut contul, urmează ghidul oficial WhatsApp de recuperare

---

## 🏷️ Tag-uri

`whatsapp` `social-engineering` `cont-compromis` `cod-verificare` `account-takeover`

---

## 🤖 Dataset AI

```json
{
  "id": "whatsapp-0001",
  "message": "Salut, mi-a venit din greșeală un cod pe numărul tău. Poți să mi-l trimiți? E urgent.",
  "label": "scam",
  "platform": "whatsapp",
  "confidence": 0.96
}
```

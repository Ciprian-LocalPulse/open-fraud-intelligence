# Fals Cumpărător OLX — Transport Plătit în Avans

> ⚠️ Toate datele personale din acest document sunt **fictive sau anonimizate**.

---

## 📋 Informații generale

| Câmp | Valoare |
|------|---------|
| **ID** | `olx-0001` |
| **Platformă** | OLX / WhatsApp |
| **Severitate** | 🔴 Înalt |
| **Țară** | România |
| **Anul documentat** | 2024–2025 |
| **Activ** | Da |

---

## 📝 Descriere scurtă

Una dintre cele mai răspândite fraude pe OLX. Escrocul pretinde că e un cumpărător serios, mută conversația pe WhatsApp, trimite un link fals de plată și obține datele bancare ale vânzătorului.

---

## 🎭 Scenariul

Vânzătorul postează un anunț pe OLX. Este contactat de un utilizator care exprimă interes și dorește să cumpere rapid, cu livrare prin curier. Conversația este mutată pe WhatsApp. Escrocul trimite un link „de confirmare a plății" care imită platforme cunoscute (Fan Courier, OLX Pay, eMAG).

---

## 📊 Pașii fraudei

1. **Contactul inițial** — Escrocul scrie pe OLX: *"Sunt interesat, mai e disponibil?"*
2. **Mutarea pe WhatsApp** — Cere numărul de telefon pentru „detalii despre livrare"
3. **Pretextul plății** — Spune că a plătit deja și trimite un link pentru „confirmare"
4. **Link-ul fals** — Pagina imită un site legitim și cere IBAN, numărul cardului sau codul CVV
5. **Furtul datelor** — Odată introduse, datele sunt folosite imediat pentru tranzacții frauduloase

---

## 🚩 Semnale de avertizare (Red Flags)

- [ ] Mută conversația de pe OLX pe WhatsApp sau Telegram
- [ ] Insistă să plătească „prin curier" sau „prin transfer OLX"
- [ ] Trimite un link extern (nu de pe olx.ro)
- [ ] Urgentează tranzacția: *"Trebuie să confirm azi"*
- [ ] Număr de telefon cu prefix străin (+44, +39, +33 etc.)
- [ ] Ofertă prea bună, acceptă prețul fără negociere
- [ ] Mesajele sunt traduse stângaci din altă limbă

---

## 💬 Mesaje tipice folosite de escroci

> *"Salut, sunt interesat de produsul tău. Îl iau la prețul cerut. Poți să-mi dai numărul de WhatsApp?"*

> *"Am plătit deja prin Fan Courier. Accesează acest link pentru a confirma și a primi banii: [link fals]"*

> *"Nu îți fă griji, e sigur. E sistemul oficial OLX."*

---

## 🛡️ Cum te protejezi

1. **Nu muta conversația** în afara platformei OLX
2. **Nu accesa linkuri** primite prin WhatsApp legate de tranzacția OLX
3. **Verifică URL-ul** — paginile legitime OLX au domeniul `olx.ro`
4. **Nu introduce niciodată** datele cardului pe un link primit de la un cumpărător
5. **Vânzătorul primește banii** — nu trebuie să confirme nimic printr-un link
6. Raportează utilizatorul direct pe OLX

---

## 🏷️ Tag-uri

`marketplace` `olx` `phishing` `whatsapp` `social-engineering` `curier-fals`

---

## 🤖 Dataset AI

```json
{
  "id": "olx-0001",
  "message": "Am plătit deja produsul. Accesați acest link pentru a confirma și a primi suma.",
  "label": "scam",
  "platform": "olx",
  "confidence": 0.98
}
```

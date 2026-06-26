# Cont Instagram Compromis — Cerere de Împrumut

> ⚠️ Toate datele personale din acest document sunt **fictive sau anonimizate**.

---

## 📋 Informații generale

| Câmp | Valoare |
|------|---------|
| **ID** | `instagram-0001` |
| **Platformă** | Instagram / DM |
| **Severitate** | 🟠 Mediu |
| **Țară** | România |
| **Anul documentat** | 2024–2025 |
| **Activ** | Da |

---

## 📝 Descriere scurtă

Escrocul preia contul unui utilizator și trimite DM-uri prietenilor acestuia cerând un împrumut urgent cu o scuză plauzibilă.

---

## 🎭 Scenariul

Un prieten „îți scrie" pe Instagram că e în urgență — a rămas fără bani, i s-a blocat cardul în vacanță sau are o urgență medicală. Cere un transfer rapid. De fapt, contul prietenului a fost compromis.

---

## 📊 Pașii fraudei

1. **Contul e compromis** — Prin phishing sau parolă slabă
2. **DM-uri trimise** — Escrocul contactează toți urmăritorii/urmăriții
3. **Urgență fabricată** — „Sunt blocat în Grecia, îmi poți trimite 300 RON?"
4. **Transfer Revolut/PayPal** — Se cere transfer rapid pe un cont străin
5. **Dispariție** — Odată primit transferul, contul e abandonat

---

## 🚩 Semnale de avertizare (Red Flags)

- [ ] Mesaj neașteptat de la un prieten care nu îți scrie de obicei
- [ ] Urgență extremă și presiune temporală
- [ ] Cere transfer pe Revolut, Western Union sau crypto
- [ ] Nu vrea să vorbească la telefon sau video
- [ ] Stilul de scriere e diferit față de prietenul real

---

## 💬 Mesaje tipice

> *"Bună! Scuză că te deranjez, dar am o urgență. Mi s-a blocat cardul și am nevoie de 300 RON până mâine dimineață. Îți dau înapoi imediat ce ajung acasă. Poți?"*

---

## 🛡️ Cum te protejezi

1. **Sună prietenul** pe telefon înainte de a transfera orice sumă
2. Pune o **întrebare personală** pe care doar prietenul real ar ști-o
3. Nu transfera bani fără confirmare vocală sau video
4. Anunță prietenul că i-a fost compromis contul

---

## 🏷️ Tag-uri

`instagram` `cont-compromis` `imprumut-fals` `social-engineering` `account-takeover`

---

## 🤖 Dataset AI

```json
{
  "id": "instagram-0001",
  "message": "Buna! Scuza ca te deranjez dar am o urgenta. Mi s-a blocat cardul, poti sa imi trimiti 300 RON pe Revolut? Iti dau inapoi maine.",
  "label": "scam",
  "platform": "instagram",
  "confidence": 0.91
}
```

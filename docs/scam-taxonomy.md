# 🗂️ Taxonomia Completă a Fraudelor Online

Acest document definește sistemul de clasificare folosit în Open Fraud Intelligence.

---

## Schema principală

```
FRAUDĂ ONLINE
│
├── 1. FINANCIARĂ
│   ├── 1.1 Crypto & Investiții
│   │   ├── Profit garantat / scheme Ponzi
│   │   ├── Pump-and-dump
│   │   ├── Platforme de trading false
│   │   └── Pig butchering (relație → investiție)
│   │
│   ├── 1.2 Phishing Bancar
│   │   ├── Email (clone bancă)
│   │   ├── SMS (smishing)
│   │   └── Telefon (vishing)
│   │
│   └── 1.3 Carduri & Transferuri
│       ├── Clonare card (skimming)
│       ├── Furt date card online
│       └── Transfer bancar fraudulos
│
├── 2. MARKETPLACE
│   ├── 2.1 Vânzare (vânzătorul e escrocul)
│   │   ├── Produs inexistent
│   │   ├── Produs diferit față de anunț
│   │   └── Calitate inferioară / contrafăcut
│   │
│   └── 2.2 Cumpărare (cumpărătorul e escrocul)
│       ├── Fals cumpărător cu transport plătit
│       ├── Link phishing de plată
│       └── Cec / ordin de plată fals
│
├── 3. SOCIAL ENGINEERING
│   ├── 3.1 Impersonare
│   │   ├── Impersonare bancă / ANAF / poliție
│   │   ├── Impersonare prieten / familie
│   │   └── Impersonare brand / magazin
│   │
│   ├── 3.2 Account Takeover
│   │   ├── Furt cod verificare WhatsApp
│   │   ├── Phishing credențiale social media
│   │   └── SIM swapping
│   │
│   └── 3.3 Inginerie socială directă
│       ├── Vishing (apel telefonic)
│       ├── Pretexting (scenariu fabricat)
│       └── Baiting (USB, link curios)
│
├── 4. ROMANTICĂ / EMOȚIONALĂ
│   ├── 4.1 Romance Scam
│   │   ├── Relație online → cerere de bani
│   │   └── Pig butchering (crypto + relație)
│   │
│   └── 4.2 Sextortion
│       ├── Material compromițător real
│       └── Amenințare fără material real
│
├── 5. LOCURI DE MUNCĂ
│   ├── 5.1 Taxe de recrutare
│   │   ├── Taxă de formare / acreditare
│   │   └── Taxă pentru echipament
│   │
│   └── 5.2 Traficare prin oferte false
│       ├── Ofertă în străinătate cu condiții false
│       └── Muncă forțată / sclavie modernă
│
├── 6. COMERȚ ELECTRONIC
│   ├── 6.1 Magazine false
│   │   ├── Site clonă brand real
│   │   └── Site independent fabricat
│   │
│   └── 6.2 Livrare falsă
│       ├── SMS / email fals curier
│       └── AWB fals / urmărire falsă
│
└── 7. ALTELE
    ├── 7.1 Loterie / Premii false
    ├── 7.2 Asistență tehnică falsă (tech support scam)
    ├── 7.3 Urgență medicală / accident fabricat
    └── 7.4 Cerșetorie organizată online
```

---

## Niveluri de severitate

| Nivel | Simbol | Criteriu |
|-------|--------|----------|
| **Înalt** | 🔴 | Pierdere financiară directă sau furt de identitate |
| **Mediu** | 🟠 | Pierdere financiară posibilă sau date personale expuse |
| **Scăzut** | 🟡 | Hărțuire, spam sau risc indirect |

---

## Vectori de atac principali

| Vector | Cod | Descriere |
|--------|-----|-----------|
| Email | `email` | Phishing, BEC, atașamente malițioase |
| SMS | `sms` | Smishing, linkuri scurte |
| Telefon | `telefon` | Vishing, impersonare |
| WhatsApp | `whatsapp` | Social engineering, furt cont |
| Facebook | `facebook` | Giveaway fals, marketplace, ads |
| Instagram | `instagram` | Cont compromis, influencer fals |
| Telegram | `telegram` | Grupuri crypto, canale false |
| OLX | `olx` | Fals cumpărător/vânzător |
| Crypto | `crypto` | Platforme false, NFT scam |

---

## Etichete pentru dataset AI

```
scam        — mesaj confirmat ca fraudulos
legitimate  — mesaj legitim (pentru antrenare echilibrată)
suspicious  — posibil fraudulos, necesită verificare
```

---

*Ultima actualizare: 2025 | Propune modificări prin Issue sau PR*

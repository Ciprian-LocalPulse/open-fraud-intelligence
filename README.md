# 🛡️ Open Fraud Intelligence

> Baza de date open-source pentru fraude și înșelătorii online din România

[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](http://creativecommons.org/publicdomain/zero/1.0/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![GitHub Stars](https://img.shields.io/github/stars/yourusername/open-fraud-intelligence?style=social)](https://github.com/yourusername/open-fraud-intelligence)

---

## 📖 Despre proiect

**Open Fraud Intelligence** este o bază de cunoștințe comunitară, actualizată constant, despre metodele de fraudă online folosite în România. Scopul este să ofere cetățenilor, cercetătorilor, jurnaliștilor și dezvoltatorilor un catalog structurat și accesibil cu tipare de înșelătorie.

> "Dacă ai primit un mesaj suspect, probabil e deja documentat aici."

---

## ⚡ Top 10 fraude frecvente în 2025

| # | Tip | Platformă | Severitate |
|---|-----|-----------|------------|
| 1 | Fals curier (Fan Courier / DPD) | SMS / Email | 🔴 Înalt |
| 2 | Fals cumpărător OLX | WhatsApp | 🔴 Înalt |
| 3 | Investiții crypto garantate | Telegram / Instagram | 🔴 Înalt |
| 4 | Job remote cu taxă de înscriere | Email / Facebook | 🟠 Mediu |
| 5 | Recuperare cont WhatsApp | WhatsApp | 🟠 Mediu |
| 6 | Fals reprezentant bancă | Telefon | 🔴 Înalt |
| 7 | Câștig fals la loterie / giveaway | Facebook / Instagram | 🟡 Scăzut |
| 8 | Fals magazin online | Facebook Ads | 🔴 Înalt |
| 9 | Înșelătorie romantică (Romance Scam) | Facebook / Telegram | 🔴 Înalt |
| 10 | Phishing BRD / BCR / ING | Email | 🔴 Înalt |

---

## 📂 Structura repository-ului

```
open-fraud-intelligence/
│
├── scams/
│   ├── olx/              # Fraude pe platforme de anunțuri
│   ├── whatsapp/         # Înșelătorii via WhatsApp
│   ├── facebook/         # Fraude pe Facebook / Messenger
│   ├── instagram/        # Fraude pe Instagram
│   ├── telegram/         # Fraude pe Telegram
│   ├── email/            # Phishing prin email
│   ├── sms/              # Fraude prin SMS
│   ├── crypto/           # Scheme crypto / investiții false
│   ├── fake-jobs/        # Oferte de muncă false
│   └── fake-shops/       # Magazine online false
│
├── datasets/
│   ├── scams.json        # Toate intrările în format JSON
│   └── scams.csv         # Toate intrările în format CSV
│
├── screenshots/          # Capturi de ecran cu exemple reale (anonimizate)
│
├── templates/
│   └── scam-template.md  # Template pentru contribuitori
│
├── docs/
│   ├── red-flags.md      # Semne generale de avertizare
│   ├── reporting-guide.md # Cum raportezi o fraudă autorităților
│   └── scam-taxonomy.md  # Taxonomia completă a fraudelor
│
└── CONTRIBUTING.md       # Ghid pentru contribuitori
```

---

## 🔍 Taxonomia fraudelor

```
Fraudă
│
├── Financiară
│   ├── Crypto & Investiții false
│   ├── Phishing bancar
│   └── Carduri / Transferuri bancare
│
├── Marketplace
│   ├── OLX / Storia / Publi24
│   ├── Facebook Marketplace
│   └── Vinted / eBay
│
├── Social Engineering
│   ├── WhatsApp (recuperare cont, coduri)
│   ├── SMS (smishing)
│   └── Telefon (vishing)
│
├── Romantică / Emoțională
│   ├── Romance Scam
│   └── Sextortion
│
├── Locuri de Muncă
│   ├── Job-uri false cu avans
│   └── Traficare prin oferte false
│
└── Comerț Electronic
    ├── Magazine false
    └── Livrare falsă
```

---

## 🤖 Componenta AI / Dataset

Fiecare intrare include etichete pentru antrenarea modelelor de detecție:

```json
{
  "message": "Bună ziua, am plătit produsul. Accesați acest link pentru confirmare.",
  "label": "scam",
  "confidence": 0.97
}
```

Dataset-ul complet este disponibil în [`datasets/scams.json`](datasets/scams.json) și poate fi folosit pentru:
- Antrenarea modelelor de clasificare text
- Cercetare academică în cybersecurity
- Filtre automate de mesaje

---

## 🤝 Cum contribui

1. **Fork** acest repository
2. Copiază [`templates/scam-template.md`](templates/scam-template.md)
3. Completează cu detaliile fraudei
4. Deschide un **Pull Request**

Citește [CONTRIBUTING.md](CONTRIBUTING.md) pentru detalii complete.

---

## 📢 Raportează o fraudă autorităților

| Autoritate | Contact |
|------------|---------|
| DIICOT | [diicot.ro](https://www.diicot.ro) |
| ANAF (fraude fiscale) | [anaf.ro](https://www.anaf.ro) |
| Poliția Română | 112 sau [politiaromana.ro](https://www.politiaromana.ro) |
| CERT-RO | [cert.ro](https://www.cert.ro) |
| ANPC (magazine false) | [anpc.ro](https://www.anpc.ro) |

---

## 📜 Licență

Acest proiect este distribuit sub licența **Creative Commons CC0 1.0 Universal** — complet liber pentru orice utilizare, inclusiv comercială.

---

## ⭐ Dacă acest proiect te-a ajutat, dă-i o stea!

> Ajuți alți oameni să găsească resursa mai ușor.

Open Fraud Intelligence-Research Support

Acest depozit este administrat independent, în timpul liber. Dacă v-a economisit ore întregi de căutare, v-a învățat ceva sau pur și simplu doriți să susțineți cercetarea independentă cu acces liber și să păstrați această listă gratuită pentru toată lumea, puteți contribui direct prin oricare dintre canalele de mai jos.
### 🇪🇺 European Payment — SEPA / EUR <sub>· CEA · AES-256</sub>

| Field | Detail |
|---|---|
| Recipient | Ciprian Stefan Plesca |
| IBAN | `BE83 9679 1975 8915` |
| SWIFT / BIC | `TRWIBEB1XXX` |
| Bank | Wise, Rue du Trône 100, 3rd floor, Brussels, 1050, Belgium |

</td></tr>
<tr><td colspan="2">

### 🇬🇧 United Kingdom Payment — Faster Payments / GBP <sub>· AIA · SHA-3</sub>

| Field | Detail |
|---|---|
| Recipient | Ciprian Stefan Plesca |
| Account number | `92055372` |
| Sort code | `23-14-70` |
| IBAN | `GB68 TRWI 2314 7092 0553 72` |
| SWIFT / BIC | `TRWIGB2LXXX` |
| Bank | Wise Payments Limited, 1st Floor, Worship Square, 65 Clifton Street, London, EC2A 4JE, United Kingdom |

</td></tr>
<tr><td colspan="2">

### 🇺🇸 United States Payment — ACH / Wire / USD <sub>· ICA · RSA-4096</sub>

| Field | Detail |
|---|---|
| Recipient | Ciprian Stefan Plesca |
| Account type | Checking |
| Routing number | `026073150` |
| Account number | `8314225367` |
| SWIFT / BIC | `CMFGUS33` |
| Bank | Community Federal Savings Bank, 89-16 Jamaica Ave, Woodhaven, NY, 11421, United States |

</td></tr>
</table>

<div align="center">

| ₿ Bitcoin (BTC) | Ξ Ethereum (ETH) | PP PayPal |
|---|---|---|
| `bc1qf3yy0w8z37rwavxpu38wem3yffpanw7wzj32qj` | `0x27d9a6a5b8507e6031bb044319410da96222d402` | [paypal.me/agentflowenterprise](https://paypal.me/agentflowenterprise) |

</div>
# 🔍 AI Phishing Inspector

> **An AI-powered phishing detection engine with MITRE ATT&CK mapping, live website fingerprinting, and a full Streamlit UI.**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-ff4b4b?style=flat-square&logo=streamlit)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange?style=flat-square&logo=scikit-learn)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📌 Overview

The **AI Phishing Inspector** is a dual-layer threat detection system that combines machine learning models with real-time heuristic analysis to identify phishing emails and URLs. Every detected signal is mapped directly to the [MITRE ATT&CK framework](https://attack.mitre.org/), giving security-aware outputs beyond a simple safe/unsafe verdict.

The system runs in two modes:
- **CLI** — lightweight terminal scanner for quick checks
- **Streamlit UI** — full-featured web dashboard with 5 functional tabs

---

## ✨ Features

### 🤖 AI Detection Engine
- **Email body analysis** — TF-IDF vectorized text fed into a Random Forest classifier trained on a labeled phishing email dataset
- **URL analysis** — separate ML model trained on URL patterns and lexical features
- **Heuristic fallback** — regex-based signal matching when `.pkl` model files are not present (no setup required to test)
- **Combined risk scoring** — worst-case scoring across email and URL channels with configurable thresholds

### 🌐 Website Fingerprinting (Live Analysis)
Fetches the actual webpage and performs four deep-inspection checks:

| Check | What It Detects | MITRE Technique |
|---|---|---|
| 🖼️ **Favicon Hotlink** | Favicon loaded from a different (legitimate) domain to fake authenticity | T1036.005 |
| 🔗 **Anchor URL Ratio** | >80% of page links point to external domains — credential harvester shell | T1185 |
| 📋 **Insecure Form** | Password form submitting over HTTP (credentials sent in plaintext) | T1056.003 |
| 📅 **Domain Age** | Domain registered < 30 days ago via WHOIS lookup | T1583.001 |

### 🗺️ MITRE ATT&CK Mapping
Every signal — from email keywords to URL patterns to fingerprint results — is mapped to a specific ATT&CK technique with tactic, technique ID, name, and description. Covered tactics:

- Initial Access · Execution · Defense Evasion
- Credential Access · Collection · Impact

### 🖥️ Streamlit UI Tabs
1. **🔍 SCAN** — Paste email + URL, get risk score, evidence chips, fingerprint summary, MITRE hits
2. **🌐 FINGERPRINT** — Standalone live website analyser with per-check MITRE mapping
3. **🗺️ MITRE MAP** — Full ATT&CK coverage browser with source tags (📧 🔗 🌐)
4. **📋 HISTORY** — Session scan log with metrics and CSV export
5. **📦 BULK SCAN** — Scan multiple URLs at once, download results as CSV

---

## 🗂️ Project Structure

```
AI-Phishing-Detection-engine/
│
├── app.py                   # Streamlit UI — full dashboard (5 tabs)
├── train_email_model.py     # Training script for email classifier (Kaggle)
│
├── email_model.pkl          # Trained email Random Forest model  [generated]
├── email_vec.pkl            # TF-IDF vectorizer for emails       [generated]
├── url_model.pkl            # Trained URL classifier             [generated]
├── url_vec.pkl              # TF-IDF vectorizer for URLs         [generated]
│
├── requirements.txt         # All Python dependencies
└── README.md
```

> **Note:** The `.pkl` files are not included in the repository. Follow the [Training](#-training-the-models) section to generate them. The app runs in **heuristic demo mode** without them.

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/dilesh591/AI-Phishing-Detection-engine-.git
cd AI-Phishing-Detection-engine-
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Streamlit app
```bash
streamlit run app.py
```

The app will open at `http://localhost:8501`

---

## 📦 Requirements

```txt
streamlit>=1.30.0
scikit-learn>=1.3.0
pandas>=2.0.0
joblib>=1.3.0
requests>=2.31.0
beautifulsoup4>=4.12.0
python-whois>=0.8.0
numpy>=1.24.0
```

Install all at once:
```bash
pip install streamlit scikit-learn pandas joblib requests beautifulsoup4 python-whois numpy
```

> **Minimum required** (app runs in heuristic mode without fingerprint deps):
> ```bash
> pip install streamlit pandas scikit-learn joblib
> ```

---

## 🧠 Training the Models

### Email Model
The email classifier was trained on the [Phishing Email dataset from Kaggle](https://www.kaggle.com/datasets/itzdilesh/pishing-mails).

Run `train_email_model.py` in a Kaggle notebook or locally:

```python
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Load dataset
df = pd.read_csv('Phishing_Email.csv')
df = df.dropna(subset=['Email Text'])

X_raw = df['Email Text']
y     = df['Email Type']

# Check class balance
print(df['Email Type'].value_counts())

# Vectorize — bigrams catch phrases like "click here", "verify account"
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000, ngram_range=(1, 2))
X = vectorizer.fit_transform(X_raw)

# Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, n_jobs=-1, class_weight='balanced', random_state=42)
model.fit(X_train, y_train)

# Evaluate
print(classification_report(y_test, model.predict(X_test)))
print(f"Accuracy: {model.score(X_test, y_test):.2%}")

# Save
joblib.dump(model,      'email_model.pkl')
joblib.dump(vectorizer, 'email_vec.pkl')
```

Place `email_model.pkl` and `email_vec.pkl` in the same folder as `app.py`.

### URL Model
A separate URL classifier should be trained on a phishing URL dataset (e.g. from [PhishTank](https://www.phishtank.com/) or [UCI Phishing URLs](https://archive.ics.uci.edu/dataset/967/phishtank+dataset)). Follow the same pattern — TF-IDF vectorize the URL strings + extracted features, train a classifier, save as `url_model.pkl` + `url_vec.pkl`.

---

## 🚀 Usage

### Streamlit UI

```bash
streamlit run app.py
```

1. Open the **SCAN** tab
2. Paste email text and/or a URL
3. Optionally enable **🌐 Live Website Fingerprint Analysis**
4. Press **⚡ SCAN THREAT**
5. Review: risk score, evidence signals, fingerprint results, MITRE ATT&CK hits

### CLI Version
The core `scan()` function can be used directly in Python:

```python
from app import scan

result = scan(
    email_text="Dear Customer, your account has been suspended. Click here immediately.",
    url="http://secure-login.bank-verify.xyz/confirm",
    run_fp=False
)

print(f"Risk: {result['risk']:.0%}")
print(f"Verdict: {result['verdict']}")
print(f"MITRE hits: {len(result['mitre'])}")
for hit in result['mitre']:
    print(f"  {hit['tactic']} — {hit['tid']} {hit['name']}")
```

### Bulk URL Scanning
Use the **📦 BULK SCAN** tab in the UI, or call `scan()` in a loop:

```python
urls = ["https://google.com", "http://free-prize-winner.xyz", ...]
for url in urls:
    r = scan("", url)
    print(f"{url[:50]:<50} {r['verdict_cls'].upper():6} {r['risk']:.0%}")
```

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name | Signal Source |
|---|---|---|---|
| Initial Access | T1566 | Phishing | 📧 Email |
| Initial Access | T1583.001 | Domains | 🌐 Fingerprint |
| Execution | T1204.001 | Malicious Link | 📧 Email |
| Execution | T1204.002 | Malicious File | 📧 Email |
| Defense Evasion | T1036 | Masquerading | 🔗 URL |
| Defense Evasion | T1036.005 | Match Legitimate Name | 🔗 URL / 🌐 Fingerprint |
| Defense Evasion | T1027 | Obfuscated Files/Information | 🔗 URL |
| Defense Evasion | T1040 | Network Sniffing | 🔗 URL |
| Defense Evasion | T1564 | Hide Artifacts | 📧 Email |
| Credential Access | T1056.003 | Web Portal Capture | 📧 Email / 🌐 Fingerprint |
| Credential Access | T1078 | Valid Accounts | 📧 Email |
| Credential Access | T1110 | Brute Force / Harvesting | 📧 Email |
| Credential Access | T1556 | Modify Authentication Process | 🔗 URL |
| Collection | T1185 | Browser Session Hijacking | 📧 Email / 🌐 Fingerprint |
| Impact | T1531 | Account Access Removal | 📧 Email |
| Impact | T1657 | Financial Theft | 📧 Email |

> Signal sources: 📧 Email body · 🔗 URL pattern · 🌐 Live website fingerprint

---

## 📊 How Risk Scoring Works

```
Final Risk = max(email_score, url_score)

If fingerprint is enabled:
  url_score += (failed_checks × 0.18) + (warned_checks × 0.07)
  url_score = min(url_score, 0.99)

Verdict thresholds (configurable in sidebar):
  ≥ 0.75  →  🚨 HIGH RISK — Likely Phishing
  ≥ 0.45  →  ⚠️  MEDIUM RISK — Suspicious
  < 0.45  →  ✅  SAFE — Looks Legitimate
```

When AI models are not loaded, heuristic scoring is used:
- Email: each regex signal match adds ~14% to score
- URL: each regex signal match adds ~22% to score

---

## 🔧 Configuration

Adjust thresholds in the **sidebar** of the Streamlit app:

| Setting | Default | Description |
|---|---|---|
| High Risk threshold | 0.75 | Score above which verdict = HIGH RISK |
| Medium Risk threshold | 0.45 | Score above which verdict = MEDIUM RISK |

---

## 🛡️ Disclaimer

This tool is built for **educational and research purposes**. It is not a replacement for enterprise-grade email security solutions. Do not rely solely on this tool in a production security environment.

---

## 🤝 Contributing

Contributions are welcome! Ideas for improvement:

- [ ] Train and include a URL model
- [ ] Add browser extension frontend
- [ ] Integrate VirusTotal API for URL reputation lookup
- [ ] Add DKIM/SPF/DMARC email header analysis
- [ ] Export scan reports as PDF
- [ ] Add Docker support for easy deployment

To contribute:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Dilesh** — [@dilesh591](https://github.com/dilesh591)

---

*Built with Python · Streamlit · scikit-learn · MITRE ATT&CK*

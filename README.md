# AI Phishing Tool

A phishing detection project with multiple interfaces:

- `app.py` - Streamlit-based phishing inspector UI
- `index.html` - HTML + Tailwind CSS frontend (client-side heuristics)
- `cli_ver.py` - command-line interface version

## Features

- Email phishing signal detection
- URL phishing signal detection
- Risk scoring and verdicts (High / Medium / Low)
- IOC extraction (URLs, domains, emails, IPs)
- Scan history and export options
- Bulk URL scanning (available in UI variants)

## Project Files

- `app.py`: Main Streamlit frontend with advanced features
- `index.html`: Static Tailwind frontend (no backend required)
- `cli_ver.py`: Terminal scanner flow
- `email_model.pkl`, `email_vec.pkl`: Email model + vectorizer
- `url_model.pkl`: URL model file

## Requirements

Python 3.9+ recommended.

Install basic dependencies:

```bash
pip install streamlit joblib pandas numpy
```

Optional dependencies for website fingerprint checks in Streamlit:

```bash
pip install requests beautifulsoup4 python-whois
```

## Run Options

### 1) Streamlit App

```bash
streamlit run app.py
```

Default URL:

- <http://localhost:8501>

### 2) HTML + Tailwind Frontend

Serve the project folder as static files:

```bash
python -m http.server 8080
```

Open:

- <http://localhost:8080/index.html>

### 3) CLI Version

```bash
python cli_ver.py
```

## Notes

- If model files are missing, the Streamlit app can still run using heuristic logic.
- The HTML frontend currently uses browser-side heuristic checks and does not call Python models directly.
- For production use, connect `index.html` to a Flask/FastAPI backend for model-backed predictions.

## Future Improvements

- Add REST API backend for model inference
- Add authentication and role-based access
- Improve reporting (PDF export, incident ticket format)
- Add unit tests and CI workflow

## Disclaimer

This project is for educational and defensive cybersecurity purposes only.  
Do not use it for unauthorized or malicious activities.

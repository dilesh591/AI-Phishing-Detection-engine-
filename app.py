import streamlit as st
import joblib
import re
import os
import numpy as np
import json
from datetime import datetime
import pandas as pd

# Optional imports for fingerprint features
try:
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urlparse, urljoin
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import whois as whois_lib
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

# ─────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="AI Phishing Inspector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
#  CUSTOM CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Exo+2:wght@300;400;700&display=swap');

:root {
    --bg:        #0a0c10;
    --bg2:       #0f1318;
    --panel:     #131820;
    --border:    #1e2a38;
    --accent:    #00d4ff;
    --danger:    #ff3c5f;
    --warn:      #ffb800;
    --safe:      #00e676;
    --text:      #c8d8e8;
    --muted:     #4a5a6a;
    --font-mono: 'Share Tech Mono', monospace;
    --font-head: 'Rajdhani', sans-serif;
    --font-body: 'Exo 2', sans-serif;
}
html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--font-body) !important;
}
[data-testid="stSidebar"] {
    background: var(--bg2) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }
.pg-header {
    display: flex; align-items: center; gap: 20px;
    padding: 26px 32px 22px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 28px;
    background: linear-gradient(135deg, #0f1318 0%, #0d1a24 100%);
    border-radius: 12px;
}
.pg-header h1 {
    font-family: var(--font-head) !important; font-size: 2.4rem !important;
    font-weight: 700 !important; letter-spacing: 3px !important;
    color: var(--accent) !important; margin: 0 !important;
    text-shadow: 0 0 22px rgba(0,212,255,0.4);
}
.pg-header p {
    color: var(--muted) !important; font-family: var(--font-mono) !important;
    font-size: 0.74rem !important; margin: 5px 0 0 !important; letter-spacing: 1.5px;
}
.pg-card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 20px 24px; margin-bottom: 16px;
    position: relative; overflow: hidden;
}
.pg-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--accent), transparent);
}
.pg-card-title {
    font-family: var(--font-head) !important; font-size: 1rem !important;
    font-weight: 700 !important; letter-spacing: 2px !important;
    color: var(--accent) !important; text-transform: uppercase; margin-bottom: 14px !important;
}
.risk-pct { font-family: var(--font-mono) !important; font-size: 4.2rem !important; font-weight: 400 !important; line-height: 1 !important; }
.risk-label { font-family: var(--font-head) !important; font-size: 1.5rem !important; font-weight: 700 !important; letter-spacing: 3px !important; margin-top: 8px !important; }
.risk-high { color: var(--danger) !important; text-shadow: 0 0 20px rgba(255,60,95,0.5); }
.risk-med  { color: var(--warn)   !important; text-shadow: 0 0 20px rgba(255,184,0,0.4); }
.risk-low  { color: var(--safe)   !important; text-shadow: 0 0 20px rgba(0,230,118,0.4); }
.score-row { margin: 10px 0; }
.score-label { font-family: var(--font-mono) !important; font-size: 0.76rem !important; color: var(--muted) !important; margin-bottom: 4px !important; }
.score-bar-bg { background: #1a2030; border-radius: 4px; height: 9px; overflow: hidden; }
.score-bar-fill { height: 9px; border-radius: 4px; }
.mitre-badge {
    display: inline-block; background: #0d1a24; border: 1px solid var(--accent);
    border-radius: 6px; padding: 5px 11px; margin: 3px;
    font-family: var(--font-mono); font-size: 0.71rem; color: var(--accent); letter-spacing: 0.5px;
}
.mitre-badge.tactic { border-color: var(--warn); color: var(--warn); background: #1a1600; }
.mitre-badge.fp     { border-color: #9b59b6; color: #c39bd3; background: #130d1a; }
.chip {
    display: inline-block; background: #1a2030; border: 1px solid var(--border);
    border-radius: 20px; padding: 3px 10px; margin: 3px;
    font-size: 0.74rem; font-family: var(--font-mono); color: var(--text);
}
.chip.danger { border-color: var(--danger); color: var(--danger); background: #1a0a10; }
.chip.warn   { border-color: var(--warn);   color: var(--warn);   background: #1a1200; }
.chip.info   { border-color: var(--accent); color: var(--accent); background: #0a1520; }
.fp-row {
    display: grid; grid-template-columns: 28px 1fr 80px;
    gap: 12px; padding: 10px 12px; border-radius: 8px; margin: 6px 0;
    background: #0d1318; border: 1px solid var(--border); align-items: center; font-size: 0.82rem;
}
.fp-icon  { font-size: 1.1rem; text-align: center; }
.fp-label { font-family: var(--font-body); color: var(--text); line-height: 1.4; }
.fp-label small { color: var(--muted); font-size: 0.72rem; display: block; }
.fp-badge { font-family: var(--font-mono); font-size: 0.68rem; text-align: center; padding: 4px 8px; border-radius: 4px; font-weight: 600; letter-spacing: 0.5px; }
.fp-pass  { background: #0a1a10; color: var(--safe);   border: 1px solid var(--safe);   }
.fp-fail  { background: #1a0a10; color: var(--danger); border: 1px solid var(--danger); }
.fp-warn  { background: #1a1200; color: var(--warn);   border: 1px solid var(--warn);   }
.fp-skip  { background: #1a2030; color: var(--muted);  border: 1px solid var(--border); }
.hist-row {
    display: grid; grid-template-columns: 1fr 2fr 1fr 1fr; gap: 12px;
    padding: 10px 0; border-bottom: 1px solid var(--border);
    font-size: 0.79rem; font-family: var(--font-mono); align-items: center;
}
.hist-row.header { color: var(--muted); font-size: 0.69rem; letter-spacing: 1px; }
.stButton > button {
    background: linear-gradient(135deg, #003d55, #005577) !important;
    border: 1px solid var(--accent) !important; color: var(--accent) !important;
    font-family: var(--font-head) !important; font-weight: 700 !important;
    letter-spacing: 2px !important; border-radius: 8px !important;
    padding: 12px 28px !important; font-size: 0.92rem !important;
    transition: all 0.2s !important; text-transform: uppercase;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #005577, #007799) !important;
    box-shadow: 0 0 20px rgba(0,212,255,0.3) !important;
}
textarea, input[type="text"] {
    background: #0d1318 !important; border: 1px solid var(--border) !important;
    color: var(--text) !important; border-radius: 8px !important; font-family: var(--font-body) !important;
}
.stTabs [data-baseweb="tab-list"] { gap: 4px; background: var(--bg2) !important; border-radius: 8px; padding: 4px; }
.stTabs [data-baseweb="tab"] {
    background: transparent !important; color: var(--muted) !important;
    font-family: var(--font-head) !important; font-weight: 600 !important;
    letter-spacing: 1px !important; border-radius: 6px !important; padding: 8px 18px !important;
}
.stTabs [aria-selected="true"] { background: var(--panel) !important; color: var(--accent) !important; border: 1px solid var(--border) !important; }
hr { border-color: var(--border) !important; }
[data-testid="stMetric"] { background: var(--panel) !important; border: 1px solid var(--border) !important; border-radius: 10px !important; padding: 16px !important; }
[data-testid="stMetricLabel"] { color: var(--muted) !important; font-family: var(--font-mono) !important; }
[data-testid="stMetricValue"] { color: var(--accent) !important; font-family: var(--font-head) !important; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  MITRE ATT&CK MAPPING
#  Each key maps directly to a detection signal in this engine.
#  Sources: email body (📧), URL patterns (🔗), website fingerprint (🌐)
# ─────────────────────────────────────────────
MITRE_MAP = {
    # ── Email body signals ──────────────────────────────────────────────
    "urgency_language":    ("Initial Access",    "T1566",     "Phishing",
                            "Urgency keywords (act now, expire, immediately) bypass victim critical thinking — hallmark of mass phishing"),
    "click_lure":          ("Execution",         "T1204.001", "Malicious Link",
                            "'Click here' language drives user-initiated execution of a malicious URL"),
    "password_request":    ("Credential Access", "T1056.003", "Web Portal Capture",
                            "Direct password request via fake login portal to harvest credentials"),
    "verify_request":      ("Credential Access", "T1078",     "Valid Accounts",
                            "Credential verification prompt used to collect valid account usernames and passwords"),
    "financial_info":      ("Collection",        "T1185",     "Browser Session Hijacking",
                            "Requests for bank / credit card data indicate financial credential targeting"),
    "reward_lure":         ("Initial Access",    "T1566",     "Phishing",
                            "Prize / lottery lure — social engineering to trigger link clicks"),
    "account_threat":      ("Impact",            "T1531",     "Account Access Removal",
                            "Suspended / blocked account threats create fear-driven compliance"),
    "bec_indicator":       ("Impact",            "T1657",     "Financial Theft",
                            "Invoice / wire / transfer keywords indicate Business Email Compromise (BEC)"),
    "generic_salutation":  ("Initial Access",    "T1566",     "Phishing",
                            "Non-personalised salutation (Dear Customer) signals mass phishing campaign"),
    "secrecy_instruction": ("Defense Evasion",   "T1564",     "Hide Artifacts",
                            "Instruction to keep communication secret suppresses victim reporting"),
    "attachment_lure":     ("Execution",         "T1204.002", "Malicious File",
                            "Email attachment used as malware / credential harvest delivery vector"),

    # ── URL pattern signals ──────────────────────────────────────────────
    "ip_in_url":           ("Defense Evasion",   "T1036.005", "Match Legitimate Name",
                            "IP address used instead of domain — evades domain reputation filters"),
    "long_url":            ("Defense Evasion",   "T1036",     "Masquerading",
                            "Excessively long URL obscures the true destination from visual inspection"),
    "auth_keyword_url":    ("Credential Access", "T1556",     "Modify Authentication Process",
                            "login / verify / secure in URL path indicates a fake authentication page"),
    "reward_lure_url":     ("Initial Access",    "T1566",     "Phishing",
                            "Reward / prize keywords in URL path — lure-based social engineering"),
    "no_https":            ("Defense Evasion",   "T1040",     "Network Sniffing",
                            "HTTP (no TLS) allows credentials to be intercepted in transit"),
    "at_sign_url":         ("Defense Evasion",   "T1036.005", "Match Legitimate Name",
                            "@ symbol in URL causes browsers to ignore the left portion — obfuscation trick"),
    "url_shortener":       ("Defense Evasion",   "T1027",     "Obfuscated Files/Information",
                            "URL shortener hides true destination, evading threat intelligence lookups"),
    "excessive_subdomains":("Defense Evasion",   "T1036",     "Masquerading",
                            "Multiple subdomains / dashes mimic trusted brands (e.g. paypal.secure-login.xyz)"),

    # ── Website Fingerprint signals ──────────────────────────────────────
    "favicon_hotlink":     ("Defense Evasion",   "T1036.005", "Match Legitimate Name",
                            "Hotlinking favicon from real brand's server makes spoofed page appear authentic"),
    "external_anchors":    ("Collection",        "T1185",     "Browser Session Hijacking",
                            "80%+ of page links point to external domain — credential harvester shell page"),
    "insecure_form":       ("Credential Access", "T1056.003", "Web Portal Capture",
                            "Password form submitted over HTTP — credentials travel in plaintext, interceptable"),
    "young_domain":        ("Initial Access",    "T1583.001", "Domains",
                            "Domain registered < 30 days ago — phishing infrastructure is ephemeral by design"),
}

TACTIC_COLORS = {
    "Initial Access":    "#ff3c5f",
    "Execution":         "#ff6b35",
    "Defense Evasion":   "#ffb800",
    "Credential Access": "#9b59b6",
    "Collection":        "#00e676",
    "Impact":            "#e74c3c",
    "Discovery":         "#00d4ff",
}

# ── Signal → MITRE key lookups ───────────────────────────────────────────
EMAIL_SIG_TO_MITRE = {
    "urgency":    "urgency_language",
    "click_lure": "click_lure",
    "password":   "password_request",
    "verify":     "verify_request",
    "financial":  "financial_info",
    "reward":     "reward_lure",
    "threat":     "account_threat",
    "bec":        "bec_indicator",
    "generic":    "generic_salutation",
    "secrecy":    "secrecy_instruction",
    "attachment": "attachment_lure",
}
URL_SIG_TO_MITRE = {
    "ip_address":    "ip_in_url",
    "long_url":      "long_url",
    "auth_keyword":  "auth_keyword_url",
    "reward_lure":   "reward_lure_url",
    "no_https":      "no_https",
    "at_sign":       "at_sign_url",
    "url_shortener": "url_shortener",
    "dash_dots":     "excessive_subdomains",
}
FP_SIG_TO_MITRE = {
    "favicon_hotlink":  "favicon_hotlink",
    "external_anchors": "external_anchors",
    "insecure_form":    "insecure_form",
    "young_domain":     "young_domain",
}

# ── Regex signal tables ──────────────────────────────────────────────────
EMAIL_SIGNALS = {
    r'urgent|immediately|right now|act now|expire':      ("urgency",    "danger", "Urgency language"),
    r'click here|click below|click the link|click this': ("click_lure", "danger", "Click-here lure"),
    r'password|passcode|pin':                            ("password",   "danger", "Password request"),
    r'verify|confirm|validate':                          ("verify",     "warn",   "Verification request"),
    r'bank|account|credit card|ssn|social sec':          ("financial",  "danger", "Financial info request"),
    r'won|winner|prize|lottery|free gift|claim':         ("reward",     "warn",   "Reward / prize lure"),
    r'suspended|blocked|locked|disabled|terminated':     ("threat",     "danger", "Account threat"),
    r'invoice|payment|wire|transfer|remittance':         ("bec",        "danger", "BEC / wire fraud indicator"),
    r'dear (customer|user|member|sir|madam|valued)':     ("generic",    "warn",   "Generic salutation"),
    r'do not (share|disclose|tell|inform)':              ("secrecy",    "warn",   "Secrecy instruction"),
    r'attachment|attached file|see attached|open file':  ("attachment", "warn",   "Attachment lure"),
}
URL_SIGNALS = {
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}':         ("ip_address",   "danger", "IP address in URL"),
    r'.{100,}':                                       ("long_url",     "warn",   "URL length > 100 chars"),
    r'login|signin|verify|account|secure|confirm':   ("auth_keyword", "danger", "Auth keyword in URL"),
    r'free|win|prize|bonus|gift|claim':              ("reward_lure",  "warn",   "Reward lure in URL"),
    r'http://':                                       ("no_https",     "danger", "No HTTPS"),
    r'@':                                             ("at_sign",      "danger", "@ symbol in URL"),
    r'bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy|is\.gd': ("url_shortener","warn",   "URL shortener"),
    r'(-{2,}|\.{4,})':                               ("dash_dots",    "warn",   "Excessive dashes/dots"),
}


# ─────────────────────────────────────────────
#  MODEL LOADING
# ─────────────────────────────────────────────
@st.cache_resource
def load_models():
    m = {}
    for key, fname in [('email_model','email_model.pkl'),('email_vec','email_vec.pkl'),
                       ('url_model','url_model.pkl'),('url_vec','url_vec.pkl')]:
        try:
            m[key] = joblib.load(fname)
        except Exception:
            m[key] = None
    m['email_ok'] = m['email_model'] is not None and m['email_vec'] is not None
    m['url_ok']   = m['url_model']   is not None and m['url_vec']   is not None
    return m

models = load_models()


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def extract_url_text(url: str) -> str:
    parts = [url]
    for kw in ['login','verify','secure','account','update','banking',
               'confirm','password','click','free','win','prize']:
        if kw in url.lower():
            parts.append(kw)
    if len(url) > 75: parts.append('long_url')
    if re.search(r'\d+\.\d+\.\d+\.\d+', url): parts.append('has_ip')
    if url.count('-') > 3 or url.count('.') > 4: parts.append('many_special_chars')
    return ' '.join(parts)

def analyse_signals(text: str, pattern_map: dict) -> list:
    found = []
    txt = text.lower()
    for pattern, (key, severity, label) in pattern_map.items():
        if re.search(pattern, txt):
            found.append((key, severity, label))
    return found

def normalize_url(url: str) -> str:
    raw = url.strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        return "https://" + raw
    return raw

def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r"^(https?://)"
        r"(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|"
        r"(\d{1,3}\.){3}\d{1,3})"
        r"(:\d{1,5})?"
        r"(/.*)?$"
    )
    return bool(pattern.match(url.strip()))

def extract_email_iocs(email_text: str) -> dict:
    txt = email_text or ""
    urls = sorted(set(re.findall(r"https?://[^\s<>\"]+", txt)))
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", txt.lower())))
    emails = sorted(set(re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", txt)))
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", txt)))
    return {"urls": urls, "domains": domains, "emails": emails, "ips": ips}


# ─────────────────────────────────────────────
#  WEBSITE FINGERPRINT ANALYSIS
# ─────────────────────────────────────────────
def fingerprint_website(url: str) -> list:
    results = []
    if not url.strip():
        return results

    # Domain Age
    if WHOIS_OK:
        try:
            parsed = urlparse(url if url.startswith('http') else 'https://' + url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            w = whois_lib.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list): creation = creation[0]
            if creation:
                age_days = (datetime.now() - creation).days
                if age_days < 30:
                    results.append({'check':'domain_age','icon':'📅','label':'Domain Age',
                        'detail':f'Registered {age_days} days ago — suspicious (< 30 days)',
                        'status':'fail','mitre_key':'young_domain'})
                elif age_days < 180:
                    results.append({'check':'domain_age','icon':'📅','label':'Domain Age',
                        'detail':f'Registered {age_days} days ago — relatively new (< 180 days)',
                        'status':'warn','mitre_key':'young_domain'})
                else:
                    results.append({'check':'domain_age','icon':'📅','label':'Domain Age',
                        'detail':f'Registered {age_days} days ago — established domain',
                        'status':'pass','mitre_key':None})
        except Exception:
            results.append({'check':'domain_age','icon':'📅','label':'Domain Age',
                'detail':'WHOIS lookup failed — could not verify domain age',
                'status':'skip','mitre_key':None})
    else:
        results.append({'check':'domain_age','icon':'📅','label':'Domain Age',
            'detail':'Install python-whois to enable domain age check',
            'status':'skip','mitre_key':None})

    if not REQUESTS_OK:
        for check, icon, label in [('favicon','🖼️','Favicon Check'),
                                    ('anchors','🔗','Anchor URL Analysis'),
                                    ('forms',  '📋','Hidden Form Check')]:
            results.append({'check':check,'icon':icon,'label':label,
                'detail':'Install requests + beautifulsoup4 to enable',
                'status':'skip','mitre_key':None})
        return results

    fetch_url = url if url.startswith('http') else 'https://' + url
    try:
        resp = requests.get(fetch_url, timeout=8, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(resp.text, 'html.parser')
        page_domain = urlparse(resp.url).netloc
    except Exception as e:
        for check, icon, label in [('favicon','🖼️','Favicon Check'),
                                    ('anchors','🔗','Anchor URL Analysis'),
                                    ('forms',  '📋','Hidden Form Check')]:
            results.append({'check':check,'icon':icon,'label':label,
                'detail':f'Could not fetch page: {str(e)[:60]}',
                'status':'skip','mitre_key':None})
        return results

    # Favicon
    try:
        fav_tags = soup.find_all('link', rel=lambda r: r and any('icon' in x.lower() for x in r))
        fav_src  = None
        if fav_tags:
            href = fav_tags[0].get('href','')
            fav_src = href if href.startswith('http') else urljoin(fetch_url, href) if href else None
        if fav_src:
            fav_domain = urlparse(fav_src).netloc
            if fav_domain and fav_domain != page_domain:
                results.append({'check':'favicon','icon':'🖼️','label':'Favicon Check',
                    'detail':f'Favicon loaded from {fav_domain} — differs from page domain ({page_domain})',
                    'status':'fail','mitre_key':'favicon_hotlink'})
            else:
                results.append({'check':'favicon','icon':'🖼️','label':'Favicon Check',
                    'detail':'Favicon loaded from same domain — no hotlinking detected',
                    'status':'pass','mitre_key':None})
        else:
            results.append({'check':'favicon','icon':'🖼️','label':'Favicon Check',
                'detail':'No explicit favicon tag found (default /favicon.ico)',
                'status':'pass','mitre_key':None})
    except Exception:
        results.append({'check':'favicon','icon':'🖼️','label':'Favicon Check',
            'detail':'Could not parse favicon tags','status':'skip','mitre_key':None})

    # Anchor URLs
    try:
        anchors = soup.find_all('a', href=True)
        total   = len(anchors)
        if total == 0:
            results.append({'check':'anchors','icon':'🔗','label':'Anchor URL Analysis',
                'detail':'No anchor tags found on page','status':'skip','mitre_key':None})
        else:
            external = sum(1 for a in anchors
                           if a['href'].startswith('http') and urlparse(a['href']).netloc != page_domain)
            pct = external / total
            if pct >= 0.8:
                results.append({'check':'anchors','icon':'🔗','label':'Anchor URL Analysis',
                    'detail':f'{int(pct*100)}% of links ({external}/{total}) point to external domains — strong phishing indicator',
                    'status':'fail','mitre_key':'external_anchors'})
            elif pct >= 0.5:
                results.append({'check':'anchors','icon':'🔗','label':'Anchor URL Analysis',
                    'detail':f'{int(pct*100)}% of links ({external}/{total}) point to external domains — suspicious',
                    'status':'warn','mitre_key':'external_anchors'})
            else:
                results.append({'check':'anchors','icon':'🔗','label':'Anchor URL Analysis',
                    'detail':f'{int(pct*100)}% external links ({external}/{total}) — within normal range',
                    'status':'pass','mitre_key':None})
    except Exception:
        results.append({'check':'anchors','icon':'🔗','label':'Anchor URL Analysis',
            'detail':'Could not analyse anchor tags','status':'skip','mitre_key':None})

    # Forms
    try:
        forms  = soup.find_all('form')
        insec  = []
        for form in forms:
            action   = form.get('action','')
            has_pwd  = bool(form.find('input', {'type': 'password'}))
            act_url  = urljoin(fetch_url, action) if action else fetch_url
            if has_pwd and act_url.startswith('http://'):
                insec.append(act_url[:60])
        if insec:
            results.append({'check':'forms','icon':'📋','label':'Hidden Form Check',
                'detail':f'Password form submits over HTTP (unencrypted): {insec[0]}',
                'status':'fail','mitre_key':'insecure_form'})
        elif forms:
            results.append({'check':'forms','icon':'📋','label':'Hidden Form Check',
                'detail':f'{len(forms)} form(s) found — all use HTTPS or have no password fields',
                'status':'pass','mitre_key':None})
        else:
            results.append({'check':'forms','icon':'📋','label':'Hidden Form Check',
                'detail':'No forms found on page','status':'pass','mitre_key':None})
    except Exception:
        results.append({'check':'forms','icon':'📋','label':'Hidden Form Check',
            'detail':'Could not analyse form tags','status':'skip','mitre_key':None})

    return results


def render_fingerprint_results(fp_results: list):
    STATUS_COLORS = {'pass':'#00e676','fail':'#ff3c5f','warn':'#ffb800','skip':'#4a5a6a'}
    STATUS_BG     = {'pass':'#0a1a10','fail':'#1a0a10','warn':'#1a1200','skip':'#1a2030'}
    for fp in fp_results:
        status = fp['status']
        color  = STATUS_COLORS.get(status,'#4a5a6a')
        bg     = STATUS_BG.get(status,'#1a2030')
        icon   = fp['icon']
        label  = fp['label']
        detail = fp['detail'].replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')
        badge  = status.upper()
        mitre_html = ''
        if fp.get('mitre_key') and fp['mitre_key'] in MITRE_MAP:
            e = MITRE_MAP[fp['mitre_key']]
            mitre_html = (
                f'<div style="margin-top:8px;">'
                f'<span style="display:inline-block;background:#1a1600;border:1px solid #ffb800;border-radius:5px;padding:3px 9px;margin:2px;font-family:monospace;font-size:0.69rem;color:#ffb800;">{e[0]}</span>'
                f'<span style="display:inline-block;background:#130d1a;border:1px solid #9b59b6;border-radius:5px;padding:3px 9px;margin:2px;font-family:monospace;font-size:0.69rem;color:#c39bd3;">{e[1]} &middot; {e[2]}</span>'
                f'</div>'
            )
        html = (
            f'<div style="background:#131820;border:1px solid #1e2a38;border-left:3px solid {color};'
            f'border-radius:10px;padding:14px 18px;margin-bottom:10px;">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start;">'
            f'<div style="display:flex;gap:12px;align-items:flex-start;">'
            f'<span style="font-size:1.4rem;line-height:1.3;">{icon}</span>'
            f'<div>'
            f'<div style="font-family:Rajdhani,sans-serif;font-weight:700;color:#c8d8e8;font-size:0.95rem;letter-spacing:1px;">{label}</div>'
            f'<div style="font-size:0.8rem;color:#7a8a9a;margin-top:4px;line-height:1.5;">{detail}</div>'
            f'{mitre_html}'
            f'</div></div>'
            f'<div style="background:{bg};color:{color};border:1px solid {color};font-family:monospace;'
            f'font-size:0.68rem;font-weight:700;padding:4px 10px;border-radius:5px;'
            f'white-space:nowrap;min-width:48px;text-align:center;">{badge}</div>'
            f'</div></div>'
        )
        st.markdown(html, unsafe_allow_html=True)


def build_mitre_hits(email_sigs, url_sigs, fp_results) -> list:
    hits = {}
    for key, _, _ in email_sigs:
        mkey = EMAIL_SIG_TO_MITRE.get(key)
        if mkey and mkey in MITRE_MAP and mkey not in hits:
            e = MITRE_MAP[mkey]
            hits[mkey] = {'tactic':e[0],'tid':e[1],'name':e[2],'desc':e[3],'source':'email'}
    for key, _, _ in url_sigs:
        mkey = URL_SIG_TO_MITRE.get(key)
        if mkey and mkey in MITRE_MAP and mkey not in hits:
            e = MITRE_MAP[mkey]
            hits[mkey] = {'tactic':e[0],'tid':e[1],'name':e[2],'desc':e[3],'source':'url'}
    for fp in fp_results:
        mkey = fp.get('mitre_key')
        if mkey and mkey in MITRE_MAP and mkey not in hits:
            e = MITRE_MAP[mkey]
            hits[mkey] = {'tactic':e[0],'tid':e[1],'name':e[2],'desc':e[3],'source':'fingerprint'}
    return list(hits.values())


def scan(email_text: str, url: str, run_fingerprint: bool = False) -> dict:
    result = {
        'email_score': None, 'url_score': None,
        'risk': 0.0, 'verdict': 'NO INPUT', 'verdict_cls': 'low',
        'email_signals': [], 'url_signals': [], 'fingerprint': [], 'mitre': [],
        'timestamp': datetime.now().strftime('%H:%M:%S'),
    }

    if email_text.strip() and models.get('email_ok'):
        feats = models['email_vec'].transform([email_text])
        result['email_score'] = float(models['email_model'].predict_proba(feats)[0][1])
    if url.strip() and models.get('url_ok'):
        feats = models['url_vec'].transform([extract_url_text(url)])
        result['url_score'] = float(models['url_model'].predict_proba(feats)[0][1])

    # Heuristic fallback when models are not loaded
    if not models.get('email_ok') and email_text.strip():
        c = sum(1 for p in EMAIL_SIGNALS if re.search(p, email_text.lower()))
        result['email_score'] = min(c * 0.14, 0.98)
    if not models.get('url_ok') and url.strip():
        c = sum(1 for p in URL_SIGNALS if re.search(p, url.lower()))
        result['url_score'] = min(c * 0.22, 0.98)

    result['email_signals'] = analyse_signals(email_text, EMAIL_SIGNALS)
    result['url_signals']   = analyse_signals(url,        URL_SIGNALS)

    if run_fingerprint and url.strip():
        result['fingerprint'] = fingerprint_website(url)
        fp_boost = (sum(1 for f in result['fingerprint'] if f['status']=='fail') * 0.18 +
                    sum(1 for f in result['fingerprint'] if f['status']=='warn') * 0.07)
        if result['url_score'] is not None:
            result['url_score'] = min(result['url_score'] + fp_boost, 0.99)
        elif fp_boost > 0:
            result['url_score'] = min(fp_boost, 0.99)

    scores = [s for s in [result['email_score'], result['url_score']] if s is not None]
    if scores:
        result['risk'] = max(scores)

    if result['risk'] >= 0.75:
        result['verdict'] = '🚨 HIGH RISK — Likely Phishing'
        result['verdict_cls'] = 'high'
    elif result['risk'] >= 0.45:
        result['verdict'] = '⚠️  MEDIUM RISK — Suspicious'
        result['verdict_cls'] = 'med'
    elif scores:
        result['verdict'] = '✅ SAFE — Looks Legitimate'
        result['verdict_cls'] = 'low'

    result['mitre'] = build_mitre_hits(result['email_signals'], result['url_signals'], result['fingerprint'])
    return result


def score_bar_html(label, score, color='#00d4ff'):
    if score is None:
        return f'<div class="score-row"><div class="score-label">{label} — N/A</div><div class="score-bar-bg"><div class="score-bar-fill" style="width:0%;background:#1e2a38;"></div></div></div>'
    pct = int(score * 100)
    return f'<div class="score-row"><div class="score-label">{label} — {pct}%</div><div class="score-bar-bg"><div class="score-bar-fill" style="width:{pct}%;background:{color};"></div></div></div>'


# ─────────────────────────────────────────────
#  SESSION STATE
# ─────────────────────────────────────────────
if 'history' not in st.session_state:
    st.session_state.history = []
if 'last_result' not in st.session_state:
    st.session_state.last_result = None


# ─────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:10px 0 20px;">
        <div style="font-family:'Rajdhani',sans-serif;font-size:1.55rem;color:#00d4ff;font-weight:700;letter-spacing:3px;">AI PHISHING</div>
        <div style="font-family:'Rajdhani',sans-serif;font-size:1.55rem;color:#c8d8e8;font-weight:700;letter-spacing:3px;">INSPECTOR</div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.67rem;color:#4a5a6a;letter-spacing:1px;margin-top:4px;">ENGINE v2.1 · MITRE ATT&CK MAPPED</div>
    </div>""", unsafe_allow_html=True)

    st.markdown("#### Model Status")
    for lbl, ok in [("EMAIL MODEL","email_ok"),("URL MODEL","url_ok")]:
        ok_val = models.get(ok)
        status = "🟢 Loaded" if ok_val else "🟡 Heuristic Mode"
        color  = "#00e676"   if ok_val else "#ffb800"
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:0.73rem;line-height:2.2;"><span style="color:#4a5a6a;">{lbl}  </span><span style="color:{color};">{status}</span></div>', unsafe_allow_html=True)

    if not models.get('email_ok') or not models.get('url_ok'):
        st.info("Place email_model.pkl, email_vec.pkl, url_model.pkl, url_vec.pkl in the same folder to enable AI scoring.")

    st.markdown("---")
    st.markdown("#### Fingerprint Dependencies")
    for lbl, ok, install in [("HTTP FETCH", REQUESTS_OK, "requests beautifulsoup4"),
                               ("WHOIS",      WHOIS_OK,    "python-whois")]:
        color  = "#00e676" if ok else "#ff3c5f"
        status = "🟢 Ready" if ok else f"🔴 pip install {install}"
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:0.7rem;line-height:2;"><span style="color:#4a5a6a;">{lbl}  </span><span style="color:{color};">{status}</span></div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### Risk Thresholds")
    high_thresh = st.slider("High Risk ≥",   0.5, 1.0, 0.75, 0.05)
    med_thresh  = st.slider("Medium Risk ≥", 0.2, 0.7, 0.45, 0.05)

    st.markdown("---")
    st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;font-size:0.71rem;color:#4a5a6a;">{len(st.session_state.history)} scans this session</div>', unsafe_allow_html=True)
    if st.button("🗑 Clear History"):
        st.session_state.history = []
        st.rerun()


# ─────────────────────────────────────────────
#  HEADER
# ─────────────────────────────────────────────
st.markdown("""
<div class="pg-header">
    <div style="font-size:2.8rem;line-height:1;">🔍</div>
    <div>
        <h1>AI PHISHING INSPECTOR</h1>
        <p>THREAT DETECTION ENGINE · WEBSITE FINGERPRINTING · MITRE ATT&CK MAPPED</p>
    </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  TABS
# ─────────────────────────────────────────────
tab_scan, tab_fp, tab_mitre, tab_history, tab_bulk = st.tabs([
    "🔍  SCAN", "🌐  FINGERPRINT", "🗺️  MITRE MAP", "📋  HISTORY", "📦  BULK"
])


# ══════════════════════════════════════════════
#  TAB 1 — SCAN
# ══════════════════════════════════════════════
with tab_scan:
    col_input, col_result = st.columns([1.1, 0.9], gap="large")

    with col_input:
        st.markdown('<div class="pg-card-title">📧 INPUT</div>', unsafe_allow_html=True)
        email_text = st.text_area("Email Body",
            placeholder="Paste the full email content here…", height=200)
        url_input_raw = st.text_input("URL / Link to Inspect",
            placeholder="https://example.com/verify-account")
        url_input = normalize_url(url_input_raw) if url_input_raw.strip() else ""
        if url_input and url_input != url_input_raw:
            st.caption(f"Normalized URL: `{url_input}`")
        run_fp = st.checkbox("🌐 Run Website Fingerprint Analysis", value=False,
            help="Fetches the live website to check favicon hotlinking, anchor links, insecure forms, and domain age.")

        c1, c2 = st.columns(2)
        with c1: scan_clicked = st.button("⚡ SCAN THREAT", use_container_width=True)
        with c2:
            if st.button("🔄 CLEAR", use_container_width=True):
                st.rerun()

    with col_result:
        if scan_clicked and (email_text.strip() or url_input.strip()):
            if url_input and not is_valid_url(url_input):
                st.error("Please enter a valid URL (example: https://example.com/path).")
                st.stop()
            with st.spinner("Analysing threat…"):
                result = scan(email_text, url_input, run_fingerprint=run_fp)

            if result['risk'] >= high_thresh:
                result['verdict_cls'] = 'high'; result['verdict'] = '🚨 HIGH RISK — Likely Phishing'
            elif result['risk'] >= med_thresh:
                result['verdict_cls'] = 'med';  result['verdict'] = '⚠️  MEDIUM RISK — Suspicious'

            st.session_state.history.append({
                'time': result['timestamp'],
                'preview': (email_text[:40]+'…' if email_text.strip() else url_input[:40]+'…'),
                'risk': result['risk'], 'verdict': result['verdict_cls'],
            })
            st.session_state.last_result = {
                "timestamp": result["timestamp"],
                "input": {
                    "email_text": email_text,
                    "url": url_input,
                    "run_fingerprint": run_fp,
                },
                "scores": {
                    "email_score": result["email_score"],
                    "url_score": result["url_score"],
                    "combined_risk": result["risk"],
                },
                "verdict": result["verdict"],
                "signals": {
                    "email": [s[2] for s in result["email_signals"]],
                    "url": [s[2] for s in result["url_signals"]],
                    "mitre_hits": result["mitre"],
                },
                "fingerprint": result["fingerprint"],
            }

            cls  = result['verdict_cls']
            cmap = {'high':'#ff3c5f','med':'#ffb800','low':'#00e676'}
            color= cmap.get(cls,'#00d4ff')
            pct  = int(result['risk']*100)

            st.markdown(f'<div class="pg-card" style="border-color:{color};text-align:center;padding:28px;"><div class="risk-pct risk-{cls}">{pct}%</div><div class="risk-label risk-{cls}">{result["verdict"]}</div></div>', unsafe_allow_html=True)

            def vcls(s):
                if s is None: return '#4a5a6a'
                return '#ff3c5f' if s>=high_thresh else ('#ffb800' if s>=med_thresh else '#00e676')

            st.markdown('<div class="pg-card">', unsafe_allow_html=True)
            st.markdown('<div class="pg-card-title">SCORE BREAKDOWN</div>', unsafe_allow_html=True)
            st.markdown(score_bar_html("EMAIL RISK", result['email_score'], vcls(result['email_score'])), unsafe_allow_html=True)
            st.markdown(score_bar_html("URL RISK",   result['url_score'],   vcls(result['url_score'])),   unsafe_allow_html=True)
            st.markdown(score_bar_html("COMBINED",   result['risk'],        color),                       unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

            all_sigs = result['email_signals'] + result['url_signals']
            if all_sigs:
                st.markdown('<div class="pg-card">', unsafe_allow_html=True)
                st.markdown('<div class="pg-card-title">🔎 EVIDENCE SIGNALS</div>', unsafe_allow_html=True)
                st.markdown(''.join(f'<span class="chip {sev}">{lbl}</span>' for _,sev,lbl in all_sigs), unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            if result['fingerprint']:
                st.markdown('<div class="pg-card-title" style="margin-top:8px;">🌐 FINGERPRINT SUMMARY</div>', unsafe_allow_html=True)
                render_fingerprint_results(result['fingerprint'])

            if result['mitre']:
                st.markdown('<div class="pg-card">', unsafe_allow_html=True)
                st.markdown('<div class="pg-card-title">🗺️ MITRE ATT&CK HITS</div>', unsafe_allow_html=True)
                src_icon = {'email':'📧','url':'🔗','fingerprint':'🌐'}
                for hit in result['mitre'][:7]:
                    fp_cls = ' fp' if hit.get('source')=='fingerprint' else ''
                    si     = src_icon.get(hit.get('source',''),'')
                    st.markdown(f'<div style="margin:5px 0;"><span class="mitre-badge tactic">{hit["tactic"]}</span><span class="mitre-badge{fp_cls}">{hit["tid"]} · {hit["name"]}</span> <span style="font-size:0.85rem;">{si}</span></div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            if email_text.strip():
                iocs = extract_email_iocs(email_text)
                if any(iocs.values()):
                    st.markdown('<div class="pg-card">', unsafe_allow_html=True)
                    st.markdown('<div class="pg-card-title">🧬 EXTRACTED IOCs</div>', unsafe_allow_html=True)
                    c1, c2 = st.columns(2)
                    with c1:
                        st.write(f"URLs: {len(iocs['urls'])}")
                        st.write(f"Emails: {len(iocs['emails'])}")
                    with c2:
                        st.write(f"Domains: {len(iocs['domains'])}")
                        st.write(f"IPs: {len(iocs['ips'])}")
                    with st.expander("View IOC details"):
                        st.json(iocs)
                    st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="pg-card">', unsafe_allow_html=True)
            st.markdown('<div class="pg-card-title">🛡️ RECOMMENDED ACTIONS</div>', unsafe_allow_html=True)
            if result['verdict_cls'] == 'high':
                st.error("Do not click links or open attachments. Quarantine message and report to your SOC/security team.")
            elif result['verdict_cls'] == 'med':
                st.warning("Treat as suspicious. Verify sender identity via a separate trusted channel before taking action.")
            else:
                st.success("No strong phishing indicators detected, but continue normal verification for sensitive actions.")
            st.markdown('</div>', unsafe_allow_html=True)

        else:
            st.markdown('<div class="pg-card" style="text-align:center;padding:60px 20px;border-style:dashed;"><div style="font-size:3rem;margin-bottom:16px;opacity:0.25;">🔍</div><div style="font-family:\'Share Tech Mono\',monospace;font-size:0.82rem;color:#4a5a6a;letter-spacing:2px;">AWAITING INPUT<br><br>Paste email text and/or a URL<br>then hit SCAN THREAT</div></div>', unsafe_allow_html=True)

    if st.session_state.last_result is not None:
        st.download_button(
            "📥 Download Latest Scan (JSON)",
            data=json.dumps(st.session_state.last_result, indent=2).encode("utf-8"),
            file_name=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )


# ══════════════════════════════════════════════
#  TAB 2 — FINGERPRINT
# ══════════════════════════════════════════════
with tab_fp:
    st.markdown('<div class="pg-card-title">🌐 WEBSITE FINGERPRINT ANALYSER</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;color:#4a5a6a;margin-bottom:20px;line-height:1.8;">Live website analysis — fetches the actual page and runs four deep-inspection checks, each mapped to a MITRE ATT&CK technique.</div>', unsafe_allow_html=True)

    checks_info = [
        ("🖼️", "Favicon Hotlink Check",  "T1036.005 · Defense Evasion — Match Legitimate Name",
         "Phishing sites embed the real company's favicon directly from the legitimate server. If fake-bank.com loads its icon from real-bank.com/favicon.ico, the icon looks authentic but the domain does not match.", "#ffb800"),
        ("🔗", "Anchor URL Analysis",    "T1185 · Collection — Browser Session Hijacking",
         "Checks what percentage of hyperlinks point to a different domain. Legitimate sites link mostly internally. If ≥ 80% of links point elsewhere, the page is a credential-harvesting shell with copied content.", "#9b59b6"),
        ("📋", "Hidden / Insecure Form", "T1056.003 · Credential Access — Web Portal Capture",
         "Scans all form tags for password fields that submit over HTTP. Any password entered travels the internet in plaintext and can be intercepted by a network sniffer in transit.", "#ff3c5f"),
        ("📅", "Domain Age Check",       "T1583.001 · Initial Access — Domains",
         "Queries WHOIS registration data. Phishing infrastructure is ephemeral — attackers register domains days before a campaign. Domains under 30 days old are treated as high-risk.", "#00d4ff"),
    ]

    cols = st.columns(2)
    for i, (icon, title, tid, desc, color) in enumerate(checks_info):
        with cols[i % 2]:
            st.markdown(f"""
            <div class="pg-card" style="border-color:{color}40;margin-bottom:14px;">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                    <span style="font-size:1.5rem;">{icon}</span>
                    <div>
                        <div style="font-family:'Rajdhani',sans-serif;font-size:1rem;font-weight:700;color:{color};letter-spacing:1px;">{title}</div>
                        <div style="font-family:'Share Tech Mono',monospace;font-size:0.67rem;color:#4a5a6a;">{tid}</div>
                    </div>
                </div>
                <div style="font-family:'Exo 2',sans-serif;font-size:0.81rem;color:#a0b0c0;line-height:1.6;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="pg-card-title">⚡ RUN STANDALONE FINGERPRINT</div>', unsafe_allow_html=True)
    fp_url = st.text_input("URL to fingerprint", placeholder="https://example.com", key="fp_url")

    if st.button("🌐 FINGERPRINT WEBSITE", use_container_width=True):
        if fp_url.strip():
            with st.spinner("Fetching and analysing website…"):
                fp_results = fingerprint_website(fp_url.strip())
            render_fingerprint_results(fp_results)
        else:
            st.warning("Please enter a URL.")


# ══════════════════════════════════════════════
#  TAB 3 — MITRE MAP
# ══════════════════════════════════════════════
with tab_mitre:
    st.markdown('<div class="pg-card-title">🗺️ MITRE ATT&CK COVERAGE MAP</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;color:#4a5a6a;margin-bottom:20px;line-height:1.8;">
    Every signal detected by this engine maps to a specific MITRE ATT&amp;CK technique.<br>
    Source icons show where the signal originates: 📧 email body · 🔗 URL pattern · 🌐 website fingerprint
    </div>
    """, unsafe_allow_html=True)

    # Build source map
    SOURCE_MAP = {}
    for _, mk in EMAIL_SIG_TO_MITRE.items(): SOURCE_MAP.setdefault(mk, set()).add('📧')
    for _, mk in URL_SIG_TO_MITRE.items():   SOURCE_MAP.setdefault(mk, set()).add('🔗')
    for _, mk in FP_SIG_TO_MITRE.items():    SOURCE_MAP.setdefault(mk, set()).add('🌐')

    tactics_order = ["Initial Access","Execution","Defense Evasion",
                     "Credential Access","Collection","Impact"]
    by_tactic = {t: [] for t in tactics_order}
    for mkey, (tactic, tid, name, desc) in MITRE_MAP.items():
        if tactic in by_tactic:
            by_tactic[tactic].append((tid, name, desc, mkey))

    cols = st.columns(2)
    for ci, tactic in enumerate(tactics_order):
        techs = by_tactic.get(tactic, [])
        if not techs: continue
        color = TACTIC_COLORS.get(tactic, '#00d4ff')
        with cols[ci % 2]:
            tactic_sources = ' '.join(sorted(set(
                icon for mkey in [t[3] for t in techs]
                for icon in SOURCE_MAP.get(mkey, set())
            )))
            st.markdown(f"""
            <div class="pg-card" style="border-color:{color}35;margin-bottom:14px;">
                <div style="display:flex;justify-content:space-between;align-items:center;
                            border-bottom:1px solid {color}25;padding-bottom:9px;margin-bottom:11px;">
                    <div style="font-family:'Rajdhani',sans-serif;font-size:1rem;font-weight:700;
                                color:{color};letter-spacing:2px;text-transform:uppercase;">{tactic}</div>
                    <div style="font-size:0.9rem;letter-spacing:3px;">{tactic_sources}</div>
                </div>
            """, unsafe_allow_html=True)
            seen = set()
            for tid, name, desc, mkey in techs:
                if tid in seen: continue
                seen.add(tid)
                src = ' '.join(sorted(SOURCE_MAP.get(mkey, set())))
                st.markdown(f"""
                <div style="margin:7px 0;padding:9px 11px;background:#0d1318;border-radius:6px;border-left:3px solid {color}55;">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <div style="font-family:'Share Tech Mono',monospace;font-size:0.72rem;color:{color};">{tid}</div>
                        <div style="font-size:0.8rem;letter-spacing:2px;">{src}</div>
                    </div>
                    <div style="font-family:'Exo 2',sans-serif;font-size:0.84rem;color:#c8d8e8;font-weight:600;margin-top:2px;">{name}</div>
                    <div style="font-family:'Exo 2',sans-serif;font-size:0.71rem;color:#4a5a6a;margin-top:3px;line-height:1.4;">{desc}</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="pg-card-title">📊 TECHNIQUES BY TACTIC</div>', unsafe_allow_html=True)
    counts = {t: len(set(e[0] for e in v)) for t, v in by_tactic.items() if v}
    st.bar_chart(pd.DataFrame(list(counts.items()), columns=['Tactic','Techniques']).set_index('Tactic'))


# ══════════════════════════════════════════════
#  TAB 4 — HISTORY
# ══════════════════════════════════════════════
with tab_history:
    st.markdown('<div class="pg-card-title">📋 SCAN HISTORY</div>', unsafe_allow_html=True)
    if not st.session_state.history:
        st.markdown('<div style="text-align:center;padding:40px;color:#4a5a6a;font-family:\'Share Tech Mono\',monospace;font-size:0.77rem;letter-spacing:1px;">NO SCANS YET — run a scan first</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="hist-row header"><span>TIME</span><span>PREVIEW</span><span>RISK</span><span>VERDICT</span></div>', unsafe_allow_html=True)
        vemoji = {'high':'🚨','med':'⚠️','low':'✅'}
        vcolor = {'high':'#ff3c5f','med':'#ffb800','low':'#00e676'}
        for h in reversed(st.session_state.history):
            c = vcolor.get(h['verdict'],'#00d4ff')
            e = vemoji.get(h['verdict'],'—')
            st.markdown(f'<div class="hist-row"><span style="color:#4a5a6a;">{h["time"]}</span><span style="color:#c8d8e8;">{h["preview"]}</span><span style="color:{c};font-weight:700;">{int(h["risk"]*100)}%</span><span>{e}</span></div>', unsafe_allow_html=True)
        st.markdown("---")
        total    = len(st.session_state.history)
        highs    = sum(1 for h in st.session_state.history if h['verdict']=='high')
        avg_risk = sum(h['risk'] for h in st.session_state.history) / total
        c1,c2,c3 = st.columns(3)
        c1.metric("Total Scans",     total)
        c2.metric("High Risk Found", highs)
        c3.metric("Avg Risk Score",  f"{avg_risk:.0%}")
        trend_df = pd.DataFrame(st.session_state.history)
        trend_df["scan_idx"] = range(1, len(trend_df) + 1)
        st.line_chart(trend_df.set_index("scan_idx")["risk"])
        if st.button("📥 Export History as CSV"):
            df_h = pd.DataFrame(st.session_state.history)
            st.download_button("Download CSV", df_h.to_csv(index=False).encode('utf-8'),
                               "phishing_inspector_history.csv","text/csv")


# ══════════════════════════════════════════════
#  TAB 5 — BULK SCAN
# ══════════════════════════════════════════════
with tab_bulk:
    st.markdown('<div class="pg-card-title">📦 BULK URL SCANNER</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;color:#4a5a6a;margin-bottom:16px;">One URL per line. Website fingerprinting is skipped in bulk mode for performance.</div>', unsafe_allow_html=True)
    bulk_input = st.text_area("URLs (one per line)",
        placeholder="https://google.com\nhttp://secure-login.bank-verify.xyz/confirm", height=160)
    if st.button("⚡ SCAN ALL", use_container_width=True):
        urls = [u.strip() for u in bulk_input.strip().split('\n') if u.strip()]
        if urls:
            rows, bar = [], st.progress(0)
            for i, u in enumerate(urls):
                r = scan("", u, run_fingerprint=False)
                rows.append({'URL': u[:65]+('…' if len(u)>65 else ''),
                             'Risk %': f"{int(r['risk']*100)}%",
                             'Verdict': r['verdict_cls'].upper(),
                             'Signals': len(r['url_signals']),
                             'MITRE Hits': len(r['mitre'])})
                bar.progress((i+1)/len(urls))
            df_b = pd.DataFrame(rows)
            def cv(val):
                return {'HIGH':'color: #ff3c5f','MED':'color: #ffb800','LOW':'color: #00e676'}.get(val,'')
            st.dataframe(df_b.style.applymap(cv, subset=['Verdict']), use_container_width=True)
            st.download_button("📥 Download Results CSV",
                df_b.to_csv(index=False).encode('utf-8'),"bulk_scan_results.csv","text/csv")
        else:
            st.warning("Please enter at least one URL.")

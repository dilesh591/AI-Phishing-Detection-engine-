import streamlit as st
import hashlib
import os
import sqlite3
import pyhidra
from datetime import datetime
from pathlib import Path

# --- CONFIGURATION ---
GHIDRA_PATH = os.getenv('GHIDRA_INSTALL_DIR', '/opt/ghidra') # Ensure this matches your path
DB_PATH = 'analysis_history.db'

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, 
                  hash_sha256 TEXT, status TEXT, timestamp DATETIME)''')
    conn.commit()
    conn.close()

# --- ANALYSIS LOGIC ---
class LocalScanner:
    def __init__(self, file_bytes, filename):
        self.data = file_bytes
        self.filename = filename
        
    def get_hashes(self):
        sha256 = hashlib.sha256(self.data).hexdigest()
        md5 = hashlib.md5(self.data).hexdigest()
        return sha256, md5

    def check_malicious_patterns(self):
        """
        Example logic based on your previous analyzer.
        In a real scenario, you'd use pyhidra here to inspect functions.
        """
        suspicious_score = 0
        findings = []
        
        # Simple example: check for common 'malicious' strings in bytes
        if b"CreateRemoteThread" in self.data:
            findings.append("Found suspicious API: CreateRemoteThread (Possible Injection)")
            suspicious_score += 40
        if b"ShellExecute" in self.data:
            findings.append("Found suspicious API: ShellExecute (Execution)")
            suspicious_score += 20
            
        is_safe = suspicious_score < 30
        return is_safe, findings

# --- STREAMLIT UI ---
st.set_page_config(page_title="Desktop Malware Scanner", layout="wide")
init_db()

st.title("🛡️ Desktop Malware Scanner")
st.markdown("Drag and drop files below to perform a static security scan.")

# 1. Drag & Drop File Uploader
uploaded_file = st.file_uploader(
    "Upload a binary (.exe, .bat, .bin, .elf)", 
    type=['exe', 'bat', 'bin', 'elf'],
    accept_multiple_files=False
)

if uploaded_file is not None:
    # Read file content
    file_bytes = uploaded_file.getvalue()
    scanner = LocalScanner(file_bytes, uploaded_file.name)
    sha256, md5 = scanner.get_hashes()
    
    # 2. Run Scan
    with st.spinner('Analyzing file patterns...'):
        is_safe, findings = scanner.check_malicious_patterns()
        
    # 3. Show Results (Virus Scanner Style)
    st.divider()
    if is_safe:
        st.success(f"✅ **FILE IS LIKELY SAFE**: {uploaded_file.name}")
    else:
        st.error(f"🚨 **MALICIOUS PATTERNS DETECTED**: {uploaded_file.name}")
        
    col1, col2 = st.columns(2)
    with col1:
        st.info("**File Metadata**")
        st.write(f"**Filename:** {uploaded_file.name}")
        st.write(f"**SHA256:** `{sha256}`")
        st.write(f"**MD5:** `{md5}`")
        
    with col2:
        st.warning("**Security Findings**")
        if findings:
            for f in findings:
                st.write(f"- {f}")
        else:
            st.write("No immediate suspicious patterns found in byte-string scan.")

    # Log to local history
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO scans (filename, hash_sha256, status, timestamp) VALUES (?, ?, ?, ?)",
                 (uploaded_file.name, sha256, "Safe" if is_safe else "Malicious", datetime.now()))
    conn.commit()
    conn.close()

# --- HISTORY TAB ---
st.sidebar.title("Recent Scans")
conn = sqlite3.connect(DB_PATH)
history = conn.execute("SELECT filename, status FROM scans ORDER BY id DESC LIMIT 5").fetchall()
conn.close()

for name, status in history:
    st.sidebar.write(f"{'✅' if status == 'Safe' else '🚨'} {name}")
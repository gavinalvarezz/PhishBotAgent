import streamlit as st
import re
import hashlib
from datetime import datetime
from bs4 import BeautifulSoup
from difflib import SequenceMatcher

# ✅ Expected SHA-256 hashes (replace with actual values)
expected_hashes = {
    "danger_words.txt": "87ba544385b550eab5c79d0b2830ee31ecae3d86d3672547467aeaa9700000c8",
    "safe_words.txt": "3f92565f89e10b3baa064c0ac6a5bc741be1327cb7c869b3a0b9824b80006237"
}

# ✅ File integrity check
def verify_file_integrity(filename):
    try:
        with open(filename, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash == expected_hashes.get(filename)
    except FileNotFoundError:
        return False

# ✅ Load danger words
if not verify_file_integrity("danger_words.txt"):
    st.error("⚠️ 'danger_words.txt' failed integrity check or is missing.")
    st.stop()
else:
    with open("danger_words.txt") as f:
        danger_words = [line.strip().lower() for line in f if line.strip()]

# ✅ Load safe words
if not verify_file_integrity("safe_words.txt"):
    st.warning("⚠️ 'safe_words.txt' failed integrity check or is missing. Safe word dampening disabled.")
    safe_words = []
else:
    with open("safe_words.txt") as f:
        safe_words = [line.strip().lower() for line in f if line.strip()]

# ✅ Domain reputation lists
trusted_domains = ["amazon.com", "netflix.com", "microsoft.com", "fafsa.gov"]
suspicious_domains = ["secure-payments-support.com", "netflix-support.biz", "account-alerts.org", "fasa-gov.com"]

# ✅ Credential trap detection
def detect_credential_trap(email_text):
    soup = BeautifulSoup(email_text, 'html.parser')
    inputs = soup.find_all('input')
    for i in inputs:
        if i.get('type') in ['password', 'email', 'text']:
            return True
    return False

# ✅ Domain spoofing analysis
def is_domain_spoofed(sender_domain, trusted_domains):
    for trusted in trusted_domains:
        similarity = SequenceMatcher(None, sender_domain, trusted).ratio()
        if similarity > 0.8 and sender_domain != trusted:
            return True
    return False

# ✅ Scan function
def scan_email(email_text):
    email_text = email_text.lower()
    found = []
    safe_found = []

    danger_patterns = [(word, re.compile(r'\b' + re.escape(word) + r'\b')) for word in danger_words]
    safe_patterns = [(word, re.compile(r'\b' + re.escape(word) + r'\b')) for word in safe_words]

    for word, pattern in danger_patterns:
        if pattern.search(email_text):
            found.append(word)

    for word, pattern in safe_patterns:
        if pattern.search(email_text):
            safe_found.append(word)

    score = max(0, len(found) * 10 - len(safe_found) * 15)

    sender_match = re.search(r'from:\s*.*?@([\w.-]+)', email_text)
    sender_domain = sender_match.group(1) if sender_match else None

    if sender_domain:
        if sender_domain in suspicious_domains:
            score += 30
        elif sender_domain not in trusted_domains:
            score += 15
        if is_domain_spoofed(sender_domain, trusted_domains):
            score += 20

    if detect_credential_trap(email_text):
        score += 25

    score -= len(safe_found) * 10
    score = max(0, min(score, 100))

    return found, safe_found, score, sender_domain

# ✅ Advice logic
def get_advice(score):
    if score == 0:
        return (
            "✅ This email looks safe.\n\n"
            "**What to do:** You can read and respond normally. No suspicious content detected."
        )
    elif score <= 30:
        return (
            "⚠️ Low risk detected.\n\n"
            "**What to do:** Avoid clicking links or downloading attachments unless you're sure it's from someone you trust. "
            "If unsure, visit the official website directly or contact the sender through a known method."
        )
    elif score <= 60:
        return (
            "⚠️ Medium risk detected.\n\n"
            "**What to do:** Do not click any links or reply. Contact your supervisor, IT department, or the company using a verified phone number or website. "
            "Save the email for review but avoid engaging with it."
        )
    else:
        return (
            "🚨 High risk detected!\n\n"
            "**What to do:** Immediately report this email to your manager or IT support. Do not click links, download attachments, or reply. "
            "Close the email and forward it to your security team for investigation."
        )

# ✅ Streamlit UI
st.title("📧 PhishBot: Email Scanner")
st.write("Paste an email below and I’ll check if it looks suspicious.")

email_input = st.text_area("Your Email Text", height=200)

if st.button("Scan Email"):
    if email_input.strip():
        found, safe_found, score, sender_domain = scan_email(email_input)
        st.subheader("Scan Results")
        st.caption(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        hover_style = """
        <style>
        .risk-score {
            font-weight: bold;
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 6px solid;
            transition: background-color 0.3s ease;
        }
        .no-risk {
            background-color: rgba(204, 255, 204, 0.4);
            color: #222;
            border-color: green;
        }
        .no-risk:hover {
            background-color: rgba(120, 255, 120, 0.6);
        }
        .low-risk {
            background-color: rgba(255, 255, 204, 0.4);
            color: #333;
            border-color: gold;
        }
        .low-risk:hover {
            background-color: rgba(255, 230, 128, 0.6);
        }
        .medium-risk {
            background-color: rgba(255, 224, 178, 0.4);
            color: #333;
            border-color: orange;
        }
        .medium-risk:hover {
            background-color: rgba(255, 190, 120, 0.6);
        }
        .high-risk {
            background-color: rgba(255, 204, 204, 0.4);
            color: #222;
            border-color: red;
        }
        .high-risk:hover {
            background-color: rgba(255, 120, 120, 0.6);
        }
        </style>
        """
        st.markdown(hover_style, unsafe_allow_html=True)

        if score == 0:
            st.markdown(f"<div class='risk-score no-risk'>✅ Risk Score: {score}% (Safe)</div>", unsafe_allow_html=True)
        elif score <= 30:
            st.markdown(f"<div class='risk-score low-risk'>⚠️ Risk Score: {score}% (Low)</div>", unsafe_allow_html=True)
        elif score <= 60:
            st.markdown(f"<div class='risk-score medium-risk'>⚠️ Risk Score: {score}% (Medium)</div>", unsafe_allow_html=True)
        else:
            st.markdown(f"<div class='risk-score high-risk'>🚨 Risk Score: {score}% (High)</div>", unsafe_allow_html=True)

        st.write("🛡️ Recommended Actions:")
        st.info(get_advice(score))

        if found:
            st.write("Suspicious Phrases Found:")
            for word in found:
                st.write(f"- {word}")

        if safe_found:
            st.write("✅ Safe Phrases Detected:")
            for word in safe_found:
                st.write(f"- {word}")

        if sender_domain:
            st.write(f"📨 Sender Domain: `{sender_domain}`")
            if is_domain_spoofed(sender_domain, trusted_domains):
                st.warning("⚠️ Domain spoofing detected: This domain closely resembles a trusted one.")

        if detect_credential_trap(email_input):
            st.warning("🚨 Credential trap detected: This email may contain a form or prompt requesting sensitive information.")
    else:
        st.error("Please paste an email to scan.")
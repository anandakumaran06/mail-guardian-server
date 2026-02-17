from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class HeaderRequest(BaseModel):
    header: str


# ---------- BASIC FIELD EXTRACT ----------
def extract(pattern, text):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"


# ---------- DOMAIN REPUTATION ----------
TRUSTED_TLDS = [".gov", ".edu"]
COMMON_MAIL_PROVIDERS = ["gmail.com", "outlook.com", "yahoo.com", "icloud.com"]
KNOWN_BRANDS = ["sbi", "paypal", "amazon", "google", "microsoft", "apple"]


def domain_reputation(sender_line: str):
    match = re.search(r"<(.+?)>", sender_line)
    if not match:
        return "Unknown", "Could not extract sender domain"

    email = match.group(1).lower()
    domain = email.split("@")[-1]

    if any(domain.endswith(tld) for tld in TRUSTED_TLDS):
        return "Trusted", "Official organization domain"

    if domain in COMMON_MAIL_PROVIDERS:
        return "Neutral", "Public email provider"

    name_part = sender_line.lower()
    for brand in KNOWN_BRANDS:
        if brand in name_part and brand not in domain:
            return "Suspicious", f"Brand name '{brand}' does not match domain"

    if re.search(r"\d{3,}|-|secure|login|verify", domain):
        return "Suspicious", "Domain looks auto-generated or phishing-style"

    return "Unknown", "No strong indicators"


# ---------- HEADER PHISHING CHECK ----------
def header_phishing(header: str):
    h = header.lower()
    score = 0
    reasons = []

    if "spf=fail" in h or "dkim=fail" in h or "dmarc=fail" in h:
        score += 40
        reasons.append("Email authentication failed (SPF/DKIM/DMARC)")

    if "received:" not in h:
        score += 20
        reasons.append("Header routing information missing")

    return score, reasons


# ---------- TEXT SCAM DETECTION (SCREENSHOT SUPPORT) ----------
def text_scam_detection(text: str):
    words = [
        "urgent", "verify", "suspend", "click", "reward",
        "lottery", "winner", "bank", "blocked",
        "update kyc", "password", "otp", "limited time"
    ]

    score = 0
    reasons = []

    for w in words:
        if w in text.lower():
            score += 10
            reasons.append(f"Suspicious phrase: {w}")

    if "http://" in text.lower():
        score += 20
        reasons.append("Unsecured link detected")

    return score, reasons


# ---------- MAIN ANALYSIS ----------
@app.post("/analyze")
def analyze_email(request: HeaderRequest):
    data = request.header

    # detect if input is real header or normal message
    is_header = "received:" in data.lower() or "subject:" in data.lower()

    score = 0
    reasons = []

    if is_header:
        subject = extract(r"Subject:(.*)", data)
        sender = extract(r"From:(.*)", data)
        receiver = extract(r"To:(.*)", data)
        date = extract(r"Date:(.*)", data)

        h_score, h_reasons = header_phishing(data)
        score += h_score
        reasons.extend(h_reasons)

        reputation, rep_note = domain_reputation(sender)

    else:
        subject = "Screenshot Text"
        sender = "Unknown"
        receiver = "User"
        date = "N/A"
        reputation = "Unknown"
        rep_note = "Detected from screenshot message"

    # common text detection for both
    t_score, t_reasons = text_scam_detection(data)
    score += t_score
    reasons.extend(t_reasons)

    if score >= 70:
        risk = "High"
    elif score >= 35:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No suspicious indicators found")

    return {
        "subject": subject,
        "from": sender,
        "to": receiver,
        "date": date,
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "domain_reputation": reputation,
        "domain_note": rep_note,
        "checked_at": datetime.utcnow().isoformat()
    }


@app.get("/")
def root():
    return {"status": "Mail Guardian Online Backend Running"}

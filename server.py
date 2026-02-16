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


def extract(pattern, text):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"


# ---------------- DOMAIN REPUTATION ----------------
TRUSTED_TLDS = [".gov", ".edu"]
COMMON_MAIL_PROVIDERS = ["gmail.com", "outlook.com", "yahoo.com", "icloud.com"]
KNOWN_BRANDS = ["sbi", "paypal", "amazon", "google", "microsoft", "apple"]


def domain_reputation(sender_line: str):
    match = re.search(r"<(.+?)>", sender_line)
    if not match:
        return "Unknown", "Could not extract sender domain"

    email = match.group(1).lower()
    domain = email.split("@")[-1]

    # trusted government/education
    if any(domain.endswith(tld) for tld in TRUSTED_TLDS):
        return "Trusted", "Official organization domain"

    # common providers
    if domain in COMMON_MAIL_PROVIDERS:
        return "Neutral", "Public email provider"

    # brand impersonation check
    name_part = sender_line.lower()
    for brand in KNOWN_BRANDS:
        if brand in name_part and brand not in domain:
            return "Suspicious", f"Brand name '{brand}' does not match domain"

    # random suspicious domain patterns
    if re.search(r"\d{3,}|-|secure|login|verify", domain):
        return "Suspicious", "Domain looks auto‑generated or phishing‑style"

    return "Unknown", "No strong indicators"


# ---------------- PHISHING SCORE ----------------

def detect_phishing(header: str):
    h = header.lower()
    score = 0
    reasons = []

    keywords = [
        "verify", "urgent", "suspend", "immediately", "click",
        "login", "password", "bank", "account blocked",
        "lottery", "winner", "reward", "free", "otp"
    ]

    for k in keywords:
        if k in h:
            score += 12
            reasons.append(f"Suspicious word detected: {k}")

    if "spf=fail" in h or "dkim=fail" in h:
        score += 35
        reasons.append("Authentication failure detected (SPF/DKIM)")

    if "http://" in h or "bit.ly" in h or "tinyurl" in h:
        score += 20
        reasons.append("Shortened or insecure link detected")

    if score >= 70:
        risk = "High"
    elif score >= 35:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No suspicious indicators found")

    return risk, reasons, score


@app.get("/")
def root():
    return {"status": "Mail Guardian Analyzer Running"}


@app.post("/analyze")
def analyze_email(request: HeaderRequest):
    header = request.header

    subject = extract(r"Subject:(.*)", header)
    sender = extract(r"From:(.*)", header)
    receiver = extract(r"To:(.*)", header)
    date = extract(r"Date:(.*)", header)

    risk, reasons, score = detect_phishing(header)
    reputation, rep_reason = domain_reputation(sender)

    return {
        "subject": subject,
        "from": sender,
        "to": receiver,
        "date": date,
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "domain_reputation": reputation,
        "domain_note": rep_reason,
        "checked_at": datetime.utcnow().isoformat()
    }

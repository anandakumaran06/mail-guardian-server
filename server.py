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

class ScreenshotRequest(BaseModel):
    text: str


def extract(pattern, text):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"


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
            return "Suspicious", f"Brand '{brand}' mismatch domain"

    if re.search(r"\d{3,}|-|secure|login|verify", domain):
        return "Suspicious", "Domain looks phishing-style"

    return "Unknown", "No strong indicators"


def detect_phishing(text: str):
    t = text.lower()
    score = 0
    reasons = []

    keywords = [
        "verify", "urgent", "suspend", "click",
        "login", "password", "bank",
        "account blocked", "otp", "lottery", "winner"
    ]

    for k in keywords:
        if k in t:
            score += 15
            reasons.append(f"Keyword detected: {k}")

    if "http://" in t or "bit.ly" in t:
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

    return risk, score, reasons


@app.get("/")
def root():
    return {"status": "Mail Guardian Running"}


@app.post("/analyze")
def analyze_email(request: HeaderRequest):
    header = request.header

    subject = extract(r"Subject:(.*)", header)
    sender = extract(r"From:(.*)", header)
    receiver = extract(r"To:(.*)", header)
    date = extract(r"Date:(.*)", header)

    risk, score, reasons = detect_phishing(header)
    reputation, rep_reason = domain_reputation(sender)

    return {
        "mode": "header",
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


@app.post("/analyze_screenshot")
def analyze_screenshot(request: ScreenshotRequest):
    text = request.text

    risk, score, reasons = detect_phishing(text)

    return {
        "mode": "screenshot",
        "message_text": text,
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "checked_at": datetime.utcnow().isoformat()
    }
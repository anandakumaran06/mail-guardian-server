from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re
from datetime import datetime

app = FastAPI()

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- MODEL ----------------
class HeaderRequest(BaseModel):
    header: str


# ---------------- HELPER FUNCTION ----------------
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


# ---------------- PHISHING SCORE ----------------
def detect_phishing(text: str):
    h = text.lower()
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


# ---------------- ROOT ----------------
@app.get("/")
def root():
    return {"status": "Mail Guardian Analyzer Running"}


# ---------------- HEADER ANALYSIS ----------------
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


# ---------------- SCREENSHOT ANALYSIS ----------------
@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    content = await file.read()

    try:
        text = content.decode("utf-8", errors="ignore")
    except:
        text = str(content)

    risk, reasons, score = detect_phishing(text)

    return {
        "mode": "screenshot",
        "message_text": text[:1000],  # limit response size
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "checked_at": datetime.utcnow().isoformat()
    }
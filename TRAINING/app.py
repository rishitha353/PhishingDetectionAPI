from fastapi import FastAPI
from pydantic import BaseModel
import re
from urllib.parse import urlparse
import tldextract

app = FastAPI()

# ================= CONFIG =================
LEGITIMATE_DOMAINS = {
    'google.com', 'youtube.com', 'gmail.com', 'github.com',
    'amazon.com', 'amazon.in', 'microsoft.com', 'apple.com',
    'facebook.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'netflix.com', 'paypal.com', 'flipkart.com'
}

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'info',
    'click', 'work', 'live', 'fun', 'tk', 'ml', 'ga', 'cf'
}

SUSPICIOUS_KEYWORDS = {
    'login', 'verify', 'update', 'secure', 'account',
    'signin', 'bank', 'payment', 'confirm', 'password'
}

TRUSTED_BRANDS = [
    'google', 'facebook', 'amazon', 'paypal',
    'apple', 'microsoft', 'netflix', 'instagram'
]

# ================= MODELS =================
class UrlRequest(BaseModel):
    url: str

# ================= HELPERS =================
def is_valid_url(url: str) -> bool:
    if not url or len(url) < 5:
        return False

    url = url.strip()

    if url.isdigit():
        return False

    if '.' not in url:
        return False

    pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
        r'(\/.*)?$'
    )

    return bool(pattern.match(url))


def extract_domain_info(url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    ext = tldextract.extract(parsed.netloc)

    domain = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain

    return domain.lower(), subdomain.lower()


# ================= DETECTION ENGINE =================
def analyze_url(url: str):
    score = 0
    reasons = []

    domain, subdomain = extract_domain_info(url)

    # 1. Legitimate domain check
    if domain in LEGITIMATE_DOMAINS:
        return "legitimate", ["trusted_domain"]

    # 2. Subdomain trick
    for legit in LEGITIMATE_DOMAINS:
        if legit in subdomain:
            score += 2
            reasons.append("brand_in_subdomain")

    # 3. Suspicious TLD
    tld = domain.split('.')[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 2
        reasons.append("suspicious_tld")

    # 4. Keyword detection
    url_lower = url.lower()
    keyword_hits = [k for k in SUSPICIOUS_KEYWORDS if k in url_lower]
    if keyword_hits:
        score += len(keyword_hits)
        reasons.append("suspicious_keywords")

    # 5. Brand misuse
    for brand in TRUSTED_BRANDS:
        if brand in domain and domain not in LEGITIMATE_DOMAINS:
            score += 3
            reasons.append("brand_impersonation")

    # 6. IP address check
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        score += 3
        reasons.append("ip_address_url")

    # 7. URL length
    if len(url) > 75:
        score += 1
        reasons.append("long_url")

    # ================= FINAL CLASS =================
    if score >= 5:
        return "phishing", reasons
    elif score >= 2:
        return "suspicious", reasons
    else:
        return "legitimate", reasons


# ================= API =================
@app.post("/predict")
async def predict(req: UrlRequest):
    url = req.url.strip()

    if not is_valid_url(url):
        return {
            "status": "invalid",
            "reason": "invalid_url_format"
        }

    classification, reasons = analyze_url(url)

    return {
        "status": classification,
        "reasons": reasons
    }


@app.get("/health")
async def health():
    return {
        "status": "running",
        "type": "phishing_detection_api_v2"
    }
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import re
from urllib.parse import urlparse

app = FastAPI()

# ========== COMPLETE TRUSTED LEGITIMATE DOMAINS ==========
LEGITIMATE_DOMAINS = {
    'google.com', 'youtube.com', 'gmail.com', 'drive.google.com',
    'github.com', 'stackoverflow.com', 'gitlab.com', 'bitbucket.org',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
    'twitter.com', 'facebook.com', 'instagram.com', 'linkedin.com',
    'reddit.com', 'quora.com', 'medium.com', 'wikipedia.org',
    'spotify.com', 'whatsapp.com', 'telegram.org', 'discord.com',
    'cloudflare.com', 'digitalocean.com', 'render.com', 'vercel.com',
    'paypal.com', 'stripe.com', 'square.com',
}

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.online', '.site', '.website', '.info', '.click', '.download', '.work', '.live']
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'confirm', 'signin', 'account', 'alert', 'warning', 'validate', 'authenticate', 'auth', 'security', 'billing', 'payment']

def extract_domain(url: str) -> str:
    try:
        if '://' not in url:
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except:
        return url.lower().split('/')[0]

def is_valid_url(url: str) -> bool:
    """Strict URL validation - rejects invalid inputs like '123'"""
    if not url or len(url) < 4:
        return False
    
    url = url.strip()
    
    # Reject if it's just numbers or random characters without domain structure
    if re.match(r'^[\d\s]+$', url):
        return False
    
    # Must contain at least one dot (.) for domain
    if '.' not in url:
        return False
    
    # Check for valid TLD (at least 2 characters after last dot)
    parts = url.split('.')
    if len(parts) < 2:
        return False
    
    tld = parts[-1]
    # TLD should be 2-6 characters and letters only
    if len(tld) < 2 or len(tld) > 6 or not tld.isalpha():
        return False
    
    # Valid URL pattern
    url_pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9]+([-\.][a-zA-Z0-9]+)*\.)+'
        r'[a-zA-Z]{2,}'
        r'(:\d+)?'
        r'(\/.*)?$'
    )
    return url_pattern.match(url) is not None

def detect_phishing(url: str, domain: str) -> dict:
    # RULE 1: Exact match with trusted domain
    if domain in LEGITIMATE_DOMAINS:
        return {"is_phishing": False, "reason": "trusted_domain"}
    
    # RULE 2: Subdomain of trusted domain
    for trusted in LEGITIMATE_DOMAINS:
        if domain.endswith('.' + trusted):
            return {"is_phishing": False, "reason": "subdomain_of_trusted"}
    
    # RULE 3: Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return {"is_phishing": True, "reason": f"suspicious_tld"}
    
    # RULE 4: Brand typos
    trusted_brands = ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin']
    domain_part = domain.split('.')[0]
    for brand in trusted_brands:
        if brand in domain_part and domain not in LEGITIMATE_DOMAINS:
            return {"is_phishing": True, "reason": "brand_typo"}
    
    # RULE 5: Suspicious keywords
    url_lower = url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower and domain not in LEGITIMATE_DOMAINS:
            return {"is_phishing": True, "reason": f"suspicious_keyword"}
    
    # DEFAULT: Unknown domain - mark as PHISHING
    return {"is_phishing": True, "reason": "unknown_domain"}

class UrlRequest(BaseModel):
    url: str
    model_type: str = "rules"

@app.post("/predict")
async def predict(req: UrlRequest):
    url = req.url.strip()
    
    # FIRST: Validate URL format
    if not is_valid_url(url):
        return {
            "is_phishing": False,
            "confidence": 0.0,
            "model_used": "invalid_format",
            "reason": "Invalid URL format - Please enter a valid URL (e.g., google.com)"
        }
    
    # Add http:// if no protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Extract domain
    domain = extract_domain(url)
    
    # Detect phishing
    result = detect_phishing(url, domain)
    
    return {
        "is_phishing": result["is_phishing"],
        "confidence": 0.99 if not result["is_phishing"] else 0.95,
        "model_used": "rules_engine",
        "reason": result["reason"]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "models": ["rules_engine"], "description": "Rules-based phishing detection"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
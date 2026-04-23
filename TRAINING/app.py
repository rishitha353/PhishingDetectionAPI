from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import re
from urllib.parse import urlparse

app = FastAPI()

# ========== TRUSTED LEGITIMATE DOMAINS ==========
LEGITIMATE_DOMAINS = [
    # Tech & Search
    'google.com', 'youtube.com', 'gmail.com', 'drive.google.com',
    'github.com', 'stackoverflow.com', 'gitlab.com', 'bitbucket.org',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
    'twitter.com', 'facebook.com', 'instagram.com', 'linkedin.com',
    'reddit.com', 'quora.com', 'medium.com', 'wikipedia.org',
    'spotify.com', 'whatsapp.com', 'telegram.org', 'discord.com',
    'cloudflare.com', 'digitalocean.com', 'render.com', 'vercel.com',
    
    # News & Media
    'cnn.com', 'bbc.com', 'nytimes.com', 'wsj.com', 'bloomberg.com',
    'reuters.com', 'forbes.com', 'techcrunch.com', 'theverge.com',
    'wired.com', 'arstechnica.com', 'zdnet.com',
    
    # Shopping
    'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
    'etsy.com', 'shopify.com', 'aliexpress.com',
    
    # Banking & Finance (safe ones)
    'paypal.com', 'stripe.com', 'square.com', 'chase.com',
    'bankofamerica.com', 'wellsfargo.com', 'citi.com',
    
    # Education
    'udemy.com', 'coursera.org', 'edx.org', 'khanacademy.org',
    
    # Entertainment
    'twitch.tv', 'hulu.com', 'disneyplus.com', 'hbomax.com',
    'primevideo.com', 'peacocktv.com',
    
    # Other common legitimate
    'dropbox.com', 'box.com', 'onedrive.live.com', 'icloud.com',
    'adobe.com', 'salesforce.com', 'atlassian.com', 'slack.com'
]

# ========== SUSPICIOUS PATTERNS (Phishing) ==========
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'confirm', 'signin',
    'account', 'alert', 'warning', 'validate', 'authenticate',
    'security', 'important', 'notice', 'billing', 'payment'
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.online', '.site', '.website', '.info', '.click', '.download', '.work']

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        if '://' not in url:
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except:
        return url.lower()

def is_legitimate_typo(domain: str) -> bool:
    """Check if domain is a typo of a legitimate domain (phishing)"""
    for legit in LEGITIMATE_DOMAINS:
        # Check if the typo is very similar to a legitimate domain
        legit_part = legit.split('.')[0]
        domain_part = domain.split('.')[0]
        
        # Common typos
        if len(domain_part) > 3 and len(legit_part) > 3:
            # If most characters match but not exact (e.g., gooogle vs google)
            matches = sum(1 for a, b in zip(domain_part, legit_part) if a == b)
            if matches >= len(legit_part) - 2 and domain_part != legit_part:
                return True
    return False

def analyze_url(url: str) -> dict:
    """Analyze URL and return result"""
    domain = extract_domain(url)
    
    # RULE 1: Exact match with legitimate domain → LEGITIMATE
    if domain in LEGITIMATE_DOMAINS:
        return {"is_phishing": False, "reason": "Matched trusted domain"}
    
    # RULE 2: Subdomain of legitimate domain (e.g., accounts.google.com) → LEGITIMATE
    for legit in LEGITIMATE_DOMAINS:
        if domain.endswith('.' + legit):
            return {"is_phishing": False, "reason": f"Subdomain of trusted domain ({legit})"}
    
    # RULE 3: Typo of legitimate domain → PHISHING
    if is_legitimate_typo(domain):
        return {"is_phishing": True, "reason": "Typo of trusted domain"}
    
    # RULE 4: Suspicious TLDs → PHISHING
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return {"is_phishing": True, "reason": f"Suspicious TLD ({tld})"}
    
    # RULE 5: IP address instead of domain → PHISHING
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return {"is_phishing": True, "reason": "IP address used instead of domain"}
    
    # RULE 6: Suspicious keywords in URL → PHISHING
    url_lower = url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower and domain not in LEGITIMATE_DOMAINS:
            # Check if it's NOT a legitimate domain with that word
            is_fake = True
            for legit in LEGITIMATE_DOMAINS:
                if legit in url_lower:
                    is_fake = False
                    break
            if is_fake:
                return {"is_phishing": True, "reason": f"Suspicious keyword: '{keyword}'"}
    
    # RULE 7: Gibberish domain (random characters) → PHISHING
    domain_without_tld = domain.split('.')[0]
    if len(domain_without_tld) > 15:
        return {"is_phishing": True, "reason": "Very long/random domain name"}
    
    # Check for random character patterns (low vowel/consonant ratio or vice versa)
    vowels = sum(1 for c in domain_without_tld if c in 'aeiou')
    consonants = len(domain_without_tld) - vowels
    if len(domain_without_tld) > 8:
        if vowels == 0 or vowels > len(domain_without_tld) * 0.8:
            return {"is_phishing": True, "reason": "Random/gibberish domain pattern"}
    
    # RULE 8: Check for multiple hyphens/underscores (usually phishing)
    if domain.count('-') > 2 or domain.count('_') > 2:
        return {"is_phishing": True, "reason": "Too many hyphens/underscores"}
    
    # RULE 9: Contains @ symbol in URL (phishing trick)
    if '@' in url and '://' in url:
        return {"is_phishing": True, "reason": "Contains @ symbol in URL"}
    
    # RULE 10: Very long URL (over 100 chars) with suspicious patterns
    if len(url) > 100 and ('login' in url or 'verify' in url):
        return {"is_phishing": True, "reason": "Long URL with suspicious keywords"}
    
    # DEFAULT: If nothing else matches, check if it's a known legitimate site
    # For unknown domains, we'll mark as PHISHING to be safe
    return {"is_phishing": True, "reason": "Not recognized as legitimate domain"}


# ========== API ENDPOINTS ==========

class UrlRequest(BaseModel):
    url: str
    model_type: str = "rules"

class PredictionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    model_used: str
    reason: str = ""

@app.post("/predict", response_model=PredictionResponse)
async def predict(req: UrlRequest):
    url = req.url.strip()
    
    # Add http:// if no protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Analyze URL
    result = analyze_url(url)
    
    if result["is_phishing"]:
        return PredictionResponse(
            is_phishing=True,
            confidence=0.95,
            model_used="rules_engine",
            reason=result["reason"]
        )
    else:
        return PredictionResponse(
            is_phishing=False,
            confidence=0.99,
            model_used="rules_engine",
            reason=result["reason"]
        )

@app.get("/health")
async def health_check():
    return {"status": "healthy", "models": ["rules_engine"], "description": "Rules-based phishing detection"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
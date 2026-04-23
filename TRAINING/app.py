from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import re
from urllib.parse import urlparse

app = FastAPI()

# ========== COMPLETE TRUSTED LEGITIMATE DOMAINS ==========
LEGITIMATE_DOMAINS = {
    # Search & Tech
    'google.com', 'youtube.com', 'gmail.com', 'drive.google.com',
    'github.com', 'stackoverflow.com', 'gitlab.com', 'bitbucket.org',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
    'twitter.com', 'facebook.com', 'instagram.com', 'linkedin.com',
    'reddit.com', 'quora.com', 'medium.com', 'wikipedia.org',
    'spotify.com', 'whatsapp.com', 'telegram.org', 'discord.com',
    'cloudflare.com', 'digitalocean.com', 'render.com', 'vercel.com',
    'heroku.com', 'netlify.com', 'python.org', 'docker.com',
    
    # News & Media
    'cnn.com', 'bbc.com', 'nytimes.com', 'wsj.com', 'bloomberg.com',
    'reuters.com', 'forbes.com', 'techcrunch.com', 'theverge.com',
    'wired.com', 'arstechnica.com', 'zdnet.com', 'hackernews.com',
    
    # Shopping
    'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
    'etsy.com', 'shopify.com', 'aliexpress.com', 'costco.com',
    
    # Banking & Finance (legitimate ones)
    'paypal.com', 'stripe.com', 'square.com', 'chase.com',
    'bankofamerica.com', 'wellsfargo.com', 'citi.com', 'capitalone.com',
    'discover.com', 'americanexpress.com',
    
    # Education
    'udemy.com', 'coursera.org', 'edx.org', 'khanacademy.org',
    'udacity.com', 'pluralsight.com', 'linkedin.com/learning',
    
    # Entertainment
    'twitch.tv', 'hulu.com', 'disneyplus.com', 'hbomax.com',
    'primevideo.com', 'peacocktv.com', 'paramountplus.com',
    
    # Cloud & Dev
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
    'mongodb.com', 'redis.io', 'postgresql.org', 'mysql.com',
    
    # Other legitimate
    'dropbox.com', 'box.com', 'onedrive.live.com', 'icloud.com',
    'adobe.com', 'salesforce.com', 'atlassian.com', 'slack.com',
    'zoom.us', 'teams.microsoft.com', 'meet.google.com', 'skype.com',
    
    # Indian domains
    'flipkart.com', 'amazon.in', 'paytm.com', 'phonepe.com',
    'google.co.in', 'youtube.co.in', 'irctc.co.in', 'indianrail.gov.in'
}

# ========== SUSPICIOUS PATTERNS (Phishing) ==========
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'confirm', 'signin', 'sign-in',
    'account', 'alert', 'warning', 'validate', 'authenticate', 'auth',
    'security', 'important', 'notice', 'billing', 'payment', 'paypal',
    'appleid', 'netflix-verify', 'amazon-verify', 'bank-verify'
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.online', '.site', '.website', 
                   '.info', '.click', '.download', '.work', '.live', '.fun',
                   '.gq', '.tk', '.ml', '.ga', '.cf']

def extract_domain(url: str) -> str:
    """Extract clean domain from URL"""
    try:
        # Add protocol if missing
        if '://' not in url:
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    except:
        return url.lower().split('/')[0]

def is_valid_url(url: str) -> bool:
    """Check if URL has valid format"""
    if not url or len(url) < 3:
        return False
    
    # Basic URL pattern
    url_pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9]+([-\.][a-zA-Z0-9]+)*\.)+'
        r'[a-zA-Z]{2,}'
        r'(:\d+)?'
        r'(\/.*)?$'
    )
    return url_pattern.match(url) is not None

def detect_phishing(url: str, domain: str) -> dict:
    """Detect phishing based on rules"""
    
    # RULE 1: Exact match with trusted domain (LEGITIMATE)
    if domain in LEGITIMATE_DOMAINS:
        return {"is_phishing": False, "reason": "trusted_domain", "confidence": 0.99}
    
    # RULE 2: Subdomain of trusted domain (LEGITIMATE)
    for trusted in LEGITIMATE_DOMAINS:
        if domain.endswith('.' + trusted):
            return {"is_phishing": False, "reason": "subdomain_of_trusted", "confidence": 0.99}
    
    # RULE 3: Invalid URL format (INVALID)
    if not is_valid_url(url):
        return {"is_phishing": False, "reason": "invalid_url", "confidence": 0.0}
    
    # RULE 4: Suspicious TLDs (PHISHING)
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return {"is_phishing": True, "reason": f"suspicious_tld_{tld}", "confidence": 0.95}
    
    # RULE 5: IP address instead of domain (PHISHING)
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return {"is_phishing": True, "reason": "ip_address", "confidence": 0.98}
    
    # RULE 6: Common phishing pattern - legitimate name + suspicious TLD
    url_lower = url.lower()
    domain_part = domain.split('.')[0]
    
    # Check if domain contains trusted brand name
    trusted_brands = ['google', 'facebook', 'amazon', 'paypal', 'apple', 
                      'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin']
    
    for brand in trusted_brands:
        if brand in domain_part and domain not in LEGITIMATE_DOMAINS:
            return {"is_phishing": True, "reason": "brand_typo", "confidence": 0.96}
    
    # RULE 7: Suspicious keywords (PHISHING)
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower and domain not in LEGITIMATE_DOMAINS:
            return {"is_phishing": True, "reason": f"suspicious_keyword_{keyword}", "confidence": 0.94}
    
    # RULE 8: Multiple hyphens/underscores (PHISHING)
    if domain.count('-') > 2 or domain.count('_') > 2:
        return {"is_phishing": True, "reason": "too_many_hyphens", "confidence": 0.90}
    
    # RULE 9: Contains @ symbol (PHISHING)
    if '@' in url:
        return {"is_phishing": True, "reason": "contains_at_symbol", "confidence": 0.97}
    
    # RULE 10: Very long domain with random pattern (PHISHING)
    domain_without_tld = domain.split('.')[0]
    if len(domain_without_tld) > 20:
        return {"is_phishing": True, "reason": "too_long_domain", "confidence": 0.85}
    
    # Check for random character pattern (low vowel ratio)
    if len(domain_without_tld) > 10:
        vowels = sum(1 for c in domain_without_tld if c in 'aeiou')
        if vowels == 0 or vowels < 2:
            return {"is_phishing": True, "reason": "random_pattern", "confidence": 0.92}
    
    # DEFAULT: Unknown domain - mark as PHISHING to be safe
    return {"is_phishing": True, "reason": "unknown_domain", "confidence": 0.80}


# ========== API ENDPOINTS ==========

class UrlRequest(BaseModel):
    url: str
    model_type: str = "rules"

class PredictionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    model_used: str
    reason: str = ""

@app.post("/predict")
async def predict(req: UrlRequest):
    url = req.url.strip()
    
    # Add http:// if no protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Extract domain
    domain = extract_domain(url)
    
    # Validate URL format
    if not is_valid_url(url):
        return {
            "is_phishing": False,
            "confidence": 0.0,
            "model_used": "invalid_url",
            "reason": "Invalid URL format"
        }
    
    # Detect phishing
    result = detect_phishing(url, domain)
    
    return {
        "is_phishing": result["is_phishing"],
        "confidence": result["confidence"],
        "model_used": "rules_engine",
        "reason": result["reason"]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "models": ["rules_engine"], "description": "Rules-based phishing detection"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
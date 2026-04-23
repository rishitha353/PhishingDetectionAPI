from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import re
from urllib.parse import urlparse

app = FastAPI()

# ============================================
# COMPLETE LIST OF TRUSTED LEGITIMATE DOMAINS
# ============================================
TRUSTED_DOMAINS = {
    # Search & Tech
    'google.com', 'gmail.com', 'youtube.com', 'github.com',
    'stackoverflow.com', 'gitlab.com', 'bitbucket.org',
    'microsoft.com', 'apple.com', 'icloud.com',
    
        # Social Media
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
    'reddit.com', 'pinterest.com', 'tumblr.com', 'snapchat.com',
    'tiktok.com', 'telegram.org', 'whatsapp.com', 'discord.com',
    
    # Shopping
    'amazon.com', 'amazon.in', 'flipkart.com', 'ebay.com',
    'walmart.com', 'target.com', 'bestbuy.com', 'etsy.com',
    'shopify.com', 'aliexpress.com', 'paypal.com', 'stripe.com',
    
    # Streaming & Entertainment
    'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com',
    'hbomax.com', 'primevideo.com', 'twitch.tv',
    
    # Cloud & Development
    'cloudflare.com', 'render.com', 'onrender.com', 'vercel.com', 'heroku.com',
    'netlify.com', 'digitalocean.com', 'aws.amazon.com',
    'azure.microsoft.com', 'cloud.google.com',
    
    # News & Education
    'wikipedia.org', 'medium.com', 'quora.com', 'cnn.com',
    'bbc.com', 'nytimes.com', 'forbes.com', 'techcrunch.com',
    'coursera.org', 'udemy.com', 'khanacademy.org',
    
    # Banking & Finance (Legitimate)
    'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    'citi.com', 'capitalone.com', 'discover.com',
    
    # Indian Domains
    'irctc.co.in', 'indianrail.gov.in', 'gov.in', 'nic.in'
}

# ============================================
# PHISHING DETECTION RULES
# ============================================

# Suspicious TLDs (commonly used for phishing)
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.site', '.website',
    '.info', '.click', '.download', '.work', '.live', '.fun',
    '.tk', '.ml', '.ga', '.cf', '.gq', '.link', '.press',
    '.stream', '.account', '.secure', '.verify', '.login'
}

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'confirm', 'signin',
    'account', 'alert', 'warning', 'validate', 'authenticate',
    'auth', 'security', 'billing', 'payment', 'sign-in',
    'log-in', 'verification', 'password-reset', '2fa',
    'two-factor', 'identity-verification', 'unlock', 'suspended'
]

# Brand names (if these appear in suspicious domains, it's phishing)
TRUSTED_BRANDS = [
    'google', 'facebook', 'amazon', 'paypal', 'apple',
    'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin',
    'youtube', 'whatsapp', 'spotify', 'github', 'gmail',
    'icloud', 'hotmail', 'outlook', 'yahoo', 'bank', 'chase',
    'amex', 'visa', 'mastercard', 'paytm', 'flipkart'
]


# ============================================
# HELPER FUNCTIONS
# ============================================

def is_valid_url(url: str) -> tuple:
    """
    Check if URL has valid format
    Returns: (is_valid, error_message)
    """
    if not url or len(url) < 3:
        return (False, "URL is empty or too short")
    
    url = url.strip()
    
    # Reject pure numbers
    if url.isdigit():
        return (False, "URL cannot be just numbers")
    
    # Must contain at least one dot
    if '.' not in url:
        return (False, "URL must contain a domain (e.g., example.com)")
    
    # Check for valid domain format
    pattern = re.compile(
        r'^(https?:\/\/)?'                       # Optional protocol
        r'([a-zA-Z0-9][a-zA-Z0-9-]*\.)+'         # Domain name
        r'[a-zA-Z]{2,}'                          # TLD (at least 2 letters)
        r'(:\d+)?'                               # Optional port
        r'(\/.*)?$'                              # Optional path
    )
    
    if not pattern.match(url):
        return (False, "Invalid URL format. Example: google.com")
    
    return (True, "")


def extract_domain(url: str) -> str:
    """Extract clean domain from URL"""
    try:
        # Add protocol if missing for proper parsing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    except:
        # Fallback: simple extraction
        domain = url.lower().split('/')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain


def detect_phishing(url: str, domain: str) -> dict:
    """
    Main phishing detection logic
    Returns: (is_phishing, reason, model_used)
    """
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    # ============================================
    # RULE 1: EXACT MATCH WITH TRUSTED DOMAIN → LEGITIMATE
    # ============================================
    if domain_lower in TRUSTED_DOMAINS:
        return {
            "is_phishing": False,
            "reason": "Exact match with trusted domain",
            "model_used": "whitelist"
        }
    
    # ============================================
    # RULE 2: SUBDOMAIN OF TRUSTED DOMAIN → LEGITIMATE
    # Example: mail.google.com, drive.google.com
    # ============================================
    for trusted in TRUSTED_DOMAINS:
        if domain_lower.endswith('.' + trusted):
            return {
                "is_phishing": False,
                "reason": f"Subdomain of trusted domain ({trusted})",
                "model_used": "whitelist"
            }
    
    # ============================================
    # RULE 3: BRAND IMPERSONATION → PHISHING
    # Example: paypal.com.login.xyz, google.verify-account.xyz
    # ============================================
    # Check if domain contains any trusted brand name
    for brand in TRUSTED_BRANDS:
        if brand in domain_lower:
            # Brand found but domain not in trusted list → phishing
            return {
                "is_phishing": True,
                "reason": f"Brand impersonation: '{brand}' appears in suspicious domain",
                "model_used": "brand_impersonation"
            }
    
    # ============================================
    # RULE 4: SUSPICIOUS TLDs → PHISHING
    # Example: anything.xyz, anything.top, anything.online
    # ============================================
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return {
                "is_phishing": True,
                "reason": f"Suspicious domain extension '{tld}' used for phishing",
                "model_used": "suspicious_tld"
            }
    
    # ============================================
    # RULE 5: SUSPICIOUS KEYWORDS IN URL → PHISHING
    # Example: login, verify, secure, etc.
    # ============================================
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower and domain_lower not in TRUSTED_DOMAINS:
            return {
                "is_phishing": True,
                "reason": f"Suspicious keyword '{keyword}' detected in URL",
                "model_used": "keyword_detection"
            }
    
    # ============================================
    # RULE 6: MULTIPLE DOTS PATTERN → PHISHING
    # Example: paypal.com.login.xyz (has 3+ dots trying to trick users)
    # ============================================
    if domain_lower.count('.') >= 3:
        parts = domain_lower.split('.')
        # Check if any part looks like a brand name
        for brand in TRUSTED_BRANDS:
            if brand in parts and domain_lower not in TRUSTED_DOMAINS:
                return {
                    "is_phishing": True,
                    "reason": "Suspicious multi-dot domain (malicious redirection pattern)",
                    "model_used": "multi_dot_pattern"
                }
    
    # ============================================
    # RULE 7: IP ADDRESS INSTEAD OF DOMAIN → PHISHING
    # Example: http://192.168.1.1/login
    # ============================================
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_lower.split('/')[0]):
        return {
            "is_phishing": True,
            "reason": "IP address used instead of domain name (common phishing tactic)",
            "model_used": "ip_address"
        }
    
    # ============================================
    # RULE 8: RANDOM/GIBBERISH DOMAIN → PHISHING
    # Example: ajsdhkjasdhkjasd.online
    # ============================================
    domain_name = domain_lower.split('.')[0]
    if len(domain_name) > 15:
        # Check if it looks random (low vowel count or many repeating patterns)
        vowels = sum(1 for c in domain_name if c in 'aeiou')
        if vowels < 2 or vowels > len(domain_name) - 2:
            return {
                "is_phishing": True,
                "reason": "Random/gibberish domain pattern",
                "model_used": "random_domain"
            }
    
    # ============================================
    # DEFAULT: UNKNOWN DOMAIN → PHISHING (safe default)
    # ============================================
    return {
        "is_phishing": True,
        "reason": "Unknown/untrusted domain - treated as suspicious",
        "model_used": "default_safe"
    }


# ============================================
# API ENDPOINTS
# ============================================

class UrlRequest(BaseModel):
    url: str


@app.post("/predict")
async def predict(req: UrlRequest):
    original_url = req.url.strip()
    
    print(f"Received URL: {original_url}")
    
    # Step 1: Validate URL format
    is_valid, error_msg = is_valid_url(original_url)
    
    if not is_valid:
        return {
            "is_phishing": False,
            "model_used": "invalid_format",
            "reason": error_msg
        }
    
    # Step 2: Normalize URL (add protocol if missing)
    url = original_url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Step 3: Extract domain
    domain = extract_domain(url)
    
    print(f"Extracted domain: {domain}")
    
    # Step 4: Detect phishing
    result = detect_phishing(url, domain)
    
    print(f"Result: is_phishing={result['is_phishing']}, reason={result['reason']}")
    
    return {
        "is_phishing": result["is_phishing"],
        "model_used": result["model_used"],
        "reason": result["reason"]
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "type": "phishing_detection",
        "version": "3.0.0"
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=10000)
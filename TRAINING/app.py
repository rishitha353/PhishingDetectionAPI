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
    'microsoft.com', 'apple.com', 'icloud.com', 'x.com',
    
    # Social Media
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'reddit.com', 'pinterest.com', 'tumblr.com', 'snapchat.com',
    'tiktok.com', 'telegram.org', 'whatsapp.com', 'discord.com',
    'messenger.com', 'wechat.com', 'line.me', 'viber.com', 'skype.com',
    'signal.org', 'mastodon.social', 'patreon.com', 'kickstarter.com', 'indiegogo.com',
    'change.org', 'gofundme.com', 'meetup.com', 'eventbrite.com', 'ticketmaster.com',
    'bookmyshow.com', 'stubhub.com', 'fandango.com', 'goodreads.com', 'archiveofourown.org',
    
    # Shopping
    'amazon.com', 'amazon.in', 'flipkart.com', 'ebay.com',
    'walmart.com', 'target.com', 'bestbuy.com', 'etsy.com',
    'shopify.com', 'aliexpress.com', 'paypal.com', 'stripe.com',
    'alibaba.com', 'costco.com', 'ikea.com', 'hm.com', 'zara.com',
    'nike.com', 'adidas.com', 'puma.com', 'reebok.com', 'underarmour.com',
    'myntra.com', 'ajio.com', 'nykaa.com', 'tatacliq.com', 'snapdeal.com',
    'olx.in', 'quikr.com', 'rakuten.com', 'mercadolibre.com', 'shopee.com',
    'lazada.com', 'jd.com', 'taobao.com', 'tmall.com',
    
    # Streaming & Entertainment
    'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com',
    'hbomax.com', 'primevideo.com', 'twitch.tv', 'hotstar.com',
    'sonyliv.com', 'zee5.com', 'crunchyroll.com', 'peacocktv.com',
    'paramountplus.com', 'max.com', 'appletvplus.com', 'deezer.com',
    'tidal.com', 'bandcamp.com', 'mixcloud.com', 'soundcloud.com',
    'gaana.com', 'jiosaavn.com', 'wynk.in', 'shazam.com', 'last.fm',
    'roblox.com', 'epicgames.com', 'steampowered.com', 'valvesoftware.com',
    'gog.com', 'ubisoft.com', 'ea.com', 'riotgames.com', 'blizzard.com',
    'minecraft.net', 'playstation.com', 'xbox.com', 'nintendo.com',
    'sega.com', 'bandainamcoent.com', 'capcom.com', 'square-enix.com', 'konami.com',
    
    # Cloud & Development
    'cloudflare.com', 'render.com', 'onrender.com', 'vercel.com', 'heroku.com',
    'netlify.com', 'digitalocean.com', 'aws.amazon.com', 'azure.microsoft.com',
    'cloud.google.com', 'linode.com', 'ovhcloud.com', 'mongodb.com', 'mysql.com',
    'postgresql.org', 'sqlite.org', 'jetbrains.com', 'eclipse.org', 'anaconda.com',
    'python.org', 'java.com', 'php.net', 'r-project.org', 'scala-lang.org',
    'rust-lang.org', 'go.dev', 'nodejs.org', 'react.dev', 'angular.io',
    'vuejs.org', 'tensorflow.org', 'pytorch.org', 'oraclecloud.com', 'sapstore.com',
    'workday.com', 'servicenow.com', 'hubspot.com', 'mailchimp.com', 'constantcontact.com',
    'sendgrid.com', 'twilio.com', 'plaid.com', 'squareup.com', 'adyen.com',
    'firefox.com', 'thunderbird.net', 'protonmail.com', 'fastmail.com', 'zoho.in',
    'yandex.com', 'baidu.com', 'naver.com', 'mail.ru', 'duckduckgo.com', 'ecosia.org',
    'ask.com', 'aol.com', 'live.com', 'blogger.com', 'ghost.org', 'substack.com',
    'flipboard.com', 'feedly.com', 'pocket.com', 'instapaper.com', 'evernote.com',
    'onenote.com', 'todoist.com', 'rememberthemilk.com', 'basecamp.com', 'monday.com',
    'airtable.com', 'smartsheet.com', 'zapier.com', 'ifttt.com', 'typeform.com',
    'surveymonkey.com', 'qualtrics.com', 'docusign.com', 'pandadoc.com', 'dropboxpaper.com',
    
    # News & Education
    'wikipedia.org', 'medium.com', 'quora.com', 'cnn.com',
    'bbc.com', 'nytimes.com', 'forbes.com', 'techcrunch.com',
    'coursera.org', 'udemy.com', 'khanacademy.org', 'w3schools.com',
    'geeksforgeeks.org', 'developer.mozilla.org', 'freecodecamp.org',
    'npr.org', 'reuters.com', 'apnews.com', 'wsj.com', 'ft.com',
    'bloomberg.com', 'businessinsider.com', 'economist.com', 'cnbc.com',
    'marketwatch.com', 'usatoday.com', 'latimes.com', 'theguardian.com',
    'independent.co.uk', 'aljazeera.com', 'dw.com', 'france24.com',
    'scmp.com', 'japantimes.co.jp', 'nature.com', 'science.org',
    'scientificamerican.com', 'nationalgeographic.com', 'smithsonianmag.com',
    'webmd.com', 'mayoclinic.org', 'cdc.gov', 'nih.gov', 'medlineplus.gov',
    'healthline.com', 'everydayhealth.com', 'goodrx.com', 'drugs.com', 'zocdoc.com',
    'kaggle.com', 'leetcode.com', 'hackerrank.com', 'codechef.com', 'codeforces.com',
    'topcoder.com', 'producthunt.com', 'crunchbase.com', 'glassdoor.com', 'indeed.com',
    'naukri.com', 'monsterindia.com', 'fiverr.com', 'upwork.com', 'freelancer.com',
    'behance.net', 'dribbble.com', 'envato.com', 'freepik.com', 'pixabay.com',
    'pexels.com', 'unsplash.com', 'shutterstock.com', 'gettyimages.com', 'alamy.com',
    
    # Indian Domains
    'irctc.co.in', 'indianrail.gov.in', 'gov.in', 'nic.in', 'ndtv.com',
    'hindustantimes.com', 'timesofindia.com', 'thehindu.com', 'india.com',
    'moneycontrol.com', 'investing.com', 'byjus.com', 'unacademy.com',
    'airtel.in', 'jio.com', 'vi.in', 'bsnl.co.in', 'sbi.co.in',
    'icicibank.com', 'hdfcbank.com', 'axisbank.com', 'kotak.com',
    'paytm.com', 'phonepe.com', 'razorpay.com', 'upstox.com', 'zerodha.com',
    'nseindia.com', 'bseindia.com', 'imdb.com', 'olx.in', 'quikr.com',
    'tata.com', 'mahindra.com', 'godrej.com', 'samsungindia.com', 'miindia.com',
    'lgindia.com', 'heromotocorp.com', 'bajajauto.com', 'tvsmotor.com',
    'royalenfield.com', 'marutisuzuki.com', 'hyundai.co.in', 'kia.com/in',
    'toyotabharat.com', 'hdfcergo.com', 'policybazaar.com', 'licindia.in',
    'irda.gov.in', 'sebi.gov.in', 'rbi.org.in', 'npci.org.in', 'bharatbillpay.com',
    'fastag.org', 'umang.gov.in', 'mygov.in', 'pmindia.gov.in', 'isro.gov.in',
    'drdo.gov.in', 'iitb.ac.in', 'iitm.ac.in', 'iisc.ac.in', 'du.ac.in',
    'osmania.ac.in', 'jntuh.ac.in', 'bits-pilani.ac.in', 'delhivery.com',
    'bluedart.com', 'dtdc.in', 'indiapost.gov.in', 'redbus.in', 'abhibus.com',
    'ixigo.com', 'yatra.com', 'cleartrip.com', 'easemytrip.com', 'goibibo.com',
    'makemytrip.com', 'booking.com', 'airbnb.com', 'agoda.com', 'trivago.com',
    'expedia.com', 'tripadvisor.com', 'kayak.com', 'skyscanner.net', 'hostelworld.com',
    'airindia.com', 'indigo.in', 'spicejet.com', 'akasaair.com', 'vistara.com',
    
    # Banking & Finance
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
    'capitalone.com', 'discover.com', 'americanexpress.com', 'mastercard.com',
    'visa.com', 'wise.com', 'remitly.com', 'xoom.com', 'westernunion.com',
    'moneygram.com', 'coinbase.com', 'binance.com', 'kraken.com', 'coindesk.com',
    'coinmarketcap.com', 'cointelegraph.com',
    
    # Travel & Transportation
    'uber.com', 'ola.com', 'rapido.bike', 'swiggy.com', 'zomato.com',
    'dominos.co.in', 'pizzahut.co.in', 'mcdonalds.com', 'kfc.co.in',
    'burgerking.in', 'subway.com', 'marriott.com', 'hilton.com', 'hyatt.com',
    'accor.com', 'ihg.com', 'wyndhamhotels.com', 'choicehotels.com', 'bestwestern.com',
    'bookingbuddy.com', 'cheapoair.com', 'orbitz.com', 'travelocity.com', 'priceline.com',
    'hotels.com', 'emirates.com', 'qatarairways.com', 'singaporeair.com', 'lufthansa.com',
    'britishairways.com',
    
    # Tech Hardware
    'oracle.com', 'ibm.com', 'intel.com', 'amd.com', 'nvidia.com', 'qualcomm.com',
    'mediatek.com', 'arm.com', 'tsmc.com', 'globalfoundries.com', 'analog.com',
    'st.com', 'infineon.com', 'texasinstruments.com', 'hp.com', 'dell.com',
    'lenovo.com', 'asus.com', 'acer.com', 'msi.com', 'gigabyte.com', 'asrock.com',
    'tplink.com', 'netgear.com', 'linksys.com', 'sony.com', 'panasonic.com',
    'philips.com', 'lg.com', 'bosch.com', 'whirlpool.com', 'haier.com', 'siemens.com',
    'tcl.com', 'hisense.com', 'samsung.com', 'mi.com', 'oneplus.com', 'oppo.com',
    'vivo.com', 'realme.com', 'huawei.com', 'canon.com', 'epson.com', 'brother.com',
    'logitech.com', 'razer.com', 'corsair.com', 'xerox.com',
    
    # Government & International
    'fedex.com', 'dhl.com', 'ups.com', 'usps.com', 'canada.ca', 'gov.uk',
    'whitehouse.gov', 'india.gov.in', 'uidai.gov.in', 'incometax.gov.in',
    'epfindia.gov.in', 'digilocker.gov.in', 'nasa.gov', 'noaa.gov', 'who.int',
    'un.org', 'worldbank.org', 'imf.org', 'unicef.org', 'redcross.org',
    'amnesty.org', 'greenpeace.org', 'weforum.org', 'unesco.org',
    'europa.eu', 'ec.europa.eu', 'nato.int', 'interpol.int', 'olympics.com',
    'fifa.com', 'uefa.com', 'icc-cricket.com', 'formula1.com', 'nba.com',
    'nfl.com', 'mlb.com', 'nhl.com', 'espn.com', 'cbssports.com', 'skysports.com',
    'premierleague.com', 'tennis.com', 'atptour.com', 'wtatennis.com', 'chess.com',
    'lichess.org',
    
    # Education & Learning
    'duolingo.com', 'memrise.com', 'busuu.com', 'grammarly.com', 'prowritingaid.com',
    'canva.com', 'canva.site', 'pixlr.com', 'photopea.com', 'gimp.org', 'blender.org',
    'unity.com', 'unrealengine.com', 'autocad.com', 'rhino3d.com', 'sketchup.com',
    'figma.com', 'notion.so', 'trello.com', 'asana.com', 'clickup.com', 'slack.com',
    'teams.microsoft.com', 'zoom.us', 'teamviewer.com', 'anydesk.com', 'cisco.com',
    'vmware.com',
    
    # Food Delivery
    'swiggy.com', 'zomato.com', 'dominos.co.in', 'pizzahut.co.in', 'mcdonalds.com',
    'kfc.co.in', 'burgerking.in', 'subway.com', 'tacobell.com',
    
    # Entertainment & Media
    'rottentomatoes.com', 'metacritic.com', 'ign.com', 'gamespot.com', 'pcgamer.com',
    'tomsguide.com', 'tomsherdware.com', 'anandtech.com', 'arstechnica.com',
    'zdnet.com', 'wired.com', 'engadget.com', 'theverge.com', 'cnet.com',
    'gsmarena.com', 'notebookcheck.net', 'dxomark.com', 'ifixit.com', 'macrumors.com',
    '9to5mac.com', 'androidpolice.com', 'xda-developers.com', 'makeuseof.com',
    'howtogeek.com', 'lifehacker.com', 'instructables.com', 'stackexchange.com',
    'serverfault.com', 'superuser.com', 'askubuntu.com', 'dev.to', 'hashnode.com',
    'codepen.io', 'jsfiddle.net', 'replit.com', 'glitch.com',
    
    # Security & VPN
    'lastpass.com', '1password.com', 'bitwarden.com', 'nordvpn.com', 'expressvpn.com',
    'protonvpn.com', 'avast.com', 'avg.com', 'kaspersky.com', 'mcafee.com',
    'norton.com', 'malwarebytes.com', 'eset.com', 'bitdefender.com', 'trendmicro.com',
    
    # Consulting & IT Services
    'accenture.com', 'tcs.com', 'infosys.com', 'wipro.com', 'hcltech.com',
    'cognizant.com', 'capgemini.com', 'deloitte.com', 'pwc.com', 'ey.com',
    'kpmg.com', 'mckinsey.com', 'bcg.com', 'bain.com',
    
    # Other Legitimate
    'speedtest.net', 'fast.com', 'timeanddate.com', 'accuweather.com', 'weather.com',
    'archive.org', 'wikihow.com', 'cambridge.org', 'oxford.com',
    'godaddy.com', 'namecheap.com', 'hostinger.com', 'bluehost.com',
    'okta.com', 'auth0.com', 'atlassian.com', 'zenefits.com', 'gusto.com',
    'xero.com', 'quickbooks.com', 'adp.com', 'paychex.com',
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
    """Check if URL has valid format"""
    if not url or len(url) < 3:
        return (False, "URL is empty or too short")
    
    url = url.strip()
    
    if url.isdigit():
        return (False, "URL cannot be just numbers")
    
    if '.' not in url:
        return (False, "URL must contain a domain (e.g., example.com)")
    
    pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9][a-zA-Z0-9-]*\.)+'
        r'[a-zA-Z]{2,}'
        r'(:\d+)?'
        r'(\/.*)?$'
    )
    
    if not pattern.match(url):
        return (False, "Invalid URL format. Example: google.com")
    
    return (True, "")


def extract_domain(url: str) -> str:
    """Extract clean domain from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    except:
        domain = url.lower().split('/')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain


def detect_phishing(url: str, domain: str) -> dict:
    """Main phishing detection logic"""
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    # RULE 1: EXACT MATCH WITH TRUSTED DOMAIN → LEGITIMATE
    if domain_lower in TRUSTED_DOMAINS:
        return {
            "is_phishing": False,
            "reason": "Exact match with trusted domain",
            "model_used": "whitelist"
        }
    
    # RULE 2: SUBDOMAIN OF TRUSTED DOMAIN → LEGITIMATE
    for trusted in TRUSTED_DOMAINS:
        if domain_lower.endswith('.' + trusted):
            return {
                "is_phishing": False,
                "reason": f"Subdomain of trusted domain ({trusted})",
                "model_used": "whitelist"
            }
    
    # RULE 3: BRAND IMPERSONATION → PHISHING
    for brand in TRUSTED_BRANDS:
        if brand in domain_lower:
            return {
                "is_phishing": True,
                "reason": f"Brand impersonation: '{brand}' appears in suspicious domain",
                "model_used": "brand_impersonation"
            }
    
    # RULE 4: SUSPICIOUS TLDs → PHISHING
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return {
                "is_phishing": True,
                "reason": f"Suspicious domain extension '{tld}' used for phishing",
                "model_used": "suspicious_tld"
            }
    
    # RULE 5: SUSPICIOUS KEYWORDS IN URL → PHISHING
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower and domain_lower not in TRUSTED_DOMAINS:
            return {
                "is_phishing": True,
                "reason": f"Suspicious keyword '{keyword}' detected in URL",
                "model_used": "keyword_detection"
            }
    
    # RULE 6: MULTIPLE DOTS PATTERN → PHISHING
    if domain_lower.count('.') >= 3:
        parts = domain_lower.split('.')
        for brand in TRUSTED_BRANDS:
            if brand in parts and domain_lower not in TRUSTED_DOMAINS:
                return {
                    "is_phishing": True,
                    "reason": "Suspicious multi-dot domain (malicious redirection pattern)",
                    "model_used": "multi_dot_pattern"
                }
    
    # RULE 7: IP ADDRESS → PHISHING
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_lower.split('/')[0]):
        return {
            "is_phishing": True,
            "reason": "IP address used instead of domain name",
            "model_used": "ip_address"
        }
    
    # RULE 8: RANDOM/GIBBERISH DOMAIN → PHISHING
    domain_name = domain_lower.split('.')[0]
    if len(domain_name) > 15:
        vowels = sum(1 for c in domain_name if c in 'aeiou')
        if vowels < 2 or vowels > len(domain_name) - 2:
            return {
                "is_phishing": True,
                "reason": "Random/gibberish domain pattern",
                "model_used": "random_domain"
            }
    
    # DEFAULT: UNKNOWN DOMAIN → PHISHING
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
    
    is_valid, error_msg = is_valid_url(original_url)
    
    if not is_valid:
        return {
            "is_phishing": False,
            "model_used": "invalid_format",
            "reason": error_msg
        }
    
    url = original_url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    domain = extract_domain(url)
    
    print(f"Extracted domain: {domain}")
    
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
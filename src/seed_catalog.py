"""
src/seed_catalog.py — Verified Domain Catalog Schema, 5-Class Labels & Synthetic Lookalike Registry

Defines:
- 5-class label taxonomy:
    0 = Verified phishing
    1 = Official legitimate
    2 = Legitimate third-party
    3 = Suspicious/uncertain
    4 = Compromised legitimate
- Candidate seed domains across Categories A–G for verification against Tranco,
  threat feeds, and optional live DNS/TLS checks (never blindly auto-trusted).
- Synthetic lookalike fixtures using reserved `.example` domains (unit/behavior tests only).
"""

from __future__ import annotations

MULTICLASS_LABEL_NAMES: dict[int, str] = {
    0: "verified_phishing",
    1: "official_legitimate",
    2: "legitimate_third_party",
    3: "suspicious_uncertain",
    4: "compromised_legitimate",
}

# Candidate seed inventory across Categories A-G
# Tuple format: (domain, brand, category, ownership_type, intended_label, is_hosting_platform, note)
VERIFIED_SEED_CANDIDATES: list[tuple[str, str, str, str, int, bool, str]] = [
    # A. E-commerce and shopping
    ("amazon.in", "Amazon", "ecommerce", "official", 1, False, "Official Amazon India storefront"),
    ("amazon.com", "Amazon", "ecommerce", "official", 1, False, "Official Amazon US storefront"),
    ("amazon.co.uk", "Amazon", "ecommerce", "official", 1, False, "Official Amazon UK storefront"),
    ("flipkart.com", "Flipkart", "ecommerce", "official", 1, False, "Official Flipkart marketplace"),
    ("myntra.com", "Myntra", "ecommerce", "official", 1, False, "Official Myntra fashion retail"),
    ("meesho.com", "Meesho", "ecommerce", "official", 1, False, "Official Meesho marketplace"),
    ("ajio.com", "AJIO", "ecommerce", "official", 1, False, "Official AJIO retail"),
    ("nykaa.com", "Nykaa", "ecommerce", "official", 1, False, "Official Nykaa storefront"),
    ("tatacliq.com", "Tata CLiQ", "ecommerce", "official", 1, False, "Official Tata CLiQ store"),
    ("reliancedigital.in", "Reliance Digital", "ecommerce", "official", 1, False, "Official Reliance Digital store"),
    ("croma.com", "Croma", "ecommerce", "official", 1, False, "Official Croma electronics store"),
    ("ebay.com", "eBay", "ecommerce", "official", 1, False, "Official eBay marketplace"),
    ("walmart.com", "Walmart", "ecommerce", "official", 1, False, "Official Walmart storefront"),
    ("etsy.com", "Etsy", "ecommerce", "official", 1, False, "Official Etsy marketplace"),
    ("ikea.com", "IKEA", "ecommerce", "official", 1, False, "Official IKEA store"),
    ("apple.com", "Apple", "ecommerce", "official", 1, False, "Official Apple website"),

    # B. Search engines, email and productivity
    ("google.com", "Google", "productivity", "official", 1, False, "Official Google search & portal"),
    ("google.co.in", "Google", "productivity", "official", 1, False, "Official Google India"),
    ("mail.google.com", "Google", "productivity", "official", 1, False, "Official Gmail webmail"),
    ("youtube.com", "YouTube", "media", "official", 1, False, "Official YouTube platform"),
    ("youtu.be", "YouTube", "media", "official", 1, False, "Official YouTube shortener"),
    ("drive.google.com", "Google", "productivity", "third_party", 2, True, "User file sharing host; inspect shared document links"),
    ("docs.google.com", "Google", "productivity", "third_party", 2, True, "User documents/forms host; inspect page content"),
    ("microsoft.com", "Microsoft", "productivity", "official", 1, False, "Official Microsoft domain"),
    ("outlook.com", "Microsoft", "productivity", "official", 1, False, "Official Outlook webmail"),
    ("outlook.office.com", "Microsoft", "productivity", "official", 1, False, "Official Microsoft 365 mail"),
    ("office.com", "Microsoft", "productivity", "official", 1, False, "Official Microsoft Office portal"),
    ("onedrive.live.com", "Microsoft", "productivity", "third_party", 2, True, "User cloud storage portal; inspect shared targets"),
    ("yahoo.com", "Yahoo", "productivity", "official", 1, False, "Official Yahoo portal"),
    ("proton.me", "Proton", "productivity", "official", 1, False, "Official Proton Mail & Privacy"),
    ("dropbox.com", "Dropbox", "productivity", "third_party", 2, False, "Cloud storage service"),
    ("notion.so", "Notion", "productivity", "third_party", 2, False, "Workspace & docs service"),
    ("zoom.us", "Zoom", "productivity", "official", 1, False, "Official Zoom conferencing"),
    ("slack.com", "Slack", "productivity", "official", 1, False, "Official Slack workspace"),

    # C. Social media and communication
    ("instagram.com", "Instagram", "social", "official", 1, False, "Official Instagram platform"),
    ("facebook.com", "Facebook", "social", "official", 1, False, "Official Facebook platform"),
    ("whatsapp.com", "WhatsApp", "social", "official", 1, False, "Official WhatsApp portal"),
    ("web.whatsapp.com", "WhatsApp", "social", "official", 1, False, "Official WhatsApp Web"),
    ("x.com", "X", "social", "official", 1, False, "Official X platform"),
    ("linkedin.com", "LinkedIn", "social", "official", 1, False, "Official LinkedIn network"),
    ("reddit.com", "Reddit", "social", "official", 1, False, "Official Reddit forum"),
    ("pinterest.com", "Pinterest", "social", "official", 1, False, "Official Pinterest platform"),
    ("telegram.org", "Telegram", "social", "official", 1, False, "Official Telegram website"),
    ("web.telegram.org", "Telegram", "social", "official", 1, False, "Official Telegram Web"),
    ("discord.com", "Discord", "social", "official", 1, False, "Official Discord platform"),
    ("snapchat.com", "Snapchat", "social", "official", 1, False, "Official Snapchat platform"),
    ("threads.net", "Threads", "social", "official", 1, False, "Official Threads platform"),
    ("github.com", "GitHub", "developer", "official", 1, False, "Official GitHub platform"),
    ("gitlab.com", "GitLab", "developer", "official", 1, False, "Official GitLab platform"),

    # D. Indian banking and payment services
    ("sbi.co.in", "SBI", "banking", "official", 1, False, "Official State Bank of India"),
    ("onlinesbi.sbi", "SBI", "banking", "official", 1, False, "Official OnlineSBI portal"),
    ("hdfcbank.com", "HDFC Bank", "banking", "official", 1, False, "Official HDFC Bank"),
    ("icicibank.com", "ICICI Bank", "banking", "official", 1, False, "Official ICICI Bank"),
    ("axisbank.com", "Axis Bank", "banking", "official", 1, False, "Official Axis Bank"),
    ("kotak.com", "Kotak Mahindra", "banking", "official", 1, False, "Official Kotak Bank"),
    ("bankofbaroda.in", "Bank of Baroda", "banking", "official", 1, False, "Official Bank of Baroda"),
    ("canarabank.in", "Canara Bank", "banking", "official", 1, False, "Official Canara Bank"),
    ("indianbank.in", "Indian Bank", "banking", "official", 1, False, "Official Indian Bank"),
    ("rbi.org.in", "RBI", "banking", "official", 1, False, "Reserve Bank of India"),
    ("npci.org.in", "NPCI", "banking", "official", 1, False, "National Payments Corp of India"),
    ("phonepe.com", "PhonePe", "payment", "official", 1, False, "Official PhonePe domain"),
    ("paytm.com", "Paytm", "payment", "official", 1, False, "Official Paytm domain"),
    ("pay.google.com", "Google Pay", "payment", "official", 1, False, "Official Google Pay web portal"),
    ("razorpay.com", "Razorpay", "payment", "third_party", 2, False, "Verified third-party payment gateway"),
    ("cred.club", "CRED", "payment", "official", 1, False, "Official CRED fintech platform"),

    # E. Education, jobs and developer platforms
    ("nptel.ac.in", "NPTEL", "education", "official", 1, False, "Official NPTEL education portal"),
    ("swayam.gov.in", "SWAYAM", "education", "official", 1, False, "Official Govt of India SWAYAM"),
    ("iitm.ac.in", "IIT Madras", "education", "official", 1, False, "Official IIT Madras"),
    ("iitb.ac.in", "IIT Bombay", "education", "official", 1, False, "Official IIT Bombay"),
    ("citchennai.edu.in", "CIT Chennai", "education", "official", 1, False, "Official Chennai Institute of Technology"),
    ("coursera.org", "Coursera", "education", "official", 1, False, "Official Coursera learning platform"),
    ("udemy.com", "Udemy", "education", "official", 1, False, "Official Udemy platform"),
    ("edx.org", "edX", "education", "official", 1, False, "Official edX platform"),
    ("unstop.com", "Unstop", "jobs", "official", 1, False, "Official Unstop careers platform"),
    ("naukri.com", "Naukri", "jobs", "official", 1, False, "Official Naukri jobs portal"),
    ("indeed.com", "Indeed", "jobs", "official", 1, False, "Official Indeed jobs portal"),
    ("internshala.com", "Internshala", "jobs", "official", 1, False, "Official Internshala internships"),
    ("hackerrank.com", "HackerRank", "developer", "official", 1, False, "Official HackerRank coding platform"),
    ("leetcode.com", "LeetCode", "developer", "official", 1, False, "Official LeetCode platform"),
    ("stackoverflow.com", "Stack Overflow", "developer", "official", 1, False, "Official Stack Overflow"),
    ("huggingface.co", "Hugging Face", "developer", "official", 1, False, "Official Hugging Face hub"),
    ("kaggle.com", "Kaggle", "developer", "official", 1, False, "Official Kaggle platform"),

    # F. Travel, food, entertainment and media
    ("irctc.co.in", "IRCTC", "travel", "official", 1, False, "Official IRCTC rail booking"),
    ("makemytrip.com", "MakeMyTrip", "travel", "official", 1, False, "Official MakeMyTrip portal"),
    ("booking.com", "Booking.com", "travel", "official", 1, False, "Official Booking.com portal"),
    ("airbnb.com", "Airbnb", "travel", "official", 1, False, "Official Airbnb platform"),
    ("uber.com", "Uber", "travel", "official", 1, False, "Official Uber domain"),
    ("olacabs.com", "Ola", "travel", "official", 1, False, "Official Ola Cabs domain"),
    ("zomato.com", "Zomato", "food", "official", 1, False, "Official Zomato food platform"),
    ("swiggy.com", "Swiggy", "food", "official", 1, False, "Official Swiggy food platform"),
    ("netflix.com", "Netflix", "media", "official", 1, False, "Official Netflix streaming"),
    ("spotify.com", "Spotify", "media", "official", 1, False, "Official Spotify streaming"),
    ("primevideo.com", "Prime Video", "media", "official", 1, False, "Official Amazon Prime Video"),
    ("hotstar.com", "Hotstar", "media", "official", 1, False, "Official Hotstar streaming"),
    ("bookmyshow.com", "BookMyShow", "media", "official", 1, False, "Official BookMyShow ticketing"),

    # G. Legitimate third-party platforms and services
    ("medium.com", "Medium", "third_party_media", "third_party", 2, False, "Legitimate third-party publishing platform"),
    ("blogger.com", "Blogger", "third_party_hosting", "third_party", 2, True, "Third-party blogging host; blogs require page inspection"),
    ("wordpress.com", "WordPress", "third_party_hosting", "third_party", 2, True, "Multi-tenant WordPress host; inspect individual sites"),
    ("wix.com", "Wix", "third_party_hosting", "third_party", 2, False, "Third-party website builder corporate domain"),
    ("squarespace.com", "Squarespace", "third_party_hosting", "third_party", 2, False, "Third-party website builder corporate domain"),
    ("github.io", "GitHub Pages", "third_party_hosting", "third_party", 2, True, "Multi-tenant static site hosting; tenant pages are untrusted by default"),
    ("vercel.app", "Vercel", "third_party_hosting", "third_party", 2, True, "Multi-tenant app hosting; tenant subdomains require page-level scanning"),
    ("netlify.app", "Netlify", "third_party_hosting", "third_party", 2, True, "Multi-tenant web hosting; tenant subdomains require page-level scanning"),
    ("pages.dev", "Cloudflare Pages", "third_party_hosting", "third_party", 2, True, "Multi-tenant pages host; tenant subdomains require page-level scanning"),
    ("sites.google.com", "Google Sites", "third_party_hosting", "third_party", 2, True, "Multi-tenant Google Sites host; tenant pages are NOT official Google"),
    ("canva.com", "Canva", "third_party_saas", "third_party", 2, False, "Verified third-party design SaaS"),
    ("bitly.com", "Bitly", "url_shortener", "third_party", 2, True, "Legitimate URL shortener corporate domain; short links redirect to arbitrary targets"),
    ("linktr.ee", "Linktree", "third_party_saas", "third_party", 2, True, "Multi-tenant bio-link service; destination links require inspection"),
    ("cashfree.com", "Cashfree", "payment", "third_party", 2, False, "Verified third-party payment gateway"),
    ("payu.in", "PayU", "payment", "third_party", 2, False, "Verified third-party payment processor"),
    ("stripe.com", "Stripe", "payment", "third_party", 2, False, "Verified third-party payment infrastructure"),
    ("paypal.com", "PayPal", "payment", "third_party", 2, False, "Verified payment service provider"),
    ("bbc.com", "BBC", "news", "third_party", 2, False, "Verified international news publisher"),
    ("reuters.com", "Reuters", "news", "third_party", 2, False, "Verified news publisher"),
    ("thehindu.com", "The Hindu", "news", "third_party", 2, False, "Verified news publisher"),
]

# Realistic verified non-root path/query templates per category to eliminate root-only benign dataset bias
CATEGORY_URL_TEMPLATES: dict[str, list[str]] = {
    "ecommerce": [
        "/dp/B0CHWRXH8B/ref=sr_1_1?crid=12345ABC&keywords=wireless+headphones&qid=1700000000&sprefix=wire%2Caps%2C210&sr=8-1",
        "/s?k=laptop+stand&i=electronics&crid=2K9P1L3&ref=nb_sb_noss_1",
        "/gp/cart/view.html?ref_=nav_cart",
        "/ap/signin?openid.pape.max_auth_age=0&openid.mode=checkid_setup&pageId=usflex",
    ],
    "productivity": [
        "/search?q=machine+learning+security&hl=en&source=hp",
        "/mail/u/0/#inbox",
        "/auth/signin?continue=account&lang=en",
        "/docs/workspace/overview?view=details&tab=permissions",
    ],
    "social": [
        "/explore/tags/technology/?hl=en",
        "/notifications?filter=mentions",
        "/watch?v=x9K2mPq7Z4v&list=PLresearch&index=2",
        "/settings/security?section=sessions",
    ],
    "developer": [
        "/explore?tab=repositories&q=cybersecurity&type=public",
        "/questions/tagged/python?tab=Votes&page=2",
        "/models/phishing-detection?tab=readme",
        "/problems/two-sum/description/?envType=study-plan",
    ],
    "banking": [
        "/personal-banking/savings-account?utm_medium=nav&city=chennai",
        "/netbanking/login.html?lang=en&channel=web",
        "/cards/credit-cards?category=rewards",
    ],
    "payment": [
        "/docs/payments/checkout?currency=INR&mode=upi",
        "/merchant/dashboard?period=30d",
        "/help/transactions?topic=refunds",
    ],
    "education": [
        "/courses/cyber-security-fundamentals?enrollment=audit&term=fall",
        "/learn/machine-learning/home/week/1",
        "/jobs/internship-software-engineering?location=remote&page=1",
    ],
    "jobs": [
        "/jobs?q=security+analyst&l=Bengaluru&from=searchOnHP",
        "/internships/python-development?stipend=paid",
    ],
    "travel": [
        "/flights/search?from=MAA&to=DEL&adults=1&class=economy",
        "/hotels/results?city=Bengaluru&guests=2&rooms=1",
    ],
    "food": [
        "/restaurants/chennai?sort=rating&cuisine=south-indian",
        "/checkout/cart?city=bengaluru",
    ],
    "media": [
        "/watch?v=pQ7mR2xN9tA&t=42s",
        "/browse/genre/83?bc=343992",
    ],
    "news": [
        "/news/technology-ai-security-research?page=1&sort=latest",
        "/business/markets/articles/2026-11-28/overview.html",
    ],
    "third_party_media": [
        "/@security-research/phishing-analysis-overview?source=topics_v2",
    ],
    "third_party_saas": [
        "/templates/security-presentation?category=education",
    ],
}

SYNTHETIC_LOOKALIKES: list[dict[str, str]] = [
    {"id": "1", "url": "https://amaz0n-login.example/signin", "hostname": "amaz0n-login.example", "root_domain": "amaz0n-login.example", "target_brand": "amazon", "attack_pattern": "homoglyph_leet", "expected_brand_mismatch": "1", "notes": "Reserved .example lookalike impersonating Amazon"},
    {"id": "2", "url": "https://amazon-account-verify.example/auth", "hostname": "amazon-account-verify.example", "root_domain": "amazon-account-verify.example", "target_brand": "amazon", "attack_pattern": "brand_keyword_combo", "expected_brand_mismatch": "1", "notes": "Reserved .example credential lure for Amazon"},
    {"id": "3", "url": "https://google-account-verify.example/login", "hostname": "google-account-verify.example", "root_domain": "google-account-verify.example", "target_brand": "google", "attack_pattern": "brand_keyword_combo", "expected_brand_mismatch": "1", "notes": "Reserved .example lookalike targeting Google"},
    {"id": "4", "url": "https://micros0ft-security.example/alert", "hostname": "micros0ft-security.example", "root_domain": "micros0ft-security.example", "target_brand": "microsoft", "attack_pattern": "homoglyph_leet", "expected_brand_mismatch": "1", "notes": "Reserved .example lookalike targeting Microsoft"},
    {"id": "5", "url": "https://flipkart-reward-claim.example/claim", "hostname": "flipkart-reward-claim.example", "root_domain": "flipkart-reward-claim.example", "target_brand": "flipkart", "attack_pattern": "brand_keyword_combo", "expected_brand_mismatch": "1", "notes": "Reserved .example reward scam for Flipkart"},
    {"id": "6", "url": "https://sbi-netbanking-secure.example/kyc", "hostname": "sbi-netbanking-secure.example", "root_domain": "sbi-netbanking-secure.example", "target_brand": "onlinesbi", "attack_pattern": "banking_impersonation", "expected_brand_mismatch": "1", "notes": "Reserved .example banking KYC lure"},
    {"id": "7", "url": "https://instagram-verify-account.example/appeal", "hostname": "instagram-verify-account.example", "root_domain": "instagram-verify-account.example", "target_brand": "instagram", "attack_pattern": "brand_keyword_combo", "expected_brand_mismatch": "1", "notes": "Reserved .example badge verification lure"},
    {"id": "8", "url": "https://paypa1-payment.example/checkout", "hostname": "paypa1-payment.example", "root_domain": "paypa1-payment.example", "target_brand": "paypal", "attack_pattern": "homoglyph_leet", "expected_brand_mismatch": "1", "notes": "Reserved .example payment impersonation"},
    {"id": "9", "url": "https://phonepe-cashback.example/redeem", "hostname": "phonepe-cashback.example", "root_domain": "phonepe-cashback.example", "target_brand": "phonepe", "attack_pattern": "brand_keyword_combo", "expected_brand_mismatch": "1", "notes": "Reserved .example UPI cashback scam"},
    {"id": "10", "url": "https://irctc-ticket-confirm.example/tatkal", "hostname": "irctc-ticket-confirm.example", "root_domain": "irctc-ticket-confirm.example", "target_brand": "irctc", "attack_pattern": "brand_keyword_combo", "expected_brand_mismatch": "1", "notes": "Reserved .example travel ticket lure"},
]


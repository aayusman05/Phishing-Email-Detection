import re
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {".xyz", ".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".pw", ".click"}

FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "protonmail.com"}

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook",
    "instagram", "twitter", "bank", "chase", "wellsfargo", "citibank", "ebay",
    "dropbox", "linkedin", "spotify", "uber", "airbnb",
]

# Leet-speak / typosquatting substitutions to detect misspelled brand names
LEET_MAP = str.maketrans("0134@", "oieas")


def extract_urls(email_text: str) -> dict:
    """Extract and analyse URLs found in the email text."""
    url_pattern = re.compile(
        r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+",
        re.IGNORECASE,
    )
    urls_found = url_pattern.findall(email_text)

    suspicious_urls = []

    for url in urls_found:
        reasons = []

        # Normalise — add scheme if missing
        if url.startswith("www."):
            parsed = urlparse("http://" + url)
        else:
            parsed = urlparse(url)

        hostname = parsed.hostname or ""

        # Check for IP address used as domain
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_pattern.match(hostname):
            reasons.append("IP address used as domain")

        # Check for suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                reasons.append(f"suspicious TLD ({tld})")
                break

        # Check for excessive subdomains (more than 3 dots in hostname)
        if hostname.count(".") > 3:
            reasons.append("excessive subdomains")

        # Check if a known brand appears in the subdomain/path but not as the main domain
        domain_parts = hostname.split(".")
        if len(domain_parts) >= 2:
            root_domain = domain_parts[-2].lower()
            full_host_lower = hostname.lower()
            for brand in KNOWN_BRANDS:
                # Brand appears in URL but is NOT the actual root domain
                if brand in full_host_lower and brand != root_domain:
                    reasons.append(f"brand name '{brand}' in subdomain/path (possible spoofing)")
                    break

        if reasons:
            suspicious_urls.append({"url": url, "reasons": reasons})

    total = len(urls_found)
    suspicious_count = len(suspicious_urls)

    if total == 0:
        risk_score = 0
    else:
        base = (suspicious_count / total) * 7
        bonus = min(suspicious_count * 1.5, 3)
        risk_score = min(round(base + bonus), 10)

    return {
        "urls_found": urls_found,
        "suspicious_urls": suspicious_urls,
        "risk_score": risk_score,
    }


def analyse_sender(email_text: str) -> dict:
    """Analyse the From: header for spoofing or suspicious characteristics."""
    flags = []

    # Extract the From: line (case-insensitive)
    from_match = re.search(r"^From:\s*(.+)$", email_text, re.IGNORECASE | re.MULTILINE)
    if not from_match:
        return {
            "sender": "Unknown",
            "domain": "Unknown",
            "flags": ["No From header found"],
            "risk_score": 3,
        }

    sender_line = from_match.group(1).strip()

    # Extract display name and email address
    # Formats: "Display Name <email@domain.com>" or "email@domain.com"
    email_match = re.search(r"<([^>]+)>", sender_line)
    if email_match:
        email_addr = email_match.group(1).strip()
        display_name = sender_line[: sender_line.index("<")].strip().strip('"')
    else:
        email_addr = sender_line.strip()
        display_name = ""

    # Extract domain
    at_match = re.search(r"@([\w.\-]+)", email_addr)
    domain = at_match.group(1).lower() if at_match else ""

    # Flag 1: free email provider claiming to be a company brand
    if domain in FREE_EMAIL_PROVIDERS:
        # Check if display name or local part suggests a brand
        local_part = email_addr.split("@")[0].lower() if "@" in email_addr else ""
        combined = (display_name + " " + local_part).lower()
        for brand in KNOWN_BRANDS:
            if brand in combined:
                flags.append(f"free email provider ({domain}) impersonating brand '{brand}'")
                break
        else:
            flags.append(f"sender uses free email provider ({domain})")

    # Flag 2: display name mentions a brand but domain does not match
    if display_name:
        display_lower = display_name.lower()
        for brand in KNOWN_BRANDS:
            if brand in display_lower:
                if brand not in domain:
                    flags.append(f"display name claims to be '{brand}' but domain is '{domain}'")
                break

    # Flag 3: misspelled / leet-speak brand name in domain
    domain_normalised = domain.translate(LEET_MAP)
    for brand in KNOWN_BRANDS:
        # The normalised domain contains the brand but the raw domain does not
        if brand in domain_normalised and brand not in domain:
            flags.append(f"possible typosquatting: '{domain}' resembles '{brand}'")
            break

    # Risk score
    if len(flags) >= 2:
        risk_score = 9
    elif len(flags) == 1:
        # Higher score for impersonation vs merely free provider
        if any("impersonat" in f or "display name" in f or "typosquat" in f for f in flags):
            risk_score = 8
        else:
            risk_score = 4
    else:
        risk_score = 0

    return {
        "sender": sender_line,
        "domain": domain,
        "flags": flags,
        "risk_score": risk_score,
    }


def analyse_tone(email_text: str) -> dict:
    """Scan the email body for urgency and manipulation language."""
    urgency_phrases = [
        "urgent", "immediately", "suspend", "suspended", "verify", "confirm",
        "click here", "limited time", "account will be closed", "unusual activity",
        "act now", "winner", "congratulations", "prize", "claim your",
        "action required", "your account", "unauthorized", "security alert",
        "final notice", "last chance", "expires", "locked", "blocked",
        "update your information", "validate",
    ]

    body_lower = email_text.lower()
    found = []

    for phrase in urgency_phrases:
        if phrase in body_lower and phrase not in found:
            found.append(phrase)

    count = len(found)

    if count == 0:
        risk_score = 0
    elif count == 1:
        risk_score = 2
    elif count == 2:
        risk_score = 4
    elif count == 3:
        risk_score = 6
    elif count == 4:
        risk_score = 7
    else:
        risk_score = min(8 + (count - 5), 10)

    return {
        "urgency_words_found": found,
        "count": count,
        "risk_score": risk_score,
    }

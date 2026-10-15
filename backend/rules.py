"""
QRShield - Security Rule Definitions
Rule-based heuristic checks for static URL inspection.
Standard Library only; deterministic and zero external dependencies.
"""

from typing import List, Dict, Any
import ipaddress
import re
from urllib.parse import urlparse

# Documented list of common URL shortening domains
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "goo.gl", "rebrand.ly", "tiny.cc", "shorte.st",
    "v.gd", "qr.ae", "trib.al", "bl.ink", "lnkd.in", "s.id"
}

# TLDs historically associated with high abuse rates in ephemeral phishing
HIGH_ABUSE_TLDS = {
    "top", "xyz", "work", "click", "gq", "cf", "tk", "ml", "ga",
    "buzz", "fit", "surf", "loan", "men", "tokyo", "casa"
}

# High-profile brand keywords frequently targeted for typosquatting / credential harvesting
TARGETED_BRAND_KEYWORDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "binance", "coinbase", "metamask", "whatsapp", "telegram"
}

SECURITY_ACTION_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "recover", "authenticate", "wallet", "support"
}


def evaluate_rules(parsed_url: Any, original_url: str) -> List[Dict[str, Any]]:
    """
    Evaluates static security rules against a parsed URL.
    Returns a list of triggered findings.
    """
    findings: List[Dict[str, Any]] = []
    
    scheme = parsed_url.scheme.lower()
    hostname = (parsed_url.hostname or "").lower()
    port = parsed_url.port
    path = parsed_url.path or ""
    query = parsed_url.query or ""
    netloc = parsed_url.netloc.lower()

    # 1. Scheme Check (HTTP vs HTTPS)
    if scheme == "http":
        findings.append({
            "rule_id": "SEC-SCHEME-001",
            "title": "Unencrypted HTTP Scheme",
            "severity": "MEDIUM",
            "score_impact": 20,
            "description": "The URL uses plain HTTP instead of HTTPS. Traffic to this destination is transmitted unencrypted and vulnerable to eavesdropping or man-in-the-middle interception.",
            "recommendation": "Do not enter passwords, personal details, or financial data on unencrypted HTTP pages."
        })

    # 2. Embedded Credentials (user:pass@host)
    if parsed_url.username or parsed_url.password or "@" in netloc.split(":")[0]:
        findings.append({
            "rule_id": "SEC-CRED-002",
            "title": "Embedded Authentication Credentials",
            "severity": "HIGH",
            "score_impact": 35,
            "description": "The URL embeds credentials or deceptive '@' delimiter syntax in the host portion. Attackers frequently use this technique to deceive users regarding the actual host being contacted.",
            "recommendation": "Do not open this URL. It is a recognized phishing obfuscation tactic."
        })

    # 3. IP Address Hostname
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname.strip("[]"))
        is_ip = True
        ip_desc = f"The URL connects directly to an IP address ({hostname}) rather than a registered domain name."
        if ip_obj.is_private or ip_obj.is_loopback:
            ip_desc += " The IP refers to a private/internal network address, potentially targeting local network devices or SSRF."
        
        findings.append({
            "rule_id": "SEC-IP-003",
            "title": "IP Address Used as Hostname",
            "severity": "HIGH",
            "score_impact": 30,
            "description": ip_desc,
            "recommendation": "Legitimate public websites rarely publish bare IP addresses in QR codes. Treat this destination with extreme caution."
        })
    except ValueError:
        is_ip = False

    # 4. Unusual or Non-Standard Ports
    if port is not None:
        standard_ports = [80] if scheme == "http" else [443]
        if port not in standard_ports:
            severity = "HIGH" if port in {21, 22, 23, 25, 3389, 4444, 6667} else "MEDIUM"
            impact = 25 if severity == "HIGH" else 15
            findings.append({
                "rule_id": "SEC-PORT-004",
                "title": f"Non-Standard Port ({port})",
                "severity": severity,
                "score_impact": impact,
                "description": f"The URL specifies custom port {port} instead of the standard web ports (80/443). Attackers may use custom ports to bypass network filters or reach unauthorized test/proxy listeners.",
                "recommendation": "Verify whether the service operator legitimately expects traffic on this non-standard port."
            })

    # 5. Known URL Shortener
    if hostname in KNOWN_SHORTENERS:
        findings.append({
            "rule_id": "SEC-SHORT-005",
            "title": "Known URL Shortening Service",
            "severity": "MEDIUM",
            "score_impact": 20,
            "description": f"The hostname '{hostname}' is a URL shortening service. Shorteners mask the ultimate destination and are frequently used in QR codes to conceal deceptive links.",
            "recommendation": "Use a preview or link expansion service to inspect the target destination before browsing."
        })

    # 6. Domain checks (only if not an IP address)
    if not is_ip and hostname:
        labels = [lbl for lbl in hostname.split(".") if lbl]
        
        # Excessive Subdomains
        # Example: login.update.security.bank.example.com has 6 labels
        if len(labels) >= 5:
            findings.append({
                "rule_id": "SEC-SUBDOM-006",
                "title": "Excessive Subdomain Depth",
                "severity": "MEDIUM",
                "score_impact": 15,
                "description": f"The domain possesses {len(labels)} hierarchical labels. Excessive subdomains are frequently engineered to confuse users and obscure the true registration domain.",
                "recommendation": "Verify the effective root domain (the final two labels) carefully before trusting this site."
            })

        # Unusually Long Hostname
        if len(hostname) > 45:
            findings.append({
                "rule_id": "SEC-LEN-007",
                "title": "Unusually Long Hostname",
                "severity": "LOW",
                "score_impact": 10,
                "description": f"The hostname length ({len(hostname)} characters) is significantly longer than typical web services. This pattern is commonly observed in algorithmically generated domains or subdomain stuffing.",
                "recommendation": "Inspect the root domain for legitimacy."
            })

        # Hyphen Stuffing in Domain
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            findings.append({
                "rule_id": "SEC-HYPHEN-008",
                "title": "Excessive Hyphens in Hostname",
                "severity": "MEDIUM",
                "score_impact": 15,
                "description": f"The hostname contains {hyphen_count} hyphens (e.g. 'paypal-security-login-update'). Phishing kits commonly use hyphenated keywords to mimic authentic domains.",
                "recommendation": "Confirm whether the authentic brand operates under this hyphenated domain."
            })

        # High-Risk / Abused TLD
        tld = labels[-1] if labels else ""
        if tld in HIGH_ABUSE_TLDS:
            findings.append({
                "rule_id": "SEC-TLD-009",
                "title": f"High-Risk Top-Level Domain (.{tld})",
                "severity": "LOW",
                "score_impact": 10,
                "description": f"The domain uses the '.{tld}' top-level domain, which has historically shown elevated rates of spam, abuse, and disposable phishing campaigns due to low registration costs.",
                "recommendation": "Exercise vigilance when visiting domains under low-reputation generic TLDs."
            })

        # Deceptive Brand Keywords in Subdomains or Path
        # e.g., paypal.com.attacker.com or login-paypal.suspicious.com
        registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
        subdomain_part = ".".join(labels[:-2]) if len(labels) > 2 else ""

        for brand in TARGETED_BRAND_KEYWORDS:
            # Check if brand appears in subdomain or hyphenated labels while NOT in the authentic root domain
            if brand in subdomain_part or (brand in hostname and not registered_domain.startswith(brand)):
                findings.append({
                    "rule_id": "SEC-SPOOF-010",
                    "title": f"Potential Brand Impersonation ({brand.capitalize()})",
                    "severity": "HIGH",
                    "score_impact": 30,
                    "description": f"The recognized brand name '{brand}' appears in the subdomain or prefix of a domain registered to an unrelated entity ('{registered_domain}'). This is a textbook social engineering indicator.",
                    "recommendation": "Do not provide credentials. Navigate directly to the official website by typing the official address in your browser."
                })
                break

    # 7. Obfuscated / Suspicious URL Patterns in Path and Query
    # Look for hex encoding spikes or multiple @ or redirect parameters
    raw_target = path + ("?" + query if query else "")
    
    # Check for redirect query params (e.g. url=, redirect=, next=)
    redirect_indicators = re.findall(r"(?:url|redirect|next|dest|target|link)=(?:https?%3A%2F%2F|https?://)", raw_target, re.IGNORECASE)
    if redirect_indicators:
        findings.append({
            "rule_id": "SEC-REDIR-011",
            "title": "Potential Open Redirect / Chained URL",
            "severity": "MEDIUM",
            "score_impact": 15,
            "description": "The URL query parameters contain an embedded secondary web address. This pattern can be exploited as an open redirect to bounce users to a malicious third-party site while appearing authentic.",
            "recommendation": "Ensure you verify where the redirect finally leads before authenticating."
        })

    # Excessive URL length
    if len(original_url) > 250:
        findings.append({
            "rule_id": "SEC-URLLEN-012",
            "title": "Unusually Long URL",
            "severity": "LOW",
            "score_impact": 10,
            "description": f"The full URL length ({len(original_url)} characters) is unusually large. Phishers occasionally hide tracking tokens or obfuscated payload segments in oversized URLs.",
            "recommendation": "Inspect query parameters for suspicious payload injections."
        })

    return findings

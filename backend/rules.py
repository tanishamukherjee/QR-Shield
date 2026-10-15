"""
QRShield - Security Rule Definitions
Rule-based heuristic checks for static URL inspection.
Standard Library only; deterministic and zero external dependencies.
"""

from typing import List, Dict, Any, Optional, Tuple
import ipaddress
import re
import unicodedata
from urllib.parse import unquote

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

# High-profile brand keywords frequently targeted for typosquatting / credential harvesting.
# A tuple (not a set) so matching order is deterministic and identical to the JS simulation.
TARGETED_BRAND_KEYWORDS = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "binance", "coinbase", "metamask", "whatsapp", "telegram"
)

# How each brand is written in findings ('paypal' -> 'PayPal', 'wellsfargo' -> 'Wells Fargo')
BRAND_DISPLAY_NAMES = {
    "paypal": "PayPal", "apple": "Apple", "microsoft": "Microsoft", "google": "Google",
    "amazon": "Amazon", "netflix": "Netflix", "facebook": "Facebook", "instagram": "Instagram",
    "chase": "Chase", "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America",
    "citibank": "Citibank", "binance": "Binance", "coinbase": "Coinbase", "metamask": "MetaMask",
    "whatsapp": "WhatsApp", "telegram": "Telegram"
}

# Words phishing domains glue onto a brand name (e.g. 'paypalsecure', 'appleid')
SECURITY_ACTION_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "recover", "authenticate", "wallet", "support",
    "id", "online", "service", "help", "official"
}

# Credential-harvesting words that turn brand impersonation into a phishing lure
LURE_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "recover", "authenticate", "wallet", "support"
}

# TLD-like labels used when a brand's full domain is embedded in front of another domain
# ('paypal.com.evil.com')
EMBEDDED_DOMAIN_TLDS = {"com", "net", "org", "co", "io", "in", "uk", "us", "gov", "edu", "info", "biz"}

# Two-part public suffixes, so 'amazon.co.uk' is read as name 'amazon' + suffix 'co.uk'.
# A small built-in subset of the Public Suffix List (keeps the Lambda dependency-free).
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "org.in", "ac.in", "gov.in", "net.in",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "com.cn", "com.mx",
    "co.za", "com.sg", "com.hk", "co.kr", "com.tr"
}

# Real brand-owned domains that look like 'brand + word' phishing domains
BRAND_OWNED_DOMAINS = {
    "microsoftonline.com", "google-analytics.com", "paypal-community.com", "amazon-adsystem.com"
}

# Ordinary words that are one letter away from a brand (e.g. 'finance' vs 'binance')
TYPO_EXCEPTIONS = {"finance"}

# Characters that look like Latin letters: digits, Cyrillic and Greek look-alikes.
# 'i' and '1' both map to 'l' because all three are easily confused.
LOOKALIKE_CHARS = {
    "0": "o", "1": "l", "i": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "l", "ј": "j", "ԁ": "d", "ѕ": "s", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "l", "κ": "k", "ε": "e", "υ": "u", "μ": "m"
}


def split_domain(labels: List[str]) -> Tuple[List[str], str, str]:
    """Splits host labels into (subdomain labels, registered name, public suffix)."""
    suffix_len = 2 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 1
    if len(labels) <= suffix_len:
        return [], "", ".".join(labels)
    return labels[:-suffix_len - 1], labels[-suffix_len - 1], ".".join(labels[-suffix_len:])


def decode_label(label: str) -> str:
    """Decodes a punycode ('xn--') label to the Unicode text the user actually sees."""
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return label
    return label


def skeleton(text: str) -> str:
    """Reduces text to plain letters so look-alikes compare equal ('paypa1' -> 'paypal')."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.category(c).startswith("M"))
    text = "".join(LOOKALIKE_CHARS.get(c, c) for c in text)
    return text.replace("rn", "m").replace("vv", "w")


def is_one_edit_away(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insertion, deletion, substitution or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            return True
    return False


def has_mixed_script(text: str) -> bool:
    """True when Latin letters are mixed with Cyrillic or Greek ones in the same label."""
    scripts = {unicodedata.name(c, "").split(" ")[0] for c in text if c.isalpha()}
    return "LATIN" in scripts and bool(scripts & {"CYRILLIC", "GREEK"})


def has_lure_word(words: List[str]) -> bool:
    """True when a word is a lure keyword, or a brand glued to one ('paypalsecure')."""
    for word in words:
        if word in LURE_KEYWORDS:
            return True
        for brand in TARGETED_BRAND_KEYWORDS:
            if word.startswith(brand) and word[len(brand):] in LURE_KEYWORDS:
                return True
            if word.endswith(brand) and word[:-len(brand)] in LURE_KEYWORDS:
                return True
    return False


def find_brand_word(words: List[str]) -> Optional[str]:
    """
    Returns the first brand that appears as a whole word, or glued to a security
    keyword ('paypalsecure', 'appleid'). 'pineapple' and 'purchase' do not match.
    """
    for word in words:
        for brand in TARGETED_BRAND_KEYWORDS:
            if word == brand:
                return brand
            if word.startswith(brand) and word[len(brand):] in SECURITY_ACTION_KEYWORDS:
                return brand
            if word.endswith(brand) and word[:-len(brand)] in SECURITY_ACTION_KEYWORDS:
                return brand
    return None


def evaluate_rules(parsed_url: Any, original_url: str, raw_hostname: str = None,
                   had_backslash: bool = False) -> List[Dict[str, Any]]:
    """
    Evaluates static security rules against a parsed URL.
    parsed_url must already carry the browser-equivalent hostname;
    raw_hostname is the host exactly as written (used to spot obfuscated IPs).
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
    if "@" in netloc:
        userinfo = unquote(netloc.rpartition("@")[0])
        user_part = userinfo.split(":")[0]
        looks_like_domain = re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\.?", user_part) is not None
        names_brand = find_brand_word([w for w in re.split(r"[^a-z0-9]+", user_part) if w]) is not None

        if looks_like_domain or names_brand:
            # 'google.com@evil.com' - the text before '@' pretends to be the destination
            findings.append({
                "rule_id": "SEC-CRED-002",
                "title": "Disguised Destination ('@' Trick)",
                "severity": "CRITICAL",
                "score_impact": 35,
                "description": f"The text before '@' ('{user_part}') looks like a website address, but browsers treat it as a username and actually open '{hostname}'. This is a classic trick to make a malicious link look like a trusted site.",
                "recommendation": "Do not open this URL. The real destination is the part after the '@'."
            })
        else:
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

        # 3b. IP written in a disguised numeric form ('3232235876', '0xC0A80164', '127.1')
        if ip_obj.version == 4 and raw_hostname and raw_hostname.rstrip(".") != hostname:
            findings.append({
                "rule_id": "SEC-IPOBF-014",
                "title": "Disguised IP Address",
                "severity": "CRITICAL",
                "score_impact": 25,
                "description": f"The address is written in an obfuscated numeric form ('{raw_hostname}') that browsers silently decode to {hostname}. Legitimate websites never do this; it exists only to hide the real destination.",
                "recommendation": "Do not open this URL. The address was deliberately disguised."
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
            "score_impact": 30,
            "description": f"The hostname '{hostname}' is a URL shortening service. Shorteners mask the ultimate destination and are frequently used in QR codes to conceal deceptive links.",
            "recommendation": "Use a preview or link expansion service to inspect the target destination before browsing."
        })

    # 6. Domain checks (only if not an IP address)
    if not is_ip and hostname:
        labels = [lbl for lbl in hostname.split(".") if lbl]
        subdomain_labels, registered_name, public_suffix = split_domain(labels)
        registered_domain = f"{registered_name}.{public_suffix}" if registered_name else hostname
        tld = labels[-1] if labels else ""
        # Unicode form of each label, as the user would see it ('xn--pypal-4ve' -> 'pаypal')
        decoded_labels = [decode_label(lbl) for lbl in labels]

        # Excessive Subdomains (counted in front of the registered domain, so
        # 'a.b.example.co.uk' has 2 levels, not 5 labels)
        # Example: login.update.security.bank.example.com has 4 subdomain levels
        if len(subdomain_labels) >= 3:
            findings.append({
                "rule_id": "SEC-SUBDOM-006",
                "title": "Excessive Subdomain Depth",
                "severity": "MEDIUM",
                "score_impact": 15,
                "description": f"The hostname has {len(subdomain_labels)} subdomain levels in front of the registered domain '{registered_domain}'. Excessive subdomains are frequently engineered to confuse users and obscure the true registration domain.",
                "recommendation": f"Verify the registered domain ('{registered_domain}') carefully before trusting this site."
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

        # Hyphen Stuffing in Domain (counted on the decoded labels, so the
        # 'xn--' punycode prefix of internationalized domains is not counted)
        hyphen_count = sum(lbl.count("-") for lbl in decoded_labels)
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
        if tld in HIGH_ABUSE_TLDS:
            findings.append({
                "rule_id": "SEC-TLD-009",
                "title": f"High-Risk Top-Level Domain (.{tld})",
                "severity": "LOW",
                "score_impact": 10,
                "description": f"The domain uses the '.{tld}' top-level domain, which has historically shown elevated rates of spam, abuse, and disposable phishing campaigns due to low registration costs.",
                "recommendation": "Exercise vigilance when visiting domains under low-reputation generic TLDs."
            })

        # A brand's own site: the registered name IS the brand, on a normal TLD
        # (amazon.co.uk, google.co.in, apple.com - but not paypal.xyz)
        is_official_brand_domain = (
            (registered_name in TARGETED_BRAND_KEYWORDS and tld not in HIGH_ABUSE_TLDS)
            or registered_domain in BRAND_OWNED_DOMAINS
        )

        # Brand Impersonation: a brand appears as a whole word anywhere in the host
        # e.g. paypal.account-verify.xyz, paypal-login.com, paypalsecure.com
        words = [w for lbl in labels for w in lbl.split("-") if w]
        brand = find_brand_word(words)
        if brand and not is_official_brand_domain:
            path_words = [w for w in re.split(r"[^a-z0-9]+", path.lower()) if w]
            has_lure = has_lure_word(words) or has_lure_word(path_words)
            # 'paypal.com.evil.com': the brand's full domain sits in front of the real one
            embeds_brand_domain = any(
                lbl == brand and i + 1 < len(subdomain_labels) and subdomain_labels[i + 1] in EMBEDDED_DOMAIN_TLDS
                for i, lbl in enumerate(subdomain_labels)
            )

            if has_lure or embeds_brand_domain:
                # Brand + login lure (or a fake brand domain prefix) is the classic phishing
                # pattern; a brand name alone (e.g. google.github.io) stays HIGH.
                reason = (
                    "also uses login/verification wording to lure users into entering credentials"
                    if has_lure else
                    f"places '{brand}' as a fake domain in front of the real one"
                )
                findings.append({
                    "rule_id": "SEC-SPOOF-010",
                    "title": f"Brand Impersonation with Phishing Lure ({BRAND_DISPLAY_NAMES[brand]})",
                    "severity": "CRITICAL",
                    "score_impact": 30,
                    "description": f"The brand name '{brand}' appears in '{hostname}', but the registered domain '{registered_domain}' is not an official {BRAND_DISPLAY_NAMES[brand]} domain, and the link {reason}. This is the classic phishing pattern.",
                    "recommendation": "Do not provide credentials. Navigate directly to the official website by typing the official address in your browser."
                })
            else:
                findings.append({
                    "rule_id": "SEC-SPOOF-010",
                    "title": f"Potential Brand Impersonation ({BRAND_DISPLAY_NAMES[brand]})",
                    "severity": "HIGH",
                    "score_impact": 30,
                    "description": f"The brand name '{brand}' appears in '{hostname}', but the registered domain '{registered_domain}' is not an official {BRAND_DISPLAY_NAMES[brand]} domain. This is a textbook social engineering indicator.",
                    "recommendation": "Do not provide credentials. Navigate directly to the official website by typing the official address in your browser."
                })

        # Look-alike / Typosquatted Brand Name (checked on the registered name and its words)
        if registered_name and not is_official_brand_domain:
            visible_name = decode_label(registered_name)
            candidates = [visible_name] + [w for w in visible_name.split("-") if w and w != visible_name]

            lookalike = None
            for candidate in candidates:
                for b in TARGETED_BRAND_KEYWORDS:
                    if candidate != b and skeleton(candidate) == skeleton(b):
                        lookalike = (candidate, b)
                        break
                if lookalike:
                    break

            typo = None
            if not lookalike:
                for candidate in candidates:
                    if candidate in TYPO_EXCEPTIONS:
                        continue
                    for b in TARGETED_BRAND_KEYWORDS:
                        if len(b) >= 6 and is_one_edit_away(candidate, b):
                            typo = (candidate, b)
                            break
                    if typo:
                        break

            if lookalike:
                findings.append({
                    "rule_id": "SEC-TYPO-015",
                    "title": f"Look-alike Brand Name ({BRAND_DISPLAY_NAMES[lookalike[1]]})",
                    "severity": "CRITICAL",
                    "score_impact": 35,
                    "description": f"'{lookalike[0]}' uses look-alike characters (such as 1 for l, 0 for o, or Cyrillic letters) to imitate '{lookalike[1]}'. The registered domain '{registered_domain}' is not owned by {BRAND_DISPLAY_NAMES[lookalike[1]]}.",
                    "recommendation": f"Do not open this URL. Type the official {BRAND_DISPLAY_NAMES[lookalike[1]]} address yourself."
                })
            elif typo:
                findings.append({
                    "rule_id": "SEC-TYPO-015",
                    "title": f"Possible Typosquatted Brand ({BRAND_DISPLAY_NAMES[typo[1]]})",
                    "severity": "HIGH",
                    "score_impact": 30,
                    "description": f"'{typo[0]}' is one letter away from the brand '{typo[1]}'. Attackers register misspelled brand domains to catch users who misread or mistype addresses.",
                    "recommendation": f"Check the spelling carefully. The official {BRAND_DISPLAY_NAMES[typo[1]]} site is not '{registered_domain}'."
                })

        # Internationalized (punycode) Domain
        idn_labels = [lbl for lbl in labels if lbl.startswith("xn--")]
        if idn_labels:
            display_host = ".".join(decoded_labels)
            mixed = any(has_mixed_script(decode_label(lbl)) for lbl in idn_labels)
            description = f"The domain uses international characters and displays as '{display_host}' (encoded as '{hostname}'). Look-alike letters from other alphabets can make a fake domain appear identical to a real one."
            if mixed:
                description += " It mixes Latin letters with Cyrillic or Greek letters in the same label, which legitimate domains do not do."
            findings.append({
                "rule_id": "SEC-IDN-016",
                "title": "Mixed-Alphabet Domain" if mixed else "Internationalized Domain Name",
                "severity": "HIGH" if mixed else "MEDIUM",
                "score_impact": 30 if mixed else 15,
                "description": description,
                "recommendation": "Compare each character of the address with the official site before trusting it."
            })

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

    # 8. Backslash in the address (browsers silently convert '\' to '/')
    if had_backslash:
        findings.append({
            "rule_id": "SEC-BSLASH-013",
            "title": "Backslash in URL Address",
            "severity": "CRITICAL",
            "score_impact": 30,
            "description": f"The URL contains a backslash (\\) before its path or query. Browsers treat it as a forward slash, so the link really goes to '{hostname}' even if the text suggests a different site. Attackers use this to make links appear to point to a trusted domain.",
            "recommendation": "Do not open this URL. Legitimate links never need a backslash in the address."
        })

    return findings

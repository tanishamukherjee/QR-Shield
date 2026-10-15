"""
QRShield - URL Analysis Engine
Performs static, non-intrusive heuristic security inspection on decoded QR URLs.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse, unquote
import ipaddress

from rules import evaluate_rules

ENGINE_VERSION = "1.3.0"

# Minimum score when any CRITICAL finding is present (start of the High band)
CRITICAL_SCORE_FLOOR = 70

# Characters browsers refuse inside a hostname once it has been percent-decoded
FORBIDDEN_HOST_CHARS = set(" #%/:<>?@[\\]^|")


class URLValidationError(ValueError):
    """Raised when the submitted URL fails validation."""
    pass


def _parse_ipv4_number(part: str) -> Optional[int]:
    """
    Parses one dotted IPv4 component the way browsers do (WHATWG URL Standard):
    '0x' prefix = hexadecimal, leading '0' = octal, otherwise decimal.
    Returns None when the component is not a valid number.
    """
    if part == "":
        return None
    radix, digits = 10, "0123456789"
    if part[:2] in ("0x", "0X"):
        part, radix, digits = part[2:], 16, "0123456789abcdefABCDEF"
    elif len(part) > 1 and part[0] == "0":
        part, radix, digits = part[1:], 8, "01234567"
    if part == "":
        return 0
    if not all(c in digits for c in part):
        return None
    return int(part, radix)


def _ends_in_number(host: str) -> bool:
    """WHATWG 'ends in a number' check: decides whether a host must be parsed as IPv4."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    last = parts[-1]
    if last and last.isascii() and last.isdigit():
        return True
    return _parse_ipv4_number(last) is not None


def _parse_browser_ipv4(host: str) -> Optional[str]:
    """
    Decodes IPv4 hosts written in shorthand, decimal, hex or octal form
    (e.g. '3232235876', '0xC0A80164', '0300.0250.1.100', '127.1') into dotted form,
    exactly as a browser would before connecting. Returns None if invalid.
    """
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        return None

    numbers = [_parse_ipv4_number(p) for p in parts]
    if any(n is None for n in numbers):
        return None
    if any(n > 255 for n in numbers[:-1]):
        return None
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        return None

    value = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        value += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(value))


def canonicalize_hostname(raw_host: str) -> str:
    """
    Converts a parsed hostname into the host a browser would actually connect to:
    percent-decoding, IDNA/punycode conversion and IPv4 number decoding.
    """
    # IPv6 literals (urllib strips the brackets; only bracketed hosts may contain ':')
    if ":" in raw_host:
        try:
            return str(ipaddress.IPv6Address(raw_host))
        except ValueError:
            raise URLValidationError("URL contains an invalid IPv6 address.")

    host = unquote(raw_host)
    if not host or any(c in FORBIDDEN_HOST_CHARS for c in host):
        raise URLValidationError("URL hostname contains characters that browsers reject.")

    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise URLValidationError("URL hostname contains invalid internationalized characters.")
    host = host.lower()

    if _ends_in_number(host):
        ipv4 = _parse_browser_ipv4(host)
        if ipv4 is None:
            raise URLValidationError("URL hostname looks like an IP address but is not a valid one.")
        return ipv4

    return host


def validate_and_parse_url(raw_url: Any) -> Tuple[str, Any, Dict[str, Any]]:
    """
    Validates the input string, enforces size constraints, ensures HTTP/HTTPS scheme,
    and reads the host the same way a browser would.
    Returns (normalized_url, parsed_result, context) where context holds
    'raw_hostname' (host as written) and 'had_backslash'.
    """
    if not isinstance(raw_url, str):
        raise URLValidationError("Input must be a string representing a URL.")

    url_str = raw_url.strip()

    if not url_str:
        raise URLValidationError("URL cannot be empty.")

    if len(url_str) > 2048:
        raise URLValidationError("URL exceeds the maximum permitted length of 2048 characters.")

    # Reject non-printable / control characters
    if any(ord(c) < 32 or ord(c) == 127 for c in url_str):
        raise URLValidationError("URL contains forbidden control characters.")

    # Browsers treat '\' as '/' before the query/fragment of http(s) URLs, so
    # 'https://evil.com\@google.com' really goes to evil.com. Mirror that.
    split_at = min((i for i in (url_str.find("?"), url_str.find("#")) if i != -1), default=len(url_str))
    head, tail = url_str[:split_at], url_str[split_at:]
    had_backslash = "\\" in head
    if had_backslash:
        url_str = head.replace("\\", "/") + tail

    # Parse URL
    try:
        parsed = urlparse(url_str)
    except Exception as e:
        raise URLValidationError(f"Malformed URL structure: {str(e)}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise URLValidationError(
            f"Unsupported scheme '{parsed.scheme}'. QRShield analyzes web links (http:// and https://) only."
        )

    if not parsed.netloc or not parsed.hostname:
        raise URLValidationError("URL must include a valid host / authority component.")

    try:
        port = parsed.port
    except ValueError:
        raise URLValidationError("URL contains an invalid port number.")

    raw_hostname = parsed.hostname
    host = canonicalize_hostname(raw_hostname)

    # Rebuild the authority with the browser-equivalent host
    userinfo, at, _ = parsed.netloc.rpartition("@")
    netloc = (userinfo + at) + (f"[{host}]" if ":" in host else host)
    if port is not None:
        netloc += f":{port}"

    parsed = parsed._replace(scheme=scheme, netloc=netloc)
    normalized = parsed.geturl()

    context = {"raw_hostname": raw_hostname, "had_backslash": had_backslash}
    return normalized, parsed, context


def compute_risk_score(findings: list) -> Tuple[int, str]:
    """
    Calculates a deterministic risk score (0-100) based on triggered rules.
    Maps score to Low, Medium, High categories.
    """
    if not findings:
        return 0, "Low"

    raw_score = sum(f.get("score_impact", 0) for f in findings)

    # Compound indicator penalty: When 3 or more distinct suspicious factors exist,
    # the probability of deceptive design increases noticeably.
    if len(findings) >= 3:
        raw_score += 10

    # Cap score strictly between 0 and 100
    final_score = max(0, min(100, raw_score))

    # CRITICAL findings are tricks with no legitimate use (disguised '@' destination,
    # disguised IP, look-alike brand, backslash trick): always at least High risk.
    if any(f.get("severity") == "CRITICAL" for f in findings):
        final_score = max(final_score, CRITICAL_SCORE_FLOOR)

    if final_score < 30:
        level = "Low"
    elif final_score < 70:
        level = "Medium"
    else:
        level = "High"

    return final_score, level


def build_summary(risk_level: str, findings: list, hostname: str) -> Tuple[str, list]:
    """Generates an accessible plain-language summary and list of precautions."""
    if not findings:
        summary = (
            f"No suspicious structural indicators detected for '{hostname}'. "
            "The URL conforms to standard HTTPS conventions. However, static analysis "
            "cannot verify the server's real-time intent or backend behavior."
        )
        recommendations = [
            "Proceed with standard internet precautions.",
            "Always inspect the page address bar before submitting any sensitive information."
        ]
        return summary, recommendations

    count = len(findings)
    if risk_level == "High":
        summary = (
            f"HIGH RISK: Detected {count} indicator(s) suggesting deception or abnormal configuration "
            f"on '{hostname}'. We strongly advise against visiting or trusting this destination."
        )
    elif risk_level == "Medium":
        summary = (
            f"MEDIUM RISK: Detected {count} indicator(s) worthy of caution on '{hostname}'. "
            "The URL displays non-standard structures such as unencrypted traffic, URL shortening, "
            "or complex routing."
        )
    else:
        summary = (
            f"LOW RISK: Detected {count} minor indicator(s) on '{hostname}'. "
            "Review findings prior to interaction."
        )

    # Collect unique recommendations from triggered findings
    recs = []
    seen = set()
    for f in findings:
        r = f.get("recommendation")
        if r and r not in seen:
            recs.append(r)
            seen.add(r)

    # Add general disclaimer precaution
    recs.append("Verify the organization's authentic domain independently before entering credentials.")
    return summary, recs


def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Main entry point for URL inspection.
    Validates URL, evaluates security rules, computes heuristic risk score,
    and returns structured analysis findings.
    """
    normalized_url, parsed, context = validate_and_parse_url(raw_url)
    # Length-based rules use the URL exactly as it appeared in the QR code
    findings = evaluate_rules(
        parsed,
        raw_url.strip(),
        raw_hostname=context["raw_hostname"],
        had_backslash=context["had_backslash"]
    )
    risk_score, risk_level = compute_risk_score(findings)
    summary, recommendations = build_summary(risk_level, findings, parsed.hostname or "")

    return {
        "status": "success",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "normalized_url": normalized_url,
        "hostname": parsed.hostname or "",
        "scheme": parsed.scheme.lower(),
        "port": parsed.port,
        "findings": findings,
        "summary": summary,
        "recommendations": recommendations,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "engine_version": ENGINE_VERSION
    }

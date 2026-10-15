"""
QRShield - URL Analysis Engine
Performs static, non-intrusive heuristic security inspection on decoded QR URLs.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from urllib.parse import urlparse
import re

from rules import evaluate_rules


class URLValidationError(ValueError):
    """Raised when the submitted URL fails validation."""
    pass


def validate_and_parse_url(raw_url: Any) -> Tuple[str, Any]:
    """
    Validates the input string, enforces size constraints, ensures HTTP/HTTPS scheme,
    and returns (normalized_url, parsed_result).
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

    if not parsed.netloc:
        raise URLValidationError("URL must include a valid host / authority component.")

    # Reassemble normalized URL (scheme + host in lowercase)
    normalized = parsed._replace(
        scheme=scheme,
        netloc=parsed.netloc.lower()
    ).geturl()

    return normalized, parsed


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
    normalized_url, parsed = validate_and_parse_url(raw_url)
    findings = evaluate_rules(parsed, normalized_url)
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
        "engine_version": "1.0.0"
    }

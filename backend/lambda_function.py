"""
QRShield - AWS Lambda Handler
Serves as the serverless entrypoint for QRShield URL threat analysis.
Designed for AWS Lambda Function URLs with CORS support and structured logging.
"""

import json
import base64
import os
import re
from typing import Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode

from url_analyzer import analyze_url, URLValidationError, ENGINE_VERSION

# Allowed CORS origins can be configured via environment variable
# Defaults to permissive for development and easily restricted in deployment
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")


def build_cors_headers(origin: str = "*") -> Dict[str, str]:
    """Build standard CORS headers for Lambda Function URL responses."""
    effective_origin = ALLOWED_ORIGIN if ALLOWED_ORIGIN != "*" else origin or "*"
    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": effective_origin,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
        "Access-Control-Max-Age": "86400",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    }


def sanitize_url_for_logging(url: str) -> str:
    """
    Strips query parameters and credentials to prevent logging sensitive user tokens in CloudWatch.
    """
    try:
        parsed = urlparse(url)
        # Redact credentials if present
        host = parsed.hostname or "unknown"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        # Keep path, redact query
        clean = f"{parsed.scheme}://{host}{parsed.path}"
        if parsed.query:
            clean += "?[REDACTED_QUERY]"
        return clean
    except Exception:
        return "[UNPARSEABLE_URL]"


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entrypoint.
    Handles Function URL HTTP requests and direct invoke test payloads.
    """
    headers = event.get("headers") or {}
    request_origin = headers.get("origin") or headers.get("Origin") or "*"
    cors_headers = build_cors_headers(request_origin)

    # 1. Handle HTTP OPTIONS (CORS preflight)
    http_method = ""
    if "requestContext" in event and "http" in event["requestContext"]:
        http_method = event["requestContext"]["http"].get("method", "").upper()
    elif "httpMethod" in event:
        http_method = event.get("httpMethod", "").upper()

    if http_method == "OPTIONS":
        return {
            "statusCode": 204,
            "headers": cors_headers,
            "body": ""
        }

    # 2. Health check (used by the frontend status badge)
    if http_method == "GET":
        return {
            "statusCode": 200,
            "headers": cors_headers,
            "body": json.dumps({
                "service": "QRShield",
                "status": "healthy",
                "engine_version": ENGINE_VERSION,
                "message": "Send POST requests with {\"url\": \"...\"} to analyze."
            })
        }

    # 3. Extract payload body
    body_raw = event.get("body")
    if body_raw is None:
        # Direct Lambda invoke with JSON dict (e.g., from AWS Lambda Console Test)
        payload = event
    else:
        # Check if base64 encoded
        if event.get("isBase64Encoded", False):
            try:
                body_raw = base64.b64decode(body_raw).decode("utf-8")
            except Exception:
                return {
                    "statusCode": 400,
                    "headers": cors_headers,
                    "body": json.dumps({"status": "error", "message": "Invalid base64 encoding."})
                }

        if isinstance(body_raw, str):
            try:
                payload = json.loads(body_raw)
            except json.JSONDecodeError:
                return {
                    "statusCode": 400,
                    "headers": cors_headers,
                    "body": json.dumps({"status": "error", "message": "Request body must be valid JSON."})
                }
        elif isinstance(body_raw, dict):
            payload = body_raw
        else:
            payload = {}

    target_url = payload.get("url")
    if not target_url:
        return {
            "statusCode": 400,
            "headers": cors_headers,
            "body": json.dumps({
                "status": "error",
                "message": "Missing required field 'url' in request payload."
            })
        }

    # Log safe metadata to CloudWatch
    safe_log_url = sanitize_url_for_logging(target_url)
    print(f"QRShield processing request for target: {safe_log_url}")

    # 4. Execute URL threat analysis
    try:
        analysis_result = analyze_url(target_url)
        return {
            "statusCode": 200,
            "headers": cors_headers,
            "body": json.dumps(analysis_result)
        }
    except URLValidationError as ve:
        return {
            "statusCode": 400,
            "headers": cors_headers,
            "body": json.dumps({
                "status": "error",
                "message": str(ve)
            })
        }
    except Exception as exc:
        # Log internal error without exposing stack trace to client
        print(f"ERROR during analysis: {type(exc).__name__}: {str(exc)}")
        return {
            "statusCode": 500,
            "headers": cors_headers,
            "body": json.dumps({
                "status": "error",
                "message": "An internal error occurred during security analysis."
            })
        }

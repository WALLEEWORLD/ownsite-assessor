"""HTTP security header posture checks."""

from __future__ import annotations

from typing import Any

from assessor.http_client import AssessorClient


# Header name -> (recommended presence, severity if missing, remediation)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        True,
        "medium",
        "Add HSTS: max-age=31536000; includeSubDomains; preload (after validating HTTPS).",
    ),
    "Content-Security-Policy": (
        True,
        "medium",
        "Define a CSP that denies unexpected script/style sources; avoid 'unsafe-inline' long-term.",
    ),
    "X-Content-Type-Options": (
        True,
        "low",
        "Set X-Content-Type-Options: nosniff",
    ),
    "X-Frame-Options": (
        True,
        "low",
        "Set X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    ),
    "Referrer-Policy": (
        True,
        "low",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    ),
    "Permissions-Policy": (
        True,
        "info",
        "Set Permissions-Policy to disable unused browser features.",
    ),
    "Cross-Origin-Opener-Policy": (
        False,
        "info",
        "Consider COOP: same-origin for stronger isolation.",
    ),
    "Cross-Origin-Resource-Policy": (
        False,
        "info",
        "Consider CORP for sensitive responses.",
    ),
}


def _header_get(headers: dict[str, str], name: str) -> str | None:
    lower = {k.lower(): v for k, v in headers.items()}
    return lower.get(name.lower())


def analyze_headers(url: str, headers: dict[str, str], status_code: int | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    present = {k: _header_get(headers, k) for k in SECURITY_HEADERS}

    for name, (required, severity, remediation) in SECURITY_HEADERS.items():
        value = present.get(name)
        if not value and required:
            findings.append(
                {
                    "severity": severity,
                    "url": url,
                    "title": f"Missing security header: {name}",
                    "detail": f"{name} not present on response.",
                    "remediation": remediation,
                }
            )
        elif not value and not required:
            findings.append(
                {
                    "severity": severity,
                    "url": url,
                    "title": f"Optional header absent: {name}",
                    "detail": remediation,
                }
            )

    hsts = present.get("Strict-Transport-Security")
    if hsts:
        if "max-age=" not in hsts.lower():
            findings.append(
                {
                    "severity": "medium",
                    "url": url,
                    "title": "HSTS missing max-age",
                    "detail": hsts,
                }
            )
        else:
            # crude parse
            try:
                part = [p.strip() for p in hsts.split(";") if "max-age" in p.lower()][0]
                age = int(part.split("=")[1].strip())
                if age < 15552000:  # ~180 days
                    findings.append(
                        {
                            "severity": "low",
                            "url": url,
                            "title": "HSTS max-age is short",
                            "detail": f"max-age={age}; recommend >= 15552000 (180d), ideally 31536000.",
                        }
                    )
            except (IndexError, ValueError):
                pass

    csp = present.get("Content-Security-Policy")
    if csp and "unsafe-inline" in csp:
        findings.append(
            {
                "severity": "low",
                "url": url,
                "title": "CSP allows 'unsafe-inline'",
                "detail": "Prefer nonces/hashes over unsafe-inline for scripts.",
                "remediation": "Migrate inline scripts to nonced/hashed CSP.",
            }
        )

    xfo = present.get("X-Frame-Options")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(
            {
                "severity": "low",
                "url": url,
                "title": "Unusual X-Frame-Options value",
                "detail": xfo,
            }
        )

    # Information disclosure headers
    server = _header_get(headers, "Server")
    if server and any(ch.isdigit() for ch in server):
        findings.append(
            {
                "severity": "info",
                "url": url,
                "title": "Server header discloses version-like detail",
                "detail": server,
                "remediation": "Minimize Server banner detail at the edge.",
            }
        )
    powered = _header_get(headers, "X-Powered-By")
    if powered:
        findings.append(
            {
                "severity": "low",
                "url": url,
                "title": "X-Powered-By header present",
                "detail": powered,
                "remediation": "Remove X-Powered-By from production responses.",
            }
        )

    # Cookies
    # requests merges Set-Cookie poorly when multiple; use raw if available
    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
    if set_cookie:
        sc_l = set_cookie.lower()
        if "secure" not in sc_l and url.startswith("https://"):
            findings.append(
                {
                    "severity": "medium",
                    "url": url,
                    "title": "Set-Cookie may lack Secure flag",
                    "detail": set_cookie[:300],
                    "remediation": "Mark session cookies Secure; Prefer; HttpOnly; SameSite.",
                }
            )
        if "httponly" not in sc_l:
            findings.append(
                {
                    "severity": "medium",
                    "url": url,
                    "title": "Set-Cookie may lack HttpOnly flag",
                    "detail": set_cookie[:300],
                    "remediation": "Mark session cookies HttpOnly.",
                }
            )
        if "samesite" not in sc_l:
            findings.append(
                {
                    "severity": "low",
                    "url": url,
                    "title": "Set-Cookie may lack SameSite attribute",
                    "detail": set_cookie[:300],
                    "remediation": "Set SameSite=Lax or Strict as appropriate.",
                }
            )

    if status_code and status_code >= 500:
        findings.append(
            {
                "severity": "medium",
                "url": url,
                "title": f"Server error status {status_code}",
                "detail": "Unexpected 5xx on baseline request.",
            }
        )

    return findings


def run(client: AssessorClient, url: str) -> dict[str, Any]:
    meta = client.request_meta(url)
    findings = []
    if meta.get("error"):
        findings.append(
            {
                "severity": "medium",
                "url": url,
                "title": "Request failed",
                "detail": meta["error"],
            }
        )
    else:
        findings = analyze_headers(url, meta.get("headers") or {}, meta.get("status_code"))

    return {
        "url": url,
        "response": {
            "status_code": meta.get("status_code"),
            "final_url": meta.get("final_url"),
            "elapsed_ms": meta.get("elapsed_ms"),
            "headers": meta.get("headers"),
            "error": meta.get("error"),
        },
        "findings": findings,
    }

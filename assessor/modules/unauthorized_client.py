"""Simulate unauthorized / unknown devices against your own access controls.

Mimics how a real authorized pentest validates that clients WITHOUT valid
identity, session, or device proof are rejected.

This module:
  - sends unauthenticated requests under multiple device/UA profiles
  - presents invalid / malformed / empty credentials
  - checks HTTP methods on protected paths without auth
  - does NOT brute-force passwords, crack tokens, or ship exploit payloads
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import requests

from assessor.http_client import AssessorClient


# Device / client profiles used to mimic heterogeneous unauthenticated traffic
DEVICE_PROFILES: list[dict[str, str]] = [
    {
        "name": "anonymous-desktop-chrome",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
    },
    {
        "name": "anonymous-mobile-ios",
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 "
            "Mobile/15E148 Safari/604.1"
        ),
    },
    {
        "name": "anonymous-mobile-android",
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
        ),
    },
    {
        "name": "anonymous-curl",
        "User-Agent": "curl/8.5.0",
    },
    {
        "name": "anonymous-bot-like",
        "User-Agent": "python-requests/2.31.0",
    },
    {
        "name": "empty-ua",
        "User-Agent": "",
    },
]

# Credential-shaped garbage — must be rejected (not real secrets)
INVALID_AUTH_VARIANTS: list[dict[str, Any]] = [
    {
        "name": "no-credentials",
        "headers": {},
        "cookies": {},
    },
    {
        "name": "empty-bearer",
        "headers": {"Authorization": "Bearer "},
        "cookies": {},
    },
    {
        "name": "malformed-bearer",
        "headers": {"Authorization": "Bearer not.a.real.jwt"},
        "cookies": {},
    },
    {
        "name": "basic-empty",
        "headers": {"Authorization": "Basic Og=="},  # ":" base64
        "cookies": {},
    },
    {
        "name": "random-session-cookie",
        "headers": {},
        "cookies": {"session": "invalid-unauthorized-device-probe-0000"},
    },
    {
        "name": "expired-looking-jwt-shape",
        # structurally JWT-like garbage (header.payload.sig) — not a real token
        "headers": {
            "Authorization": (
                "Bearer eyJhbGciOiJub25lIn0."
                "eyJzdWIiOiJ1bmF1dGh6In0."
                "invalid"
            )
        },
        "cookies": {},
    },
]

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")


def _is_auth_challenge(status: int | None, headers: dict[str, str], final_url: str, body: str) -> bool:
    if status in (401, 403):
        return True
    lower_h = {k.lower(): v for k, v in headers.items()}
    if "www-authenticate" in lower_h:
        return True
    final = (final_url or "").lower()
    if any(
        x in final
        for x in (
            "login",
            "signin",
            "sign-in",
            "oauth",
            "sso",
            "accounts.google",
            "login.microsoftonline",
            "okta.com",
            "auth0.com",
            "cloudflareaccess",
        )
    ):
        return True
    if status in (302, 303, 307, 308):
        loc = lower_h.get("location", "").lower()
        if any(x in loc for x in ("login", "signin", "oauth", "sso", "authorize")):
            return True
    bl = (body or "").lower()
    if status == 200 and any(k in bl for k in ("sign in", "log in", "authenticate")) and (
        "password" in bl or "oauth" in bl or "sso" in bl
    ):
        return True
    return False


def _looks_like_app_content(status: int | None, body: str, content_type: str) -> bool:
    if status != 200:
        return False
    if not body or len(body) < 80:
        return False
    ct = (content_type or "").lower()
    if "json" in ct:
        # bare error JSON is OK; object-y success payloads are suspicious without auth
        low = body.lower()
        if any(k in low for k in ('"error"', '"unauthorized"', '"message":"auth')):
            return False
        return True
    if "html" in ct or body.lstrip().lower().startswith(("<!doctype", "<html")):
        low = body.lower()
        # login page is a challenge, not app content
        if any(k in low for k in ("sign in", "log in", "password", "oauth")):
            return False
        # generic marketing shell is weak signal — require app-ish markers
        if any(k in low for k in ("dashboard", "logout", "sign out", "admin panel", "api token")):
            return True
    return False


def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    timeout: float,
    allow_redirects: bool = True,
) -> dict[str, Any]:
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            cookies=cookies or None,
            timeout=timeout,
            allow_redirects=allow_redirects,
            data=b"{}" if method in ("POST", "PUT", "PATCH") else None,
        )
        return {
            "status_code": resp.status_code,
            "final_url": str(resp.url),
            "headers": {k: v for k, v in resp.headers.items()},
            "content_type": resp.headers.get("Content-Type", ""),
            "body_sample": (resp.text or "")[:1500],
            "content_length": len(resp.content or b""),
            "error": None,
        }
    except requests.RequestException as exc:
        return {
            "status_code": None,
            "final_url": None,
            "headers": {},
            "content_type": "",
            "body_sample": "",
            "content_length": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }


def run(
    scheme: str,
    host: str,
    protected_paths: list[str],
    *,
    timeout: float = 10.0,
    profiles: list[dict[str, str]] | None = None,
    max_paths: int = 8,
    max_profiles: int = 6,
    method_check: bool = True,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    results: dict[str, Any] = {
        "device_matrix": [],
        "invalid_credential_matrix": [],
        "method_matrix": [],
        "findings": findings,
    }

    paths = list(protected_paths or [])[:max_paths]
    if not paths:
        findings.append(
            {
                "severity": "info",
                "host": host,
                "title": "No protected paths configured for unauthorized-client tests",
                "detail": "Set target.auth_protected_paths in config.",
            }
        )
        return results

    used_profiles = (profiles or DEVICE_PROFILES)[:max_profiles]
    base = f"{scheme}://{host}"

    # --- Device profile × protected path (no credentials) ---
    for path in paths:
        url = urljoin(base + "/", path.lstrip("/"))
        for prof in used_profiles:
            headers = {
                "User-Agent": prof.get("User-Agent", ""),
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            }
            meta = _request("GET", url, headers=headers, cookies={}, timeout=timeout)
            challenged = _is_auth_challenge(
                meta.get("status_code"),
                meta.get("headers") or {},
                meta.get("final_url") or "",
                meta.get("body_sample") or "",
            )
            open_content = _looks_like_app_content(
                meta.get("status_code"),
                meta.get("body_sample") or "",
                meta.get("content_type") or "",
            )
            entry = {
                "path": path,
                "profile": prof.get("name"),
                "status_code": meta.get("status_code"),
                "final_url": meta.get("final_url"),
                "auth_challenge": challenged,
                "appears_authorized_content": open_content,
                "error": meta.get("error"),
            }
            results["device_matrix"].append(entry)

            if meta.get("error"):
                continue
            if open_content and not challenged:
                findings.append(
                    {
                        "severity": "high",
                        "url": url,
                        "title": (
                            f"Unauthorized device profile reached app content on {path} "
                            f"({prof.get('name')})"
                        ),
                        "detail": (
                            f"Unauthenticated {prof.get('name')} GET returned HTTP "
                            f"{meta.get('status_code')} with app-like content and no auth challenge. "
                            "Real-world unauthorized clients should be denied."
                        ),
                        "remediation": (
                            "Enforce authentication at the edge (Access/IAP/oauth2-proxy) "
                            "or application middleware for all non-public routes."
                        ),
                    }
                )
            elif meta.get("status_code") == 200 and not challenged and (meta.get("content_length") or 0) > 400:
                findings.append(
                    {
                        "severity": "medium",
                        "url": url,
                        "title": (
                            f"Protected path returned 200 without clear challenge "
                            f"({prof.get('name')}: {path})"
                        ),
                        "detail": (
                            "May be SPA shell fallback. Confirm API/data endpoints behind it "
                            "also reject unauthorized clients."
                        ),
                        "remediation": "Ensure APIs return 401/403 without a valid session/token.",
                    }
                )

    # --- Invalid credential variants (primary protected path) ---
    primary = paths[0]
    primary_url = urljoin(base + "/", primary.lstrip("/"))
    desktop_ua = DEVICE_PROFILES[0]["User-Agent"]
    for variant in INVALID_AUTH_VARIANTS:
        headers = {
            "User-Agent": desktop_ua,
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
            **(variant.get("headers") or {}),
        }
        meta = _request(
            "GET",
            primary_url,
            headers=headers,
            cookies=variant.get("cookies") or {},
            timeout=timeout,
        )
        challenged = _is_auth_challenge(
            meta.get("status_code"),
            meta.get("headers") or {},
            meta.get("final_url") or "",
            meta.get("body_sample") or "",
        )
        open_content = _looks_like_app_content(
            meta.get("status_code"),
            meta.get("body_sample") or "",
            meta.get("content_type") or "",
        )
        entry = {
            "path": primary,
            "variant": variant["name"],
            "status_code": meta.get("status_code"),
            "auth_challenge": challenged,
            "appears_authorized_content": open_content,
            "error": meta.get("error"),
        }
        results["invalid_credential_matrix"].append(entry)

        if open_content and not challenged:
            findings.append(
                {
                    "severity": "critical",
                    "url": primary_url,
                    "title": f"Invalid credentials accepted as authorized ({variant['name']})",
                    "detail": (
                        f"Variant '{variant['name']}' received app-like content without an "
                        "auth challenge. Unauthorized clients must not gain access with "
                        "empty/malformed tokens."
                    ),
                    "remediation": (
                        "Reject missing/invalid Authorization headers and session cookies "
                        "server-side; never trust client-supplied identity claims without verification."
                    ),
                }
            )
        elif challenged or meta.get("status_code") in (401, 403, 302, 303, 307, 308):
            findings.append(
                {
                    "severity": "info",
                    "url": primary_url,
                    "title": f"Invalid credential variant correctly challenged ({variant['name']})",
                    "detail": f"status={meta.get('status_code')} challenge={challenged}",
                }
            )

    # --- Method matrix without auth (one path) ---
    if method_check:
        for method in HTTP_METHODS:
            meta = _request(
                method,
                primary_url,
                headers={"User-Agent": desktop_ua, "Accept": "*/*", "Content-Type": "application/json"},
                cookies={},
                timeout=timeout,
                allow_redirects=False,
            )
            status = meta.get("status_code")
            challenged = _is_auth_challenge(
                status,
                meta.get("headers") or {},
                meta.get("final_url") or "",
                meta.get("body_sample") or "",
            )
            entry = {
                "path": primary,
                "method": method,
                "status_code": status,
                "auth_challenge": challenged,
                "allow_header": (meta.get("headers") or {}).get("Allow")
                or (meta.get("headers") or {}).get("allow"),
                "error": meta.get("error"),
            }
            results["method_matrix"].append(entry)

            # Dangerous: mutating method returns 2xx without auth
            if method in ("POST", "PUT", "PATCH", "DELETE") and status and 200 <= status < 300 and not challenged:
                findings.append(
                    {
                        "severity": "high",
                        "url": primary_url,
                        "title": f"Unauthenticated {method} appears accepted on {primary}",
                        "detail": (
                            f"HTTP {status} without auth challenge. Unauthorized devices "
                            "should not perform state-changing operations."
                        ),
                        "remediation": f"Require auth for {method}; return 401/403 when unauthenticated.",
                    }
                )
            elif method == "OPTIONS" and status and 200 <= status < 300:
                allow = entry.get("allow_header") or ""
                findings.append(
                    {
                        "severity": "info",
                        "url": primary_url,
                        "title": "OPTIONS response observed on protected path",
                        "detail": f"status={status} Allow={allow}",
                    }
                )

    # Summary finding if all device profiles correctly challenged on all paths
    highs = [f for f in findings if f.get("severity") in ("critical", "high")]
    if paths and used_profiles and not highs:
        challenged_rows = [
            r for r in results["device_matrix"] if r.get("auth_challenge") or r.get("status_code") in (401, 403)
        ]
        if len(challenged_rows) >= max(1, len(results["device_matrix"]) // 2):
            findings.append(
                {
                    "severity": "info",
                    "host": host,
                    "title": "Unauthorized device simulation: most protected paths challenge anonymous clients",
                    "detail": (
                        f"Profiles tested={len(used_profiles)}, paths={len(paths)}. "
                        "Continue with manual ZAP/Burp review for business-logic gaps."
                    ),
                }
            )

    return results

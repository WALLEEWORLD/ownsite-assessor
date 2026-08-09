"""Verify access-control gates behave as intended (authorized self-test).

Checks whether protected paths reject unauthenticated access and whether
public paths remain reachable. Does not attempt credential stuffing,
brute force, or auth bypass exploits.
"""

from __future__ import annotations

from typing import Any

from assessor.http_client import AssessorClient


AUTH_HINT_STATUSES = {401, 403, 302, 303, 307, 308}
LOGIN_HINTS = (
    "login",
    "sign-in",
    "signin",
    "auth",
    "sso",
    "oauth",
    "cloudflareaccess",
    "accounts.google",
    "login.microsoftonline",
    "okta.com",
    "auth0.com",
)


def _looks_like_auth_challenge(meta: dict[str, Any]) -> bool:
    status = meta.get("status_code")
    if status in (401, 403):
        return True
    headers = {k.lower(): v for k, v in (meta.get("headers") or {}).items()}
    if "www-authenticate" in headers:
        return True
    final = (meta.get("final_url") or "").lower()
    if any(h in final for h in LOGIN_HINTS):
        return True
    body = (meta.get("body_sample") or "").lower()
    if status in (200, 401, 403) and any(
        k in body for k in ("sign in", "log in", "authenticate", "sso")
    ):
        # weak signal only
        return status != 200 or "password" in body or "oauth" in body
    if status in AUTH_HINT_STATUSES and meta.get("redirected"):
        return True
    return False


def run(
    client: AssessorClient,
    scheme: str,
    host: str,
    protected_paths: list[str],
    public_paths: list[str],
    *,
    authenticated_client: AssessorClient | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    results: dict[str, Any] = {
        "protected": [],
        "public": [],
        "authenticated_baseline": [],
        "findings": findings,
    }

    # --- Protected paths should NOT be openly readable without auth ---
    for path in protected_paths:
        url = AssessorClient.build_url(scheme, host, path)
        # Use a fresh-ish request without relying on cookies from auth client
        meta = client.request_meta(url)
        entry = {
            "path": path,
            "url": url,
            "status_code": meta.get("status_code"),
            "final_url": meta.get("final_url"),
            "error": meta.get("error"),
            "auth_challenge_detected": False,
        }
        if meta.get("error"):
            findings.append(
                {
                    "severity": "info",
                    "url": url,
                    "title": f"Protected path request error: {path}",
                    "detail": meta["error"],
                }
            )
        else:
            challenged = _looks_like_auth_challenge(meta)
            entry["auth_challenge_detected"] = challenged
            status = meta.get("status_code")
            # 200 with substantial body and no auth challenge = possible open access
            if status == 200 and not challenged and (meta.get("content_length") or 0) > 200:
                findings.append(
                    {
                        "severity": "high",
                        "url": url,
                        "title": f"Protected path appears publicly readable: {path}",
                        "detail": (
                            f"Unauthenticated GET returned HTTP {status} with "
                            f"{meta.get('content_length')} bytes and no clear auth challenge. "
                            "Confirm this path is intentionally public or enforce auth."
                        ),
                        "remediation": (
                            "Require authentication at the edge (Cloudflare Access / IAP / "
                            "oauth2-proxy) or application middleware; return 401/403 or redirect to IdP."
                        ),
                    }
                )
            elif status == 404:
                findings.append(
                    {
                        "severity": "info",
                        "url": url,
                        "title": f"Protected path not found: {path}",
                        "detail": "Path returned 404 — update config if route moved.",
                    }
                )
            elif challenged:
                findings.append(
                    {
                        "severity": "info",
                        "url": url,
                        "title": f"Auth gate observed on {path}",
                        "detail": f"status={status}, final_url={meta.get('final_url')}",
                    }
                )
            elif status in (401, 403):
                entry["auth_challenge_detected"] = True
        results["protected"].append(entry)

    # --- Public paths should be reachable ---
    for path in public_paths:
        url = AssessorClient.build_url(scheme, host, path)
        meta = client.request_meta(url)
        entry = {
            "path": path,
            "url": url,
            "status_code": meta.get("status_code"),
            "final_url": meta.get("final_url"),
            "error": meta.get("error"),
        }
        status = meta.get("status_code")
        if meta.get("error"):
            findings.append(
                {
                    "severity": "medium",
                    "url": url,
                    "title": f"Public path unreachable: {path}",
                    "detail": meta["error"],
                }
            )
        elif status and status >= 500:
            findings.append(
                {
                    "severity": "medium",
                    "url": url,
                    "title": f"Public path server error: {path}",
                    "detail": f"HTTP {status}",
                }
            )
        elif status == 404 and path in ("/", "/health"):
            findings.append(
                {
                    "severity": "low",
                    "url": url,
                    "title": f"Expected public path missing: {path}",
                    "detail": f"HTTP {status}",
                }
            )
        results["public"].append(entry)

    # --- Optional authenticated baseline (session cookie provided) ---
    if authenticated_client is not None:
        for path in protected_paths:
            url = AssessorClient.build_url(scheme, host, path)
            meta = authenticated_client.request_meta(url)
            entry = {
                "path": path,
                "url": url,
                "status_code": meta.get("status_code"),
                "final_url": meta.get("final_url"),
                "error": meta.get("error"),
            }
            status = meta.get("status_code")
            if status in (401, 403):
                findings.append(
                    {
                        "severity": "medium",
                        "url": url,
                        "title": f"Authenticated session still denied on {path}",
                        "detail": (
                            f"HTTP {status}. Cookie may be invalid/expired, or path requires "
                            "stronger role than the provided session."
                        ),
                    }
                )
            elif status and 200 <= status < 400:
                findings.append(
                    {
                        "severity": "info",
                        "url": url,
                        "title": f"Authenticated access OK on {path}",
                        "detail": f"HTTP {status}",
                    }
                )
            results["authenticated_baseline"].append(entry)

    return results

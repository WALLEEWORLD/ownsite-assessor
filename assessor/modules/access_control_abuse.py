"""Access-control abuse cases used in authorized real-world pentests.

Simulates common ways unauthorized or low-privilege clients try to reach
protected resources — without exploit payloads or credential attacks.

Checks:
  - Trust of spoofable client identity headers (X-Forwarded-*, X-Original-URL, ...)
  - Path normalization / traversal-style route confusions (encoded dots, slash tricks)
  - CORS reflection from arbitrary unauthorized origins
  - Cacheability of authenticated-looking responses
  - Host-header confusion signals
  - Optional vertical/horizontal path probes from config (no brute force)
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import requests


def _get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    allow_redirects: bool = True,
) -> dict[str, Any]:
    try:
        resp = requests.get(
            url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        return {
            "status_code": resp.status_code,
            "final_url": str(resp.url),
            "headers": {k: v for k, v in resp.headers.items()},
            "content_type": resp.headers.get("Content-Type", ""),
            "body_sample": (resp.text or "")[:2000],
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


def _challenged(meta: dict[str, Any]) -> bool:
    status = meta.get("status_code")
    if status in (401, 403):
        return True
    headers = {k.lower(): v for k, v in (meta.get("headers") or {}).items()}
    if "www-authenticate" in headers:
        return True
    final = (meta.get("final_url") or "").lower()
    loc = headers.get("location", "").lower()
    blob = final + " " + loc
    return any(x in blob for x in ("login", "signin", "oauth", "sso", "authorize", "cloudflareaccess"))


def _app_content(meta: dict[str, Any]) -> bool:
    if meta.get("status_code") != 200:
        return False
    body = (meta.get("body_sample") or "").lower()
    ct = (meta.get("content_type") or "").lower()
    if len(body) < 60:
        return False
    if any(k in body for k in ("sign in", "log in", "password", "unauthorized", "access denied")):
        return False
    if "json" in ct:
        return not any(k in body for k in ('"error"', '"status":401', '"status":403'))
    if "html" in ct or body.lstrip().startswith(("<!doctype", "<html")):
        return any(k in body for k in ("dashboard", "logout", "sign out", "admin", "welcome back"))
    return False


# Header sets unauthorized clients sometimes use hoping the app trusts them
SPOOF_HEADER_CASES: list[dict[str, Any]] = [
    {
        "name": "x-forwarded-for-loopback",
        "headers": {"X-Forwarded-For": "127.0.0.1"},
    },
    {
        "name": "x-real-ip-loopback",
        "headers": {"X-Real-IP": "127.0.0.1"},
    },
    {
        "name": "x-original-url-admin",
        "headers": {"X-Original-URL": "/admin"},
    },
    {
        "name": "x-rewrite-url-admin",
        "headers": {"X-Rewrite-URL": "/admin"},
    },
    {
        "name": "x-custom-ip-authorization",
        "headers": {"X-Custom-IP-Authorization": "127.0.0.1"},
    },
    {
        "name": "forwarded-for-internal",
        "headers": {"Forwarded": "for=10.0.0.1;proto=https"},
    },
    {
        "name": "x-forwarded-host-localhost",
        "headers": {"X-Forwarded-Host": "localhost"},
    },
]


def _path_confusion_variants(path: str) -> list[tuple[str, str]]:
    """Safe route-confusion probes (no OS payload execution)."""
    p = path if path.startswith("/") else f"/{path}"
    base = p.rstrip("/") or "/"
    name = base.split("/")[-1] or "admin"
    parent = base.rsplit("/", 1)[0] or ""
    return [
        (f"{base}/", "trailing-slash"),
        (f"{base}/.", "dot-segment"),
        (f"{base}%2f", "encoded-slash-suffix"),
        (f"{base}%20", "encoded-space"),
        (f"{base};.css", "path-param-css"),
        (f"{base}.json", "extension-json"),
        (f"/{name}", "stripped-prefix") if parent else (f"//{name}", "double-slash"),
        (f"{parent}/.{name}" if parent else f"/.{name}", "dot-prefix-name"),
        (f"{base}%00", "null-byte-suffix"),
        (f"/{name.upper()}" if name != name.upper() else f"{base}/./", "case-shift"),
    ]


def run(
    scheme: str,
    host: str,
    protected_paths: list[str],
    *,
    timeout: float = 10.0,
    cors_test_origin: str = "https://unauthorized-device.example",
    extra_probe_paths: list[str] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    out: dict[str, Any] = {
        "spoof_headers": [],
        "path_confusion": [],
        "cors": [],
        "cache": [],
        "host_header": [],
        "extra_paths": [],
        "findings": findings,
    }

    paths = list(protected_paths or [])[:6]
    if not paths:
        findings.append(
            {
                "severity": "info",
                "host": host,
                "title": "No protected paths for access-control abuse simulation",
                "detail": "Configure target.auth_protected_paths.",
            }
        )
        return out

    base = f"{scheme}://{host}"
    ua = "OwnSiteAssessor/1.0 (+authorized-access-control-abuse-sim)"
    primary = paths[0]
    primary_url = urljoin(base + "/", primary.lstrip("/"))

    # Baseline unauthenticated request
    baseline = _get(
        primary_url,
        headers={"User-Agent": ua, "Accept": "*/*"},
        timeout=timeout,
    )
    baseline_status = baseline.get("status_code")
    baseline_len = baseline.get("content_length") or 0
    baseline_challenged = _challenged(baseline)

    # --- Spoofable identity / rewrite headers ---
    for case in SPOOF_HEADER_CASES:
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            **case["headers"],
        }
        # For X-Original-URL style, hit a public path so rewrite would matter
        url = urljoin(base + "/", "/") if "original-url" in case["name"] or "rewrite-url" in case["name"] else primary_url
        meta = _get(url, headers=headers, timeout=timeout)
        open_ = _app_content(meta)
        improved = (
            meta.get("status_code") == 200
            and not _challenged(meta)
            and (meta.get("content_length") or 0) > max(baseline_len, 200)
            and baseline_challenged
        )
        entry = {
            "case": case["name"],
            "url": url,
            "status_code": meta.get("status_code"),
            "content_length": meta.get("content_length"),
            "auth_challenge": _challenged(meta),
            "appears_authorized_content": open_,
            "possible_bypass_signal": bool(improved or (open_ and baseline_challenged)),
            "error": meta.get("error"),
        }
        out["spoof_headers"].append(entry)
        if entry["possible_bypass_signal"]:
            findings.append(
                {
                    "severity": "high",
                    "url": url,
                    "title": f"Possible access-control trust of client header ({case['name']})",
                    "detail": (
                        f"Unauthenticated request with {case['headers']} obtained a stronger "
                        f"response (status={meta.get('status_code')}, len={meta.get('content_length')}) "
                        f"than baseline (status={baseline_status}, challenged={baseline_challenged}). "
                        "Apps must not trust spoofable client headers for authz."
                    ),
                    "remediation": (
                        "Ignore X-Original-URL/X-Rewrite-URL from the public internet; "
                        "only trust hop-by-hop headers from your own reverse proxy with "
                        "connection sanitization. Never authorize on X-Forwarded-For alone."
                    ),
                }
            )

    # --- Path confusion / normalization ---
    for path in paths[:3]:
        for variant, label in _path_confusion_variants(path):
            url = urljoin(base + "/", variant.lstrip("/"))
            # urljoin may collapse; build manually for odd encodings
            url = f"{base}{variant}" if variant.startswith("/") else urljoin(base + "/", variant)
            meta = _get(
                url,
                headers={"User-Agent": ua, "Accept": "*/*"},
                timeout=timeout,
            )
            open_ = _app_content(meta)
            entry = {
                "base_path": path,
                "variant": variant,
                "label": label,
                "status_code": meta.get("status_code"),
                "final_url": meta.get("final_url"),
                "auth_challenge": _challenged(meta),
                "appears_authorized_content": open_,
                "error": meta.get("error"),
            }
            out["path_confusion"].append(entry)
            if open_ and not _challenged(meta) and baseline_challenged:
                findings.append(
                    {
                        "severity": "high",
                        "url": url,
                        "title": f"Path confusion may skip auth gate ({label})",
                        "detail": (
                            f"Variant `{variant}` of `{path}` returned app-like content while "
                            "the canonical path challenges unauthenticated users."
                        ),
                        "remediation": (
                            "Normalize paths before authz; deny encoded/alternate forms; "
                            "apply auth middleware before static/SPA fallbacks."
                        ),
                    }
                )

    # --- CORS from unauthorized origin ---
    for path in paths[:2]:
        url = f"{base}{path if path.startswith('/') else '/' + path}"
        meta = _get(
            url,
            headers={
                "User-Agent": ua,
                "Origin": cors_test_origin,
                "Accept": "*/*",
            },
            timeout=timeout,
        )
        headers = {k.lower(): v for k, v in (meta.get("headers") or {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        entry = {
            "path": path,
            "origin": cors_test_origin,
            "status_code": meta.get("status_code"),
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "error": meta.get("error"),
        }
        out["cors"].append(entry)
        if acao == "*":
            findings.append(
                {
                    "severity": "medium" if acac.lower() != "true" else "high",
                    "url": url,
                    "title": "CORS allows any origin on protected path",
                    "detail": f"ACAO=* credentials={acac}",
                    "remediation": "Reflect only trusted origins; never pair ACAO:* with credentials.",
                }
            )
        elif acao == cors_test_origin:
            sev = "high" if acac.lower() == "true" else "medium"
            findings.append(
                {
                    "severity": sev,
                    "url": url,
                    "title": "CORS reflects unauthorized origin",
                    "detail": (
                        f"Server reflected Origin {cors_test_origin}. "
                        f"Allow-Credentials={acac or '(absent)'}."
                    ),
                    "remediation": "Allowlist explicit trusted web origins; reject unknown devices' browsers.",
                }
            )

    # --- Cache headers on protected responses ---
    meta = baseline
    headers = {k.lower(): v for k, v in (meta.get("headers") or {}).items()}
    cc = headers.get("cache-control", "")
    out["cache"].append(
        {
            "path": primary,
            "status_code": meta.get("status_code"),
            "cache_control": cc,
            "pragma": headers.get("pragma"),
            "expires": headers.get("expires"),
            "vary": headers.get("vary"),
        }
    )
    if meta.get("status_code") == 200 and cc:
        if any(x in cc.lower() for x in ("public", "max-age=")) and "private" not in cc.lower() and "no-store" not in cc.lower():
            findings.append(
                {
                    "severity": "medium",
                    "url": primary_url,
                    "title": "Protected path response may be publicly cacheable",
                    "detail": f"Cache-Control: {cc}",
                    "remediation": "Use Cache-Control: no-store (or private, no-cache) on authenticated responses.",
                }
            )

    # --- Host header basic confusion (response comparison only) ---
    for injected_host in ("localhost", "evil.example", host + ".evil.example"):
        try:
            resp = requests.get(
                primary_url,
                headers={"User-Agent": ua, "Host": injected_host, "Accept": "*/*"},
                timeout=timeout,
                allow_redirects=False,
            )
            loc = resp.headers.get("Location", "")
            entry = {
                "injected_host": injected_host,
                "status_code": resp.status_code,
                "location": loc,
                "error": None,
            }
            out["host_header"].append(entry)
            if loc and injected_host in loc:
                findings.append(
                    {
                        "severity": "medium",
                        "url": primary_url,
                        "title": "Host header reflected in redirect Location",
                        "detail": f"Host={injected_host} → Location={loc}",
                        "remediation": "Use a configured canonical host; do not trust Host for redirects/auth.",
                    }
                )
        except requests.RequestException as exc:
            out["host_header"].append(
                {"injected_host": injected_host, "error": f"{type(exc).__name__}: {exc}"}
            )

    # --- Extra probe paths (from config) as unauthorized client ---
    for path in list(extra_probe_paths or [])[:20]:
        url = f"{base}{path if path.startswith('/') else '/' + path}"
        meta = _get(url, headers={"User-Agent": ua, "Accept": "*/*"}, timeout=timeout)
        entry = {
            "path": path,
            "status_code": meta.get("status_code"),
            "auth_challenge": _challenged(meta),
            "appears_authorized_content": _app_content(meta),
            "content_length": meta.get("content_length"),
            "error": meta.get("error"),
        }
        out["extra_paths"].append(entry)
        if entry["appears_authorized_content"] and not entry["auth_challenge"]:
            findings.append(
                {
                    "severity": "high",
                    "url": url,
                    "title": f"Extra probe path readable without auth: {path}",
                    "detail": f"status={meta.get('status_code')} len={meta.get('content_length')}",
                    "remediation": "Require auth or remove the route from public exposure.",
                }
            )

    if not any(f.get("severity") in ("critical", "high") for f in findings):
        findings.append(
            {
                "severity": "info",
                "host": host,
                "title": "Access-control abuse simulation found no high-confidence bypass signals",
                "detail": (
                    "Spoofed headers, path confusion, and unauthorized CORS origin were tested. "
                    "This is not a guarantee of safety — continue manual authorized review."
                ),
            }
        )

    return out

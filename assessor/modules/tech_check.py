"""Lightweight technology / stack fingerprinting from headers and body samples."""

from __future__ import annotations

import re
from typing import Any

from assessor.http_client import AssessorClient


HEADER_HINTS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-drupal-cache": "Drupal",
    "x-generator": "Generator",
    "x-shopify-stage": "Shopify",
    "x-vercel-id": "Vercel",
    "x-vercel-cache": "Vercel",
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "CloudFront",
    "x-amz-request-id": "AWS",
    "x-azure-ref": "Azure",
    "x-served-by": "Fastly/Varnish",
    "x-nextjs-cache": "Next.js",
    "x-nextjs-request-id": "Next.js",
    "x-supabase-api-version": "Supabase",
}

BODY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("WordPress", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
    ("React", re.compile(r"data-reactroot|_next/static|__NEXT_DATA__", re.I)),
    ("Next.js", re.compile(r"__NEXT_DATA__|_next/static", re.I)),
    ("Angular", re.compile(r"ng-version=|angular\.js", re.I)),
    ("Vue.js", re.compile(r"data-v-[a-f0-9]{6,}|vue\.js", re.I)),
    ("jQuery", re.compile(r"jquery[.-]", re.I)),
    ("Bootstrap", re.compile(r"bootstrap[.-]", re.I)),
    ("Django", re.compile(r"csrfmiddlewaretoken", re.I)),
    ("Laravel", re.compile(r"laravel_session|csrf-token", re.I)),
    ("Shopify", re.compile(r"cdn\.shopify\.com", re.I)),
    ("Google Analytics", re.compile(r"gtag\(|google-analytics\.com|googletagmanager", re.I)),
]


def run(client: AssessorClient, url: str) -> dict[str, Any]:
    meta = client.request_meta(url)
    findings: list[dict[str, Any]] = []
    tech: list[str] = []
    evidence: dict[str, str] = {}

    if meta.get("error"):
        return {
            "url": url,
            "technologies": [],
            "evidence": {},
            "findings": [
                {
                    "severity": "info",
                    "url": url,
                    "title": "Tech fingerprint skipped (request error)",
                    "detail": meta["error"],
                }
            ],
            "response": meta,
        }

    headers = {k.lower(): v for k, v in (meta.get("headers") or {}).items()}
    for hk, label in HEADER_HINTS.items():
        if hk in headers:
            tech.append(label)
            evidence[label] = f"header {hk}: {headers[hk][:120]}"

    body = meta.get("body_sample") or ""
    for label, pat in BODY_PATTERNS:
        if pat.search(body):
            tech.append(label)
            evidence.setdefault(label, f"body pattern: {pat.pattern}")

    # de-dupe preserve order
    seen: set[str] = set()
    uniq: list[str] = []
    for t in tech:
        if t not in seen:
            seen.add(t)
            uniq.append(t)

    if any(t in uniq for t in ("Cloudflare", "CloudFront", "Vercel", "Fastly/Varnish", "Azure")):
        findings.append(
            {
                "severity": "info",
                "url": url,
                "title": "Edge/CDN signals detected",
                "detail": ", ".join(
                    t
                    for t in uniq
                    if t in ("Cloudflare", "CloudFront", "Vercel", "Fastly/Varnish", "Azure")
                ),
            }
        )

    # version disclosure already covered partly in headers module
    if "X-Powered-By" in uniq or any("ASP.NET" in t for t in uniq):
        findings.append(
            {
                "severity": "low",
                "url": url,
                "title": "Stack disclosure via headers/body",
                "detail": ", ".join(uniq),
                "remediation": "Reduce verbose framework banners in production.",
            }
        )

    return {
        "url": url,
        "technologies": uniq,
        "evidence": evidence,
        "findings": findings,
        "response": {
            "status_code": meta.get("status_code"),
            "final_url": meta.get("final_url"),
        },
    }

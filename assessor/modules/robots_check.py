"""Fetch robots.txt and security.txt (RFC 9116) for hygiene signals."""

from __future__ import annotations

from typing import Any

from assessor.http_client import AssessorClient


def run(client: AssessorClient, scheme: str, host: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    out: dict[str, Any] = {"robots": None, "security_txt": None, "findings": findings}

    robots_url = AssessorClient.build_url(scheme, host, "/robots.txt")
    sec_url = AssessorClient.build_url(scheme, host, "/.well-known/security.txt")
    sec_url_alt = AssessorClient.build_url(scheme, host, "/security.txt")

    r_meta = client.request_meta(robots_url)
    out["robots"] = {
        "url": robots_url,
        "status_code": r_meta.get("status_code"),
        "body": (r_meta.get("body_sample") or "")[:4000],
        "error": r_meta.get("error"),
    }
    if r_meta.get("status_code") == 200:
        body = (r_meta.get("body_sample") or "").lower()
        sensitive_disallows = [
            line.strip()
            for line in (r_meta.get("body_sample") or "").splitlines()
            if line.lower().strip().startswith("disallow:")
            and any(
                k in line.lower()
                for k in ("/admin", "/api", "/internal", "/debug", "/.env", "/backup")
            )
        ]
        if sensitive_disallows:
            findings.append(
                {
                    "severity": "info",
                    "url": robots_url,
                    "title": "robots.txt lists sensitive-looking paths",
                    "detail": (
                        "Disallow does not protect paths — it advertises them. "
                        f"Samples: {sensitive_disallows[:8]}"
                    ),
                    "remediation": "Rely on auth/network controls; avoid leaking internal routes in robots.txt.",
                }
            )
        if "disallow: /" in body and "allow:" not in body:
            findings.append(
                {
                    "severity": "info",
                    "url": robots_url,
                    "title": "robots.txt disallows all crawlers",
                    "detail": "Intentional for private apps; fine if site is not meant to be indexed.",
                }
            )
    elif r_meta.get("status_code") == 404:
        findings.append(
            {
                "severity": "info",
                "url": robots_url,
                "title": "No robots.txt",
                "detail": "Optional; consider one for private apps (Disallow: /).",
            }
        )

    s_meta = client.request_meta(sec_url)
    if s_meta.get("status_code") != 200:
        s_meta = client.request_meta(sec_url_alt)
        sec_url = sec_url_alt

    out["security_txt"] = {
        "url": sec_url,
        "status_code": s_meta.get("status_code"),
        "body": (s_meta.get("body_sample") or "")[:4000],
        "error": s_meta.get("error"),
    }
    if s_meta.get("status_code") == 200:
        body = s_meta.get("body_sample") or ""
        if "Contact:" not in body and "contact:" not in body.lower():
            findings.append(
                {
                    "severity": "low",
                    "url": sec_url,
                    "title": "security.txt missing Contact field",
                    "detail": "RFC 9116 requires at least one Contact.",
                }
            )
        else:
            findings.append(
                {
                    "severity": "info",
                    "url": sec_url,
                    "title": "security.txt present",
                    "detail": "Good hygiene for vulnerability reporting.",
                }
            )
    else:
        findings.append(
            {
                "severity": "info",
                "url": sec_url,
                "title": "No security.txt found",
                "detail": "Consider publishing /.well-known/security.txt with a contact.",
                "remediation": "Add security.txt per https://securitytxt.org/",
            }
        )

    return out

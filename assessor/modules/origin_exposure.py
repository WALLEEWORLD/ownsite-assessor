"""Check for common origin / bypass exposure patterns (defensive).

Detects situations where a hostname resolves to an origin IP that answers
directly without the expected edge auth, or where common debug paths respond.
Does not exploit or force bypasses.
"""

from __future__ import annotations

import socket
from typing import Any

from assessor.http_client import AssessorClient


DEBUG_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/server-status",
    "/debug",
    "/actuator",
    "/actuator/health",
    "/phpinfo.php",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/api/docs",
    "/graphql",
    "/metrics",
    "/.well-known/openid-configuration",
]


def _resolve_ips(host: str) -> list[str]:
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(host, None):
            ip = info[4][0]
            if ip:
                ips.add(ip)
    except socket.gaierror:
        pass
    return sorted(ips)


def _is_private_ip(ip: str) -> bool:
    if ":" in ip:
        lower = ip.lower()
        return lower.startswith("fc") or lower.startswith("fd") or lower == "::1"
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o1, o2 = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if o1 == 10:
        return True
    if o1 == 127:
        return True
    if o1 == 192 and o2 == 168:
        return True
    if o1 == 172 and 16 <= o2 <= 31:
        return True
    if o1 == 169 and o2 == 254:
        return True
    return False


def run(
    client: AssessorClient,
    scheme: str,
    host: str,
    resolved_ips: list[str] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    ips = resolved_ips or _resolve_ips(host)
    result: dict[str, Any] = {
        "host": host,
        "resolved_ips": ips,
        "direct_ip_probes": [],
        "debug_paths": [],
        "findings": findings,
    }

    if not ips:
        findings.append(
            {
                "severity": "info",
                "host": host,
                "title": "No IPs resolved for origin exposure checks",
                "detail": host,
            }
        )
        return result

    public_ips = [ip for ip in ips if not _is_private_ip(ip)]
    private_ips = [ip for ip in ips if _is_private_ip(ip)]
    if private_ips:
        findings.append(
            {
                "severity": "info",
                "host": host,
                "title": "Private/RFC1918 addresses in resolution",
                "detail": f"{private_ips} — expected if testing inside a VPC/VPN.",
            }
        )

    baseline_url = AssessorClient.build_url(scheme, host, "/")
    baseline = client.request_meta(baseline_url)

    for ip in public_ips[:5]:
        url = f"{scheme}://{ip}/"
        resp_meta: dict[str, Any] = {
            "ip": ip,
            "url": url,
            "status_code": None,
            "error": None,
            "server": None,
        }
        try:
            r = client.session.get(
                url,
                headers={"Host": host, "User-Agent": client.user_agent},
                timeout=client.timeout,
                allow_redirects=False,
                verify=False,
            )
            resp_meta["status_code"] = r.status_code
            resp_meta["server"] = r.headers.get("Server")
            if r.status_code == 200 and baseline.get("status_code") in (401, 403, 302):
                findings.append(
                    {
                        "severity": "high",
                        "host": host,
                        "title": "Origin IP may answer without edge auth challenge",
                        "detail": (
                            f"Direct {scheme}://{ip}/ with Host: {host} returned 200 while "
                            f"hostname baseline returned {baseline.get('status_code')}. "
                            "Lock down origin to only accept traffic from your CDN/edge "
                            "(authenticated origin pulls / allowlist edge IPs / tunnel)."
                        ),
                        "remediation": (
                            "Put origin behind Cloudflare Tunnel / private network, or "
                            "allowlist only edge IP ranges and require authenticated origin pulls."
                        ),
                    }
                )
            elif r.status_code and r.status_code < 500:
                findings.append(
                    {
                        "severity": "medium",
                        "host": host,
                        "title": "Public origin IP accepts direct HTTP(S) connections",
                        "detail": (
                            f"{ip} responded HTTP {r.status_code}. Even if content is empty, "
                            "prefer hiding origin behind a tunnel or strict edge allowlist."
                        ),
                        "remediation": "Deny public internet to origin; allow only edge/tunnel.",
                    }
                )
        except Exception as exc:  # noqa: BLE001
            resp_meta["error"] = f"{type(exc).__name__}: {exc}"
        result["direct_ip_probes"].append(resp_meta)

    for path in DEBUG_PATHS:
        url = AssessorClient.build_url(scheme, host, path)
        meta = client.request_meta(url)
        status = meta.get("status_code")
        entry = {
            "path": path,
            "status_code": status,
            "final_url": meta.get("final_url"),
            "error": meta.get("error"),
            "content_length": meta.get("content_length"),
        }
        result["debug_paths"].append(entry)
        if status != 200 or (meta.get("content_length") or 0) <= 0:
            continue

        body = (meta.get("body_sample") or "").lower()
        ctype = (meta.get("content_type") or "").lower()
        looks_html = "text/html" in ctype or body.lstrip().startswith(
            ("<!doctype", "<html")
        )
        interesting = False

        if path == "/.git/HEAD" and "ref:" in body:
            interesting = True
        elif path == "/.env" and not looks_html and "=" in body and any(
            k in body for k in ("password", "secret", "api_key", "token", "aws_")
        ):
            interesting = True
        elif path == "/server-status" and "apache" in body and "server version" in body:
            interesting = True
        elif path == "/phpinfo.php" and "php version" in body:
            interesting = True
        elif path.startswith("/actuator") and not looks_html and (
            "status" in body or "uptime" in body
        ):
            interesting = True
        elif "swagger" in path and not looks_html and (
            "swagger" in body or "openapi" in body
        ):
            interesting = True
        elif path == "/metrics" and ("# help" in body or "http_requests" in body):
            interesting = True
        elif path == "/graphql" and not looks_html and (
            "graphql" in body or "__schema" in body
        ):
            interesting = True
        elif not looks_html and ("json" in ctype or "text/plain" in ctype):
            interesting = True

        if interesting:
            findings.append(
                {
                    "severity": "high",
                    "url": url,
                    "title": f"Sensitive path publicly readable: {path}",
                    "detail": (
                        f"HTTP 200, content-type={meta.get('content_type')}, "
                        f"len={meta.get('content_length')}"
                    ),
                    "remediation": (
                        f"Block {path} at edge/app; never expose secrets, git, "
                        "or admin debug endpoints."
                    ),
                }
            )
        elif not looks_html:
            findings.append(
                {
                    "severity": "low",
                    "url": url,
                    "title": f"Debug-ish path returned 200: {path}",
                    "detail": "Manual review recommended.",
                }
            )

    return result

"""Non-aggressive TCP connect checks against common service ports.

Note: Scanning a CDN/anycast hostname (Cloudflare, etc.) often yields
misleading "open" results. Prefer scanning true origin IPs only when you
own them and they are in scope. Default mode only checks web ports.
"""

from __future__ import annotations

import socket
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


# Default: only web-ish ports (safe, low noise)
WEB_PORTS = [80, 443, 8000, 8080, 8443, 3000, 5000, 8888, 9090]

COMMON_PORTS = WEB_PORTS + [
    22,
    25,
    53,
    21,
    110,
    143,
    465,
    587,
    993,
    995,
    3306,
    5432,
    6379,
    27017,
    3389,
]

EXTENDED_EXTRA = [
    23,
    111,
    135,
    139,
    445,
    512,
    513,
    514,
    873,
    1080,
    1433,
    1521,
    1883,
    2049,
    2375,
    2376,
    4443,
    5601,
    5672,
    5900,
    5984,
    6443,
    7001,
    8008,
    8081,
    9200,
    9092,
    9418,
    11211,
    10250,
]

RISKY_PUBLIC = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    2375: "Docker API",
    2376: "Docker API TLS",
    5672: "RabbitMQ",
    10250: "Kubelet",
}


def _check_port(host: str, port: int, timeout: float = 1.5) -> dict[str, Any]:
    """TCP connect + light liveness check to reduce CDN false opens."""
    result: dict[str, Any] = {
        "port": port,
        "open": False,
        "state": "closed",
        "error": None,
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((host, port))
        if code != 0:
            result["state"] = "closed"
            return result

        # Connected — try to see if the peer actually speaks
        s.setblocking(False)
        try:
            # Wait briefly for data or error
            readable, _, errored = select.select([s], [], [s], 0.4)
            if errored:
                result["state"] = "filtered"
                return result
            if readable:
                try:
                    data = s.recv(64)
                    if data == b"":
                        # orderly close right away — often not a real service
                        result["state"] = "closed"
                        return result
                    result["open"] = True
                    result["state"] = "open"
                    result["banner_len"] = len(data)
                    return result
                except BlockingIOError:
                    pass
            # No immediate data — try a benign probe for HTTP-ish ports
            if port in (80, 8080, 8000, 3000, 5000, 8888, 8008, 8081):
                try:
                    s.setblocking(True)
                    s.settimeout(0.8)
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                    resp = s.recv(128)
                    if resp:
                        result["open"] = True
                        result["state"] = "open"
                        return result
                    result["state"] = "open-unconfirmed"
                    result["open"] = True
                    return result
                except OSError:
                    # some open ports reset on HTTP probe — still open
                    result["open"] = True
                    result["state"] = "open"
                    return result
            elif port in (443, 8443, 4443):
                # TLS ports: successful TCP connect is a reasonable signal
                result["open"] = True
                result["state"] = "open"
                return result
            else:
                # Non-HTTP: TCP connect success counts, but mark unconfirmed
                # if nothing was readable (CDNs often accept then blackhole)
                result["open"] = True
                result["state"] = "open-unconfirmed"
                return result
        finally:
            pass
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["state"] = "error"
        return result
    finally:
        try:
            s.close()
        except OSError:
            pass
    return result


def run(
    host: str,
    ports: list[int] | None = None,
    mode: str = "common",
    workers: int = 32,
    timeout: float = 1.5,
) -> dict[str, Any]:
    # modes:
    #   web (default via common if only web needed) — use "common" = web+admin subset
    #   common — web + a few admin/data
    #   extended — broader
    if ports:
        port_list = sorted(set(int(p) for p in ports))
    elif mode == "extended":
        port_list = sorted(set(COMMON_PORTS + EXTENDED_EXTRA))
    elif mode == "web":
        port_list = list(WEB_PORTS)
    else:
        # "common" — prefer web-first low-noise default
        port_list = list(WEB_PORTS) + [22, 3306, 5432, 6379, 27017, 3389]
        port_list = sorted(set(port_list))

    findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return {
            "host": host,
            "ports": [],
            "open_ports": [],
            "findings": [
                {
                    "severity": "info",
                    "host": host,
                    "title": "Host did not resolve for port checks",
                    "detail": str(exc),
                }
            ],
        }

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 64))) as pool:
        futs = {pool.submit(_check_port, host, p, timeout): p for p in port_list}
        for fut in as_completed(futs):
            results.append(fut.result())

    results.sort(key=lambda r: r["port"])
    open_ports = [r["port"] for r in results if r.get("open")]
    unconfirmed = [r["port"] for r in results if r.get("state") == "open-unconfirmed"]

    # CDN / anycast heuristic: too many non-web opens → unreliable
    non_web_open = [p for p in open_ports if p not in WEB_PORTS]
    if len(non_web_open) >= 5:
        findings.append(
            {
                "severity": "info",
                "host": host,
                "title": "Port results look CDN/anycast-unreliable",
                "detail": (
                    f"Many non-web ports appear open ({non_web_open}). "
                    "CDN edges often accept TCP broadly. Do not treat these as "
                    "real origin services. Re-test against private origin IPs in scope."
                ),
                "remediation": (
                    "Scan origin hosts over VPN/bastion; hide origin behind tunnel; "
                    "do not expose databases/SSH on public anycast hostnames."
                ),
            }
        )
        # Downgrade individual risky findings in this case
        for p in open_ports:
            if p in (80, 443):
                findings.append(
                    {
                        "severity": "info",
                        "host": host,
                        "title": f"Web port open: {p}",
                        "detail": f"TCP/{p} open (expected for public sites).",
                    }
                )
            elif p in WEB_PORTS:
                findings.append(
                    {
                        "severity": "low",
                        "host": host,
                        "title": f"Alternate web port open: {p}",
                        "detail": "Confirm intentional on this hostname.",
                    }
                )
        return {
            "host": host,
            "mode": mode,
            "scanned_ports": port_list,
            "results": results,
            "open_ports": open_ports,
            "unconfirmed_ports": unconfirmed,
            "findings": findings,
            "cdn_noise_suspected": True,
        }

    for p in open_ports:
        state = next((r.get("state") for r in results if r["port"] == p), "open")
        suffix = " (unconfirmed banner)" if state == "open-unconfirmed" else ""
        if p in RISKY_PUBLIC:
            sev = "medium" if state == "open-unconfirmed" else "high"
            findings.append(
                {
                    "severity": sev,
                    "host": host,
                    "title": f"Potentially sensitive port open: {p} ({RISKY_PUBLIC[p]}){suffix}",
                    "detail": (
                        f"TCP/{p} accepts connections from this scanner network. "
                        "If this host is a public edge, restrict admin/data planes to VPN/private nets."
                    ),
                    "remediation": f"Firewall {RISKY_PUBLIC[p]} from the public internet; allow only bastion/VPN.",
                }
            )
        elif p in (80, 443):
            findings.append(
                {
                    "severity": "info",
                    "host": host,
                    "title": f"Expected web port open: {p}",
                    "detail": f"TCP/{p} open",
                }
            )
        elif p in WEB_PORTS:
            findings.append(
                {
                    "severity": "low",
                    "host": host,
                    "title": f"Alternate web port open: {p}",
                    "detail": "Confirm intentional; avoid exposing dev servers publicly.",
                }
            )
        else:
            findings.append(
                {
                    "severity": "low",
                    "host": host,
                    "title": f"Open port: {p}{suffix}",
                    "detail": "Review whether this service should be internet-facing.",
                }
            )

    if 80 in open_ports and 443 not in open_ports:
        findings.append(
            {
                "severity": "medium",
                "host": host,
                "title": "HTTP open without HTTPS",
                "detail": "Port 80 open but 443 closed — enable TLS.",
            }
        )

    return {
        "host": host,
        "mode": mode,
        "scanned_ports": port_list,
        "results": results,
        "open_ports": open_ports,
        "unconfirmed_ports": unconfirmed,
        "findings": findings,
        "cdn_noise_suspected": False,
    }

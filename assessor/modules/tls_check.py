"""TLS/SSL configuration checks (defensive)."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def _fetch_cert(host: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    # We still want to inspect even if verify fails, but note the failure.
    verify_ok = True
    verify_error = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                cert = x509.load_der_x509_certificate(der, default_backend())
    except ssl.SSLCertVerificationError as exc:
        verify_ok = False
        verify_error = str(exc)
        # Retry without verification to still extract cert details
        ctx2 = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                cert = x509.load_der_x509_certificate(der, default_backend())
    except OSError as exc:
        return {"reachable": False, "error": f"{type(exc).__name__}: {exc}"}

    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    return {
        "reachable": True,
        "verify_ok": verify_ok,
        "verify_error": verify_error,
        "tls_version": version,
        "cipher": {
            "name": cipher[0] if cipher else None,
            "protocol": cipher[1] if cipher else None,
            "bits": cipher[2] if cipher else None,
        },
        "certificate": {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "san": sans,
            "serial": format(cert.serial_number, "x"),
        },
    }


def run(host: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    data = _fetch_cert(host, port=port, timeout=timeout)
    findings: list[dict[str, Any]] = []

    if not data.get("reachable"):
        findings.append(
            {
                "severity": "medium",
                "host": host,
                "title": f"TLS port {port} unreachable",
                "detail": data.get("error", "connection failed"),
            }
        )
        return {"host": host, "port": port, "tls": data, "findings": findings}

    if not data.get("verify_ok"):
        findings.append(
            {
                "severity": "high",
                "host": host,
                "title": "Certificate verification failed",
                "detail": data.get("verify_error") or "Unknown verify error",
                "remediation": "Install a valid chain from a trusted CA; fix hostname mismatch or expiry.",
            }
        )

    cert = data.get("certificate") or {}
    days = cert.get("days_until_expiry")
    if isinstance(days, int):
        if days < 0:
            findings.append(
                {
                    "severity": "critical",
                    "host": host,
                    "title": "TLS certificate expired",
                    "detail": f"Expired {-days} days ago ({cert.get('not_after')}).",
                    "remediation": "Renew certificate immediately.",
                }
            )
        elif days < 14:
            findings.append(
                {
                    "severity": "high",
                    "host": host,
                    "title": "TLS certificate expiring soon",
                    "detail": f"{days} days remaining ({cert.get('not_after')}).",
                    "remediation": "Renew certificate; enable auto-renewal (ACME).",
                }
            )
        elif days < 30:
            findings.append(
                {
                    "severity": "medium",
                    "host": host,
                    "title": "TLS certificate expires within 30 days",
                    "detail": f"{days} days remaining ({cert.get('not_after')}).",
                }
            )

    version = (data.get("tls_version") or "").upper()
    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
        findings.append(
            {
                "severity": "high",
                "host": host,
                "title": f"Weak negotiated TLS version: {version}",
                "detail": "Modern clients should negotiate TLS 1.2+ (prefer 1.3).",
                "remediation": "Disable TLS < 1.2 on the edge/load balancer.",
            }
        )
    elif version == "TLSv1.2":
        findings.append(
            {
                "severity": "info",
                "host": host,
                "title": "Negotiated TLS 1.2",
                "detail": "Acceptable; prefer enabling/preferring TLS 1.3.",
            }
        )

    sans = cert.get("san") or []
    if sans and host not in sans and f"*.{'.'.join(host.split('.')[1:])}" not in sans:
        # soft check — wildcard match is approximate
        wildcard_ok = any(
            s.startswith("*.") and host.endswith(s[1:]) for s in sans
        )
        cn_match = host in (cert.get("subject") or "")
        if not wildcard_ok and not cn_match:
            findings.append(
                {
                    "severity": "medium",
                    "host": host,
                    "title": "Hostname may not match certificate SAN",
                    "detail": f"Host={host}; SAN={sans}",
                }
            )

    return {"host": host, "port": port, "tls": data, "findings": findings}

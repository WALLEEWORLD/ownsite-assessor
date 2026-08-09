"""DNS posture checks for authorized self-assessment."""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver


RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


def _query(name: str, rdtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=5.0)
        return sorted({rdata.to_text() for rdata in answers})
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        return []


def run(host: str, alt_hosts: list[str] | None = None) -> dict[str, Any]:
    hosts = [host] + list(alt_hosts or [])
    # de-dupe preserve order
    seen: set[str] = set()
    unique_hosts: list[str] = []
    for h in hosts:
        h = h.strip().lower().rstrip(".")
        if h and h not in seen:
            seen.add(h)
            unique_hosts.append(h)

    results: dict[str, Any] = {"hosts": {}, "findings": []}

    for h in unique_hosts:
        host_data: dict[str, Any] = {"records": {}}
        for rtype in RECORD_TYPES:
            host_data["records"][rtype] = _query(h, rtype)

        # CAA (certificate authority authorization)
        host_data["records"]["CAA"] = _query(h, "CAA")

        # SPF / DMARC via TXT
        txts = host_data["records"].get("TXT", [])
        host_data["spf"] = [t for t in txts if "v=spf1" in t.lower()]
        host_data["dmarc"] = _query(f"_dmarc.{h}", "TXT")

        a_records = host_data["records"].get("A", [])
        aaaa = host_data["records"].get("AAAA", [])
        host_data["resolved_ips"] = a_records + aaaa
        results["hosts"][h] = host_data

        if not a_records and not aaaa and not host_data["records"].get("CNAME"):
            results["findings"].append(
                {
                    "severity": "info",
                    "host": h,
                    "title": "No A/AAAA/CNAME resolution",
                    "detail": f"{h} did not resolve to an address record from this resolver.",
                }
            )
        if not host_data["records"].get("CAA"):
            results["findings"].append(
                {
                    "severity": "low",
                    "host": h,
                    "title": "Missing CAA DNS record",
                    "detail": (
                        "CAA records limit which CAs may issue certificates for this domain. "
                        "Consider adding CAA for production domains."
                    ),
                    "remediation": "Add CAA records (e.g. issue \"letsencrypt.org\").",
                }
            )
        if h == host or h.startswith("www."):
            # mail-ish checks more relevant for apex
            apexish = h.count(".") <= 2
            if apexish and not host_data["spf"]:
                results["findings"].append(
                    {
                        "severity": "info",
                        "host": h,
                        "title": "No SPF TXT observed",
                        "detail": "If this domain sends mail, publish an SPF record.",
                    }
                )
            if apexish and not host_data["dmarc"]:
                results["findings"].append(
                    {
                        "severity": "info",
                        "host": h,
                        "title": "No DMARC record observed",
                        "detail": "If this domain sends mail, publish _dmarc TXT.",
                    }
                )

    return results

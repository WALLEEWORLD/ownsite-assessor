#!/usr/bin/env python3
"""OwnSite Assessor CLI — authorized defensive checks for your own systems."""

from __future__ import annotations

import argparse
import os
import sys
import warnings
from pathlib import Path
from typing import Any

import urllib3
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Allow running as script from repo root
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from assessor import __disclaimer__, __version__  # noqa: E402
from assessor.http_client import AssessorClient  # noqa: E402
from assessor.modules import (  # noqa: E402
    auth_gates,
    dns_check,
    headers_check,
    origin_exposure,
    ports_check,
    robots_check,
    tech_check,
    tls_check,
)
from assessor.report import (  # noqa: E402
    collect_findings,
    stamp,
    summarize,
    write_json,
    write_markdown,
)

console = Console()


def load_config(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"Invalid config: {path}")
    return data


def enforce_authorization(cfg: dict[str, Any], assume_yes: bool) -> None:
    auth = cfg.get("authorization") or {}
    flagged = bool(auth.get("i_own_or_have_written_permission"))
    if flagged:
        return
    console.print(
        Panel.fit(
            "[bold red]Authorization gate[/bold red]\n\n"
            "This tool must only be used on systems you own or have "
            "explicit written permission to test.\n\n"
            "Set authorization.i_own_or_have_written_permission: true in your "
            "config after confirming scope, or pass [bold]--i-am-authorized[/bold].",
            title="OwnSite Assessor",
        )
    )
    if assume_yes:
        raise SystemExit(
            "Refusing to run: authorization not confirmed in config "
            "(--i-am-authorized alone is not enough without the flag meaning; "
            "pass --i-am-authorized to override)."
        )
    # interactive
    console.print(
        "Type [bold]I AM AUTHORIZED[/bold] to continue, or anything else to abort."
    )
    try:
        answer = input("> ").strip()
    except EOFError:
        answer = ""
    if answer != "I AM AUTHORIZED":
        raise SystemExit("Aborted: authorization not confirmed.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ownsite-assessor",
        description=(
            "Authorized defensive security assessment for websites/domains/IPs you own. "
            "No exploit payloads."
        ),
    )
    p.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to YAML config (see configs/example-target.yaml)",
    )
    p.add_argument("--host", help="Target hostname (overrides config)")
    p.add_argument(
        "--scheme",
        choices=["https", "http"],
        default=None,
        help="http or https (default https)",
    )
    p.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirm you own the target or have written permission",
    )
    p.add_argument(
        "--session-cookie",
        default=None,
        help="Optional session cookie for authenticated baseline (or env OWNSITE_SESSION_COOKIE)",
    )
    p.add_argument(
        "--port-mode",
        choices=["web", "common", "extended"],
        default=None,
        help="Port check intensity (web=lowest noise, common=default, extended=broader)",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Report output directory",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    # Quiet insecure-request warnings from optional direct-IP HTTPS probes
    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

    args = build_parser().parse_args(argv)
    cfg: dict[str, Any] = {}
    if args.config:
        cfg = load_config(args.config)

    target = dict(cfg.get("target") or {})
    scan = dict(cfg.get("scan") or {})
    report_cfg = dict(cfg.get("report") or {})
    auth_cfg = dict(cfg.get("authorization") or {})

    if args.host:
        target["host"] = args.host
    if args.scheme:
        target["scheme"] = args.scheme
    if args.port_mode:
        scan["port_mode"] = args.port_mode
    if args.i_am_authorized:
        auth_cfg["i_own_or_have_written_permission"] = True
        cfg["authorization"] = auth_cfg

    host = (target.get("host") or "").strip()
    if not host:
        console.print("[red]No target host. Pass --host or --config.[/red]")
        return 2

    cfg["authorization"] = auth_cfg
    enforce_authorization(cfg, assume_yes=False)

    scheme = (target.get("scheme") or "https").lower()
    alt_hosts = list(target.get("alt_hosts") or [])
    ports = list(target.get("ports") or [])
    protected = list(target.get("auth_protected_paths") or ["/admin", "/dashboard"])
    public = list(target.get("public_paths") or ["/", "/health"])
    modules_cfg = dict(
        scan.get("modules")
        or {
            "dns": True,
            "tls": True,
            "headers": True,
            "tech": True,
            "auth_gates": True,
            "origin_exposure": True,
            "ports": True,
            "robots_security_txt": True,
        }
    )
    timeout = float(scan.get("request_timeout_seconds") or 10)
    ua = scan.get("user_agent") or "OwnSiteAssessor/1.0 (+authorized-self-test)"
    port_mode = scan.get("port_mode") or "common"
    port_workers = int(scan.get("port_workers") or 32)

    session_cookie = (
        args.session_cookie
        or target.get("session_cookie")
        or os.environ.get("OWNSITE_SESSION_COOKIE")
    )

    client = AssessorClient(timeout=timeout, user_agent=ua)
    auth_client = (
        AssessorClient(timeout=timeout, user_agent=ua, session_cookie=session_cookie)
        if session_cookie
        else None
    )

    console.print(
        Panel.fit(
            f"[bold]OwnSite Assessor v{__version__}[/bold]\n"
            f"Target: [cyan]{scheme}://{host}[/cyan]\n\n"
            f"{__disclaimer__}",
            title="Starting assessment",
        )
    )

    report: dict[str, Any] = {
        "meta": {
            "tool": "OwnSite Assessor",
            "version": __version__,
            "generated_at": stamp(),
            "engagement_note": auth_cfg.get("engagement_note"),
            "contact": auth_cfg.get("contact"),
            "disclaimer": __disclaimer__,
        },
        "target": {
            "host": host,
            "scheme": scheme,
            "alt_hosts": alt_hosts,
            "ports": ports,
        },
        "modules": {},
    }

    # DNS
    if modules_cfg.get("dns", True):
        console.print("[bold]• DNS[/bold]")
        report["modules"]["dns"] = dns_check.run(host, alt_hosts)

    resolved_ips: list[str] = []
    dns_mod = report["modules"].get("dns") or {}
    host_dns = (dns_mod.get("hosts") or {}).get(host.lower().rstrip(".")) or {}
    resolved_ips = list(host_dns.get("resolved_ips") or [])

    # TLS
    if modules_cfg.get("tls", True) and scheme == "https":
        console.print("[bold]• TLS[/bold]")
        tls_port = 443
        if ports:
            for p in ports:
                if p in (443, 8443):
                    tls_port = p
                    break
        report["modules"]["tls"] = tls_check.run(host, port=tls_port, timeout=timeout)

    base_url = AssessorClient.build_url(scheme, host, "/")

    # Headers
    if modules_cfg.get("headers", True):
        console.print("[bold]• Security headers[/bold]")
        report["modules"]["headers"] = headers_check.run(client, base_url)

    # Tech
    if modules_cfg.get("tech", True):
        console.print("[bold]• Technology fingerprint[/bold]")
        report["modules"]["tech"] = tech_check.run(client, base_url)

    # robots / security.txt
    if modules_cfg.get("robots_security_txt", True):
        console.print("[bold]• robots.txt / security.txt[/bold]")
        report["modules"]["robots_security_txt"] = robots_check.run(client, scheme, host)

    # Auth gates
    if modules_cfg.get("auth_gates", True):
        console.print("[bold]• Auth gate verification[/bold]")
        report["modules"]["auth_gates"] = auth_gates.run(
            client,
            scheme,
            host,
            protected,
            public,
            authenticated_client=auth_client,
        )

    # Origin exposure
    if modules_cfg.get("origin_exposure", True):
        console.print("[bold]• Origin / sensitive path exposure[/bold]")
        report["modules"]["origin_exposure"] = origin_exposure.run(
            client, scheme, host, resolved_ips=resolved_ips
        )

    # Ports
    if modules_cfg.get("ports", True):
        console.print("[bold]• Port checks[/bold]")
        report["modules"]["ports"] = ports_check.run(
            host,
            ports=ports or None,
            mode=port_mode,
            workers=port_workers,
        )

    findings = collect_findings(report)
    counts = summarize(findings)
    report["summary"] = counts

    out_dir = Path(
        args.output_dir
        or report_cfg.get("output_dir")
        or (ROOT / "assessor" / "reports")
    )
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    ts = report["meta"]["generated_at"]
    safe_host = host.replace(":", "_").replace("/", "_")
    json_path = out_dir / f"{safe_host}_{ts}.json"
    md_path = out_dir / f"{safe_host}_{ts}.md"

    formats = report_cfg.get("formats") or ["json", "markdown"]
    if "json" in formats:
        write_json(report, json_path)
    if "markdown" in formats:
        write_markdown(report, md_path)

    table = Table(title="Finding summary")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev, n in counts.items():
        style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }.get(sev, "")
        table.add_row(sev, str(n), style=style)
    console.print(table)
    console.print(f"[green]JSON:[/green] {json_path}")
    console.print(f"[green]Markdown:[/green] {md_path}")

    # Exit code: 2 if critical/high present (useful in CI for own sites)
    if counts.get("critical", 0) or counts.get("high", 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

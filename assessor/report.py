"""Report writers (JSON + Markdown)."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def collect_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    modules = report.get("modules") or {}
    for name, payload in modules.items():
        if not isinstance(payload, dict):
            continue
        for f in payload.get("findings") or []:
            item = dict(f)
            item.setdefault("module", name)
            findings.append(item)
    return findings


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    c = Counter((f.get("severity") or "info").lower() for f in findings)
    return {k: c.get(k, 0) for k in SEVERITY_ORDER}


def write_json(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


def write_markdown(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = collect_findings(report)
    counts = summarize(findings)
    meta = report.get("meta") or {}
    target = report.get("target") or {}

    lines: list[str] = []
    lines.append(f"# OwnSite Assessor Report")
    lines.append("")
    lines.append(f"- **Generated:** {meta.get('generated_at')}")
    lines.append(f"- **Host:** `{target.get('host')}`")
    lines.append(f"- **Scheme:** {target.get('scheme')}")
    lines.append(f"- **Engagement:** {meta.get('engagement_note')}")
    lines.append(f"- **Contact:** {meta.get('contact')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.append("")
    lines.append(
        "> Authorized defensive assessment only. No exploit payloads were used."
    )
    lines.append("")

    # Module snapshots
    mods = report.get("modules") or {}
    if "dns" in mods:
        lines.append("## DNS")
        lines.append("")
        for h, data in (mods["dns"].get("hosts") or {}).items():
            ips = ", ".join(data.get("resolved_ips") or []) or "(none)"
            lines.append(f"- `{h}` → {ips}")
        lines.append("")

    if "tls" in mods:
        lines.append("## TLS")
        lines.append("")
        tls = mods["tls"].get("tls") or {}
        cert = tls.get("certificate") or {}
        if tls.get("reachable"):
            lines.append(f"- Version: **{tls.get('tls_version')}**")
            lines.append(f"- Verify OK: **{tls.get('verify_ok')}**")
            lines.append(f"- Issuer: {cert.get('issuer')}")
            lines.append(
                f"- Expires: {cert.get('not_after')} ({cert.get('days_until_expiry')} days)"
            )
            lines.append(f"- SAN: {', '.join(cert.get('san') or [])}")
        else:
            lines.append(f"- Unreachable: {tls.get('error')}")
        lines.append("")

    if "ports" in mods:
        lines.append("## Open Ports")
        lines.append("")
        opens = mods["ports"].get("open_ports") or []
        lines.append(f"- {', '.join(str(p) for p in opens) if opens else '(none detected)'}")
        lines.append("")

    if "tech" in mods:
        lines.append("## Technologies")
        lines.append("")
        techs = mods["tech"].get("technologies") or []
        lines.append(f"- {', '.join(techs) if techs else '(none fingerprinted)'}")
        lines.append("")

    if "auth_gates" in mods:
        lines.append("## Auth Gates")
        lines.append("")
        for p in mods["auth_gates"].get("protected") or []:
            lines.append(
                f"- protected `{p.get('path')}` → status={p.get('status_code')} "
                f"challenge={p.get('auth_challenge_detected')}"
            )
        for p in mods["auth_gates"].get("public") or []:
            lines.append(
                f"- public `{p.get('path')}` → status={p.get('status_code')}"
            )
        lines.append("")

    if "unauthorized_client" in mods:
        lines.append("## Unauthorized Device Simulation")
        lines.append("")
        uc = mods["unauthorized_client"]
        dm = uc.get("device_matrix") or []
        challenged = sum(1 for r in dm if r.get("auth_challenge"))
        openish = sum(1 for r in dm if r.get("appears_authorized_content"))
        lines.append(f"- Device×path probes: {len(dm)}")
        lines.append(f"- Auth challenges observed: {challenged}")
        lines.append(f"- App-content-without-auth signals: {openish}")
        inv = uc.get("invalid_credential_matrix") or []
        if inv:
            lines.append("- Invalid credential variants:")
            for row in inv:
                lines.append(
                    f"  - `{row.get('variant')}` → status={row.get('status_code')} "
                    f"challenge={row.get('auth_challenge')}"
                )
        lines.append("")

    if "access_control_abuse" in mods:
        lines.append("## Access-Control Abuse Simulation")
        lines.append("")
        ac = mods["access_control_abuse"]
        lines.append(f"- Spoof-header cases: {len(ac.get('spoof_headers') or [])}")
        lines.append(f"- Path-confusion probes: {len(ac.get('path_confusion') or [])}")
        lines.append(f"- CORS probes: {len(ac.get('cors') or [])}")
        bypass = [
            r for r in (ac.get("spoof_headers") or [])
            if r.get("possible_bypass_signal")
        ]
        if bypass:
            lines.append(f"- Possible bypass signals: {len(bypass)}")
        lines.append("")

    if "pentest_playbook" in mods:
        lines.append("## Authorized Pentest Playbook")
        lines.append("")
        for phase in mods["pentest_playbook"].get("phases") or []:
            lines.append(f"### Phase {phase.get('phase')}: {phase.get('name')}")
            lines.append("")
            for c in phase.get("checks") or []:
                lines.append(f"- [ ] {c}")
            lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings.")
    else:
        ordered = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.index((f.get("severity") or "info").lower())
            if (f.get("severity") or "info").lower() in SEVERITY_ORDER
            else 99,
        )
        for f in ordered:
            sev = (f.get("severity") or "info").upper()
            title = f.get("title") or "(untitled)"
            lines.append(f"### [{sev}] {title}")
            lines.append("")
            if f.get("module"):
                lines.append(f"- Module: `{f['module']}`")
            if f.get("url"):
                lines.append(f"- URL: `{f['url']}`")
            if f.get("host"):
                lines.append(f"- Host: `{f['host']}`")
            if f.get("detail"):
                lines.append(f"- Detail: {f['detail']}")
            if f.get("remediation"):
                lines.append(f"- Remediation: {f['remediation']}")
            lines.append("")

    lines.append("## Disclaimer")
    lines.append("")
    lines.append(
        "Use only on systems you own or have written authorization to test. "
        "This report documents configuration and access-control posture checks."
    )
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

# OwnSite Assessor

**Authorized defensive security assessment** for websites, domains, and IPs **you own** (or have written permission to test).

OwnSite Assessor checks posture — DNS, TLS, security headers, auth gates, origin exposure signals, common ports, and light stack fingerprinting — then writes JSON + Markdown reports.

It does **not** ship exploit payloads, credential stuffing, or attack automation.

---

## Table of contents

1. [Legal / ethical use](#1-legal--ethical-use)
2. [What it checks](#2-what-it-checks)
3. [Requirements](#3-requirements)
4. [Install](#4-install)
5. [Quick start](#5-quick-start)
6. [Configuration](#6-configuration)
7. [CLI reference](#7-cli-reference)
8. [Reading reports](#8-reading-reports)
9. [Authenticated baseline](#9-authenticated-baseline)
10. [Optional recon stack](#10-optional-recon-stack)
11. [Full pipeline](#11-full-pipeline)
12. [Access control guidance](#12-access-control-guidance-private-but-global-apps)
13. [CI integration](#13-ci-integration)
14. [Project layout](#14-project-layout)
15. [Troubleshooting](#15-troubleshooting)
16. [Security & scope boundary](#16-security--scope-boundary)
17. [License / disclaimer](#17-license--disclaimer)

---

## 1. Legal / ethical use

| You may | You may not |
|---------|-------------|
| Assess systems you own | Scan third-party sites without written permission |
| Assess systems with a signed engagement / ROE | Use this as an attack toolkit |
| Hardening and regression checks on your staging/prod | Bypass auth on systems outside your scope |

Every run requires an authorization confirmation:

- `authorization.i_own_or_have_written_permission: true` in YAML, **or**
- `--i-am-authorized` on the CLI, **or**
- Interactive prompt: type `I AM AUTHORIZED`

Unauthorized scanning can be illegal. You are responsible for scope.

---

## 2. What it checks

| Module | What it does |
|--------|----------------|
| **dns** | A/AAAA/CNAME/MX/NS/TXT/CAA; SPF/DMARC signals |
| **tls** | Certificate validity, expiry, negotiated TLS version, SAN |
| **headers** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, cookie flags, X-Powered-By |
| **tech** | Light CDN/framework fingerprint from headers + body sample |
| **robots_security_txt** | robots.txt leakage signals + `security.txt` hygiene |
| **auth_gates** | Protected paths should challenge anonymous users; public paths should stay up |
| **origin_exposure** | Direct origin-IP answers; sensitive path content signals (`.git`, `.env`, actuators, etc.) |
| **ports** | Non-aggressive TCP checks (CDN-aware; low-noise defaults) |

---

## 3. Requirements

| Item | Notes |
|------|--------|
| **Python** | 3.10+ (3.11/3.12 recommended) |
| **OS** | Linux, macOS, Windows, or **WSL2** (recommended on Windows) |
| **Network** | Outbound HTTPS/DNS to your target |
| **Optional** | `nmap`, Go + ProjectDiscovery tools, `testssl.sh`, OWASP ZAP / Burp / Caido |

### Platform recommendation

| Environment | Recommendation |
|-------------|----------------|
| Best overall | Linux (Debian/Ubuntu) or Kali VM |
| Windows dev box | **WSL2** (Ubuntu or Kali) for CLI + this suite |
| Manual proxy work | ZAP / Burp / Caido on Windows or Linux GUI |

---

## 4. Install

### 4.1 Clone

```bash
git clone https://github.com/<YOUR_USER>/ownsite-assessor.git
cd ownsite-assessor
```

### 4.2 Linux / macOS / WSL

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x scripts/*.sh
```

Or use the launcher (creates the venv if missing):

```bash
./scripts/run_assessment.sh --help
```

### 4.3 Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Or:

```powershell
.\scripts\run_assessment.ps1 --help
```

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 4.4 Verify install

```bash
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
python -m assessor.cli --version
```

---

## 5. Quick start

### One-liner (authorized)

```bash
./scripts/run_assessment.sh --host staging.yourdomain.com --i-am-authorized
```

Windows:

```powershell
.\scripts\run_assessment.ps1 --host staging.yourdomain.com --i-am-authorized
```

### Config-driven (recommended)

```bash
cp configs/example-target.yaml configs/my-site.yaml
```

Edit `configs/my-site.yaml`:

1. Set `target.host` to your hostname  
2. List `auth_protected_paths` and `public_paths`  
3. Set `authorization.i_own_or_have_written_permission: true`  
4. Fill `engagement_note` and `contact`

Run:

```bash
./scripts/run_assessment.sh -c configs/my-site.yaml
```

Reports are written to `assessor/reports/`:

- `your.host_TIMESTAMP.json`
- `your.host_TIMESTAMP.md`

---

## 6. Configuration

Example (`configs/example-target.yaml`):

```yaml
target:
  host: "staging.example.com"
  alt_hosts:
    - "example.com"
    - "www.example.com"
    - "api.example.com"
  scheme: "https"
  ports:
    - 80
    - 443
    - 8080
    - 8443
  auth_protected_paths:
    - "/admin"
    - "/dashboard"
    - "/api/private"
    - "/internal"
  public_paths:
    - "/"
    - "/health"
    - "/.well-known/security.txt"
  # Prefer env OWNSITE_SESSION_COOKIE instead of committing secrets
  # session_cookie: "session=..."

authorization:
  i_own_or_have_written_permission: false   # set true after confirming scope
  engagement_note: "Self-assessment of my staging environment"
  contact: "security@example.com"

scan:
  request_timeout_seconds: 10
  max_redirects: 5
  user_agent: "OwnSiteAssessor/1.0 (+authorized-self-test)"
  modules:
    dns: true
    tls: true
    headers: true
    tech: true
    auth_gates: true
    origin_exposure: true
    ports: true
    robots_security_txt: true
  # web = lowest noise (best for CDN hostnames)
  # common = web + a few admin/data ports
  # extended = broader — prefer on private origin hosts over VPN
  port_mode: "web"
  port_workers: 32

report:
  output_dir: "assessor/reports"
  formats:
    - json
    - markdown
```

### Port modes

| Mode | When to use |
|------|-------------|
| `web` | Default. 80/443 + common app ports. Best against CDN/anycast hostnames |
| `common` | Web + a few admin/data ports |
| `extended` | Broader list. Use on **origin** hosts via VPN/bastion, not public CDN names |

CDN edges often accept TCP on many ports. The tool flags “CDN noise” when results look unreliable.

---

## 7. CLI reference

```text
python -m assessor.cli [options]
```

| Flag | Description |
|------|-------------|
| `-c`, `--config PATH` | YAML config file |
| `--host HOST` | Target hostname (overrides config) |
| `--scheme {https,http}` | URL scheme (default `https`) |
| `--i-am-authorized` | Confirm ownership / written permission |
| `--session-cookie STR` | Cookie header for authenticated baseline |
| `--port-mode {web,common,extended}` | Port check intensity |
| `--output-dir PATH` | Report directory |
| `--version` | Print version |

### Examples

```bash
# Minimal authorized run
python -m assessor.cli --host app.example.com --i-am-authorized

# Config + custom output
python -m assessor.cli -c configs/my-site.yaml --output-dir ./out

# HTTP-only internal host over VPN
python -m assessor.cli --host 10.0.1.20 --scheme http --i-am-authorized --port-mode extended

# Authenticated baseline via env
export OWNSITE_SESSION_COOKIE='session=abc123; other=xyz'
python -m assessor.cli -c configs/my-site.yaml
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; no critical/high findings |
| `1` | Completed; at least one critical or high finding |
| `2` | Usage / config / authorization error |

Useful as a CI gate on **your** staging.

---

## 8. Reading reports

### Markdown report sections

- **Summary** — counts by severity (`critical` → `info`)
- **DNS / TLS / Open Ports / Technologies / Auth Gates** — snapshots
- **Findings** — each item with module, URL/host, detail, remediation

### Severity guide

| Severity | Typical meaning | Action |
|----------|-----------------|--------|
| critical | Broken TLS (expired), severe exposure | Fix immediately |
| high | Public protected path, real `.env`/`.git`, sensitive port on origin | Fix soon |
| medium | Missing HSTS/CSP, origin IP reachable, weak cookie flags | Plan hardening |
| low | Optional headers, alt ports, stack banners | Backlog |
| info | Expected signals, hygiene notes | Awareness |

### Access-control signals

| Signal | Interpretation |
|--------|----------------|
| Protected path → `401` / `403` / IdP redirect | Auth gate working |
| Protected path → `200` + large body, no challenge | Enforce auth at edge or app |
| Origin IP answers while hostname challenges | Hide origin (tunnel / edge-only) |
| HTML `200` on random debug paths | Often SPA/CDN fallback — usually noise |
| Real content on `/.git/HEAD`, `/.env`, actuators | Remove / block immediately |

---

## 9. Authenticated baseline

Optionally prove that a **valid session** can reach protected routes (still not an attack):

```bash
# Copy Cookie header value from your browser devtools (Application → Cookies)
export OWNSITE_SESSION_COOKIE='session=...'
./scripts/run_assessment.sh -c configs/my-site.yaml
```

Or:

```bash
./scripts/run_assessment.sh -c configs/my-site.yaml \
  --session-cookie 'session=...'
```

Do **not** commit real cookies or tokens. Prefer environment variables. Rotate anything that was pasted into a shell history.

---

## 10. Optional recon stack

Installs common **defensive** CLI tools (Debian/Ubuntu/Kali/WSL). Review packages before running.

```bash
./scripts/install_recon_stack.sh --i-am-authorized
```

Includes (when available):

- `nmap`, `whois`, `dnsutils`, `curl`, `jq`, `openssl`
- If Go is installed: `httpx`, `nuclei`, `dnsx`, `tlsx`, `subfinder`

Then:

```bash
nuclei -update-templates
# Prefer: nuclei -severity info,low  and only your hosts
```

Manual GUI tools (install yourself):

- [OWASP ZAP](https://www.zaproxy.org/download/)
- [Burp Suite Community](https://portswigger.net/burp/communitydownload)
- [Caido](https://caido.io/)
- [testssl.sh](https://github.com/drwetter/testssl.sh)

---

## 11. Full pipeline

Chains OwnSite Assessor with optional external tools **only against hosts you authorize**:

```bash
./scripts/pipeline_authorized.sh staging.yourdomain.com --i-am-authorized
```

Steps:

1. OwnSite Assessor (this repo)  
2. `nmap` on web ports (if installed)  
3. `httpx` status/tech probe (if installed)  
4. `nuclei` with **info,low** only (if installed)  
5. `testssl.sh` TLS deep check (if installed)  

Output directory: `assessor/reports/pipeline_<host>_<timestamp>/`

---

## 12. Access control guidance (private but global apps)

If many legitimate users are worldwide, **do not rely on IP/MAC allowlists alone**.

Recommended pattern:

1. **Identity-first Zero Trust** — Cloudflare Access, Google IAP, AWS Verified Access, oauth2-proxy + OIDC  
2. **Hide origin** — Cloudflare Tunnel / private ingress (no public origin IP)  
3. **Strong auth** — SSO, MFA, passkeys  
4. **Device posture** — only where you manage devices (MDM), not open consumer fleets  

Use this assessor to verify:

- Anonymous users hit an auth challenge on protected paths  
- Origin is not bare on the public internet  
- TLS and security headers are solid  
- Debug / secret paths are closed  

Deeper research: [`docs/TOOLS-AND-ACCESS-CONTROL.md`](docs/TOOLS-AND-ACCESS-CONTROL.md)

---

## 13. CI integration

Example GitHub Actions workflow (run against **your** staging only):

```yaml
# .github/workflows/ownsite-assess.yml
name: OwnSite Assess Staging

on:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * 1"   # weekly Monday 06:00 UTC

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install
        run: |
          python -m pip install -r requirements.txt

      - name: Run assessment
        env:
          # Optional: inject a short-lived staging session via secrets
          OWNSITE_SESSION_COOKIE: ${{ secrets.STAGING_SESSION_COOKIE }}
        run: |
          python -m assessor.cli \
            --host staging.yourdomain.com \
            --i-am-authorized \
            --port-mode web \
            --output-dir assessor/reports

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ownsite-reports
          path: assessor/reports/
```

The job fails (exit `1`) when critical/high findings are present.

---

## 14. Project layout

```text
ownsite-assessor/
├── README.md
├── requirements.txt
├── configs/
│   └── example-target.yaml
├── docs/
│   ├── USAGE.md
│   └── TOOLS-AND-ACCESS-CONTROL.md
├── scripts/
│   ├── run_assessment.sh          # Linux/macOS/WSL launcher
│   ├── run_assessment.ps1         # Windows launcher
│   ├── install_recon_stack.sh     # optional tools
│   └── pipeline_authorized.sh     # chained assessment
└── assessor/
    ├── __main__.py                # python -m assessor
    ├── cli.py                     # CLI entry
    ├── http_client.py
    ├── report.py
    ├── modules/
    │   ├── dns_check.py
    │   ├── tls_check.py
    │   ├── headers_check.py
    │   ├── tech_check.py
    │   ├── robots_check.py
    │   ├── auth_gates.py
    │   ├── origin_exposure.py
    │   └── ports_check.py
    └── reports/                   # generated output (gitignored)
```

---

## 15. Troubleshooting

| Problem | Fix |
|---------|-----|
| `No target host` | Pass `--host` or set `target.host` in YAML |
| Authorization gate / aborted | Pass `--i-am-authorized` or set the YAML flag |
| TLS errors on internal MITM | Fix corporate proxy trust, or test from a network that can reach the real cert |
| All ports look open on Cloudflare hostname | Expected CDN noise — use `--port-mode web` and test origin over VPN |
| Protected path always `200` HTML | SPA fallback; confirm whether the **API** behind it is actually open |
| `ModuleNotFoundError: assessor` | Activate venv and run from repo root: `python -m assessor.cli ...` |
| PowerShell script blocked | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Cookie baseline still 401 | Session expired, wrong cookie name, or path needs a stronger role |

---

## 16. Security & scope boundary

**In scope (this tool):**

- Passive / semi-passive configuration and access-control posture checks  
- Auth-gate verification (challenge present / session accepted)  
- Reporting and remediation hints  

**Out of scope (intentionally):**

- SQL injection / XSS / RCE exploit automation  
- Password spraying or credential stuffing  
- Weaponized WAF or auth-bypass kits  
- Scanning assets outside your config  

For deep application testing of **your** apps, use manual review with ZAP/Burp plus [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — still only with authorization.

---

## 17. License / disclaimer

Provided as-is for defensive security engineering and authorized self-assessment.

- You are solely responsible for ensuring you have permission to test each target.  
- Authors and contributors are not liable for misuse or damages.  
- Prefer staging first; rate-limit and schedule production checks politely.

---



---

## Unauthorized device & access-control pentest simulation (v1.1)

These modules mimic how a **real authorized penetration test** validates that
**unknown / non-authorized clients** cannot reach private resources.

| Module | What it simulates |
|--------|-------------------|
| `unauthorized_client` | Multiple device UAs (desktop, iOS, Android, curl, empty UA) with **no credentials**; invalid Bearer/session shapes; unauthenticated HTTP method matrix |
| `access_control_abuse` | Spoofable headers (`X-Forwarded-For`, `X-Original-URL`, …), path normalization tricks, CORS from an unauthorized origin, cacheability, Host-header redirect issues |
| `pentest_playbook` | Phased engagement checklist (ROE → recon → anonymous client → session boundaries → edge/origin → manual WSTG → report) |

### What this is

- Authorized **access-control** testing of **your** app
- Answers: “If a random device on the internet hits my private routes, are they blocked?”
- Safe probes only (no password spraying, no exploit payloads, no weaponized bypass kits)

### What this is not

- Not a license to test third-party systems
- Not RCE/SQLi/XSS exploit automation
- Not credential stuffing or token cracking

### Run

```bash
./scripts/run_assessment.sh --host staging.yourdomain.com --i-am-authorized
```

Ensure `target.auth_protected_paths` lists routes that must reject strangers.
Optional: `target.unauthorized_probe_paths` for extra API/admin aliases.

Reports include **Unauthorized Device Simulation** and **Access-Control Abuse**
sections plus a full **Authorized Pentest Playbook** checklist.

## Docs

| Doc | Description |
|-----|-------------|
| [`docs/USAGE.md`](docs/USAGE.md) | Short operator guide |
| [`docs/TOOLS-AND-ACCESS-CONTROL.md`](docs/TOOLS-AND-ACCESS-CONTROL.md) | Kali/modern tool catalog + Zero Trust access patterns |

---

## Contributing

1. Fork and branch from `main`  
2. Keep changes defensive — **no exploit payloads**  
3. Test with `python -m assessor.cli --host example.com --i-am-authorized --port-mode web` (connectivity smoke only)  
4. Open a PR with a clear description of the defensive check added  

---

**Own only what you assess. Assess only what you own.**

# OwnSite Assessor — Usage

## Authorization

Only run against systems you own or have **written** permission to test.

```bash
./scripts/run_assessment.sh --host YOUR_HOST --i-am-authorized
```

Or set in YAML:

```yaml
authorization:
  i_own_or_have_written_permission: true
  engagement_note: "Self-test of my staging app"
  contact: "you@example.com"
```

## Config-driven run

```bash
cp configs/example-target.yaml configs/my-site.yaml
# edit host, protected paths, modules
./scripts/run_assessment.sh -c configs/my-site.yaml
```

## Windows

```powershell
.\scripts\run_assessment.ps1 --host your.site --i-am-authorized
```

Prefer **WSL2** for the optional recon stack (`nmap`, ProjectDiscovery tools).

## Authenticated baseline

Export a browser session cookie for paths that require login:

```bash
export OWNSITE_SESSION_COOKIE='session=...'
./scripts/run_assessment.sh -c configs/my-site.yaml
```

This only verifies that *your* session can reach protected routes. It does not attack logins.

## Port modes

| Mode | Use |
|------|-----|
| `web` | Ports 80/443 + common app ports only (lowest noise; best for CDN hostnames) |
| `common` | Web + a few admin/data ports |
| `extended` | Broader list — use on **origin** hosts over VPN, not CDN anycast names |

```bash
./scripts/run_assessment.sh --host origin.internal --i-am-authorized --port-mode extended
```

## Optional external pipeline

```bash
./scripts/install_recon_stack.sh --i-am-authorized
./scripts/pipeline_authorized.sh your.domain.com --i-am-authorized
```

Pipeline adds (if installed): nmap web ports, httpx, nuclei (`info,low` only), testssl.sh.

## Interpreting results for access-controlled apps

| Signal | Meaning |
|--------|---------|
| Protected path → 401/403/IdP redirect | Auth gate working |
| Protected path → 200 large body, no challenge | **Fix:** enforce auth at edge or app |
| Origin IP answers while hostname challenges | **Fix:** tunnel/lock origin |
| Missing HSTS/CSP/HttpOnly | Hardening gaps |
| Sensitive path real content (`.git`, `.env`) | **Fix immediately** |
| Many non-web ports “open” on Cloudflare hostname | Usually CDN noise — retest origin privately |

## What this tool will not do

- Exploit SQLi/XSS/RCE
- Brute-force credentials
- Bypass WAFs or sell “undetectable” attack kits
- Scan third-party assets

For deep app testing of **your** code, pair with OWASP ZAP/Burp manual review and OWASP WSTG — still only in scope.


## Unauthorized device simulation

Enabled by default (`unauthorized_client`, `access_control_abuse`, `pentest_playbook`).

```bash
./scripts/run_assessment.sh -c configs/my-site.yaml
```

Uses clean clients (no valid session) across device profiles to verify private
routes challenge or deny access — the same class of checks used in authorized
penetration tests for access control. No exploit payloads.

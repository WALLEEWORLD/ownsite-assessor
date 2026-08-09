# Tools, Pipelines & Access Control (Authorized Self-Testing)

This document merges research on assessment tooling and access-control architectures for **systems you own**.

**Hard rules**
- Only test assets you own or have written authorization to assess.
- This project ships **no exploit payloads**.
- For large global user bases, prefer **identity-based Zero Trust** over IP/MAC allowlists.

Related code: `ownsite-assessor/` (Python suite).

---



# Part 1 — Tool Catalog

# Penetration Testing Tools Catalog for Authorized Web/Domain/IP Security Assessment

**Scope and ethics note:** This report catalogs tools used for *authorized* security assessment of systems you own or have explicit written permission to test (e.g., an internal pentest engagement, a bug bounty program's defined scope, or your own infrastructure). It does not include exploit code, payloads, or instructions for attacking systems without authorization. Tools like sqlmap, dalfox, xray/afrog, and Burp/ZAP scanners are inherently dual-use — they are standard, legitimate instruments in professional security assessment, but using them against systems you don't own or lack permission to test is illegal in most jurisdictions (e.g., under the U.S. Computer Fraud and Abuse Act). Always confirm scope and rules of engagement before scanning.

---

## 1. Kali Linux Tool Categories for Web/Domain/IP Assessment

Kali Linux organizes its 600+ tools into metapackages/categories such as `kali-tools-information-gathering`, `kali-tools-vulnerability`, and `kali-tools-web`, documented at the [official Kali tools index](https://www.kali.org/tools/) and [Kali metapackages documentation](https://www.kali.org/docs/general-use/metapackages/). The Kali homepage highlights flagship tools including Aircrack-ng, Burp Suite, Hydra, Nmap, sqlmap, and Wireshark ([kali.org](https://www.kali.org/)).

### 1.1 Reconnaissance / Information Gathering

| Tool | Purpose | Authorized use | When NOT to use | Official docs |
|---|---|---|---|---|
| **Nmap / Zenmap** | Network discovery, port scanning, service/OS fingerprinting via the Nmap Scripting Engine | Mapping your own network's exposed hosts/services before a deeper assessment | Against hosts outside your authorized scope; on production systems sensitive to scan-induced load without a maintenance window | [nmap.org](https://nmap.org/), [Kali tool page](https://www.kali.org/tools/nmap/) |
| **Amass (OWASP)** | Attack-surface mapping: passive/active subdomain enumeration, DNS mapping, ASN/netblock discovery | Enumerating your organization's full subdomain/asset inventory | Aggressive brute-force/zone-transfer attempts against DNS infrastructure you don't control | [owasp-amass/amass](https://github.com/owasp-amass/amass), [user guide](https://raw.githubusercontent.com/OWASP/Amass/master/doc/user_guide.md) |
| **theHarvester** | OSINT gathering (emails, subdomains, names) from search engines and public sources | Early-stage OSINT recon for a scoped engagement | Treating OSINT results as verified live assets without confirmation | [Kali tools](https://www.kali.org/tools/theharvester/) |
| **recon-ng** | Modular web reconnaissance framework | Structured OSINT workflows within a defined scope | Using untrusted third-party modules against unscoped targets | [Kali tool page](https://www.kali.org/tools/recon-ng/) |
| **DMitry** | Basic host info gathering (whois, subdomains, email addresses) | Quick initial footprinting of an authorized target | As a substitute for thorough recon on larger scopes (limited feature set) | [Kali tool page](https://www.kali.org/tools/dmitry/) |
| **dnsrecon / dnsenum / massdns** | DNS enumeration and mass resolution | Mapping DNS records for domains you're authorized to assess | Zone-transfer attempts against nameservers without permission | [Kali tools index](https://www.kali.org/tools/all-tools/) |

### 1.2 Web Application Analysis

| Tool | Purpose | Authorized use | When NOT to use | Official docs |
|---|---|---|---|---|
| **Burp Suite** (Community/Pro) | Intercepting proxy, manual testing, and automated web vulnerability scanner | Core tool for manual + automated web app assessment within scope, especially authenticated testing via session-handling macros | Running unthrottled automated active scans against fragile/production systems without change-control approval | [PortSwigger docs](https://portswigger.net/burp/documentation), [BApp Store](https://portswigger.net/bappstore) |
| **OWASP ZAP** | Free/open-source intercepting proxy and DAST scanner, maps to OWASP Top 10 | Free alternative/complement to Burp for scoped DAST scanning, scriptable authenticated scans | Unattended full active scans on production apps without rate-limiting | [zaproxy.org docs](https://www.zaproxy.org/docs/), [OWASP Top 10 mapping](https://www.zaproxy.org/docs/guides/zapping-the-top-10-2021/) |
| **Caido** | Lightweight modern web security auditing toolkit (Burp-like proxy + scanner) | Proxy-based manual testing and passive/active scanning of in-scope web apps | As a full replacement for Burp Pro's mature BApp ecosystem in complex enterprise engagements (Caido is newer/leaner) | [docs.caido.io](https://docs.caido.io/app/quickstart/) |
| **nikto** | Web server scanner for misconfigurations, outdated software, default files | Fast baseline check of a web server's hygiene | As a stealthy or comprehensive scanner — it is noisy and signature-based only | [Kali tool page](https://www.kali.org/tools/nikto/) |
| **dirb / dirbuster / gobuster / feroxbuster / ffuf** | Directory/file/content discovery via brute force or wordlists | Discovering hidden endpoints on an in-scope web app | Extremely large wordlists/high concurrency against rate-limited or shared production infrastructure | [Kali tools](https://www.kali.org/tools/dirb/), see also section 2 |
| **wpscan** | WordPress-specific vulnerability scanner (plugins, themes, users, core) | Assessing your own or authorized WordPress sites | Scanning WordPress sites without the site owner's permission — the vulnerability database access also requires an API token per WPScan's terms | [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan/), [user docs](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation) |
| **sqlmap** | Automates detection and (optionally) exploitation of SQL injection | **Authorized SQL injection testing only** — confirming and demonstrating impact of a suspected SQLi in a scoped engagement | Any use against systems without explicit written authorization; this tool can modify/exfiltrate data and must be used with strict scope discipline | [sqlmap.org](https://sqlmap.org/), [GitHub](https://github.com/sqlmapproject/sqlmap), [usage wiki](https://github.com/sqlmapproject/sqlmap/wiki/usage) |
| **whatweb** | Web technology/CMS fingerprinting (1800+ plugins, 4 aggression levels) | Identifying tech stack of an in-scope target to scope further testing | Aggressive mode against production sites where extra requests could trigger alerts/WAF bans without prior coordination | [urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb), [Kali tool page](https://www.kali.org/tools/whatweb/) |
| **sslyze / wapiti / zaproxy (Kali packages)** | TLS auditing, generic web vuln scanning | Baseline hygiene checks within scope | See Section 2 for sslyze detail | [Kali tools](https://www.kali.org/tools/sslyze/), [wapiti](https://www.kali.org/tools/wapiti/) |

### 1.3 Vulnerability Analysis

| Tool | Purpose | Authorized use | When NOT to use | Official docs |
|---|---|---|---|---|
| **OpenVAS / Greenbone (GVM)** | Full vulnerability management scanner with CVE database | Scheduled vulnerability scanning of owned infrastructure | Scanning shared/cloud multi-tenant infrastructure without provider approval (may violate ToS) | [Kali tools index](https://www.kali.org/tools/all-tools/) |
| **Nmap NSE vuln scripts** | Targeted vulnerability checks via Nmap's scripting engine | Verifying specific known CVEs on in-scope hosts | Running intrusive/DoS-risk scripts against production without a maintenance window | [NSE usage docs](https://nmap.org/book/nse-usage.html) |

**General "when NOT to use" guidance for all Kali categories:** Do not run any of these tools against systems you do not own or lack signed authorization for; avoid noisy/aggressive scan modes on production systems without a change window; and never use exploitation-capable tools (sqlmap, Metasploit, etc.) beyond the minimum needed to confirm a finding in an authorized engagement.

---

## 2. Standalone Web/Domain/IP Assessment Tools

These tools are commonly used outside of, or alongside, a Kali installation — many are lightweight Go/Rust binaries popular in bug-bounty and pentest recon pipelines.

### 2.1 Network & Port Scanning

| Tool | Purpose | Notes | Docs |
|---|---|---|---|
| **nmap** | The de facto network discovery/security auditing tool; supports NSE scripting for vuln checks | Industry standard; use `-sV`/`-sC` for service/version + default scripts | [nmap.org](https://nmap.org/), [docs](https://nmap.org/docs.html), [port scanning guide](https://nmap.org/book/port-scanning.html) |
| **masscan** | Internet-scale asynchronous TCP port scanner (up to ~10M packets/sec) | Nmap-like syntax; requires root/raw sockets; best for very large IP ranges before a targeted nmap pass | [GitHub](https://github.com/robertdavidgraham/masscan) |
| **naabu** (ProjectDiscovery) | Fast Go-based port scanner (SYN/CONNECT/UDP) built for chaining into other PD tools | Actively maintained; commonly piped into `httpx`/`nuclei` | [GitHub](https://github.com/projectdiscovery/naabu) |
| **rustscan** | "Modern port scanner" written in Rust, pipes results into nmap for deeper scanning | Very fast initial sweep; actively maintained | [GitHub](https://github.com/RustScan/RustScan) |

### 2.2 Subdomain & DNS Enumeration

| Tool | Purpose | Notes | Docs |
|---|---|---|---|
| **subfinder** (ProjectDiscovery) | Passive subdomain enumeration from many public sources | Actively maintained, core of PD recon stack | [GitHub](https://github.com/projectdiscovery/subfinder) |
| **amass** (OWASP) | Passive + active subdomain enumeration, DNS mapping, ASN/netblock/graph database | More exhaustive but slower than subfinder; supports `enum`, `intel`, `db` subcommands | [GitHub](https://github.com/owasp-amass/amass), [tutorial](https://github.com/owasp-amass/amass/blob/master/doc/tutorial.md) |
| **dnsx** (ProjectDiscovery) | Fast multi-purpose DNS toolkit: resolution, bruteforce, wildcard filtering | Commonly used to filter live subdomains from passive enumeration output, e.g. `subfinder -d target.com \| dnsx` | [GitHub](https://github.com/projectdiscovery/dnsx), [docs](https://docs.projectdiscovery.io/opensource/dnsx/running) |
| **tlsx** (ProjectDiscovery) | Fast, configurable TLS/SSL data grabber; extracts subdomains from certificate SANs | Can pipe cert-derived hostnames into `dnsx`/`httpx` | [GitHub](https://github.com/projectdiscovery/tlsx) |
| **chaos-client** (ProjectDiscovery) | Client for the Chaos DB API — a continuously updated internet-wide DNS/subdomain dataset | Requires a PDCP API key; good supplemental passive source | [GitHub](https://github.com/projectdiscovery/chaos-client), [Chaos docs](https://chaos.projectdiscovery.io/docs) |

### 2.3 HTTP Probing, Crawling & Tech Detection

| Tool | Purpose | Notes | Docs |
|---|---|---|---|
| **httpx** (ProjectDiscovery) | HTTP toolkit for probing live hosts, status codes, titles, tech detection | Central "liveness filter" in most recon pipelines | [GitHub](https://github.com/projectdiscovery/httpx), [docs](https://docs.projectdiscovery.io/opensource/httpx/running) |
| **katana** (ProjectDiscovery) | Next-generation CLI web crawler (JS-aware) | Faster/more modern than older crawlers; integrates into PD pipeline | [GitHub](https://github.com/projectdiscovery/katana), [intro blog](https://projectdiscovery.io/blog/introducing-katana-the-best-cli-web-crawler) |
| **gospider** | Fast Go web spider for endpoint/link/JS-file discovery, built for chaining | Maintained under the jaeles-project org | [GitHub](https://github.com/jaeles-project/gospider) |
| **hakrawler** | Go web crawler for endpoints, forms, subdomains, related domains, JS files; designed to pipe with other recon tools | Classic tomnomnom-ecosystem-adjacent tool | [GitHub](https://github.com/hakluke/hakrawler) (community forks exist, e.g. [Elsfa7-110/hakrawler](https://github.com/Elsfa7-110/hakrawler)) |
| **waybackurls** (tomnomnom) | Fetches all URLs the Wayback Machine has archived for a domain | Passive; useful for finding old/forgotten endpoints | [GitHub](https://github.com/tomnomnom/waybackurls) |
| **gau ("getallurls")** | Fetches known URLs from AlienVault OTX, Wayback Machine, Common Crawl, URLScan | Explicitly inspired by waybackurls, broader source coverage | [GitHub](https://github.com/lc/gau) |
| **cariddi** | Crawls domains and scans crawled content for secrets, API keys, endpoints, juicy file extensions, and errors in one pass | Actively maintained, popular for bug-bounty recon | [GitHub](https://github.com/edoardottt/cariddi) |
| **whatweb** | Ruby-based fingerprinting tool, 1800+ plugins to detect CMS/server/JS libraries | 4 configurable aggression levels | [GitHub](https://github.com/urbanadventurer/WhatWeb) |
| **Wappalyzer** | Technology detection (browser extension / SaaS API) | **Note:** the original open-source GitHub project was discontinued around November 2024; it is now primarily a commercial SaaS/browser extension, with unofficial community forks of varying freshness | [wappalyzer.com](https://www.wappalyzer.com/), [API](https://www.wappalyzer.com/api/) |

### 2.4 Vulnerability Scanning

| Tool | Purpose | Notes | Docs |
|---|---|---|---|
| **nuclei** (ProjectDiscovery) | YAML-template-based vulnerability scanner covering HTTP, DNS, network, headless, and file-based checks | MIT-licensed, huge community template library, industry standard for automated scanning | [GitHub](https://github.com/projectdiscovery/nuclei), [docs](https://docs.projectdiscovery.io/opensource/nuclei/overview) |
| **nikto** | Web server misconfiguration/vulnerability scanner | See Section 1.2 | [GitHub mirror](https://github.com/lattera/nikto) |
| **sslyze** | Python tool/library auditing TLS: certs, cipher suites, known vulnerabilities (Heartbleed, ROBOT, CCS injection), Mozilla config compliance | Can be used as CLI or library | [GitHub](https://github.com/nabla-c0d3/sslyze), [docs](https://nabla-c0d3.github.io/sslyze/documentation/) |
| **testssl.sh** | Bash + OpenSSL script checking TLS/SSL ciphers, protocols, vulnerabilities; supports STARTTLS | No install required beyond bash/openssl | [GitHub](https://github.com/testssl/testssl.sh), [usage docs](https://github.com/testssl/testssl.sh/wiki/Usage-Documentation) |
| **wpscan** | WordPress vulnerability scanner | See Section 1.2; note dual license, API token needed for full vuln DB | [GitHub](https://github.com/wpscanteam/wpscan/) |

### 2.5 Fuzzing & Content/Parameter Discovery

| Tool | Purpose | Notes | Docs |
|---|---|---|---|
| **ffuf** | Fast Go web fuzzer for directories, virtual hosts, and parameters | Actively maintained, highly configurable | [GitHub](https://github.com/ffuf/ffuf), [wiki](https://github.com/ffuf/ffuf/wiki) |
| **gobuster** | Go directory/DNS/vhost brute-forcer, also supports S3/GCS bucket enumeration | Maintained by OJ Reeves | [GitHub](https://github.com/OJ/gobuster) |
| **feroxbuster** | Rust-based fast recursive content-discovery tool | Good for deep recursive directory brute-forcing | [GitHub](https://github.com/epi052/feroxbuster), [docs](https://epi052.github.io/feroxbuster-docs/docs/) |
| **qsreplace** (tomnomnom) | Reads URLs on stdin, replaces query-string values with a supplied value, dedupes param/host/path combos | Used to prep URL lists for parameter-based scanners like dalfox | [pkg.go.dev](https://pkg.go.dev/github.com/tomnomnom/qsreplace) |
| **anew** (tomnomnom) | Appends stdin lines to a file only if not already present (dedup) | Ubiquitous pipeline "glue" tool for building unique target lists across runs | [GitHub](https://github.com/tomnomnom/anew) |

### 2.6 Manual Testing Proxies

| Tool | Purpose | Notes | Docs |
|---|---|---|---|
| **Burp Suite** | Interception proxy, manual testing, scanner, extensible via BApp Store | See Section 1.2 | [PortSwigger](https://portswigger.net/burp/documentation), [downloads](https://portswigger.net/burp/downloads) |
| **OWASP ZAP** | Free intercepting proxy/scanner, API-driven, maintained by Checkmarx | Requires Java 8+ | [zaproxy.org](https://www.zaproxy.org/), [API docs](https://www.zaproxy.org/docs/api/) |
| **Caido** | Lightweight modern alternative with a Burp-to-Caido feature-mapping guide, Scanner and Autorize (authz-testing) plugins | Growing fast, good for lighter-weight or CI-embedded workflows | [docs.caido.io](https://docs.caido.io/app/quickstart/), [Burp mapping](https://docs.caido.io/burp-suite/core/overview.md) |

### 2.7 Screenshotting / Visual Recon

| Tool | Purpose | Notes | Docs |
|---|---|---|---|
| **gowitness** | Go-based screenshot tool using headless Chrome, generates an HTML report | Actively maintained by SensePost | [GitHub](https://github.com/sensepost/gowitness) |
| **aquatone** | Classic pipeline-friendly screenshot tool, reads hosts from stdin, generates `aquatone_report.html` | Less actively updated than gowitness in recent years | [GitHub](https://github.com/michenriksen/aquatone) |

---

## 3. Newer / Under-the-Radar Tools (2024–2026)

All tools below are open-source and independently verifiable via their repositories; maintenance status is noted based on recent release/commit activity observed at research time (August 2026).

| Tool | Purpose | Maintenance status | Docs |
|---|---|---|---|
| **dalfox** | Fast Go/DOM-parser-based XSS scanner and parameter analysis tool; supports pipe/file/URL modes, WAF-evasion payload sets, deep DOM-XSS checks, and blind-XSS callback integration | Actively maintained — v3.1.1 released June 2026; has a dedicated docs site and official GitHub Action | [GitHub](https://github.com/hahwul/dalfox), [docs](https://dalfox.hahwul.com/) |
| **interactsh** (ProjectDiscovery) | Open-source out-of-band (OOB) interaction server/client for detecting blind vulnerabilities (SSRF, blind XSS, blind SQLi, XXE) via DNS/HTTP(S)/SMTP(S)/LDAP callbacks | Actively maintained — latest release v1.3.1 (March 2026); integrates natively with `nuclei` and has an OAST add-on for ZAP | [GitHub](https://github.com/projectdiscovery/interactsh), [docs](https://docs.projectdiscovery.io/opensource/interactsh/running) |
| **uncover** (ProjectDiscovery) | Queries internet-asset search engines (Shodan, Censys, etc.) via their APIs for passive target discovery | Actively maintained as part of the core PD stack | [docs.projectdiscovery.io](https://docs.projectdiscovery.io/opensource/uncover/install) |
| **tlsx** (ProjectDiscovery) | Fast configurable TLS grabber for cert/cipher-suite data collection and subdomain extraction from SANs | Actively maintained | [GitHub](https://github.com/projectdiscovery/tlsx) |
| **dnsx** (ProjectDiscovery) | Multi-purpose DNS toolkit (resolution, bruteforce, wildcard handling) | Actively maintained | [GitHub](https://github.com/projectdiscovery/dnsx) |
| **chaos-client** (ProjectDiscovery) | Client for the continuously updated Chaos subdomain/DNS dataset | Actively maintained | [GitHub](https://github.com/projectdiscovery/chaos-client), [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/) |
| **afrog** | High-performance vulnerability scanner with user-defined and built-in PoC templates (CVE, CNVD, default passwords, info disclosure, unauthorized access, etc.), generates HTML reports | Actively maintained on GitHub | [GitHub](https://github.com/zan8in/afrog), [wiki](https://github.com/zan8in/afrog/wiki/Getting-Started) |
| **xray** (Chaitin Tech) | Comprehensive Chinese-origin security assessment tool supporting active crawler-based scanning and passive proxy-based scanning with custom POCs | Actively maintained, but **not open source** — only compiled binaries are distributed; community POC repo is open | [GitHub](https://github.com/chaitin/xray), [README (EN)](https://github.com/chaitin/xray/blob/master/README_EN.md), [docs](https://docs.xray.cool/Introduction.md) |
| **jaeles** | Extensible Go framework for building custom web application scanners via YAML-style "signatures" | Maintained under jaeles-project org, docs site active | [GitHub](https://github.com/jaeles-project/jaeles), [docs](https://jaeles-project.github.io/) |
| **cariddi** | Crawler + secrets/endpoint/error scanner in one tool | Actively maintained, recent releases (e.g. v1.4.5, Jan 2026) | [GitHub](https://github.com/edoardottt/cariddi) |
| **gospider** | Fast Go web spider for recon pipelines | Actively maintained under jaeles-project org | [GitHub](https://github.com/jaeles-project/gospider) |
| **hakrawler** | Lightweight Go crawler for chaining into other tools | Original repo by hakluke; community forks continue development | [GitHub](https://github.com/hakluke/hakrawler) |
| **anew** | Dedup-append utility, ubiquitous pipeline glue | Stable/mature; low churn expected for a utility this simple | [GitHub](https://github.com/tomnomnom/anew) |
| **qsreplace** | Query-string value replacement/dedup utility | Stable/mature utility tool | [pkg.go.dev](https://pkg.go.dev/github.com/tomnomnom/qsreplace) |
| **waybackurls** | Wayback Machine URL fetcher | Stable, low-churn | [GitHub](https://github.com/tomnomnom/waybackurls) |

**Observation:** The ProjectDiscovery stack (subfinder, httpx, katana, naabu, dnsx, tlsx, uncover, chaos, interactsh, nuclei) is the most cohesively maintained and interoperable open-source toolchain for recon-to-scan pipelines as of 2026, per the [ProjectDiscovery open-source hub](https://docs.projectdiscovery.io/opensource). The tomnomnom-authored utilities (anew, qsreplace, waybackurls) remain the standard glue for chaining these tools together in shell pipelines.

---

## 4. Best Tool Pipelines for Authorized Assessment of Access-Controlled Targets

Access-controlled targets — behind login, VPN, IP allowlist, or otherwise private — require a hybrid approach: automated recon/scanning tools cover what's reachable, but manual, authenticated testing covers what automated crawlers can't reach without valid session state.

### 4.1 Generic public-surface recon pipeline (establishes the baseline before auth-specific work)

A widely used chain, drawn from [ProjectDiscovery's own katana announcement](https://projectdiscovery.io/blog/introducing-katana-the-best-cli-web-crawler) and community write-ups, is:

```
subfinder -d target.com -silent \
  | dnsx -silent \
  | httpx -silent \
  | katana -jc -depth 2 \
  | nuclei -t nuclei-templates/ -severity high,critical
```

This establishes what subdomains exist, which resolve, which serve HTTP(S), what pages/endpoints a crawler can reach, and runs template-based vulnerability checks — all before any authentication is involved.

A secrets/endpoint-focused variant swaps in cariddi:
```
subfinder -d target.com -silent | httpx -silent | cariddi -s -e -d 3 -c 30
```
([rootsec.in cariddi reference](https://www.rootsec.in/tools/vulnerability-scanners/general-scanners/cariddi))

### 4.2 The core limitation for access-controlled targets

None of the above tools authenticate. `httpx`, `katana`, `gospider`, `hakrawler`, and `nuclei`'s default HTTP templates will only see what's visible to an unauthenticated (or IP-allowlisted-out) requester — for a target behind login/VPN/allowlist this means they will mostly return login pages, 403s, or nothing at all unless run **from inside the allowed network/VPN** or **with valid session credentials injected**.

Two structural requirements follow directly from this:
1. **Network reachability**: run the scanning tooling from a host that is inside the VPN or on the IP-allowlist (a jump box, a VPN-connected workstation, or a cloud instance whose egress IP has been added to scope). Nmap, naabu, httpx, and nuclei all work identically once network reachability is solved — reachability, not the tool, is the actual blocker.
2. **Session/auth injection**: for logged-in application testing, the crawler/scanner must carry valid cookies, bearer tokens, or replay a login flow.

### 4.3 Authenticated scanning workflow (Burp Suite / ZAP — the standard approach)

The professional standard for authenticated DAST is Burp Suite's **session handling rules + macros**, documented officially by PortSwigger:

1. Log in manually through Burp's browser with valid, authorized test credentials, and identify a URL that is only reachable when authenticated (e.g. `/my-account`) as well as the literal string that appears on an invalid/logged-out response ([PortSwigger: Maintaining an authenticated session](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management/maintaining-authenticated-session)).
2. Create a **macro** — a recorded, replayable sequence of the login requests (`Project options → Sessions → Macros → Add`) ([PortSwigger session handling rule editor](https://portswigger.net/burp/documentation/desktop/settings/sessions/session-handling-rules)).
3. Create a **session handling rule** with a "Check session is valid" action pointing at the identified expression; if invalid, configure it to automatically re-run the login macro before continuing ([PortSwigger docs](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management/maintaining-authenticated-session)).
4. Scope the rule to the relevant tools (Scanner, Repeater, Intruder) and URL range so it only fires for the in-scope authenticated app.
5. For token-based/JWT/OAuth2/2FA apps, Burp extensions or ZAP scripts can extract and inject rotating tokens automatically — documented patterns include custom "Set Authorization Header" extensions and Google Authenticator/stepper-plugin integrations for 2FA flows ([PortSwigger example-custom-session-tokens](https://github.com/PortSwigger/example-custom-session-tokens), [2FA automation writeup](https://medium.com/@thelazypentester/automating-authenticated-scans-in-burp-suite-for-2fa-applications-ae93882e26c9)).
6. **Note:** Burp Scanner automatically manages sessions during its own crawl-driven audits — session handling rules are not applied to Scanner's internal requests, only to manually-scoped tools like Repeater/Intruder, per [PortSwigger's session handling rules documentation](https://yw9381.github.io/Burp_Suite_Doc_en_us/burp/documentation/desktop/options/sessions/index.html).

OWASP ZAP supports an equivalent authenticated-scan model using **Context + User configuration**, **Forced User Mode**, and scripted authentication (JavaScript scripts handling login/logout flows), as demonstrated for OAuth2 flows in [ZAP OAuth2 authenticated scan guidance](https://www.youtube.com/watch?v=Jgp1f242B-k) and covered generally in the [OWASP Web Security Testing Guide's Authentication Testing chapter](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README).

### 4.4 CLI-tool authentication injection

The Go-based CLI recon tools accept headers/cookies directly, which lets them participate in authenticated pipelines without a full proxy:
- `httpx -H "Cookie: session=..."` and `katana -H "Authorization: Bearer ..."` — pass session cookies or bearer tokens on every request.
- `nuclei -H "Cookie: ..."` — run template-based scans against authenticated endpoints.
- Feed URLs collected from an authenticated Burp/ZAP crawl (exported sitemap) into `nuclei`, `dalfox`, or `cariddi` for automated template/XSS/secrets scanning on top of the manually-mapped authenticated surface.

### 4.5 Recommended combined workflow for an access-controlled target

1. **Network access**: connect via the authorized VPN or from an allowlisted host/IP before running any tooling.
2. **Manual authenticated mapping**: browse the entire authenticated application through Burp/ZAP's proxy to build a complete sitemap, per OWASP's authentication and authorization testing guides ([WSTG Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README), [WSTG Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)).
3. **Set up session handling** (Burp macros / ZAP Forced User + scripts) so automated crawl-driven scanning stays logged in throughout.
4. **Export the authenticated sitemap** (URL list) from Burp/ZAP.
5. **Layer in template and parameter scanning** against that authenticated URL list: `nuclei -H "Cookie: ..." -l urls.txt`, `dalfox file urls.txt -b <interactsh-oob-url>` for XSS with OOB confirmation via `interactsh`, and `cariddi` for secrets/endpoints on the crawled content.
6. **Manual review and authorization testing**: use Burp Repeater to test privilege boundaries (does user A's session reach user B's data — IDOR/BOLA checks) per the OWASP Authorization Testing chapter — this step cannot be meaningfully automated and is where most authenticated-app findings actually surface.
7. **OOB/blind-vuln confirmation**: self-host or use `interactsh` to catch SSRF/blind-SQLi/blind-XSS callbacks that would otherwise be invisible in a synchronous scan, since a self-hosted or default `interactsh-server` can validate that the access-controlled app can still reach an external listener even from inside a VPN-restricted network ([Interactsh docs](https://docs.projectdiscovery.io/opensource/interactsh/running), [self-hosted setup walkthrough](https://jacobriggs.io/blog/posts/how-to-integrate-nuclei-with-interactsh-and-notify-31)).

---

## 5. Platform Recommendation: Linux vs. Windows (WSL2 + Kali)

### 5.1 Recommendation

For a developer already working primarily on Windows (Cursor/VS Code, PowerShell) who wants to add authorized security-assessment capability without switching daily-driver OS: **install Kali Linux via WSL2**. This gives near-native Linux tooling, apt access to the full Kali repository, and GUI tool support via Win-KeX, while keeping your existing Windows development environment intact. Reserve a dedicated native Linux install (bare metal or a VM) only if you need raw network-adapter access for wireless/802.11 testing, custom kernel modules, or maximum performance for very large scans — WSL2's virtualized networking has known limitations for those specific use cases.

### 5.2 Why WSL2 + Kali works well for web/domain/IP assessment specifically

All of the tools in Sections 1–3 (nmap, the ProjectDiscovery stack, ffuf, gobuster, Burp/ZAP/Caido, sqlmap, testssl.sh, etc.) are CLI/Java/Go/Python tools that don't require raw Layer-2 network access or custom drivers — they work identically well inside WSL2 as on bare-metal Linux. This is a categorically different situation from Wi-Fi/802.11 tooling (aircrack-ng suite, wireless injection), which does have real WSL2 limitations due to lack of native USB Wi-Fi adapter passthrough for monitor mode.

### 5.3 Setup steps (WSL2 + Kali)

Per the [official Kali WSL documentation](https://www.kali.org/docs/wsl/):

1. Enable WSL and set default version to 2 (elevated PowerShell):
   ```
   wsl --install
   wsl --set-default-version 2
   ```
2. Install Kali from the Microsoft Store, or via CLI: `wsl --install -d kali-linux` ([community setup guide](https://github.com/SagarBiswas-MultiHAT/WSL2-Kali-Setup-Guide)).
3. On first launch, create your non-root Kali user, then update:
   ```
   sudo apt update && sudo apt full-upgrade -y
   ```
4. Install the tool metapackages you need (rather than everything) — e.g. `sudo apt install kali-tools-web kali-tools-information-gathering kali-tools-vulnerability`, or `kali-linux-large`/`kali-linux-everything` for the full set, per [Kali metapackages documentation](https://www.kali.org/docs/general-use/metapackages/).
5. (Optional, for GUI tools like Burp's desktop app, wireshark, or a file manager) install Win-KeX:
   ```
   sudo apt install -y kali-win-kex
   kex --win -s      # windowed mode with sound
   ```
   Win-KeX also supports Enhanced Session Mode (`kex --esm -s`, RDP-based, best performance) and Seamless mode (`kex --sl -s`, Kali apps appear as native Windows windows) — full details at the [official Win-KeX docs](https://www.kali.org/docs/wsl/win-kex/), [window mode](https://www.kali.org/docs/wsl/win-kex-win/), and [seamless mode](https://www.kali.org/docs/wsl/win-kex-sl/) pages.
6. Go-based tools (nuclei, httpx, katana, subfinder, naabu, dnsx, tlsx, ffuf alternatives, dalfox, cariddi, gospider, anew, qsreplace, waybackurls, gau) install cleanly via `go install ...@latest` once Go is installed inside the WSL2 Kali environment (`sudo apt install golang-go`).
7. For VPN-gated targets, connect the VPN client on the Windows host; WSL2 (in default NAT networking mode) generally routes through the Windows host's active connections, so a Windows-side VPN connection is typically sufficient for WSL2 tools to reach the private network — verify actual reachability with `curl`/`ping` from inside WSL2 before running a full scan, since WSL2's default NAT mode can occasionally interact unpredictably with corporate VPN split-tunneling; WSL's newer "mirrored" networking mode (`networkingMode=mirrored` in `.wslconfig`) resolves most such conflicts by making WSL2 share the host's network interfaces directly.

### 5.4 Kali vs. Parrot OS (if considering a native/VM install instead)

If a native Linux security distro is preferred over WSL2, Kali and Parrot OS are the two leading choices:

| Aspect | Kali Linux | Parrot OS (Security edition) |
|---|---|---|
| Base | Debian (rolling) | Debian 13 stable base with rolling security tools |
| Default desktop | XFCE | KDE Plasma 6 (or MATE, XFCE-optional per other sources) |
| Resource usage | Higher RAM/CPU | Lighter/more optimized, better for lower-spec hardware |
| Built-in privacy/anonymity | Minimal | AnonSurf (system-wide Tor), more privacy-focused defaults |
| Tool count | 600+ | 500+ |
| Best fit | Professional pentesters, most third-party tutorials/docs target Kali | Privacy-focused testers, older/lower-spec machines |

(Comparison drawn from [ComputingForGeeks Kali vs ParrotOS](https://computingforgeeks.com/parrot-os-vs-kali-linux/) and [CyberPanel's comparison guide](https://cyberpanel.net/blog/kali-linux-vs-parrot-os).) For a developer who will mostly be following mainstream documentation, community write-ups, and the ProjectDiscovery/ffuf/Burp ecosystem (which overwhelmingly assume Kali or plain Debian/Ubuntu), Kali remains the more broadly compatible default; Parrot is a reasonable alternative if lighter resource usage or built-in anonymity tooling matters more.

### 5.5 Practical recommendation summary for a Windows-based developer

- **Daily driver stays Windows** with Cursor/VS Code/PowerShell as today.
- **Kali via WSL2** for all the tools in Sections 1–3 (nmap, ProjectDiscovery stack, Burp/ZAP/Caido, sqlmap, testssl.sh, etc.) — no dual-boot or VM overhead required, and copy-paste/file-sharing between Windows and WSL2 is seamless.
- **Win-KeX in Enhanced Session Mode** if GUI tools (Burp desktop, Wireshark, a browser for manual proxying) are needed regularly — it performs better than Window mode.
- **Escalate to a dedicated Kali VM or bare-metal install only if** wireless/802.11 assessment, custom kernel-level tooling, or maximum raw scanning throughput becomes a real requirement — none of which is implied by the web/domain/IP tool set covered in this report.

---

## Sources

All claims above are sourced from the official project documentation, GitHub repositories, or vendor documentation linked inline throughout each section, including: [Kali Linux Documentation](https://www.kali.org/docs/), [Kali Tools Index](https://www.kali.org/tools/), [Nmap](https://nmap.org/), [ProjectDiscovery Open Source Docs](https://docs.projectdiscovery.io/opensource), [PortSwigger/Burp Suite Documentation](https://portswigger.net/burp/documentation), [OWASP ZAP Documentation](https://www.zaproxy.org/docs/), [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/), [OWASP Amass](https://github.com/owasp-amass/amass), [sqlmap](https://sqlmap.org/), [WPScan](https://github.com/wpscanteam/wpscan/), and the individual tool GitHub repositories cited in each table.


# Part 2 — Access Control Patterns

# Access Control Patterns: Restricting Public Access While Serving a Large Global Authorized User Base

**Scope:** How to keep a website/domain/API away from the general public while still serving thousands to millions of legitimate users worldwide. Covers network-layer blocking, application-layer access control, edge/CDN patterns, device-centric controls, recommended architectures, and defensive security testing. No exploit code is included anywhere in this document.

**Bottom line up front:** For any authorized population beyond a small, static office network, **IP allowlisting and device/MAC binding do not scale** — carrier-grade NAT, dynamic IPs, and mobile networks make "trusted IP" a fiction at global scale. The industry has converged on **identity-based Zero Trust**: authenticate the user/device/workload cryptographically on every request, authorize per-session with dynamic policy, and stop treating network location as a proxy for trust. This is codified in [NIST SP 800-207](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf), the U.S. government's Zero Trust Architecture standard.

---

## 1. Network-Layer Blocking / Allowlisting

### 1.1 IP allowlisting and why it fails at global scale

IP allowlisting restricts access to a predefined set of source addresses. It works for small, static populations (e.g., a handful of office egress IPs) but breaks down as the authorized population grows and globalizes:

- **Carrier-grade NAT (CGNAT):** Many mobile carriers and ISPs share one public IPv4 address across large customer pools, so allowlisting one address can inadvertently admit — or block — an entire neighborhood of unrelated users ([NordLayer](https://nordlayer.com/blog/ip-whitelisting-for-cloud-security/), [stackandsystem.com](https://stackandsystem.com/series/software-security-fundamentals/12f-what-is-ip-whitelisting)).
- **Dynamic IP assignment:** Home and mobile IPs are frequently reassigned; a legitimate user can lose access mid-session with no security event having occurred ([NordLayer](https://nordlayer.com/blog/ip-whitelisting-for-cloud-security/)).
- **Multi-network roaming:** A single user moves between office Wi-Fi, home Wi-Fi, and cellular data — sometimes within minutes — presenting a different source IP each time ([stackandsystem.com](https://stackandsystem.com/series/software-security-fundamentals/12f-what-is-ip-whitelisting)).
- **Spoofability:** Source IPs are not cryptographically bound to identity; allowlists verify network origin, not who is actually connecting ([NordLayer](https://nordlayer.com/blog/ip-whitelisting-for-cloud-security/)).
- **IPv6 growth compounds fragility:** IPv6's vastly larger address space and common dynamic/privacy-extension allocation make static allowlists even harder to maintain ([stackandsystem.com](https://stackandsystem.com/series/software-security-fundamentals/12f-what-is-ip-whitelisting)).

None of this means IP filtering is useless — it remains a useful *defense-in-depth* layer (e.g., allowing only known CDN/edge ranges to reach an origin server). The point is that IP address alone must never be the sole basis for authorization at scale. This is the explicit premise of Zero Trust: network location is never sufficient evidence of trust ([Cloudflare, "What is ZTNA?"](https://www.cloudflare.com/learning/access-management/what-is-ztna/)).

### 1.2 VPN and mesh-networking technologies

| Technology | Layer / Model | Crypto | Notes |
|---|---|---|---|
| **WireGuard** | Kernel module (Linux 5.6+, merged March 2020) | Fixed suite: Curve25519, ChaCha20-Poly1305, BLAKE2s | ~4,000 lines of code, UDP-only, 1.5-RTT handshake, no built-in certificate revocation (keys must be rotated manually) ([Tailscale docs](https://tailscale.com/docs/concepts/wireguard), [geeksynapse.com comparison](https://www.geeksynapse.com/2026/03/wireguard-vs-openvpn-in-2026-self.html)) |
| **OpenVPN** | Userspace daemon | TLS/SSL control channel, AES-256-GCM default since 2.6 | ~70,000–120,000 lines, supports TCP (can traverse firewalls via port 443) or UDP, full X.509 PKI with CRL/OCSP revocation ([tech-insider.org](https://tech-insider.org/wireguard-vs-openvpn-2026/), [Contabo](https://contabo.com/blog/wireguard-vs-openvpn-a-deep-dive-protocol-comparison/)) |
| **Tailscale** | Managed mesh built on WireGuard | WireGuard crypto + coordinator-issued keys | Nodes authenticate to a coordination server, exchange public keys, attempt direct P2P WireGuard tunnels with NAT traversal, fall back to DERP relay when direct connection fails ([Tailscale: How it works](https://tailscale.com/blog/how-tailscale-works), [Understanding mesh VPNs](https://tailscale.com/learn/understanding-mesh-vpns)) |
| **ZeroTier** | Layer 2 (Ethernet) virtual switch/mesh | Own suite: Salsa20/Poly1305, Curve25519 (not WireGuard-based) | Emulates a flat virtual LAN across the internet ([dev.to comparison](https://dev.to/selfhostingsh/zerotier-vs-tailscale-which-mesh-vpn-to-use-c1o), [vpnsmith.com comparison](https://www.vpnsmith.com/en/blog/zerotier-vs-tailscale-2026)) |
| **Cloudflare WARP** | Forward-proxy client | Tunnels device traffic to nearest Cloudflare PoP | Paired with Cloudflare Tunnel (`cloudflared`) and Access policies to build full ZTNA without a traditional VPN concentrator ([Cloudflare: Introducing Zero Trust Private Networking](https://blog.cloudflare.com/private-networking/), [A bridge to Zero Trust](https://blog.cloudflare.com/bridge-to-zero-trust/), [Warp-to-warp](https://blog.cloudflare.com/warp-to-warp/)) |

Independent benchmarking generally finds WireGuard 3–5x faster than OpenVPN with lower CPU overhead and faster reconnection ([vpnsmith.com benchmarks](https://www.vpnsmith.com/en/blog/wireguard-vs-openvpn-vps-benchmarks-2026)); a peer-reviewed performance comparison is available via ACM ([dl.acm.org](https://dl.acm.org/doi/10.1145/3374664.3379532)).

**Cloudflare's own framing is instructive for scale:** they explicitly market Zero Trust Network Access as a *replacement* for traditional default-allow VPNs, moving to default-deny, identity-based, per-application policies ([Cloudflare ZTNA overview](https://www.cloudflare.com/learning/access-management/what-is-ztna/), [VPN Replacement](https://www.cloudflare.com/sase/use-cases/vpn-replacement/)).

### 1.3 Private networks and VPC peering

- **AWS VPC Peering** connects two VPCs directly over private IPv4/IPv6 with no gateway, VPN, or physical hardware in the path, no bandwidth bottleneck, and support across regions/accounts — but peered VPC CIDR ranges must not overlap ([AWS VPC Peering docs](https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html), [AWS VPC FAQs](https://aws.amazon.com/vpc/faqs/), [AWS networking best practices](https://aws.github.io/aws-networking-best-practices/foundation/vpc/)).
- **Site-to-site VPN** (AWS Virtual Private Gateway + Customer Gateway) is the standard way to connect a VPC to on-premises infrastructure ([AWS VPN connections docs](https://docs.aws.amazon.com/vpc/latest/userguide/vpn-connections.html), [AWS connectivity options whitepaper](https://d1.awsstatic.com/whitepapers/aws-amazon-vpc-connectivity-options.pdf)).
- These patterns are appropriate for service-to-service or datacenter-to-cloud connectivity, not for authenticating a large, distributed human user population — they solve *network reachability*, not *identity*.

### 1.4 Geo-blocking and its limits

- IP-based geolocation accuracy is generally cited as 95–99% at the country level but drops to roughly 50–80% (within ~25 km) at the city level; cloud-provider IP ranges are often only accurate to the datacenter, and mobile carrier IPs are often only accurate to the carrier's regional hub city ([sadiqbd.com](https://sadiqbd.com/blog/internet/reverse-dns/ip-geolocation-how-it-works-accuracy-vpn-problem)).
- VPNs defeat geo-blocking trivially by presenting the exit-node's location instead of the user's true location; an academic study on VPN-based geo-unblocking found that even VPN-aware geolocation systems are typically reliable only at the country level ([University of Twente](https://ris.utwente.nl/ws/portalfiles/portal/300808180/978_3_031_28486_1_3.pdf)).
- Geo-blocking is therefore best treated as a coarse risk signal or compliance control (e.g., sanctions/export-control geography), never as the primary access-control mechanism for an authorized-user population.

### 1.5 ISP/firewall network ACLs

Traditional network ACLs (router/firewall rules keyed on source IP, port, and protocol) remain useful as a coarse outer perimeter — for example, restricting inbound traffic on an origin server to only a CDN provider's published IP ranges. This is a defense-in-depth measure layered *underneath* identity-based access control, not a substitute for it; see §3.5 on origin-lockdown, where this exact pattern (allow only Cloudflare's published ranges, block everything else) is described as a best practice specifically because it prevents attackers from bypassing the identity/WAF layer by hitting the origin IP directly ([tigzig.com](https://www.tigzig.com/agents-faq/can-attackers-bypass-cloudflare-and-hit-my-server), [Indusface, Cloudflare origin protection limitations](https://www.indusface.com/blog/cloudflare-origin-protection-limitations/)).

---

## 2. Application-Layer Access Control

### 2.1 Authentication standards: SAML vs. OAuth 2.0 vs. OIDC

| Standard | Purpose | Mechanism | Era |
|---|---|---|---|
| **SAML** | Enterprise SSO **authentication** | XML assertions, browser-redirect based; no direct IdP–SP backchannel required | 2005, OASIS |
| **OAuth 2.0** | Delegated **authorization** (NOT authentication) | Access tokens issued to a client for scoped resource access | RFC 6749, 2012 |
| **OIDC (OpenID Connect)** | **Authentication** layer built on top of OAuth 2.0 | JWT-based ID tokens carrying identity claims | 2014, OpenID Foundation; now the default choice for new SSO builds |

Flows:
- **SAML:** user → service provider (SP) → redirect to identity provider (IdP) → IdP authenticates the user → signed XML assertion is POSTed back to the SP via the browser.
- **OIDC:** redirect to the OpenID provider → user authenticates → an authorization code is issued → the app exchanges the code for an access token and an ID token (a JWT carrying identity claims).

Sources: [Pomerium: SSO, OAuth2 vs OIDC vs SAML](https://www.pomerium.com/blog/sso-oauth2-vs-oidc-vs-saml), [Cisco Duo: SAML vs OAuth vs OIDC](https://duo.com/learn/saml-vs-oauth-vs-oidc), [Clerk 2026 decision guide](https://clerk.com/articles/oidc-vs-saml-for-enterprise-sso-a-2026-decision-guide), [Okta: SAML vs OAuth](https://www.okta.com/en-ca/identity-101/saml-vs-oauth/), [Auth0: SAML vs OIDC](https://auth0.com/intro-to-iam/saml-vs-openid-connect-oidc).

### 2.2 Passwordless authentication: magic links and passkeys/WebAuthn

- **Passkeys / WebAuthn / FIDO2** use hardware-backed public-key credentials that are phishing-resistant by design — the private key never leaves the device/secure enclave, and the credential is bound to the origin it was created for.
- **Magic links** and **one-time-password (OTP)** flows are alternative passwordless options with weaker phishing resistance than passkeys.
- AWS publishes a reference passwordless implementation for Cognito supporting FIDO2/WebAuthn, magic links, and SMS OTP together ([AWS Cognito passwordless sample](https://github.com/aws-samples/amazon-cognito-passwordless-auth)); a broader technology comparison is available from [WWPass](https://www.wwpass.com/blog/passwordless-authentication-methods-comparison-8-technologies-evaluated/).

### 2.3 Authorization models: RBAC, ABAC, ReBAC

| Model | Basis | Granularity | Complexity | Typical use |
|---|---|---|---|---|
| **RBAC** (Role-Based Access Control) | User's assigned role(s) | Coarse | Low | AWS IAM, Kubernetes RBAC; standardized in ANSI INCITS 359-2004 and referenced by NIST SP 800-207 |
| **ABAC** (Attribute-Based Access Control) | Attributes of subject, resource, and environment evaluated at runtime (time-of-day, geography, classification, etc.) | Fine, context-aware | High | Canonical policy language: XACML 3.0 |
| **ReBAC** (Relationship-Based Access Control) | Graph of relationships between entities ("Zanzibar-style," after Google's 2019 internal system) | Fine, relationship-aware | Medium–high | Multi-tenant SaaS, nested org hierarchies; implemented by OpenFGA, SpiceDB, Ory Keto |

Sources: [permit.io: RBAC vs ABAC vs ReBAC](https://www.permit.io/blog/rbac-vs-abac-and-rebac-choosing-the-right-authorization-model), [aserto.com](https://www.aserto.com/blog/rbac-abac-and-rebac-differences-and-scenarios), [pangea.cloud](https://pangea.cloud/blog/rbac-vs-rebac-vs-abac/), [webdevsimplified](https://blog.webdevsimplified.com/2025-11/rbac-vs-abac-vs-rebac/), [osohq.com: RBAC vs ABAC vs ReBAC](https://www.osohq.com/learn/rbac-vs-abac-vs-rebac-what-is-the-best-access-policy-paradigm), [osohq.com: Ten types of authorization](https://www.osohq.com/post/ten-types-of-authorization) (notes that ABAC is the most general model, ReBAC is a subset of ABAC, and RBAC is a subset of ReBAC). In practice, production systems typically compose all three — RBAC for coarse gating, ABAC/ReBAC layered on top for fine-grained decisions.

### 2.4 Mutual TLS (mTLS)

Both client and server present X.509 certificates and prove possession of the corresponding private key during the TLS handshake (`CertificateVerify` message). mTLS provides **authentication only** — it does not by itself decide *what* an authenticated party may do; that is a separate authorization step.

Sources: [goteleport.com: What is mTLS?](https://goteleport.com/learn/what-is-mtls/), [Cloudflare: What is mutual TLS?](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/), [ngrok: What is mTLS](https://ngrok.com/blog/what-is-mtls), [Google Cloud Load Balancing mTLS](https://docs.cloud.google.com/load-balancing/docs/mtls), [F5: What is mTLS](https://www.f5.com/labs/articles/what-is-mtls), [AWS ALB mutual authentication](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html), [Azure Application Gateway mutual auth](https://learn.microsoft.com/en-us/azure/application-gateway/mutual-authentication-overview).

OAuth mTLS client authentication goes further and binds an access token to the client's certificate ("certificate-bound tokens"), preventing a stolen bearer token from being replayed from a different client: [Raidiam: mTLS client authentication explained](https://www.raidiam.com/developers/blog/mtls-client-authentication-explained), [Auth0: Authenticate with mTLS](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authenticate-with-mtls), [Curity: OAuth client authentication with mTLS](https://curity.io/resources/learn/oauth-client-authentication-mutual-tls/).

### 2.5 API keys, device binding, and short-TTL signed tokens

- Static API keys are simple but are bearer secrets: anyone holding the key can use it. They are commonly strengthened by binding a key to a specific client/device fingerprint or certificate, rate-limiting per key, and rotating frequently.
- Signed tokens (JWTs) with **short time-to-live (TTL)** limit the blast radius of a leaked token — the standard OIDC/OAuth pattern issues short-lived access tokens (minutes) alongside longer-lived refresh tokens that can be revoked server-side.
- Device attestation (§4) provides a stronger, hardware-backed alternative to naive device binding for mobile clients — see below.

### 2.6 CAPTCHA and bot management

- **Cloudflare Turnstile** uses non-interactive JavaScript challenges — proof-of-work, proof-of-space, browser API probing, and behavioral analysis — and can leverage hardware attestation on compatible devices (e.g., recent iPhones, which contact Apple's servers for a token) instead of visual puzzles ([Cloudflare Turnstile docs](https://developers.cloudflare.com/turnstile/)).
- **hCaptcha** offers a comparable non-interactive/interactive hybrid model; a vendor comparison of the two is published by hCaptcha itself ([hCaptcha vs Turnstile](https://www.hcaptcha.com/blog/hcaptcha-vs-turnstile)) — useful for understanding both products' mechanics even though it is a vendor source.
- Bot management products are a complement to, not a substitute for, authentication — they filter automated traffic before or alongside login, not instead of it.

---

## 3. Edge/CDN Access Control for Large Global Audiences

Edge and CDN-based identity-aware proxies let a globally distributed audience reach an application performantly while still enforcing per-request authentication and authorization close to the user, rather than backhauling every request to a central VPN concentrator.

### 3.1 Cloudflare Access / Zero Trust / Cloudflare Tunnel

- **Cloudflare Tunnel** (`cloudflared` daemon) creates an **outbound-only** connection from the origin server to Cloudflare's edge — no inbound ports are opened and no public IP is required on the origin at all ([Cloudflare Tunnel docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/), [Cloudflare: Ridiculously easy to use Tunnels](https://blog.cloudflare.com/ridiculously-easy-to-use-tunnels/)).
- **Cloudflare Access** sits in front of Tunnel as an identity-aware reverse proxy: it authenticates the user against an IdP (Okta, Azure AD/Entra ID, Google Workspace, GitHub, etc.), can evaluate device posture, and applies contextual rules (geography, time of day, group membership) before forwarding the request ([Cloudflare Zero Trust guide](https://ayinedjimi-consultants.fr/articles/cloudflare-zero-trust-tunnel-access-gateway-guide), [community walkthrough](https://www.linkedin.com/pulse/zero-trust-action-securing-applications-cloudflare-qf2lf), [Hacker News discussion](https://news.ycombinator.com/item?id=45946865)).
- This combination is a canonical pattern for exposing an internal or private application to a large, distributed, but fully authenticated user population without a traditional VPN.

### 3.2 AWS: WAF + CloudFront signed URLs/cookies (+ Cognito for identity)

- **CloudFront signed URLs/signed cookies** validate a query-string or cookie parameter against a signature made with a private key held by a "trusted key group"; CloudFront checks the signature, expiration, and start-time before serving private content ([AWS: private content with signed cookies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-cookies.html), [trusted signers docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html), [Security and private content overview](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/SecurityAndPrivateContent.html)).
- **Lambda@Edge** functions are a common way to generate signed URLs/cookies dynamically and check domain/session context at the edge ([AWS blog: signed-cookie authentication with Lambda@Edge, part 2](https://aws.amazon.com/blogs/networking-and-content-delivery/signed-cookie-based-authentication-with-amazon-cloudfront-and-aws-lambdaedge-part-2-authorization/)).
- **AWS WAF** sits in front of CloudFront/ALB and filters malicious or unauthorized request patterns (rate limits, managed rule groups, geo rules) as a complementary layer to identity-based access. A worked example combining Origin Access Control, signed URLs, WAF, and Shield is walked through in this video: [YouTube: OAC, Signed URLs, WAF, Shield](https://www.youtube.com/watch?v=2kvm5IKWkkM).
- **Amazon Cognito** provides the identity layer (user pools for authentication, identity pools for AWS credential federation) that is typically paired with API Gateway/CloudFront/ALB to authenticate the human or machine user before a signed URL/cookie or session token is ever issued — the general pattern is: Cognito authenticates → application issues a scoped, short-lived token or CloudFront-signed cookie → CloudFront/WAF enforces it at the edge.

### 3.3 Azure Front Door + Entra ID

Azure Front Door provides global edge routing, WAF, and TLS termination; when paired with **Microsoft Entra ID** (formerly Azure AD) for authentication — typically via an application gateway/reverse-proxy pattern or Entra-integrated app registration — it forms the Azure-native equivalent of Cloudflare Access or Google IAP: authenticate centrally against the tenant's identity provider, then route only authenticated, authorized traffic to backend origins through the CDN/WAF layer.

### 3.4 Google Cloud Identity-Aware Proxy (IAP)

- IAP is Google's cloud-native alternative to VPNs: it enforces identity and authorization at the **application level**, eliminating the need for broad network-level access, and supports context-aware policies based on identity, group membership, device security status, and location/IP ([GCP IAP docs](https://docs.cloud.google.com/iap/docs), [IAP concepts overview](https://docs.cloud.google.com/iap/docs/concepts-overview), [Google Cloud blog: getting started with IAP](https://cloud.google.com/blog/products/identity-security/getting-started-with-cloud-identity-aware-proxy)).
- Flow: a user requests a URL → if unauthenticated, IAP redirects to the configured identity provider → the IdP issues an identity token → IAP checks the caller against IAM policy → IAP forwards the request to the backend with signed identity headers; the backend should be firewalled to accept traffic only from IAP's known IP ranges as defense-in-depth ([Medium: fortifying Zero Trust with IAP](https://medium.com/google-cloud/fortifying-your-cloud-zero-trust-with-identity-aware-proxy-iap-ba4a69124e40), [Google Codelab: user auth with IAP](https://codelabs.developers.google.com/codelabs/user-auth-with-iap)).
- IAP also supports **TCP forwarding** for SSH/RDP tunneling with the same identity-based access model ([TCP forwarding overview](https://docs.cloud.google.com/iap/docs/tcp-forwarding-overview), [Using IAP for TCP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding)), and can front **on-premises applications** as well as cloud-hosted ones ([IAP for on-prem apps](https://docs.cloud.google.com/iap/docs/cloud-iap-for-on-prem-apps-overview)). Original launch announcement: [Google Cloud Blog, 2017](https://cloud.google.com/blog/products/gcp/cloud-identity-aware-proxy-protect-application-access-on-the-cloud).

### 3.5 Fastly / Akamai and origin-lockdown as a general pattern

Fastly and Akamai are CDN/edge platforms comparable in role to Cloudflare and CloudFront: they terminate global traffic at edge points-of-presence and can be configured with WAF rules, edge compute (Fastly Compute@Edge, Akamai EdgeWorkers), and token-based or signed-URL authentication at the edge, following the same general "authenticate/authorize before forwarding to origin" pattern described above for Cloudflare/AWS/GCP. Regardless of vendor, the same origin-lockdown discipline applies once an edge/CDN identity layer is in place:

1. **Proxy every DNS record** through the CDN (Cloudflare's "orange cloud" or the equivalent on other platforms) — a DNS-only ("grey cloud") record publishes the real origin IP, and any code that trusts a client-supplied header like `CF-Connecting-IP` without the proxy in the path will accept spoofed values ([tigzig.com](https://www.tigzig.com/agents-faq/can-attackers-bypass-cloudflare-and-hit-my-server)).
2. **Remove or firewall stale subdomains** (`dev`, `staging`, `cp`, `panel`, `webmail`, `direct`, etc.) that may resolve straight to the origin, bypassing the CDN entirely ([Libyan Spider: prevent direct access to origin](https://help.libyanspider.com/kb-article/how-to-prevent-direct-access-to-your-website-origin-server/)).
3. **Restrict inbound 80/443 on the origin firewall to the CDN's published IP ranges only**, and refresh that allowlist on a schedule since providers rotate ranges ([fixvibe.app: Cloudflare origin & proxy posture](https://www.fixvibe.app/lb/checks/platform-cloudflare), [tigzig.com](https://www.tigzig.com/agents-faq/can-attackers-bypass-cloudflare-and-hit-my-server)).
4. **Enable Authenticated Origin Pulls / mTLS between edge and origin** so that even a discovered origin IP cannot be used to bypass the edge WAF/Access layer without also presenting a valid client certificate ([Indusface: Cloudflare origin protection limitations](https://www.indusface.com/blog/cloudflare-origin-protection-limitations/), [pentesting.se: why Cloudflare proxying alone isn't enough](https://pentesting.se/en/blog/cloudflare-origin-bypass)).
5. **Best option where supported: remove the public origin IP entirely** via an outbound-only tunnel (Cloudflare Tunnel or equivalent), so there is no IP to discover in the first place ([fixvibe.app](https://www.fixvibe.app/lb/checks/platform-cloudflare)).
6. Audit for origin-IP leakage via historical DNS records, TLS certificate transparency logs, and internet-wide scanning indexes (Shodan/Censys) — tools such as [BehindTheCDN](https://github.com/Loop-Man/BehindTheCDN) exist to help defenders find their *own* leaking origin as part of an authorized audit.

### 3.6 Reverse-proxy auth: oauth2-proxy, Pomerium, Traefik-forward-auth, Authentik/Authelia/Keycloak

| Tool | Language / stars (approx.) | IdP support | Policy engine | mTLS/gRPC | Best for |
|---|---|---|---|---|---|
| **oauth2-proxy** | Go, ~14,200 stars | 20+ IdPs | Basic RBAC via headers | No | General-purpose auth proxy |
| **Pomerium** | Go, ~4,700 stars | OIDC, Google, Azure | Full CEL policy engine (fine-grained RBAC) | Yes | Zero-Trust / enterprise BeyondCorp-style deployments |
| **Traefik-forward-auth** | Go, ~2,400 stars | Google, OIDC only | None | No | Simplicity, native Traefik integration |

Source for the comparison table: [pistack.xyz: oauth2-proxy vs Pomerium vs Traefik-forward-auth (2026)](https://www.pistack.xyz/posts/oauth2-proxy-vs-pomerium-vs-traefik-forward-auth-2026/), [Pomerium comparisons page](https://www.pomerium.com/comparisons), [best-of-web.builder.io: Pomerium](https://best-of-web.builder.io/library/pomerium/pomerium).

For full identity-provider stacks rather than thin proxies: **Authentik** is a full IdP, **Authelia** is a certified OIDC/OAuth2 authentication gateway, and **Keycloak** is an enterprise IAM platform supporting OIDC, OAuth2, and SAML together ([authhost.de comparison](https://authhost.de/en/blog/authentik-vs-authelia-vs-keycloak)).

---

## 4. Device-Centric Controls at Scale

### 4.1 MDM and device certificates for corporate fleets

Mobile Device Management (MDM) issues and manages device certificates, enforces compliance policies (OS version, disk encryption, jailbreak/root detection), and reports device health. MDM is not itself a Zero Trust Architecture — it is a **signal source** that a Zero Trust policy engine consumes when deciding whether to grant access ([faq.miniorange.com: MDM and Zero Trust](https://faq.miniorange.com/knowledgebase/mdm-zero-trust-security/), [Microsoft Zero Trust Workshop guidance on device certs/Wi-Fi/VPN](https://microsoft.github.io/zerotrustassessment/docs/workshop-guidance/devices/RMD_018)). A robust certificate-based device-trust program pairs an internal PKI (private CA) with automated enrollment protocols (SCEP/ACME/step-ca) and continuous posture checking via MDM/EDR/UEM, with audit logging throughout ([hackersvanguard.com](https://hackersvanguard.com/certificate-based-device/)).

### 4.2 Mobile device attestation (Play Integrity, App Attest/DeviceCheck, Firebase App Check)

- **Google Play Integrity API** (successor to SafetyNet) verifies that an app was installed via the Play Store, that the device is not rooted or an emulator, that the APK has not been tampered with, and — on Android 13+ — provides hardware-backed proof that the bootloader is locked and the OS image is a certified manufacturer build ([Android developer docs](https://developer.android.com/google/play/integrity), [overview](https://developer.android.com/google/play/integrity/overview)).
- **Apple App Attest / DeviceCheck** generates a hardware-backed key pair in the device's Secure Enclave; Apple attests that the key genuinely originates from a real device running the genuine app, after which the app signs server requests with the attested key. DeviceCheck additionally persists two bits of per-device state across reinstalls, useful for abuse prevention such as free-trial limiting ([Apple: Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [DeviceCheck overview](https://developer.apple.com/documentation/devicecheck), [WWDC21 session](https://developer.apple.com/videos/play/wwdc2021/10244/), [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)).
- **Firebase App Check** unifies DeviceCheck/App Attest (iOS), Play Integrity (Android), and reCAPTCHA Enterprise (web) into a single attestation layer, rejecting backend requests that lack a valid attestation token ([Firebase App Check docs](https://firebase.google.com/docs/app-check)).
- Crucially, mobile proxies and VPNs do **not** defeat this class of attestation, because it operates at the device/app-binary layer (hardware-backed key material and OS integrity checks), not at the network layer that IP-based controls inspect ([mobileproxies.org](https://mobileproxies.org/blog/mobile-app-attestation-play-integrity)).

### 4.3 Why pure MAC/IP device binding does not scale globally

Binding authorization to a MAC address or IP address assumes a stable 1:1 mapping between network identifier and device/user — an assumption that collapses at global consumer scale for the same reasons IP allowlisting fails (§1.1): CGNAT sharing, dynamic reassignment, multi-network roaming, MAC randomization on modern mobile OSes for privacy, and the fact that neither a MAC nor an IP is cryptographically tied to a specific human or app instance. This is precisely the gap that hardware-backed attestation (§4.2) and identity-first Zero Trust are designed to close.

### 4.4 Recommended pattern: identity-first Zero Trust, not IP allowlists

[NIST SP 800-207](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf) (also on [NIST CSRC](https://csrc.nist.gov/pubs/sp/800/207/final), announced in [this NIST news release](https://www.nist.gov/news-events/news/2020/08/zero-trust-architecture-nist-publishes-sp-800-207)) defines seven tenets of Zero Trust Architecture:

1. All data sources and computing services are treated as resources.
2. All communication is secured regardless of network location.
3. Access to individual resources is granted on a per-session basis.
4. Access is determined by dynamic policy — including observable state of identity, device, and behavior.
5. The enterprise monitors and measures the integrity and security posture of all owned/associated assets continuously.
6. All resource authentication and authorization are dynamic and strictly enforced *before* access is allowed.
7. The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications, and uses it to improve its security posture.

[NIST SP 800-207A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf) extends this specifically for cloud-native environments, describing the shift from network-perimeter segmentation (IP/subnet-based) to identity-based access policies. [NIST SP 1800-35](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-35.pdf) (and the accompanying [project site](https://pages.nist.gov/zero-trust-architecture/)) documents practical, vendor-tested implementation guidance.

**Practical translation:** for any authorized population that is large, global, or mobile, replace "is this request coming from a known IP/MAC?" with "can this request cryptographically prove who/what it is, and does dynamic policy allow this identity to do this action, right now, on this resource?"

---

## 5. Recommended Architectures

### 5.1 A private web app with thousands–millions of authorized users worldwide

- **Identity layer:** OIDC-based SSO (Cognito, Entra ID, Okta, Google Workspace, or a self-hosted IdP like Keycloak/Authentik) issuing short-TTL JWTs, with passkeys/WebAuthn preferred over passwords where feasible (§2.1–2.2).
- **Edge/CDN layer:** Cloudflare Access + Cloudflare Tunnel, **or** AWS CloudFront + WAF + Cognito + signed cookies, **or** Azure Front Door + Entra ID, **or** Google Cloud IAP — pick the stack matching existing cloud investment (§3).
- **Authorization:** RBAC for coarse tiers (free/paid/admin), layered with ABAC/ReBAC for fine-grained, per-resource or per-tenant decisions (§2.3) — this is the standard pattern for multi-tenant SaaS serving a large distributed user base.
- **Origin lockdown:** origin never directly reachable from the public internet; only the CDN/edge layer's published IP ranges (or an outbound-only tunnel) can reach it; Authenticated Origin Pulls / mTLS between edge and origin (§3.5).
- **Bot/abuse defense:** Turnstile or hCaptcha at signup/login and other bot-prone actions (§2.6); device attestation (App Attest / Play Integrity / Firebase App Check) if there is a first-party mobile client (§4.2).
- **Do NOT** rely on IP allowlisting or geo-blocking as the primary gate — use them only as coarse, defense-in-depth signals layered under the identity system (§1.1, §1.4).

### 5.2 A staging/internal site off the public internet with occasional external access

- **Default posture:** no public DNS record, no public origin IP — expose only via an outbound-only tunnel (Cloudflare Tunnel, or an equivalent reverse-proxy tunnel) so there is nothing to discover or attack from the public internet ([Cloudflare Tunnel docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)).
- **Access for internal team:** identity-aware proxy (Cloudflare Access, Google Cloud IAP, or a self-hosted reverse-proxy-auth tool like Pomerium/oauth2-proxy — §3.6) gated on the corporate IdP, with device-posture checks via MDM signals where available (§4.1).
- **Occasional external access** (e.g., a client demo or an external auditor): time-boxed Access policy grants scoped to that identity/email domain rather than opening network-level access or issuing a standing VPN credential — this is the core advantage of identity-based over network-based gating: access can be granted and revoked per-identity, per-session, without touching network topology.
- **Never** fall back to "just open port 443 to a specific IP" for these occasional-access cases — that reintroduces every CGNAT/dynamic-IP fragility described in §1.1 for a use case that is even more security-sensitive (pre-production/internal systems).

### 5.3 API-only services

- **Machine-to-machine auth:** OAuth 2.0 client-credentials grant (or mTLS client-certificate authentication, §2.4) rather than long-lived static API keys alone.
- **Token hygiene:** short-TTL signed JWTs (§2.5) for access tokens; longer-lived, individually revocable refresh/client credentials stored server-side, never in a mobile app binary or public repo.
- **Transport security:** mTLS between service-to-service callers where both ends are under your control (internal microservices, partner integrations); the OAuth mTLS certificate-bound-token pattern (§2.4) if the API is exposed to external partners over OAuth.
- **Edge protection:** WAF + rate limiting (per-key and per-IP) in front of the API gateway; CloudFront/API Gateway or Cloudflare in front of the origin regardless of CDN choice (§3).
- **Device/app binding for mobile-originated API calls:** attestation tokens (App Attest/Play Integrity/Firebase App Check, §4.2) attached to API requests rather than IP or MAC binding.

---

## 6. Security-Testing Your Own Access Controls (Authorized, Defensive — No Exploit Code)

All resources below describe benign, non-destructive verification techniques (status-code checks, token/parameter swaps between your own test accounts, configuration scanners) appropriate for authorized testing of systems you own or have explicit permission to test.

### 6.1 Verify unauthenticated requests are rejected

- Use forced-browsing tests: attempt direct, unauthenticated access to every protected URL/endpoint and confirm a 401/403 (never a 200) is returned, per the [OWASP Web Security Testing Guide's bypass-authorization-schema methodology](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema).
- Tools: **Postman** or **curl** for scripted, repeatable endpoint checks; **Burp Suite** (industry-standard intercepting proxy, using its Repeater feature to manually replay requests with and without credentials) ([strobes.co tools overview](https://strobes.co/blog/web-application-penetration-testing-tools/), [cyberfortify.co](https://cyberfortify.co/blog/web-application-penetration-testing-tools)).

### 6.2 Verify authorization boundaries (IDOR, privilege escalation)

- **IDOR (Insecure Direct Object Reference) methodology:** map all object references in the app (IDs in URLs, form fields, API payloads), then — using two or more test accounts of different privilege levels — swap the identifier and confirm the server returns 403/404 rather than another user's data, per [OWASP's IDOR testing guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) and the [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).
- **"Multi-User Replay" pattern:** authenticate as User A, create/own a resource, then authenticate as User B and attempt to read/update/delete that same resource — every attempt must fail, per the [OWASP Authorization Regression Testing Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html), which also recommends systematically testing every non-admin role against every admin endpoint (privilege-escalation check) and validating multi-tenant data isolation.
- **Horizontal/vertical privilege testing:** use two same-role test accounts and swap session tokens between them; also test header-based bypasses (e.g., `X-Original-URL`, `X-Rewrite-URL`) that some reverse-proxy configurations mistakenly trust, per the [OWASP bypass-authorization-schema guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema).
- Practical worked examples using only benign curl/Postman requests (parameter and token swapping, status-code assertions — no injection payloads) are documented at [codereviewlab.com](https://www.codereviewlab.com/learning/idor-access-control), [chs.us authorization guide](https://chs.us/guides/authz/), [aquilax.ai](https://aquilax.ai/blog/broken-access-control-idor-explained), and [cybercloud.guru's authorization-matrix testing approach](https://cybercloud.guru/product-security/application-security/authorization-security/).
- The [OWASP Penetration Testing Kit (PTK)](https://owasp.org/www-project-penetration-testing-kit/) is an open-source browser extension for running this kind of authorized, session-based testing without separate tooling.
- For JWT-based auth specifically, **jwt.io** (decode/verify signature and claims) and **jwt_tool** (systematic weakness analysis, e.g., algorithm confusion, missing expiry) support inspection without needing to fabricate exploit payloads.

### 6.3 Verify TLS/header posture

- **Qualys SSL Labs Server Test** ([ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/)) grades TLS configuration (protocol versions, cipher suites, certificate chain, known vulnerabilities); Qualys also publishes the open-source **ssllabs-scan** CLI for automated/CI use ([SSL Labs APIs](https://www.ssllabs.com/projects/ssllabs-apis/index.html), [assessment tools wiki](https://github.com/ssllabs/research/wiki/Assessment-Tools)).
- **testssl.sh** is an open-source CLI performing a comprehensive local TLS assessment (protocols, ciphers, known vulnerabilities) without needing to submit your domain to a third party ([cyborux.com guide](https://www.cyborux.com/blog/tls-ssl-security-assessment-check-fix-grade)).
- **openssl s_client** provides quick manual handshake inspection for spot checks.
- **Security-header scanners:** securityheaders.io and the Mozilla Observatory check for the [OWASP-recommended baseline security headers](https://owasp.org/www-project-secure-headers/) — HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options (or CSP `frame-ancestors`), and the cross-origin trio COOP/COEP/CORP — per the [OWASP HTTP Security Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) and [OWASP HSTS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html); a comparison of checker tools is at [interssl.com](https://www.interssl.com/en/ssl-tools.php) and [sitesecurityscore.com](https://www.sitesecurityscore.com/learning-center/best-security-headers-checkers-compared).

### 6.4 Verify bypass paths are closed (direct origin IP, alternate hostnames, debug endpoints)

- **Confirm the origin is not directly reachable:** from a host *not* behind the CDN, attempt a direct connection to the known/suspected origin IP over 443 — it should time out or be refused, while the normal public hostname continues to resolve and respond normally through the CDN ([tigzig.com: verifying origin lockdown](https://www.tigzig.com/agents-faq/can-attackers-bypass-cloudflare-and-hit-my-server)).
- **Check for DNS leakage:** run `dig` against every known subdomain (mail, dev, staging, admin panels) to confirm none resolve directly to the origin outside the CDN-proxied path ([pentesting.se checklist](https://pentesting.se/en/blog/cloudflare-origin-bypass)); review historical DNS records via a service such as SecurityTrails for old A/AAAA records that may still point at the origin.
- **Check certificate transparency logs and internet-wide scan indexes** (Shodan, Censys) for your own origin's TLS certificate or banner leaking outside the CDN — the same technique defenders use to find their own exposure is documented (for authorized, defensive use against your own infrastructure) in tools like [BehindTheCDN](https://github.com/Loop-Man/BehindTheCDN), which explicitly supports a Censys-backed lookup mode.
- **Confirm Authenticated Origin Pulls / mTLS is enforced** between edge and origin, and that the origin firewall accepts inbound 443 only from the CDN's currently published IP ranges (re-verify after any provider range rotation) ([Indusface: Cloudflare origin protection limitations](https://www.indusface.com/blog/cloudflare-origin-protection-limitations/), [fixvibe.app checklist](https://www.fixvibe.app/lb/checks/platform-cloudflare)).
- **Inventory and close debug/legacy endpoints:** confirm no `/debug`, `/admin`, `/actuator`, `/.git`, or similar development artifacts are reachable in production, and that any staging-only routes are excluded from production builds.
- A structured defensive checklist combining all of the above bypass-verification steps is laid out at [pentesting.se: Why Cloudflare proxying alone isn't enough](https://pentesting.se/en/blog/cloudflare-origin-bypass) and [kbeezie.com: blocking direct-to-origin access with a cloud firewall](https://kbeezie.com/blocking-direct-to-origin-access-with-a-cloud-firewall).

### 6.5 Tooling summary (no exploit payloads)

| Purpose | Tool |
|---|---|
| Intercept/replay HTTP requests for manual authz testing | Burp Suite (Repeater, Intruder used for benign fuzzing of IDs/tokens, not payload delivery) |
| Free automated web app scanning | OWASP ZAP |
| Scripted API endpoint / status-code checks | Postman, curl |
| JWT inspection | jwt.io, jwt_tool |
| TLS configuration grading | Qualys SSL Labs, testssl.sh, openssl s_client |
| Security header checking | securityheaders.io, Mozilla Observatory |
| Origin-exposure discovery (defensive, own infrastructure) | Shodan, Censys, BehindTheCDN, SecurityTrails (historical DNS) |

Sources: [strobes.co](https://strobes.co/blog/web-application-penetration-testing-tools/), [cyberfortify.co](https://cyberfortify.co/blog/web-application-penetration-testing-tools), [OWASP WSTG — IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References), [OWASP WSTG — bypassing authorization schema](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema), [OWASP Authorization Regression Testing Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html), [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [OWASP Penetration Testing Kit](https://owasp.org/www-project-penetration-testing-kit/).

---

## Key Takeaway

Across every layer — network, application, edge, and device — the pattern that scales to a large, global, legitimate user base is the same: **stop authenticating the network path and start authenticating the identity.** IP allowlists, MAC binding, and geo-blocking all degrade predictably as an authorized population grows past a small, static set of known locations, because none of them cryptographically verify *who* or *what* is connecting. Identity-based Zero Trust — OIDC/SAML SSO, passkeys, mTLS, short-TTL signed tokens, RBAC/ABAC/ReBAC authorization, and device attestation, all enforced at an identity-aware edge/proxy layer with a locked-down origin — is what [NIST SP 800-207](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf) and every major cloud vendor's own architecture guidance (Cloudflare, AWS, Azure, Google Cloud) converge on as the correct model, and it is the only one of the two approaches that actually scales to millions of users worldwide.

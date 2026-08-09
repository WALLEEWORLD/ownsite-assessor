#!/usr/bin/env bash
# Optional: install a defensive recon stack for authorized self-tests.
# Designed for Debian/Ubuntu/Kali or WSL2. Review every package before use.
# Does NOT install exploit frameworks or weaponized payloads.
set -euo pipefail

echo "==> OwnSite optional recon stack installer"
echo "    Only run on machines you use for authorized testing of your own systems."
echo

if [[ "${1:-}" != "--i-am-authorized" ]]; then
  echo "Pass --i-am-authorized to continue."
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo required"
  exit 1
fi

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  nmap \
  whois \
  dnsutils \
  curl \
  wget \
  git \
  python3-pip \
  python3-venv \
  jq \
  openssl

# Optional Go-based ProjectDiscovery tools if go is present
if command -v go >/dev/null 2>&1; then
  echo "==> Installing ProjectDiscovery helpers via go install"
  export PATH="$PATH:$(go env GOPATH)/bin"
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true
  go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest || true
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  echo "Go tools installed to $(go env GOPATH)/bin"
  echo "Update nuclei templates with: nuclei -update-templates"
  echo "IMPORTANT: nuclei templates can include intrusive checks — use -severity info,low and scope carefully on your own assets only."
else
  echo "Go not found — skipped ProjectDiscovery tools. Install Go then re-run for httpx/nuclei/dnsx/tlsx/subfinder."
fi

# Optional: ZAP weekly (manual download recommended)
echo
echo "Recommended GUI proxies for manual authorized testing:"
echo "  - OWASP ZAP: https://www.zaproxy.org/download/"
echo "  - Burp Suite Community: https://portswigger.net/burp/communitydownload"
echo "  - Caido: https://caido.io/"
echo
echo "TLS deep checks:"
echo "  - testssl.sh: https://github.com/drwetter/testssl.sh"
echo "  - sslyze: pipx install sslyze"
echo
echo "Done."

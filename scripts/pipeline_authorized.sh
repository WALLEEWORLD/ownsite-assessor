#!/usr/bin/env bash
# Example authorized assessment pipeline chaining OwnSite Assessor with optional
# external tools (if installed). ONLY against assets you own.
set -euo pipefail

if [[ "${1:-}" == "" || "${2:-}" != "--i-am-authorized" ]]; then
  cat <<'EOF'
Usage:
  ./scripts/pipeline_authorized.sh <hostname> --i-am-authorized

Runs:
  1) OwnSite Assessor (Python suite in this repo)
  2) nmap (if installed) — version/service detect on common web ports only
  3) httpx (if installed) — tech/status probe
  4) nuclei (if installed) — severity info,low only, tags ssl,dns,http,misconfig
  5) testssl.sh (if installed) — TLS deep check

No credential attacks. No exploit modules.
EOF
  exit 1
fi

HOST="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/assessor/reports/pipeline_${HOST}_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

echo "[1/5] OwnSite Assessor"
bash "$ROOT/scripts/run_assessment.sh" --host "$HOST" --i-am-authorized --output-dir "$OUT"

if command -v nmap >/dev/null 2>&1; then
  echo "[2/5] nmap (web ports)"
  nmap -Pn -sV -p 80,443,8080,8443 --open -oA "$OUT/nmap_web" "$HOST" || true
else
  echo "[2/5] nmap not installed — skip"
fi

if command -v httpx >/dev/null 2>&1; then
  echo "[3/5] httpx"
  printf 'https://%s\nhttp://%s\n' "$HOST" "$HOST" \
    | httpx -silent -status-code -title -tech-detect -tls-grab -o "$OUT/httpx.txt" || true
else
  echo "[3/5] httpx not installed — skip"
fi

if command -v nuclei >/dev/null 2>&1; then
  echo "[4/5] nuclei (info,low only — still review templates before use)"
  nuclei -u "https://$HOST" \
    -severity info,low \
    -tags ssl,dns,http,misconfig,tech \
    -o "$OUT/nuclei.txt" || true
else
  echo "[4/5] nuclei not installed — skip"
fi

if command -v testssl.sh >/dev/null 2>&1; then
  echo "[5/5] testssl.sh"
  testssl.sh --quiet --logfile "$OUT/testssl.log" "https://$HOST" || true
elif [[ -x "$HOME/tools/testssl.sh/testssl.sh" ]]; then
  echo "[5/5] testssl.sh (local)"
  "$HOME/tools/testssl.sh/testssl.sh" --quiet --logfile "$OUT/testssl.log" "https://$HOST" || true
else
  echo "[5/5] testssl.sh not installed — skip"
fi

echo "Pipeline complete → $OUT"
ls -la "$OUT"

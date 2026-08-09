# OwnSite Assessor launcher (Windows PowerShell)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if (-not (Test-Path ".venv")) {
    python -m venv .venv
    & .\.venv\Scripts\Activate.ps1
    pip install -q -r requirements.txt
} else {
    & .\.venv\Scripts\Activate.ps1
}

python -m assessor.cli @args
exit $LASTEXITCODE

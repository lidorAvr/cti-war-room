# CTI War Room — launcher (Windows / PowerShell).
# Ensures a virtual environment + dependencies, then starts the Streamlit app.
#   .\run.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$venv = Join-Path $root ".venv"
$py = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $py)) {
    Write-Host "Creating virtual environment (.venv)..." -ForegroundColor Cyan
    $base = Get-Command python -ErrorAction SilentlyContinue
    if (-not $base) { throw "Python not found on PATH. Install Python 3.11+ and retry." }
    & $base.Source -m venv $venv
    & $py -m pip install --upgrade pip
}

Write-Host "Installing dependencies..." -ForegroundColor Cyan
& $py -m pip install --quiet -r (Join-Path $root "requirements.txt")

if (-not (Test-Path (Join-Path $root ".streamlit\secrets.toml"))) {
    Write-Host "No .streamlit\secrets.toml found - AI/enrichment will be disabled." -ForegroundColor Yellow
    Write-Host "  (copy .streamlit\secrets.toml.example to .streamlit\secrets.toml and add keys)" -ForegroundColor Yellow
}

Write-Host "Starting CTI War Room..." -ForegroundColor Green
& $py -m streamlit run (Join-Path $root "app.py")

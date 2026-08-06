# OwlEyeEngine Global Quick Installer for Windows PowerShell
Write-Host "🦉 Initializing OwlEyeEngine v3.0 Global Installation..." -ForegroundColor Cyan

# Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[X] Python is required but not installed in PATH." -ForegroundColor Red
    Exit 1
}

Write-Host "[+] Installing Python dependencies..." -ForegroundColor Green
python -m pip install -r requirements.txt

Write-Host "[+] Starting OwlEye Engine Service..." -ForegroundColor Green
python sentry.py

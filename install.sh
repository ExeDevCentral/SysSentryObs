#!/bin/bash
# OwlEyeEngine Global Quick Installer for Linux
set -e

echo "🦉 Initializing OwlEyeEngine v3.0 Global Installation..."

if [ "$EUID" -ne 0 ]; then
  echo "[!] Warning: Running as non-root. Active Defense (iptables/process kill) may require sudo privileges."
fi

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[X] Python 3 is required but not installed."
    exit 1
fi

echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt || pip install -r requirements.txt

echo "[+] Starting OwlEye Engine Service..."
python3 sentry.py

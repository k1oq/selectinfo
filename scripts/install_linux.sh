#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer targets Ubuntu/Debian systems with apt-get." >&2
  exit 1
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=()
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required when the installer is not run as root." >&2
    exit 1
  fi
  SUDO=(sudo)
fi

echo "[1/4] Installing Ubuntu/Debian system packages..."
"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y \
  git \
  nmap \
  python3 \
  python3-dev \
  python3-pip \
  python3-testresources \
  python3-venv

cd "$PROJECT_ROOT"

echo "[2/4] Installing project Python dependencies..."
"$PYTHON_BIN" -m pip install --upgrade pip setuptools wheel
"$PYTHON_BIN" -m pip install -r requirements.txt

echo "[3/4] Fixing executable permissions for Linux binaries..."
if [[ -f tools/subfinder/subfinder ]]; then
  chmod +x tools/subfinder/subfinder
fi
find tools/oneforall/thirdparty/massdns -maxdepth 1 -type f -name 'massdns_linux_*' -exec chmod +x {} + 2>/dev/null || true

if [[ -f config/local_settings.json ]]; then
  echo "Found config/local_settings.json."
  echo "This file is host-local. If it was copied from Windows, reset stale tool paths before deployment."
fi

echo "[4/4] Running tool self-check..."
"$PYTHON_BIN" tools/self_check.py

echo "Linux install completed."
echo "Next steps:"
echo "  edit config/local_settings.json if you need local tool path overrides"
echo "  python tools/self_check.py"
echo "  python scan.py example.com --port-scan --web-fingerprint"
echo "  python -m unittest discover -s tests -p \"test_*.py\" -v"
echo "  python main.py"

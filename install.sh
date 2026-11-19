#!/usr/bin/env bash
set -euo pipefail

# One-step installer for angry-cli (`ipscan`) on Linux/macOS servers.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v java >/dev/null 2>&1; then
    echo "Error: Java 21+ is required. Install with: sudo apt install openjdk-21-jdk" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3.10+ is required." >&2
    exit 1
fi

cd "$REPO_DIR"
python3 -m pip install --user --break-system-packages --no-build-isolation -e . 2>/dev/null \
    || python3 -m pip install --user --no-build-isolation -e . \
    || python3 -m pip install --user --break-system-packages --no-deps --no-build-isolation -e .

export PATH="$HOME/.local/bin:$PATH"
echo "Installed: $(command -v ipscan)"
ipscan --version
ipscan backend verify

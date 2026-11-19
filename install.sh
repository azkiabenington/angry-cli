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

# Ensure ~/.local/bin is persisted in shell startup files
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && ! grep -qs '\.local/bin' "$rc"; then
        printf '\n# Added by angry-cli installer\n%s\n' "$PATH_LINE" >> "$rc"
    fi
done

export PATH="$HOME/.local/bin:$PATH"
echo ""
echo "Installed: $(command -v ipscan)"
ipscan --version
ipscan backend verify
echo ""
echo "Ready! If 'ipscan' is not found in your current terminal, run:"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
echo "Try your first scan:"
echo "  ipscan quick 127.0.0.1 --profile quick-ping"
echo "  ipscan quick 192.168.1.0/24 --profile lan-audit --alive-only"

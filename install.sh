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

LOCAL_BIN="$HOME/.local/bin/ipscan"
if [ ! -x "$LOCAL_BIN" ]; then
    echo "Error: Expected installed binary not found at $LOCAL_BIN" >&2
    exit 1
fi

# Ensure ~/.local/bin is prepended in shell startup files
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && ! grep -qs '\.local/bin' "$rc"; then
        printf '\n# Added by angry-cli installer\n%s\n' "$PATH_LINE" >> "$rc"
    fi
done

# Override /usr/bin/ipscan (desktop Angry IP Scanner GUI) via /usr/local/bin/ipscan
LINKED_GLOBAL=0
if [ -w "/usr/local/bin" ]; then
    ln -sf "$LOCAL_BIN" /usr/local/bin/ipscan && LINKED_GLOBAL=1
elif [ -x "/usr/bin/ipscan" ] || [ "${1:-}" = "--global" ]; then
    echo ""
    echo "Notice: Found existing desktop GUI binary at /usr/bin/ipscan."
    echo "Linking /usr/local/bin/ipscan -> $LOCAL_BIN so 'ipscan' runs angry-cli (headless) first..."
    if command -v sudo >/dev/null 2>&1 && sudo ln -sf "$LOCAL_BIN" /usr/local/bin/ipscan; then
        LINKED_GLOBAL=1
    else
        echo "Warning: Could not create /usr/local/bin/ipscan symlink automatically."
    fi
fi

export PATH="$HOME/.local/bin:$PATH"
echo ""
echo "Installed: $LOCAL_BIN"
if [ "$LINKED_GLOBAL" -eq 1 ]; then
    echo "Global symlink: /usr/local/bin/ipscan -> $LOCAL_BIN"
fi
"$LOCAL_BIN" --version
"$LOCAL_BIN" backend verify
echo ""
echo "IMPORTANT — Refresh your current shell cache before running 'ipscan':"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\" && hash -r 2>/dev/null || rehash"
if [ -x "/usr/bin/ipscan" ] && [ "$LINKED_GLOBAL" -eq 0 ]; then
    echo ""
    echo "Or link globally so 'ipscan' overrides desktop /usr/bin/ipscan in all shells:"
    echo "  sudo ln -sf \"$LOCAL_BIN\" /usr/local/bin/ipscan && hash -r 2>/dev/null || rehash"
fi
echo ""
echo "Try your first scan:"
echo "  ipscan quick 127.0.0.1 --profile quick-ping"
echo "  ipscan quick 192.168.1.0/24 --profile lan-audit --alive-only"

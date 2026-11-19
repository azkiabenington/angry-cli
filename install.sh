#!/usr/bin/env bash

# One-step installer for angry-cli (`ipscan`) on Linux/macOS.
# - Works with or without `pip` / `setuptools` installed.
# - Links `/usr/local/bin/ipscan` by default so `ipscan` works immediately in the
#   current terminal without needing `export PATH` (pass `--user-only` to skip).
# - Also safe to run with `source install.sh` in both bash and zsh.

_angry_cli_is_sourced() {
    if [ -n "${ZSH_VERSION:-}" ]; then
        case "${ZSH_EVAL_CONTEXT:-}" in *:file*) return 0 ;; esac
        return 1
    elif [ -n "${BASH_VERSION:-}" ]; then
        [ "${BASH_SOURCE[0]}" != "$0" ]
        return $?
    fi
    return 1
}

_angry_cli_install() {
    local USER_ONLY=0
    local arg
    for arg in "$@"; do
        case "$arg" in
            --user-only) USER_ONLY=1 ;;
            --global)    USER_ONLY=0 ;;
        esac
    done

    local SCRIPT_PATH=""
    if [ -n "${ZSH_VERSION:-}" ]; then
        SCRIPT_PATH="$(eval 'printf "%s" "${(%):-%N}"')"
    elif [ -n "${BASH_VERSION:-}" ]; then
        SCRIPT_PATH="${BASH_SOURCE[0]}"
    else
        SCRIPT_PATH="$0"
    fi
    local REPO_DIR
    REPO_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

    if ! command -v java >/dev/null 2>&1; then
        echo "Error: Java 11+ is required. Install with: sudo apt install -y openjdk-11-jdk (or openjdk-21-jdk)" >&2
        return 1
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: Python 3.6+ is required." >&2
        return 1
    fi

    mkdir -p "$HOME/.local/bin"
    local LOCAL_BIN="$HOME/.local/bin/ipscan"
    local INSTALL_MODE=""

    # 1. Try pip editable install if pip is available
    if python3 -m pip --version >/dev/null 2>&1; then
        if (cd "$REPO_DIR" && (
            python3 -m pip install --user --break-system-packages --no-build-isolation -e . 2>/dev/null \
            || python3 -m pip install --user --no-build-isolation -e . 2>/dev/null \
            || python3 -m pip install --user --break-system-packages --no-deps --no-build-isolation -e . 2>/dev/null \
            || python3 -m pip install --user --no-deps --no-build-isolation -e . 2>/dev/null
        )); then
            INSTALL_MODE="pip"
        fi
    fi

    # 2. Zero-pip fallback: ensure `click` is available and create direct launcher shim
    if [ -z "$INSTALL_MODE" ] || [ ! -x "$LOCAL_BIN" ]; then
        echo "pip not available (or editable install skipped) — using direct zero-pip launcher mode."
        if ! python3 -c "import click" >/dev/null 2>&1; then
            echo "Python 'click' module not found — attempting to install python3-click via apt..."
            if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
                sudo apt-get update -qq && sudo apt-get install -y python3-click || true
            fi
        fi

        if ! python3 -c "import click" >/dev/null 2>&1; then
            echo "Error: Python 'click' package is required." >&2
            echo "Install it with: sudo apt install -y python3-click" >&2
            return 1
        fi

        cat > "$LOCAL_BIN" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$REPO_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m angry_cli "\$@"
EOF
        chmod +x "$LOCAL_BIN"
        INSTALL_MODE="direct-launcher"
    fi

    # 3. Persist ~/.local/bin in shell startup files (~/.bashrc and ~/.zshrc)
    local PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
    local rc
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ] && ! grep -qs '\.local/bin' "$rc"; then
            printf '\n# Added by angry-cli installer\n%s\n' "$PATH_LINE" >> "$rc"
        fi
    done

    # 4. Symlink into /usr/local/bin/ipscan by default so `ipscan` works IMMEDIATELY
    #    in the current shell (no `export PATH` needed) and overrides desktop /usr/bin/ipscan.
    local LINKED_GLOBAL=0
    if [ "$USER_ONLY" -eq 0 ] && [ -d "/usr/local/bin" ]; then
        if [ -w "/usr/local/bin" ]; then
            ln -sf "$LOCAL_BIN" /usr/local/bin/ipscan && LINKED_GLOBAL=1
        elif command -v sudo >/dev/null 2>&1; then
            echo "Linking /usr/local/bin/ipscan -> $LOCAL_BIN (so 'ipscan' works immediately in this shell)..."
            if sudo ln -sf "$LOCAL_BIN" /usr/local/bin/ipscan; then
                LINKED_GLOBAL=1
            else
                echo "Warning: Skipped /usr/local/bin/ipscan symlink (sudo unavailable or cancelled)."
            fi
        fi
    fi

    # 5. If sourced, also refresh PATH and command hash directly in the active shell
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) export PATH="$HOME/.local/bin:$PATH" ;;
    esac
    if [ -n "${ZSH_VERSION:-}" ]; then
        rehash 2>/dev/null || true
    else
        hash -r 2>/dev/null || true
    fi

    echo ""
    echo "Installed ($INSTALL_MODE): $LOCAL_BIN"
    if [ "$LINKED_GLOBAL" -eq 1 ]; then
        echo "Global link: /usr/local/bin/ipscan -> $LOCAL_BIN"
    fi
    "$LOCAL_BIN" --version
    "$LOCAL_BIN" backend verify || return 1

    echo ""
    if [ "$LINKED_GLOBAL" -eq 1 ] || _angry_cli_is_sourced; then
        echo "Ready! Run your first scan immediately:"
        echo "  ipscan quick 127.0.0.1 --profile quick-ping"
        echo "  ipscan quick 192.168.1.0/24 --profile lan-audit --alive-only"
    else
        echo "Run once in this shell to activate PATH (or re-run with 'source install.sh'):"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\" && hash -r 2>/dev/null || rehash"
    fi
}

if _angry_cli_is_sourced; then
    _angry_cli_install "$@"
else
    set -euo pipefail
    _angry_cli_install "$@"
fi

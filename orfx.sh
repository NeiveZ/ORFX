#!/usr/bin/env bash
# ORFX - Offensive Recon Framework
# Author: NeiveZ | github.com/NeiveZ/ORFX

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

ok()   { echo -e "  ${GREEN}[+]${RESET} $*"; }
err()  { echo -e "  ${RED}[-]${RESET} $*"; }
info() { echo -e "  ${CYAN}[*]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; }

check_python() {
    command -v "$PYTHON" &>/dev/null || { err "Python 3 not found. Install: https://www.python.org"; exit 1; }
    PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if "$PYTHON" -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
        ok "Python $PY_VER detected"
    else
        warn "Python $PY_VER detected — ORFX recommends Python 3.10+"
    fi
}

check_deps() {
    info "Checking optional system tools..."
    for tool in whois dig nslookup; do
        command -v "$tool" &>/dev/null \
            && ok "$tool found" \
            || warn "$tool not found (some modules may have limited functionality)"
    done
}

install_python_deps() {
    info "Installing Python dependencies..."
    for pkg in python-whois; do
        if "$PYTHON" -c "import ${pkg//-/_}" &>/dev/null 2>&1; then
            ok "$pkg already installed"
        else
            info "Installing $pkg..."
            "$PYTHON" -m pip install "$pkg" --quiet --break-system-packages 2>/dev/null \
                || "$PYTHON" -m pip install "$pkg" --quiet 2>/dev/null \
                || warn "Could not install $pkg (optional)"
        fi
    done
}

create_dirs() {
    mkdir -p "$SCRIPT_DIR/reports" "$SCRIPT_DIR/wordlists"
    ok "Directory structure verified"
}

run_tool() {
    cd "$SCRIPT_DIR"
    exec "$PYTHON" orfx.py "$@"
}

case "${1:-}" in
    --install|-i)
        echo -e "\n${BOLD}${RED}ORFX Installer${RESET}\n"
        check_python
        check_deps
        install_python_deps
        create_dirs
        chmod +x "$SCRIPT_DIR/orfx.py" 2>/dev/null || true
        echo
        ok "Installation complete."
        info "Run with: ${CYAN}./orfx.sh${RESET}"
        echo
        ;;
    --check)
        check_python
        check_deps
        ;;
    --help|-h)
        echo -e """
${BOLD}${RED}ORFX${RESET} — Offensive Recon Framework

${BOLD}Usage:${RESET}
  ./orfx.sh             Launch interactive shell
  ./orfx.sh --install   Install dependencies
  ./orfx.sh --check     Check system dependencies
  ./orfx.sh --help      Show this help
"""
        ;;
    *)
        check_python
        create_dirs
        run_tool "$@"
        ;;
esac

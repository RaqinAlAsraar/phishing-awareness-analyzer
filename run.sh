#!/usr/bin/env bash
# ==============================================================================
# Phishing Awareness Analyzer - Fast Launcher
# Author: Ali Abbas Haidar (Raqin Al-Asraar)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source ".venv/bin/activate"
    exec python main.py "$@"
else
    exec python3 main.py "$@"
fi

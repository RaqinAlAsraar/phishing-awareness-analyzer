#!/usr/bin/env bash
# ==============================================================================
# Phishing Awareness Analyzer - Linux Setup & Auto-Configuration Script
# Cybersecurity Batch 01 - Task 2
# Author: Ali Abbas Haidar (Raqin Al-Asraar) | @raqinalasraar
# Email: aliabbashaidar313@gmail.com
# ==============================================================================

set -e

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}   Phishing Awareness Analyzer - Setup & Environment Initializer${NC}"
echo -e "${CYAN}   Cybersecurity Internship - Batch 01 - Task 2${NC}"
echo -e "${CYAN}   Author: Ali Abbas Haidar (Raqin Al-Asraar) | @raqinalasraar${NC}"
echo -e "${CYAN}======================================================================${NC}"

# 1. OS Verification
OS_NAME="Linux"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_NAME="$PRETTY_NAME"
else
    DISTRO_NAME="$(uname -s) $(uname -r)"
fi
echo -e "${BLUE}[*] Detected Linux Distribution:${NC} ${DISTRO_NAME}"

# 2. Python 3 Check
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Error: python3 is not installed.${NC}"
    echo -e "${YELLOW}[*] Please install Python 3 using your package manager:${NC}"
    echo -e "    Debian/Ubuntu/Kali: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
    echo -e "    Arch/Manjaro:       sudo pacman -S python python-pip"
    echo -e "    Fedora/RHEL:        sudo dnf install -y python3 python3-pip"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[✓] Found Python ${PY_VER}${NC}"

# 3. Virtual Environment Management
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${BLUE}[*] Creating Python virtual environment in .venv/...${NC}"
    python3 -m venv "$VENV_DIR" || {
        echo -e "${YELLOW}[!] Failed to create venv using 'python3 -m venv'. Trying with system pip...${NC}"
    }
fi

if [ -f "$VENV_DIR/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    PYTHON_EXEC="$VENV_DIR/bin/python"
    PIP_EXEC="$VENV_DIR/bin/pip"
    echo -e "${GREEN}[✓] Virtual environment activated (.venv)${NC}"
else
    PYTHON_EXEC="python3"
    PIP_EXEC="pip3"
fi

# 4. Dependency Installation
echo -e "${BLUE}[*] Checking and installing dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    "$PIP_EXEC" install -q --upgrade pip 2>/dev/null || true
    "$PIP_EXEC" install -q -r requirements.txt 2>/dev/null || {
        echo -e "${YELLOW}[!] pip install requirements had warnings or used system packages. Core engine is stdlib-based.${NC}"
    }
    echo -e "${GREEN}[✓] Dependencies verified.${NC}"
fi

# 5. Routing Actions
if [ "$1" == "--test" ]; then
    echo -e "${CYAN}[*] Running Automated Unit Test Suite...${NC}"
    "$PYTHON_EXEC" -m unittest discover -s tests -v
    exit 0
elif [ "$1" == "--corpus" ]; then
    echo -e "${CYAN}[*] Running Benchmark Suite across Synthetic Corpus...${NC}"
    "$PYTHON_EXEC" main.py --corpus
    exit 0
elif [ "$1" == "--cli" ]; then
    echo -e "${CYAN}[*] Launching CLI Console...${NC}"
    "$PYTHON_EXEC" main.py --cli
    exit 0
elif [ "$1" == "--qt" ]; then
    echo -e "${CYAN}[*] Launching Native PyQt6 Desktop GUI...${NC}"
    "$PYTHON_EXEC" main.py --qt
    exit 0
fi

# Default: Launch modern Desktop Web GUI
echo -e "${GREEN}[✓] Setup complete! Launching Phishing Awareness Analyzer...${NC}"
"$PYTHON_EXEC" main.py "$@"

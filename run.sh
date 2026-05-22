#!/usr/bin/env bash
# =============================================================================
#  NetWatch - Universal Auto-Setup & Launch Script
#  Supports: Linux (x86_64, ARM64, ARMv7), macOS (Intel & Apple Silicon)
#  Usage: bash run.sh   OR   ./run.sh
# =============================================================================

set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${CYAN}"
cat << 'EOF'
███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
EOF
echo -e "${RESET}"
echo -e "${BOLD}      Network Traffic Monitoring & Detection | Auto-Setup v2.0${RESET}"
echo "════════════════════════════════════════════════════════════════════════"

# ── Detect OS & Architecture ──────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected OS: ${BOLD}${OS}${RESET}  |  Architecture: ${BOLD}${ARCH}${RESET}"

# ── Script Directory ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
info "Working directory: $SCRIPT_DIR"

# ── Check Root / Sudo ─────────────────────────────────────────────────────────
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        SUDO=""
    elif command -v sudo &>/dev/null; then
        SUDO="sudo"
        warn "NetWatch needs root for packet sniffing. You may be prompted for your password."
    else
        error "Root privileges required but 'sudo' not found. Please run as root: sudo bash run.sh"
    fi
}

# ── Install System Dependencies ───────────────────────────────────────────────
install_system_deps() {
    info "Checking system package manager..."

    # macOS
    if [ "$OS" = "Darwin" ]; then
        if ! command -v brew &>/dev/null; then
            warn "Homebrew not found. Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            # Add brew to PATH for Apple Silicon
            if [ "$ARCH" = "arm64" ]; then
                eval "$(/opt/homebrew/bin/brew shellenv)"
            fi
        fi
        success "Homebrew found: $(brew --version | head -1)"

        # Ensure libpcap is available (needed by scapy)
        if ! brew list libpcap &>/dev/null 2>&1; then
            info "Installing libpcap via Homebrew..."
            brew install libpcap
        else
            success "libpcap already installed."
        fi
        return
    fi

    # Linux — detect package manager
    if command -v apt-get &>/dev/null; then
        info "Using APT (Debian/Ubuntu/Raspberry Pi OS)..."
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq python3 python3-pip python3-venv \
            libpcap-dev libpcap0.8 tcpdump curl 2>/dev/null || true

    elif command -v dnf &>/dev/null; then
        info "Using DNF (Fedora/RHEL/Rocky)..."
        $SUDO dnf install -y python3 python3-pip libpcap libpcap-devel tcpdump curl 2>/dev/null || true

    elif command -v yum &>/dev/null; then
        info "Using YUM (CentOS/RHEL)..."
        $SUDO yum install -y python3 python3-pip libpcap libpcap-devel tcpdump curl 2>/dev/null || true

    elif command -v pacman &>/dev/null; then
        info "Using Pacman (Arch Linux/Manjaro)..."
        $SUDO pacman -Sy --noconfirm python python-pip libpcap tcpdump curl 2>/dev/null || true

    elif command -v zypper &>/dev/null; then
        info "Using Zypper (openSUSE)..."
        $SUDO zypper install -y python3 python3-pip libpcap-devel tcpdump curl 2>/dev/null || true

    elif command -v apk &>/dev/null; then
        info "Using APK (Alpine Linux)..."
        $SUDO apk add --no-cache python3 py3-pip libpcap-dev tcpdump curl 2>/dev/null || true

    else
        warn "Unknown package manager. Skipping system package installation."
        warn "Make sure python3, pip3, and libpcap are installed manually."
    fi
}

# ── Find Python ───────────────────────────────────────────────────────────────
find_python() {
    PYTHON=""
    for cmd in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            VER=$("$cmd" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
            MAJOR=$("$cmd" -c "import sys; print(sys.version_info[0])" 2>/dev/null)
            MINOR=$("$cmd" -c "import sys; print(sys.version_info[1])" 2>/dev/null)
            if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
                PYTHON="$cmd"
                success "Found Python: $PYTHON ($VER)"
                return
            fi
        fi
    done
    error "Python 3.10+ not found! Please install Python 3.10 or newer."
}

# ── Setup Virtual Environment ─────────────────────────────────────────────────
setup_venv() {
    VENV_DIR="$SCRIPT_DIR/.venv"

    if [ ! -d "$VENV_DIR" ]; then
        info "Creating Python virtual environment..."
        $PYTHON -m venv "$VENV_DIR"
        success "Virtual environment created at: $VENV_DIR"
    else
        success "Virtual environment already exists."
    fi

    # Activate venv
    source "$VENV_DIR/bin/activate"
    PYTHON="$VENV_DIR/bin/python"
    PIP="$VENV_DIR/bin/pip"
}

# ── Install Python Dependencies ───────────────────────────────────────────────
install_python_deps() {
    info "Upgrading pip..."
    $PIP install --upgrade pip -q

    if [ -f "requirements.txt" ]; then
        info "Installing from requirements.txt..."
        $PIP install -r requirements.txt -q
        success "All Python dependencies installed!"
    else
        warn "requirements.txt not found. Installing defaults: flask scapy pyfiglet"
        $PIP install flask scapy pyfiglet -q
        success "Default dependencies installed!"
    fi
}

# ── Verify Imports ────────────────────────────────────────────────────────────
verify_imports() {
    info "Verifying Python imports..."
    $PYTHON -c "import flask; import scapy; print('  flask ✓  scapy ✓')" 2>/dev/null \
        && success "All imports verified!" \
        || error "Import verification failed. Check errors above."
}

# ── Launch NetWatch ───────────────────────────────────────────────────────────
launch() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════"
    success "Setup complete! Launching NetWatch..."
    echo -e "${YELLOW}  → Dashboard will be available at: ${BOLD}http://127.0.0.1:5000${RESET}"
    echo -e "${YELLOW}  → Press Ctrl+C to stop.${RESET}"
    echo "════════════════════════════════════════════════════════════════════════"
    echo ""

    # Run with sudo (required for raw socket / packet sniffing)
    if [ "$EUID" -eq 0 ]; then
        $PYTHON netwatch.py
    else
        $SUDO "$PYTHON" netwatch.py
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    check_sudo
    install_system_deps
    find_python
    setup_venv
    install_python_deps
    verify_imports
    launch
}

main

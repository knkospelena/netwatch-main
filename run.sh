#!/usr/bin/env bash
# =============================================================================
#  NetWatch - Bulletproof Universal Auto-Setup & Launch Script v3.0
#  Supports: Linux (x86_64, ARM64, ARMv7), macOS (Intel & Apple Silicon)
#  Usage:    bash run.sh   OR   ./run.sh
#  NOTE:     NO set -e  — every error is handled gracefully, script never
#            exits unexpectedly. Falls back at each step to keep running.
# =============================================================================

# ── Colors (safe fallback if terminal has no color) ──────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
fatal()   { echo -e "${RED}[✗ FATAL]${RESET} $*"; echo ""; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${CYAN}"
cat << 'BANNER'
███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
BANNER
echo -e "${RESET}"
echo -e "${BOLD}      Network Traffic Monitoring & Detection | Auto-Setup v3.0${RESET}"
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# ── Globals ───────────────────────────────────────────────────────────────────
OS="$(uname -s 2>/dev/null || echo "Unknown")"
ARCH="$(uname -m 2>/dev/null || echo "unknown")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
PYTHON=""
PIP=""
SUDO=""

info "Detected OS   : ${BOLD}${OS}${RESET}  |  Architecture: ${BOLD}${ARCH}${RESET}"
info "Project folder: ${SCRIPT_DIR}"

# Guard: make sure we can cd into the project dir
cd "${SCRIPT_DIR}" 2>/dev/null || fatal "Cannot access project directory: ${SCRIPT_DIR}"

# =============================================================================
# STEP 1 — Privilege Check
# =============================================================================
step_check_sudo() {
    info "Step 1/6 — Checking privileges..."
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        SUDO=""
        success "Running as root."
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        warn "Root needed for packet sniffing — you may be asked for your password."
    else
        warn "sudo not found and not root. Packet sniffing may fail."
        warn "If it fails, re-run as: sudo bash run.sh"
        SUDO=""
    fi
}

# =============================================================================
# STEP 2 — System Package Installation
# =============================================================================
step_system_deps() {
    info "Step 2/6 — Installing system dependencies..."

    # ── macOS ──────────────────────────────────────────────────────────────────
    if [ "${OS}" = "Darwin" ]; then
        # Ensure Homebrew is available
        if ! command -v brew >/dev/null 2>&1; then
            warn "Homebrew not found. Attempting to install..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" 2>/dev/null || {
                warn "Homebrew install failed — will continue without it."
                return
            }
            # Add brew to PATH for Apple Silicon
            [ "${ARCH}" = "arm64" ] && eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null)" 2>/dev/null || true
            [ "${ARCH}" = "x86_64" ] && eval "$(/usr/local/bin/brew shellenv 2>/dev/null)" 2>/dev/null || true
        fi
        success "Homebrew: $(brew --version 2>/dev/null | head -1 || echo 'found')"

        # libpcap for scapy
        if ! brew list libpcap >/dev/null 2>&1; then
            info "Installing libpcap..."
            brew install libpcap 2>/dev/null || warn "libpcap install failed — scapy may still work with system libpcap."
        else
            success "libpcap already installed."
        fi
        return
    fi

    # ── Linux ──────────────────────────────────────────────────────────────────
    if command -v apt-get >/dev/null 2>&1; then
        info "Package manager: APT (Debian / Ubuntu / Kali / Raspberry Pi OS)"
        ${SUDO} apt-get update -qq 2>/dev/null || warn "apt-get update failed — continuing anyway."

        # Install each package separately so one failure doesn't block others
        for pkg in python3 python3-pip python3-venv python3-dev \
                   libpcap-dev libpcap0.8 tcpdump curl build-essential; do
            ${SUDO} apt-get install -y -qq "${pkg}" 2>/dev/null || \
                warn "Could not install ${pkg} — skipping."
        done

    elif command -v dnf >/dev/null 2>&1; then
        info "Package manager: DNF (Fedora / RHEL / Rocky)"
        for pkg in python3 python3-pip python3-devel libpcap libpcap-devel tcpdump curl gcc; do
            ${SUDO} dnf install -y -q "${pkg}" 2>/dev/null || warn "Could not install ${pkg} — skipping."
        done

    elif command -v yum >/dev/null 2>&1; then
        info "Package manager: YUM (CentOS / RHEL)"
        for pkg in python3 python3-pip libpcap libpcap-devel tcpdump curl gcc; do
            ${SUDO} yum install -y -q "${pkg}" 2>/dev/null || warn "Could not install ${pkg} — skipping."
        done

    elif command -v pacman >/dev/null 2>&1; then
        info "Package manager: Pacman (Arch / Manjaro / BlackArch)"
        ${SUDO} pacman -Sy --noconfirm python python-pip libpcap tcpdump curl 2>/dev/null || \
            warn "Pacman install had issues — continuing."

    elif command -v zypper >/dev/null 2>&1; then
        info "Package manager: Zypper (openSUSE)"
        for pkg in python3 python3-pip python3-devel libpcap-devel tcpdump curl; do
            ${SUDO} zypper install -y -q "${pkg}" 2>/dev/null || warn "Could not install ${pkg} — skipping."
        done

    elif command -v apk >/dev/null 2>&1; then
        info "Package manager: APK (Alpine Linux)"
        ${SUDO} apk add --no-cache python3 py3-pip libpcap-dev tcpdump curl 2>/dev/null || \
            warn "APK install had issues — continuing."

    else
        warn "No recognised package manager found."
        warn "Make sure python3, pip3, and libpcap are installed manually."
    fi

    success "System dependency step complete."
}

# =============================================================================
# STEP 3 — Find Python (3.8+ acceptable, 3.10+ preferred)
# =============================================================================
step_find_python() {
    info "Step 3/6 — Locating Python interpreter..."
    PYTHON=""

    # Try newest first, down to 3.8 as absolute minimum for scapy+flask
    for cmd in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
        if command -v "${cmd}" >/dev/null 2>&1; then
            _major=$("${cmd}" -c "import sys; print(sys.version_info[0])" 2>/dev/null || echo "0")
            _minor=$("${cmd}" -c "import sys; print(sys.version_info[1])" 2>/dev/null || echo "0")
            _ver=$("${cmd}" --version 2>&1 | head -1)

            if [ "${_major}" -ge 3 ] && [ "${_minor}" -ge 8 ] 2>/dev/null; then
                PYTHON="${cmd}"
                if [ "${_minor}" -lt 10 ]; then
                    warn "Python ${_ver} found — 3.10+ is recommended but we'll try with this."
                else
                    success "Python found: ${_ver}"
                fi
                return
            fi
        fi
    done

    fatal "Python 3.8+ not found. Install it with:
  Debian/Ubuntu : sudo apt-get install python3
  Arch/Kali     : sudo pacman -S python
  Fedora        : sudo dnf install python3
  macOS         : brew install python
  Or download   : https://python.org/downloads/"
}

# =============================================================================
# STEP 4 — Virtual Environment (auto-recreate if broken)
# =============================================================================
step_setup_venv() {
    info "Step 4/6 — Setting up virtual environment..."

    # Check if existing venv is healthy (check both python AND pip)
    if [ -d "${VENV_DIR}" ]; then
        if "${VENV_DIR}/bin/python" -c "import sys" >/dev/null 2>&1; then
            success "Existing virtual environment is healthy."
        else
            warn "Virtual environment appears broken — recreating..."
            rm -rf "${VENV_DIR}"
        fi
    fi

    if [ ! -d "${VENV_DIR}" ]; then
        info "Creating new virtual environment..."

        # Method 1: python -m venv (standard)
        if "${PYTHON}" -m venv "${VENV_DIR}" 2>/dev/null; then
            success "Virtual environment created (venv)."

        # Method 2: python -m venv --without-pip then bootstrap pip manually
        elif "${PYTHON}" -m venv --without-pip "${VENV_DIR}" 2>/dev/null; then
            warn "Created venv without pip — will bootstrap pip separately."

        # Method 3: install python3-venv via apt and retry
        elif command -v apt-get >/dev/null 2>&1; then
            warn "venv failed — installing python3-venv system package..."
            ${SUDO} apt-get install -y -qq python3-venv python3-full 2>/dev/null || true
            "${PYTHON}" -m venv "${VENV_DIR}" 2>/dev/null || \
                fatal "Cannot create virtual environment. Run: sudo apt install python3-venv"

        # Method 4: virtualenv fallback
        elif command -v virtualenv >/dev/null 2>&1; then
            warn "Falling back to virtualenv..."
            virtualenv -p "${PYTHON}" "${VENV_DIR}" 2>/dev/null || \
                fatal "Could not create virtual environment."
        else
            fatal "Cannot create virtual environment. Try: sudo apt install python3-venv"
        fi
    fi

    # Activate venv
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate" 2>/dev/null || \
        fatal "Cannot activate virtual environment at ${VENV_DIR}"

    # Always use 'python -m pip' — more reliable than the pip binary
    PYTHON="${VENV_DIR}/bin/python"
    PIP="${PYTHON} -m pip"
    success "Virtual environment active: ${VENV_DIR}"
}

# =============================================================================
# STEP 5 — Python Package Installation (multi-method, bulletproof)
# =============================================================================

# pip_install <pkg>  — tries multiple methods until one works
pip_install() {
    local pkg="$1"
    local base="${pkg%%[>=<!]*}"

    # Method A: python -m pip (most reliable, bypasses broken pip binary)
    if ${PIP} install "${pkg}" --quiet 2>/dev/null; then
        return 0
    fi

    # Method B: --break-system-packages (needed on Debian/Kali PEP 668 systems)
    if ${PIP} install "${pkg}" --break-system-packages --quiet 2>/dev/null; then
        warn "  Installed ${pkg} with --break-system-packages."
        return 0
    fi

    # Method C: no cache + trusted host (helps with SSL / cache corruption)
    if ${PIP} install "${pkg}" --no-cache-dir \
        --trusted-host pypi.org --trusted-host files.pythonhosted.org \
        --quiet 2>/dev/null; then
        warn "  Installed ${pkg} via no-cache trusted-host."
        return 0
    fi

    # Method D: bare package name without version pin
    if [ "${base}" != "${pkg}" ]; then
        if ${PIP} install "${base}" --break-system-packages --quiet 2>/dev/null; then
            warn "  Installed ${base} (version pin dropped)."
            return 0
        fi
    fi

    warn "  Could not install ${pkg} — skipping."
    return 1
}

# Bootstrap pip if it's missing from the venv
ensure_pip() {
    if ! ${PIP} --version >/dev/null 2>&1; then
        warn "pip not found in venv — bootstrapping with ensurepip..."
        "${PYTHON}" -m ensurepip --upgrade 2>/dev/null || true
        "${PYTHON}" -m ensurepip 2>/dev/null || true
    fi

    # Still not working? Download get-pip.py as last resort
    if ! ${PIP} --version >/dev/null 2>&1; then
        warn "ensurepip failed — downloading get-pip.py..."
        local getpip_tmp
        getpip_tmp="$(mktemp /tmp/get-pip-XXXXXX.py 2>/dev/null || echo /tmp/get-pip.py)"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "${getpip_tmp}" 2>/dev/null
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "${getpip_tmp}" https://bootstrap.pypa.io/get-pip.py 2>/dev/null
        fi
        if [ -f "${getpip_tmp}" ] && [ -s "${getpip_tmp}" ]; then
            "${PYTHON}" "${getpip_tmp}" --quiet 2>/dev/null || true
            rm -f "${getpip_tmp}"
        fi
    fi

    if ${PIP} --version >/dev/null 2>&1; then
        success "pip is ready: $(${PIP} --version 2>/dev/null | head -1)"
    else
        warn "pip could not be bootstrapped — installs may fail."
    fi
}

step_install_packages() {
    info "Step 5/6 — Installing Python packages..."

    # Make sure pip is present first
    ensure_pip

    # Upgrade pip (non-fatal)
    ${PIP} install --upgrade pip --quiet 2>/dev/null || \
        ${PIP} install --upgrade pip --break-system-packages --quiet 2>/dev/null || \
        warn "pip upgrade skipped."

    # Install from requirements.txt if present, otherwise use defaults
    if [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
        info "Found requirements.txt — installing packages..."

        # Try batch install first (fastest)
        if ${PIP} install -r "${SCRIPT_DIR}/requirements.txt" \
            --break-system-packages --quiet 2>/dev/null; then
            success "All packages installed from requirements.txt."
        elif ${PIP} install -r "${SCRIPT_DIR}/requirements.txt" \
            --no-cache-dir --trusted-host pypi.org \
            --trusted-host files.pythonhosted.org --quiet 2>/dev/null; then
            success "All packages installed (no-cache fallback)."
        else
            warn "Batch install failed — installing one by one..."
            while IFS= read -r line || [ -n "${line}" ]; do
                [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
                [[ "${line}" =~ ^# ]] && continue
                pkg="${line%%#*}"
                pkg="${pkg//[[:space:]]/}"
                [ -z "${pkg}" ] && continue
                pip_install "${pkg}" && success "  Installed: ${pkg%%[>=<!]*}"
            done < "${SCRIPT_DIR}/requirements.txt"
        fi
    else
        warn "requirements.txt not found — installing defaults: flask scapy"
        pip_install flask && pip_install scapy
    fi

    # Final import check
    info "Verifying critical imports..."
    MISSING=""
    for mod in flask scapy; do
        if ! "${PYTHON}" -c "import ${mod}" 2>/dev/null; then
            MISSING="${MISSING} ${mod}"
        fi
    done

    if [ -z "${MISSING}" ]; then
        success "All imports verified. ✓"
    else
        warn "Missing modules:${MISSING}"
        warn "Attempting system-level pip3 as emergency fallback..."
        for mod in ${MISSING}; do
            ${SUDO} pip3 install "${mod}" --break-system-packages --quiet 2>/dev/null || \
            ${SUDO} pip install "${mod}" --break-system-packages --quiet 2>/dev/null || \
                warn "  System pip also failed for ${mod}."
        done

        # Re-check after emergency install
        STILL_MISSING=""
        for mod in flask scapy; do
            "${PYTHON}" -c "import ${mod}" 2>/dev/null || STILL_MISSING="${STILL_MISSING} ${mod}"
        done
        if [ -z "${STILL_MISSING}" ]; then
            success "Emergency install succeeded. ✓"
        else
            warn "WARN: modules still missing:${STILL_MISSING} — NetWatch may crash."
        fi
    fi
}

# =============================================================================
# STEP 6 — Launch NetWatch
# =============================================================================
step_launch() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════"
    success "Setup complete! Launching NetWatch..."
    echo -e "${YELLOW}  → Dashboard : ${BOLD}http://127.0.0.1:5000${RESET}"
    echo -e "${YELLOW}  → Network   : ${BOLD}http://0.0.0.0:5000${RESET} (LAN access)"
    echo -e "${YELLOW}  → Stop      : Press ${BOLD}Ctrl+C${RESET}"
    echo "════════════════════════════════════════════════════════════════════════"
    echo ""

    NETWATCH_SCRIPT="${SCRIPT_DIR}/netwatch.py"

    if [ ! -f "${NETWATCH_SCRIPT}" ]; then
        fatal "netwatch.py not found in ${SCRIPT_DIR}"
    fi

    # Packet sniffing needs root — run via sudo when not already root
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        "${PYTHON}" "${NETWATCH_SCRIPT}"
    elif [ -n "${SUDO}" ]; then
        ${SUDO} "${PYTHON}" "${NETWATCH_SCRIPT}"
    else
        warn "Running without root — packet sniffing may be unavailable."
        "${PYTHON}" "${NETWATCH_SCRIPT}"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    step_check_sudo
    step_system_deps
    step_find_python
    step_setup_venv
    step_install_packages
    step_launch
}

main
    # ── macOS ──────────────────────────────────────────────────────────────────
    if [ "${OS}" = "Darwin" ]; then
        # Ensure Homebrew is available
        if ! command -v brew >/dev/null 2>&1; then
            warn "Homebrew not found. Attempting to install..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" 2>/dev/null || {
                warn "Homebrew install failed — will continue without it."
                return
            }
            # Add brew to PATH for Apple Silicon
            [ "${ARCH}" = "arm64" ] && eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null)" 2>/dev/null || true
            [ "${ARCH}" = "x86_64" ] && eval "$(/usr/local/bin/brew shellenv 2>/dev/null)" 2>/dev/null || true
        fi
        success "Homebrew: $(brew --version 2>/dev/null | head -1 || echo 'found')"

        # libpcap for scapy
        if ! brew list libpcap >/dev/null 2>&1; then
            info "Installing libpcap..."
            brew install libpcap 2>/dev/null || warn "libpcap install failed — scapy may still work with system libpcap."
        else
            success "libpcap already installed."
        fi
        return
    fi

    # ── Linux ──────────────────────────────────────────────────────────────────
    if command -v apt-get >/dev/null 2>&1; then
        info "Package manager: APT (Debian / Ubuntu / Kali / Raspberry Pi OS)"
        ${SUDO} apt-get update -qq 2>/dev/null || warn "apt-get update failed — continuing anyway."

        # Install each package separately so one failure doesn't block others
        for pkg in python3 python3-pip python3-venv python3-dev \
                   libpcap-dev libpcap0.8 tcpdump curl build-essential; do
            ${SUDO} apt-get install -y -qq "${pkg}" 2>/dev/null || \
                warn "Could not install ${pkg} — skipping."
        done

    elif command -v dnf >/dev/null 2>&1; then
        info "Package manager: DNF (Fedora / RHEL / Rocky)"
        for pkg in python3 python3-pip python3-devel libpcap libpcap-devel tcpdump curl gcc; do
            ${SUDO} dnf install -y -q "${pkg}" 2>/dev/null || warn "Could not install ${pkg} — skipping."
        done

    elif command -v yum >/dev/null 2>&1; then
        info "Package manager: YUM (CentOS / RHEL)"
        for pkg in python3 python3-pip libpcap libpcap-devel tcpdump curl gcc; do
            ${SUDO} yum install -y -q "${pkg}" 2>/dev/null || warn "Could not install ${pkg} — skipping."
        done

    elif command -v pacman >/dev/null 2>&1; then
        info "Package manager: Pacman (Arch / Manjaro / BlackArch)"
        ${SUDO} pacman -Sy --noconfirm python python-pip libpcap tcpdump curl 2>/dev/null || \
            warn "Pacman install had issues — continuing."

    elif command -v zypper >/dev/null 2>&1; then
        info "Package manager: Zypper (openSUSE)"
        for pkg in python3 python3-pip python3-devel libpcap-devel tcpdump curl; do
            ${SUDO} zypper install -y -q "${pkg}" 2>/dev/null || warn "Could not install ${pkg} — skipping."
        done

    elif command -v apk >/dev/null 2>&1; then
        info "Package manager: APK (Alpine Linux)"
        ${SUDO} apk add --no-cache python3 py3-pip libpcap-dev tcpdump curl 2>/dev/null || \
            warn "APK install had issues — continuing."

    else
        warn "No recognised package manager found."
        warn "Make sure python3, pip3, and libpcap are installed manually."
    fi

    success "System dependency step complete."
}

# =============================================================================
# STEP 3 — Find Python (3.8+ acceptable, 3.10+ preferred)
# =============================================================================
step_find_python() {
    info "Step 3/6 — Locating Python interpreter..."
    PYTHON=""

    # Try newest first, down to 3.8 as absolute minimum for scapy+flask
    for cmd in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
        if command -v "${cmd}" >/dev/null 2>&1; then
            _major=$("${cmd}" -c "import sys; print(sys.version_info[0])" 2>/dev/null || echo "0")
            _minor=$("${cmd}" -c "import sys; print(sys.version_info[1])" 2>/dev/null || echo "0")
            _ver=$("${cmd}" --version 2>&1 | head -1)

            if [ "${_major}" -ge 3 ] && [ "${_minor}" -ge 8 ] 2>/dev/null; then
                PYTHON="${cmd}"
                if [ "${_minor}" -lt 10 ]; then
                    warn "Python ${_ver} found — 3.10+ is recommended but we'll try with this."
                else
                    success "Python found: ${_ver}"
                fi
                return
            fi
        fi
    done

    fatal "Python 3.8+ not found. Install it with:
  Debian/Ubuntu : sudo apt-get install python3
  Arch/Kali     : sudo pacman -S python
  Fedora        : sudo dnf install python3
  macOS         : brew install python
  Or download   : https://python.org/downloads/"
}

# =============================================================================
# STEP 4 — Virtual Environment (auto-recreate if broken)
# =============================================================================
step_setup_venv() {
    info "Step 4/6 — Setting up virtual environment..."

    # Check if existing venv is functional; if not, nuke and recreate
    if [ -d "${VENV_DIR}" ]; then
        if "${VENV_DIR}/bin/python" -c "import sys" >/dev/null 2>&1; then
            success "Existing virtual environment is healthy."
        else
            warn "Virtual environment appears broken — recreating..."
            rm -rf "${VENV_DIR}"
        fi
    fi

    if [ ! -d "${VENV_DIR}" ]; then
        info "Creating new virtual environment..."

        # Try venv first, then virtualenv as fallback
        if "${PYTHON}" -m venv "${VENV_DIR}" 2>/dev/null; then
            success "Virtual environment created."
        elif command -v virtualenv >/dev/null 2>&1; then
            warn "python -m venv failed. Trying virtualenv..."
            virtualenv -p "${PYTHON}" "${VENV_DIR}" 2>/dev/null || \
                fatal "Could not create virtual environment. Try: pip install virtualenv"
        else
            warn "venv creation failed. Trying to install python3-venv..."
            ${SUDO} apt-get install -y python3-venv 2>/dev/null || true
            ${SUDO} apt-get install -y "python${_major}.${_minor}-venv" 2>/dev/null || true
            "${PYTHON}" -m venv "${VENV_DIR}" 2>/dev/null || \
                fatal "Cannot create virtual environment. Install python3-venv manually."
        fi
    fi

    # Activate
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate" 2>/dev/null || \
        fatal "Cannot activate virtual environment at ${VENV_DIR}"

    PYTHON="${VENV_DIR}/bin/python"
    PIP="${VENV_DIR}/bin/pip"
    success "Virtual environment active: ${VENV_DIR}"
}

# =============================================================================
# STEP 5 — Python Package Installation (with retry)
# =============================================================================
step_install_packages() {
    info "Step 5/6 — Installing Python packages..."

    # Upgrade pip silently; failure is non-fatal
    "${PIP}" install --upgrade pip --quiet 2>/dev/null || \
        warn "pip upgrade failed — using existing version."

    # Install from requirements.txt if present, otherwise use defaults
    if [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
        info "Found requirements.txt — installing packages..."
        if "${PIP}" install -r "${SCRIPT_DIR}/requirements.txt" --quiet 2>/dev/null; then
            success "All packages installed from requirements.txt."
        else
            warn "Batch install failed. Trying packages one by one..."
            while IFS= read -r line || [ -n "${line}" ]; do
                # Skip blank lines and comments
                [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
                [[ "${line}" =~ ^# ]] && continue
                pkg="${line%%#*}"          # strip inline comments
                pkg="${pkg//[[:space:]]/}" # strip whitespace
                [ -z "${pkg}" ] && continue

                if "${PIP}" install "${pkg}" --quiet 2>/dev/null; then
                    success "  Installed: ${pkg}"
                else
                    # Try without version constraint
                    base="${pkg%%[>=<!]*}"
                    if "${PIP}" install "${base}" --quiet 2>/dev/null; then
                        warn "  Installed ${base} (without version pin)."
                    else
                        warn "  Could not install ${pkg} — skipping."
                    fi
                fi
            done < "${SCRIPT_DIR}/requirements.txt"
        fi
    else
        warn "requirements.txt not found — installing defaults: flask scapy"
        "${PIP}" install flask scapy --quiet 2>/dev/null || \
            warn "Default install had issues — will try to run anyway."
    fi

    # Final import check — warn but don't abort
    info "Verifying critical imports..."
    MISSING=""
    for mod in flask scapy; do
        if ! "${PYTHON}" -c "import ${mod}" 2>/dev/null; then
            MISSING="${MISSING} ${mod}"
        fi
    done

    if [ -z "${MISSING}" ]; then
        success "All imports verified. ✓"
    else
        warn "The following modules could not be imported:${MISSING}"
        warn "NetWatch may not work correctly, but we'll try anyway."
    fi
}

# =============================================================================
# STEP 6 — Launch NetWatch
# =============================================================================
step_launch() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════════"
    success "Setup complete! Launching NetWatch..."
    echo -e "${YELLOW}  → Dashboard : ${BOLD}http://127.0.0.1:5000${RESET}"
    echo -e "${YELLOW}  → Network   : ${BOLD}http://0.0.0.0:5000${RESET} (LAN access)"
    echo -e "${YELLOW}  → Stop      : Press ${BOLD}Ctrl+C${RESET}"
    echo "════════════════════════════════════════════════════════════════════════"
    echo ""

    NETWATCH_SCRIPT="${SCRIPT_DIR}/netwatch.py"

    if [ ! -f "${NETWATCH_SCRIPT}" ]; then
        fatal "netwatch.py not found in ${SCRIPT_DIR}"
    fi

    # Packet sniffing needs root — run via sudo when not already root
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        "${PYTHON}" "${NETWATCH_SCRIPT}"
    elif [ -n "${SUDO}" ]; then
        ${SUDO} "${PYTHON}" "${NETWATCH_SCRIPT}"
    else
        warn "Running without root — packet sniffing may be unavailable."
        "${PYTHON}" "${NETWATCH_SCRIPT}"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    step_check_sudo
    step_system_deps
    step_find_python
    step_setup_venv
    step_install_packages
    step_launch
}

main

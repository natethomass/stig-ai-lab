#!/bin/bash
# =============================================================
# setup.sh — STIG AI Lab Setup Script for RHEL 9
# Run as root or with sudo
# =============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success(){ echo -e "${GREEN}[OK]${NC} $1"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║       STIG AI Hardening Lab — Setup          ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check RHEL ──────────────────────────────────────────────
if ! grep -q "Red Hat" /etc/os-release 2>/dev/null; then
    warn "This script is designed for RHEL 9. Proceeding anyway..."
fi

# ── System dependencies ──────────────────────────────────────
log "Installing system packages..."
dnf install -y \
    python3 python3-pip python3-venv \
    openscap-scanner \
    scap-security-guide \
    ansible \
    git \
    curl || error "Failed to install system packages"
success "System packages installed"

# ── Python virtual environment ───────────────────────────────
log "Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate
success "Virtual environment created"

# ── Python dependencies ──────────────────────────────────────
log "Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
success "Python dependencies installed"

# ── Ollama ───────────────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
    log "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    success "Ollama installed"
else
    success "Ollama already installed"
fi

# ── Start Ollama service ─────────────────────────────────────
log "Starting Ollama service..."
systemctl enable --now ollama 2>/dev/null || ollama serve &>/dev/null &
sleep 3

# ── Pull AI model ─────────────────────────────────────────────
MODEL="${OLLAMA_MODEL:-llama3.1}"
log "Pulling Ollama model: $MODEL (this may take a while on first run)..."
ollama pull "$MODEL"
success "Model $MODEL ready"

# ── Config ───────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    success "Created .env from .env.example — review and customize if needed"
else
    warn ".env already exists — skipping"
fi

# ── Verify SCAP content ───────────────────────────────────────
SCAP_PATH="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
if [ -f "$SCAP_PATH" ]; then
    success "SCAP content found at $SCAP_PATH"
else
    warn "SCAP content not found at expected path. Check your RHEL version."
    warn "Try: find /usr -name 'ssg-rhel*-ds.xml' 2>/dev/null"
fi

# ── Verify oscap ──────────────────────────────────────────────
if oscap --version &>/dev/null; then
    OSCAP_VER=$(oscap --version | head -1)
    success "OpenSCAP ready: $OSCAP_VER"
else
    error "oscap not found after installation"
fi

# ── Directories ───────────────────────────────────────────────
mkdir -p reports playbooks
chmod 750 reports playbooks
success "Output directories created"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Setup Complete!                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "  1. Activate venv : source .venv/bin/activate"
echo "  2. Run a dry run : sudo python agent.py --dry-run"
echo "  3. Full scan+fix : sudo python agent.py"
echo ""
echo "Optional flags:"
echo "  --scan-only       Scan without remediation"
echo "  --model mistral   Use a different Ollama model"
echo "  --results FILE    Use existing scan results XML"

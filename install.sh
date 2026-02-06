#!/bin/sh
# Anty installer — Linux & macOS
# Usage: curl -fsSL https://anty.dev/install.sh | sh
set -e

REPO="voulspiros/Anty"
INSTALL_DIR="$HOME/.anty/bin"
BINARY_NAME="anty"

# ── Colours (if terminal supports them) ──────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

info()  { printf "${BOLD}${CYAN}  ▸ %s${RESET}\n" "$1"; }
ok()    { printf "${GREEN}  ✔ %s${RESET}\n" "$1"; }
warn()  { printf "${YELLOW}  ⚠ %s${RESET}\n" "$1"; }
fail()  { printf "${RED}  ✖ %s${RESET}\n" "$1"; exit 1; }

# ── Detect OS and architecture ───────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    *)      fail "Unsupported OS: $OS. For Windows use: irm https://anty.dev/install.ps1 | iex" ;;
esac

case "$ARCH" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)             fail "Unsupported architecture: $ARCH" ;;
esac

ASSET="${BINARY_NAME}-${PLATFORM}-${ARCH}"

# ── Resolve latest release ───────────────────────────────────────────
info "Finding latest Anty release..."

API_URL="https://api.github.com/repos/${REPO}/releases/latest"

if command -v curl >/dev/null 2>&1; then
    RELEASE_JSON=$(curl -fsSL "$API_URL")
elif command -v wget >/dev/null 2>&1; then
    RELEASE_JSON=$(wget -qO- "$API_URL")
else
    fail "Neither curl nor wget found. Install one and retry."
fi

VERSION=$(printf '%s' "$RELEASE_JSON" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
[ -z "$VERSION" ] && fail "Could not determine latest version from GitHub API."

info "Anty ${VERSION} for ${PLATFORM}/${ARCH}"

# ── Download binary + checksums ──────────────────────────────────────
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${ASSET}..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP_DIR}/${ASSET}"
    curl -fsSL "${BASE_URL}/SHA256SUMS.txt" -o "${TMP_DIR}/SHA256SUMS.txt"
else
    wget -q "${BASE_URL}/${ASSET}" -O "${TMP_DIR}/${ASSET}"
    wget -q "${BASE_URL}/SHA256SUMS.txt" -O "${TMP_DIR}/SHA256SUMS.txt"
fi

# ── Verify checksum ──────────────────────────────────────────────────
info "Verifying SHA-256 checksum..."

EXPECTED=$(grep "${ASSET}" "${TMP_DIR}/SHA256SUMS.txt" | awk '{print $1}')
[ -z "$EXPECTED" ] && fail "No checksum entry found for ${ASSET} in SHA256SUMS.txt"

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TMP_DIR}/${ASSET}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${TMP_DIR}/${ASSET}" | awk '{print $1}')
else
    fail "No sha256sum or shasum found — cannot verify download."
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
    fail "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}\n\nThe download may be corrupted. Please try again."
fi
ok "Checksum verified"

# ── Install ──────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
mv "${TMP_DIR}/${ASSET}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

ok "Anty ${VERSION} installed to ${INSTALL_DIR}/${BINARY_NAME}"

# ── PATH guidance ────────────────────────────────────────────────────
echo ""
case "$PATH" in
    *"$INSTALL_DIR"*)
        ok "PATH already includes ${INSTALL_DIR}"
        echo ""
        "${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || true
        ;;
    *)
        warn "${INSTALL_DIR} is not in your PATH yet."
        echo ""
        SHELL_NAME="$(basename "${SHELL:-/bin/sh}")"
        case "$SHELL_NAME" in
            zsh)  RC_FILE="~/.zshrc" ;;
            bash) RC_FILE="~/.bashrc" ;;
            fish) RC_FILE="~/.config/fish/config.fish" ;;
            *)    RC_FILE="your shell config" ;;
        esac
        echo "  Add this line to ${CYAN}${RC_FILE}${RESET}:"
        echo ""
        if [ "$SHELL_NAME" = "fish" ]; then
            echo "    ${BOLD}set -gx PATH \"${INSTALL_DIR}\" \$PATH${RESET}"
        else
            echo "    ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${RESET}"
        fi
        echo ""
        echo "  Then restart your terminal and run:"
        echo "    ${BOLD}anty --version${RESET}"
        ;;
esac

echo ""
echo "  ${BOLD}Get started:${RESET}"
echo "    anty          ${DIM}# interactive wizard${RESET}"
echo "    anty scan .   ${DIM}# scan current directory${RESET}"
echo ""

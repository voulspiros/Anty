#!/bin/sh
set -e

REPO="voulspiros/Anty"
BINARY_NAME="anty"
INSTALL_DIR="${ANTY_INSTALL_DIR:-$HOME/.local/bin}"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    *)      echo "Error: Unsupported OS: $OS. Use Windows binaries from GitHub Releases."; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)             echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

ASSET="${BINARY_NAME}-${PLATFORM}-${ARCH}"

# Get latest version
echo "Finding latest Anty release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)

if [ -z "$VERSION" ]; then
    echo "Error: Could not determine latest version"
    exit 1
fi

echo "Downloading Anty ${VERSION} for ${PLATFORM}/${ARCH}..."

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS.txt"

# Download binary
curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${ASSET}"

# Verify checksum
echo "Verifying checksum..."
curl -fsSL "$CHECKSUM_URL" -o "/tmp/SHA256SUMS.txt"
EXPECTED=$(grep "$ASSET" "/tmp/SHA256SUMS.txt" | awk '{print $1}')

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "/tmp/${ASSET}" | awk '{print $1}')
else
    ACTUAL=$(shasum -a 256 "/tmp/${ASSET}" | awk '{print $1}')
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Error: Checksum verification failed!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    rm -f "/tmp/${ASSET}" "/tmp/SHA256SUMS.txt"
    exit 1
fi
echo "Checksum OK."

# Install
mkdir -p "$INSTALL_DIR"
mv "/tmp/${ASSET}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
rm -f "/tmp/SHA256SUMS.txt"

echo ""
echo "✅ Anty ${VERSION} installed to ${INSTALL_DIR}/${BINARY_NAME}"
echo ""

# Check PATH
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "⚠  ${INSTALL_DIR} is not in your PATH."
    echo "   Add this to your shell config:"
    echo ""
    echo "   export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
fi

echo "Run: anty scan ."

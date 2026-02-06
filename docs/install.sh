#!/bin/sh
set -eu

REPO="voulspiros/Anty"
BASE_URL="https://github.com/$REPO/releases/latest/download"
CHECKSUMS_URL="$BASE_URL/SHA256SUMS.txt"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64) ASSET="anty-linux-x86_64" ;;
      aarch64|arm64) ASSET="anty-linux-aarch64" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      x86_64) ASSET="anty-macos-x86_64" ;;
      arm64) ASSET="anty-macos-aarch64" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

TMP_DIR="$(mktemp -d)"
BIN_PATH="$TMP_DIR/anty"
CHECKSUMS_PATH="$TMP_DIR/SHA256SUMS.txt"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "Installing ANTY..."

curl -fsSL "$BASE_URL/$ASSET" -o "$BIN_PATH"
curl -fsSL "$CHECKSUMS_URL" -o "$CHECKSUMS_PATH"

echo "Verifying checksum..."

EXPECTED="$(grep " $ASSET" "$CHECKSUMS_PATH" | awk '{print $1}' | head -n 1)"
if [ -z "$EXPECTED" ]; then
  echo "Checksum entry not found for $ASSET"
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$BIN_PATH" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$BIN_PATH" | awk '{print $1}')"
else
  echo "No SHA256 tool found (sha256sum or shasum)."
  exit 1
fi

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Checksum verification failed."
  exit 1
fi

INSTALL_DIR="$HOME/.anty/bin"
mkdir -p "$INSTALL_DIR"
cp "$BIN_PATH" "$INSTALL_DIR/anty"
chmod +x "$INSTALL_DIR/anty"

echo "Installed successfully"

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    ;;
  *)
    echo "Add to PATH: export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac

echo "Run: anty"

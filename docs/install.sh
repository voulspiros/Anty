#!/bin/sh
set -eu

REPO="voulspiros/Anty"
API_URL="https://api.github.com/repos/$REPO/releases/latest"

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

HTTP_CODE="$(curl -sL -o "$TMP_DIR/release.json" -w "%{http_code}" -H "User-Agent: anty-installer" "$API_URL")"
case "$HTTP_CODE" in
  200) ;;
  404)
    echo "Error: No GitHub Release found. Publish a release by pushing a version tag (e.g. git tag v0.1.0 && git push origin v0.1.0)."
    exit 1
    ;;
  403)
    echo "Error: GitHub API rate limit exceeded. Try again later."
    exit 1
    ;;
  *)
    echo "Error: Failed to fetch release info (HTTP $HTTP_CODE)."
    exit 1
    ;;
esac

TAG="$(sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' "$TMP_DIR/release.json" | head -n 1)"
if [ -z "$TAG" ]; then
  echo "Error: Could not determine release tag."
  exit 1
fi

echo "Found release: $TAG"

DOWNLOAD_BASE="https://github.com/$REPO/releases/download/$TAG"
BINARY_URL="$DOWNLOAD_BASE/$ASSET"
CHECKSUMS_URL="$DOWNLOAD_BASE/SHA256SUMS.txt"

curl -fsSL "$BINARY_URL" -o "$BIN_PATH"
curl -fsSL "$CHECKSUMS_URL" -o "$CHECKSUMS_PATH"

echo "Verifying checksum..."

EXPECTED="$(grep " $ASSET\$" "$CHECKSUMS_PATH" | awk '{print $1}' | head -n 1)"
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
  echo "  Expected: $EXPECTED"
  echo "  Got:      $ACTUAL"
  exit 1
fi

INSTALL_DIR="$HOME/.anty/bin"
mkdir -p "$INSTALL_DIR"
cp "$BIN_PATH" "$INSTALL_DIR/anty"
chmod +x "$INSTALL_DIR/anty"

echo "Installed successfully ($TAG)"

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    ;;
  *)
    echo "Add to PATH: export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac

echo "Run: anty"

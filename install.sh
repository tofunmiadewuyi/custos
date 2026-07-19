#!/usr/bin/env bash
# Install the custos daemon (custosd) on a host and run its self-install.
# Usage: curl -fsSL <raw-url>/install.sh | sudo bash
#   pin a version: CUSTOS_VERSION=v1.2.3 ... | sudo bash
set -euo pipefail

REPO="tofunmiadewuyi/custos"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$OS" != "linux" ]; then
  echo "custosd runs on Linux only (it wires systemd + sshd); got: $OS" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  arm64 | aarch64) ARCH="arm64" ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Resolve the daemon version: explicit pin, else newest custosd/ release.
VERSION="${CUSTOS_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=30" \
    | grep '"tag_name":' | grep 'custosd/' | head -n1 \
    | sed -E 's/.*"custosd\/([^"]+)".*/\1/')
fi
if [ -z "$VERSION" ]; then
  echo "could not determine latest custosd release; set CUSTOS_VERSION=vX.Y.Z" >&2
  exit 1
fi

FILENAME="custosd_${VERSION}_linux_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/custosd/${VERSION}/${FILENAME}"

echo "Installing custosd $VERSION for linux/$ARCH..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fSL "$URL" -o "$TMP_DIR/custosd.tar.gz"
tar -xzf "$TMP_DIR/custosd.tar.gz" -C "$TMP_DIR"
chmod +x "$TMP_DIR/custosd"

# custosd install (needs root) copies itself to /usr/local/bin, creates the
# custos user + state dir, writes the systemd unit, and wires the sshd drop-in.
if [ "$(id -u)" -ne 0 ]; then
  echo "custosd install needs root; re-running under sudo..."
  sudo "$TMP_DIR/custosd" install
else
  "$TMP_DIR/custosd" install
fi

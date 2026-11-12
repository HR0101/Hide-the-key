#!/usr/bin/env bash
# Installer for hide-the-key CLI

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BIN_SOURCE="$DIR/bin/hide-the-key"

TARGET_DIR="$HOME/.local/bin"
mkdir -p "$TARGET_DIR"

TARGET_LINK="$TARGET_DIR/hide-the-key"

echo "Installing hide-the-key to $TARGET_LINK ..."
ln -sf "$BIN_SOURCE" "$TARGET_LINK"

echo "✅ Installed successfully!"
echo ""
echo "Make sure $TARGET_DIR is in your PATH."
echo "If not already added, add the following line to your ~/.zshrc or ~/.bashrc:"
echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
echo "Try running:"
echo "    hide-the-key --help"

#!/usr/bin/env bash

set -e

RELEASE_URL="https://api.github.com/repos/crodjer/biip/releases/latest"
OS_ARCH=$(uname -sm)

case $OS_ARCH in
    "Linux aarch64")
        BINARY="biip-aarch64-unknown-linux-gnu"
        ;;
    "Linux armv7l")
        BINARY="biip-armv7-unknown-linux-gnueabihf"
        ;;
    "Linux x86_64")
        BINARY="biip-x86_64-unknown-linux-gnu"
        ;;
    "Darwin arm64")
        BINARY="biip-aarch64-apple-darwin"
        ;;
    "Darwin x86_64")
        BINARY="biip-x86_64-apple-darwin"
        ;;
    *)
        echo "Unsupported OS/architecture: $OS_ARCH"
        exit 1
        ;;
esac

TEMP_BIIP_BIN=/tmp/biip
DOWNLOAD_URL=$(curl -sfSL "$RELEASE_URL" | grep -oE "https://.+$BINARY")

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Failed to retrieve download URL"
    exit 1
fi

curl -sfSL $DOWNLOAD_URL -o $TEMP_BIIP_BIN
chmod +x $TEMP_BIIP_BIN

# If ~/.local/bin, ~/.cargo/bin or ~/.bin exists and in $PATH, install biip there
if [ -d "$HOME/.local/bin" ] && [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
    mv $TEMP_BIIP_BIN $HOME/.local/bin/biip
    echo "Installed to $HOME/.local/bin/biip"
elif [ -d "$HOME/.cargo/bin" ] && [[ ":$PATH:" == *":$HOME/.cargo/bin:"* ]]; then
    mv $TEMP_BIIP_BIN $HOME/.cargo/bin/biip
    echo "Installed to $HOME/.cargo/bin/biip"
elif [ -d "$HOME/.bin" ] && [[ ":$PATH:" == *":$HOME/.bin:"* ]]; then
    mv $TEMP_BIIP_BIN $HOME/.bin/biip
    echo "Installed to $HOME/.bin/biip"
elif [ -d "/usr/local/bin" ] && [[ ":$PATH:" == *":/usr/local/bin:"* ]]; then
    echo "Installing to /usr/local/bin/biip, require sudo..."
    sudo mv $TEMP_BIIP_BIN /usr/local/bin/biip
    echo "Installed to /usr/local/bin/biip"
else
    echo "Downloaded $TEMP_BIIP_BIN!"
    exit 0
fi

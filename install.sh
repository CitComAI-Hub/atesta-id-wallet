#!/usr/bin/env bash
# Installs atesta-id-wallet for the current user (no sudo) and registers the
# openid4vp:// and openid-credential-offer:// links on the desktop.
#   ./install.sh                     install or update from the code in this directory
#   ./install.sh --no-gui            no graphical interface (terminal only; saves ~250 MB of Qt)
#   ./install.sh --update            git pull and reinstall (same as: atesta-id-wallet update)
#   ./install.sh --uninstall         uninstall (credentials and key are kept)
#   ./install.sh --uninstall --purge uninstall and DELETE credentials, key and profiles
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
VENV="$DATA_HOME/atesta-id-wallet-venv"
WALLET_DATA="${ATESTA_ID_WALLET_HOME:-$DATA_HOME/atesta-id-wallet}"
BIN_DIR="$HOME/.local/bin"

if [[ "${1:-}" == "--uninstall" ]]; then
    [[ -x "$BIN_DIR/atesta-id-wallet" ]] && "$BIN_DIR/atesta-id-wallet" uninstall-handler || true
    rm -f "$BIN_DIR/atesta-id-wallet" "$BIN_DIR/atesta-id-wallet-gui"
    rm -rf "$VENV"
    if [[ "${2:-}" == "--purge" ]]; then
        read -r -p "ALL credentials and keys in $WALLET_DATA will be deleted. Type 'delete' to confirm: " answer
        if [[ "$answer" == "delete" ]]; then
            rm -rf "$WALLET_DATA"
            echo "✔ Uninstalled and data deleted."
        else
            echo "✔ Uninstalled. Data kept in $WALLET_DATA/"
        fi
    else
        echo "✔ Uninstalled. Your credentials are still in $WALLET_DATA/"
    fi
    exit 0
fi

GUI=1
for arg in "$@"; do
    case "$arg" in
        --update) git -C "$SRC_DIR" pull --ff-only ;;
        --no-gui) GUI=0 ;;
    esac
done

if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "python3-venv is missing:  sudo apt install python3-venv" >&2
    exit 1
fi
command -v wl-paste >/dev/null || command -v xclip >/dev/null || \
    echo "Note: to read links from the clipboard, install wl-clipboard:  sudo apt install wl-clipboard"

# Versions before 0.6 were called oid4vc-wallet: remove that installation. Its data is moved to
# the new folder the first time the wallet starts.
if [[ -d "$DATA_HOME/oid4vc-wallet-venv" ]]; then
    echo "Removing the previous installation (oid4vc-wallet) ..."
    rm -rf "$DATA_HOME/oid4vc-wallet-venv"
    rm -f "$BIN_DIR/oid4vc-wallet" "$BIN_DIR/oid4vc-wallet-gui" "$DATA_HOME/applications/oid4vc-wallet.desktop" \
          "$DATA_HOME/icons/hicolor/256x256/apps/oid4vc-wallet.png"
fi

echo "Installing into $VENV ..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
if [[ $GUI == 1 ]]; then
    "$VENV/bin/pip" install --quiet --upgrade "$SRC_DIR[gui]"
else
    "$VENV/bin/pip" install --quiet --upgrade "$SRC_DIR"
    "$VENV/bin/pip" uninstall --quiet --yes PySide6-Essentials shiboken6 2>/dev/null || true
fi
echo "$SRC_DIR" > "$VENV/atesta-id-wallet-source"   # for 'atesta-id-wallet update'

mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/atesta-id-wallet" "$BIN_DIR/atesta-id-wallet"
if [[ $GUI == 1 ]]; then
    ln -sf "$VENV/bin/atesta-id-wallet-gui" "$BIN_DIR/atesta-id-wallet-gui"
else
    rm -f "$BIN_DIR/atesta-id-wallet-gui"
fi
PATH="$BIN_DIR:$PATH" "$BIN_DIR/atesta-id-wallet" install-handler

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Note: add $BIN_DIR to your PATH (open a new terminal or run: export PATH=\"$BIN_DIR:\$PATH\")" ;;
esac
if [[ $GUI == 1 ]]; then
    echo "✔ Done. Open 'Atesta ID Wallet' from the applications menu, or run: atesta-id-wallet-gui"
else
    echo "✔ Done. Try:  atesta-id-wallet --help"
fi

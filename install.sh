#!/usr/bin/env bash
# Installs oid4vc-wallet for the current user (no sudo) and registers the
# openid4vp:// and openid-credential-offer:// links on the desktop.
#   ./install.sh                     install or update from the code in this directory
#   ./install.sh --no-gui            no graphical interface (terminal only; saves ~250 MB of Qt)
#   ./install.sh --update            git pull and reinstall (same as: oid4vc-wallet update)
#   ./install.sh --uninstall         uninstall (credentials and key are kept)
#   ./install.sh --uninstall --purge uninstall and DELETE credentials, key and profiles
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
VENV="$DATA_HOME/oid4vc-wallet-venv"
WALLET_DATA="${OID4VC_WALLET_HOME:-$DATA_HOME/oid4vc-wallet}"
BIN_DIR="$HOME/.local/bin"

if [[ "${1:-}" == "--uninstall" ]]; then
    [[ -x "$BIN_DIR/oid4vc-wallet" ]] && "$BIN_DIR/oid4vc-wallet" uninstall-handler || true
    rm -f "$BIN_DIR/oid4vc-wallet" "$BIN_DIR/oid4vc-wallet-gui"
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

echo "Installing into $VENV ..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
if [[ $GUI == 1 ]]; then
    "$VENV/bin/pip" install --quiet --upgrade "$SRC_DIR[gui]"
else
    "$VENV/bin/pip" install --quiet --upgrade "$SRC_DIR"
    "$VENV/bin/pip" uninstall --quiet --yes PySide6-Essentials shiboken6 2>/dev/null || true
fi
echo "$SRC_DIR" > "$VENV/oid4vc-wallet-source"   # for 'oid4vc-wallet update'

mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/oid4vc-wallet" "$BIN_DIR/oid4vc-wallet"
if [[ $GUI == 1 ]]; then
    ln -sf "$VENV/bin/oid4vc-wallet-gui" "$BIN_DIR/oid4vc-wallet-gui"
else
    rm -f "$BIN_DIR/oid4vc-wallet-gui"
fi
PATH="$BIN_DIR:$PATH" "$BIN_DIR/oid4vc-wallet" install-handler

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Note: add $BIN_DIR to your PATH (open a new terminal or run: export PATH=\"$BIN_DIR:\$PATH\")" ;;
esac
if [[ $GUI == 1 ]]; then
    echo "✔ Done. Open 'OID4VC Wallet' from the applications menu, or run: oid4vc-wallet-gui"
else
    echo "✔ Done. Try:  oid4vc-wallet --help"
fi

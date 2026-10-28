#!/usr/bin/env bash
# Packages for Linux the folder made by PyInstaller (packaging/atesta-id-wallet.spec):
#   Atesta_ID_Wallet-VERSION-x86_64.AppImage   a single file, no installation (any distro)
#   atesta-id-wallet_VERSION_amd64.deb         Debian/Ubuntu: menu, links and commands in /usr/bin
# Usage:  packaging/build_linux.sh [PYINSTALLER_FOLDER] [OUTPUT]
#   FORMATS="deb"                    only some formats (default: "appimage deb")
#   APPIMAGETOOL=/path/appimagetool  to avoid downloading it
#   MAINTAINER="Name <email>"        Maintainer field of the .deb
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="$(realpath "${1:-$ROOT/dist/atesta-id-wallet}")"
OUT="$(realpath -m "${2:-$ROOT/dist}")"
FORMATS="${FORMATS:-appimage deb}"
MAINTAINER="${MAINTAINER:-Joan Ciprià <joamoteo@upv.es>}"
[[ -x "$BUNDLE/atesta-id-wallet-gui" ]] || { echo "No GUI executable in $BUNDLE" >&2; exit 1; }
VERSION="$("$BUNDLE/atesta-id-wallet" --version | awk '{print $2}')"
ICON="$ROOT/atesta_id_wallet/gui/icons/app-icon.png"
APPIMAGETOOL_VERSION=1.9.1
APPIMAGETOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

desktop_entry() {  # $1 = Exec
    cat <<DESKTOP
[Desktop Entry]
Type=Application
Name=Atesta ID Wallet
Comment=Verifiable credentials wallet (OpenID4VCI / OpenID4VP)
Comment[es]=Wallet de credenciales verificables (OpenID4VCI / OpenID4VP)
Comment[da]=Wallet til verificerbare legitimationer (OpenID4VCI / OpenID4VP)
Exec=$1 %u
Icon=atesta-id-wallet
Terminal=false
Categories=Utility;Security;
MimeType=x-scheme-handler/openid4vp;x-scheme-handler/openid-credential-offer;
DESKTOP
}

build_appimage() {
    local appdir="$WORK/AppDir" tool="${APPIMAGETOOL:-}"
    mkdir -p "$appdir/usr/lib"
    cp -a "$BUNDLE" "$appdir/usr/lib/atesta-id-wallet"
    cat > "$appdir/AppRun" <<'APPRUN'
#!/bin/sh
# No arguments or a link: the graphical interface.  'cli ...': the terminal (atesta-id-wallet ...).
HERE="$(dirname "$(readlink -f "$0")")"
if [ "$1" = "cli" ]; then
    shift
    exec "$HERE/usr/lib/atesta-id-wallet/atesta-id-wallet" "$@"
fi
exec "$HERE/usr/lib/atesta-id-wallet/atesta-id-wallet-gui" "$@"
APPRUN
    chmod 755 "$appdir/AppRun"
    desktop_entry atesta-id-wallet-gui > "$appdir/atesta-id-wallet.desktop"
    cp "$ICON" "$appdir/atesta-id-wallet.png"
    ln -s atesta-id-wallet.png "$appdir/.DirIcon"
    if [[ -z "$tool" ]]; then
        # Fixed version and checksum (the 'continuous' build changes without notice).
        tool="$WORK/appimagetool"
        curl -fsSL -o "$tool" "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-x86_64.AppImage"
        echo "$APPIMAGETOOL_SHA256  $tool" | sha256sum -c --quiet -
        chmod 755 "$tool"
    fi
    local target="$OUT/Atesta_ID_Wallet-$VERSION-x86_64.AppImage"
    # Without FUSE (containers, CI): appimagetool extracts itself and runs.
    APPIMAGE_EXTRACT_AND_RUN=1 ARCH=x86_64 "$tool" --no-appstream "$appdir" "$target" >/dev/null
    echo "✔ $target"
}

build_deb() {
    local pkg="$WORK/deb"
    mkdir -p "$pkg/DEBIAN" "$pkg/opt" "$pkg/usr/bin" "$pkg/usr/share/applications" \
             "$pkg/usr/share/icons/hicolor/256x256/apps"
    cp -a "$BUNDLE" "$pkg/opt/atesta-id-wallet"
    ln -s /opt/atesta-id-wallet/atesta-id-wallet "$pkg/usr/bin/atesta-id-wallet"
    ln -s /opt/atesta-id-wallet/atesta-id-wallet-gui "$pkg/usr/bin/atesta-id-wallet-gui"
    desktop_entry /opt/atesta-id-wallet/atesta-id-wallet-gui > "$pkg/usr/share/applications/atesta-id-wallet.desktop"
    cp "$ICON" "$pkg/usr/share/icons/hicolor/256x256/apps/atesta-id-wallet.png"
    # Only what PyInstaller leaves out of the bundle: libc and the graphics driver (EGL). The X11/xcb,
    # xkbcommon and fontconfig libraries are inside /opt/atesta-id-wallet/_internal.
    cat > "$pkg/DEBIAN/control" <<CONTROL
Package: atesta-id-wallet
Version: $VERSION
Architecture: amd64
Maintainer: $MAINTAINER
Installed-Size: $(du -sk "$pkg" | cut -f1)
Depends: libc6 (>= 2.35), libegl1
Recommends: wl-clipboard | xclip
Section: utils
Priority: optional
Homepage: https://github.com/CitComAI-Hub/atesta-id-wallet
Description: Desktop wallet for verifiable credentials
 OpenID4VCI 1.0 + OpenID4VP 1.0 (SD-JWT VC) without a smartphone: receive
 credentials from an issuer and present them to verifiers, with explicit
 consent for every presentation.
CONTROL
    chmod -R go-w "$pkg"
    local target="$OUT/atesta-id-wallet_${VERSION}_amd64.deb"
    dpkg-deb --root-owner-group --build "$pkg" "$target" >/dev/null
    echo "✔ $target"
}

for format in $FORMATS; do
    case "$format" in
        appimage) build_appimage ;;
        deb) build_deb ;;
        *) echo "Unknown format: $format" >&2; exit 1 ;;
    esac
done

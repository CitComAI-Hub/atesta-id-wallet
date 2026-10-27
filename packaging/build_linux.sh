#!/usr/bin/env bash
# Empaqueta para Linux la carpeta que genera PyInstaller (packaging/oid4vc-wallet.spec):
#   OID4VC_Wallet-VERSION-x86_64.AppImage   un solo fichero, sin instalar (cualquier distro)
#   oid4vc-wallet_VERSION_amd64.deb         Debian/Ubuntu: menú, enlaces y comandos en /usr/bin
# Uso:  packaging/build_linux.sh [CARPETA_PYINSTALLER] [SALIDA]
#   FORMATS="deb"                    solo algunos formatos (por defecto: "appimage deb")
#   APPIMAGETOOL=/ruta/appimagetool  para no descargarlo
#   MAINTAINER="Nombre <correo>"     campo Maintainer del .deb
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="$(realpath "${1:-$ROOT/dist/oid4vc-wallet}")"
OUT="$(realpath -m "${2:-$ROOT/dist}")"
FORMATS="${FORMATS:-appimage deb}"
MAINTAINER="${MAINTAINER:-Joan Ciprià <joamoteo@upv.es>}"
[[ -x "$BUNDLE/oid4vc-wallet-gui" ]] || { echo "No GUI executable in $BUNDLE" >&2; exit 1; }
VERSION="$("$BUNDLE/oid4vc-wallet" --version | awk '{print $2}')"
ICON="$ROOT/oid4vc_wallet/gui/icons/app-icon.png"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

desktop_entry() {  # $1 = Exec
    cat <<DESKTOP
[Desktop Entry]
Type=Application
Name=OID4VC Wallet
Comment=Verifiable credentials wallet (OpenID4VCI / OpenID4VP)
Comment[es]=Wallet de credenciales verificables (OpenID4VCI / OpenID4VP)
Comment[da]=Wallet til verificerbare legitimationer (OpenID4VCI / OpenID4VP)
Exec=$1 %u
Icon=oid4vc-wallet
Terminal=false
Categories=Utility;Security;
MimeType=x-scheme-handler/openid4vp;x-scheme-handler/openid-credential-offer;
DESKTOP
}

build_appimage() {
    local appdir="$WORK/AppDir" tool="${APPIMAGETOOL:-}"
    mkdir -p "$appdir/usr/lib"
    cp -a "$BUNDLE" "$appdir/usr/lib/oid4vc-wallet"
    cat > "$appdir/AppRun" <<'APPRUN'
#!/bin/sh
# Sin argumentos o con un enlace: la interfaz gráfica.  'cli ...': la terminal (oid4vc-wallet ...).
HERE="$(dirname "$(readlink -f "$0")")"
if [ "$1" = "cli" ]; then
    shift
    exec "$HERE/usr/lib/oid4vc-wallet/oid4vc-wallet" "$@"
fi
exec "$HERE/usr/lib/oid4vc-wallet/oid4vc-wallet-gui" "$@"
APPRUN
    chmod 755 "$appdir/AppRun"
    desktop_entry oid4vc-wallet-gui > "$appdir/oid4vc-wallet.desktop"
    cp "$ICON" "$appdir/oid4vc-wallet.png"
    ln -s oid4vc-wallet.png "$appdir/.DirIcon"
    if [[ -z "$tool" ]]; then
        # Versión fija: la 13 de AppImageKit (la 'continuous' cambia sin aviso).
        tool="$WORK/appimagetool"
        curl -fsSL -o "$tool" https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage
        chmod 755 "$tool"
    fi
    local target="$OUT/OID4VC_Wallet-$VERSION-x86_64.AppImage"
    # Sin FUSE (contenedores, CI): appimagetool se extrae a sí mismo y se ejecuta.
    APPIMAGE_EXTRACT_AND_RUN=1 ARCH=x86_64 "$tool" --no-appstream "$appdir" "$target" >/dev/null
    echo "✔ $target"
}

build_deb() {
    local pkg="$WORK/deb"
    mkdir -p "$pkg/DEBIAN" "$pkg/opt" "$pkg/usr/bin" "$pkg/usr/share/applications" \
             "$pkg/usr/share/icons/hicolor/256x256/apps"
    cp -a "$BUNDLE" "$pkg/opt/oid4vc-wallet"
    ln -s /opt/oid4vc-wallet/oid4vc-wallet "$pkg/usr/bin/oid4vc-wallet"
    ln -s /opt/oid4vc-wallet/oid4vc-wallet-gui "$pkg/usr/bin/oid4vc-wallet-gui"
    desktop_entry /opt/oid4vc-wallet/oid4vc-wallet-gui > "$pkg/usr/share/applications/oid4vc-wallet.desktop"
    cp "$ICON" "$pkg/usr/share/icons/hicolor/256x256/apps/oid4vc-wallet.png"
    cat > "$pkg/DEBIAN/control" <<CONTROL
Package: oid4vc-wallet
Version: $VERSION
Architecture: amd64
Maintainer: $MAINTAINER
Installed-Size: $(du -sk "$pkg" | cut -f1)
Depends: libc6 (>= 2.35), libegl1, libfontconfig1, libxkbcommon0, libxcb-cursor0
Recommends: wl-clipboard | xclip
Section: utils
Priority: optional
Homepage: https://github.com/CitComAI-Hub/oid4vc-wallet
Description: Desktop wallet for verifiable credentials
 OpenID4VCI 1.0 + OpenID4VP 1.0 (SD-JWT VC) without a smartphone: receive
 credentials from an issuer and present them to verifiers, with explicit
 consent for every presentation.
CONTROL
    chmod -R go-w "$pkg"
    local target="$OUT/oid4vc-wallet_${VERSION}_amd64.deb"
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

#!/usr/bin/env bash
# Signed APT repository (flat) with the given .deb, for GitHub Pages:
#   packaging/build_apt_repo.sh atesta-id-wallet_X.Y.Z_amd64.deb site/apt
# Needs APT_SIGNING_KEY: the armored secret OpenPGP key whose public part is
# packaging/apt-archive-keyring.gpg (the one the .deb trusts). See docs/RELEASING.md.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEB="$(realpath "$1")"
OUT="$(realpath -m "$2")"
[[ -n "${APT_SIGNING_KEY:-}" ]] || { echo "APT_SIGNING_KEY is not set" >&2; exit 1; }
export GNUPGHOME="$(mktemp -d)"
trap 'rm -rf "$GNUPGHOME"' EXIT

gpg --batch --quiet --import <<<"$APT_SIGNING_KEY"
expected=$(gpg --batch --with-colons --show-keys "$ROOT/packaging/apt-archive-keyring.gpg" | awk -F: '/^fpr/{print $10; exit}')
gpg --batch --with-colons --list-secret-keys "$expected" >/dev/null \
    || { echo "APT_SIGNING_KEY is not the key in packaging/apt-archive-keyring.gpg ($expected)" >&2; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT"
cp "$DEB" "$OUT/"
cp "$ROOT/packaging/apt-archive-keyring.gpg" "$OUT/atesta-id-wallet-archive-keyring.gpg"
cd "$OUT"
apt-ftparchive packages . > Packages
gzip -9kn Packages
apt-ftparchive -o APT::FTPArchive::Release::Origin="Atesta ID Wallet" \
    -o APT::FTPArchive::Release::Label="Atesta ID Wallet" \
    -o APT::FTPArchive::Release::Architectures="amd64" release . > "$GNUPGHOME/Release"
mv "$GNUPGHOME/Release" Release  # written apart: it must not list itself
gpg --batch --yes --local-user "$expected" --clearsign -o InRelease Release
gpg --batch --yes --local-user "$expected" -abs -o Release.gpg Release
gpg --batch --quiet --no-default-keyring --keyring "$ROOT/packaging/apt-archive-keyring.gpg" --verify InRelease 2>/dev/null \
    || { echo "InRelease does not verify with packaging/apt-archive-keyring.gpg" >&2; exit 1; }
echo "✔ $OUT"

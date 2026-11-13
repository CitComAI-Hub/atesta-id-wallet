# -*- coding: utf-8 -*-
"""
New versions (GitHub Releases): notice and automatic update.

GitHub is asked once a day (setting `update_check`, on by default; off: only when the user asks
in Settings or with `atesta-id-wallet update`). The request carries no wallet data: GitHub only
sees the IP address and the version in the User-Agent.

Where the application can replace itself (the AppImage, and Windows installed with the setup
program) the new version is downloaded in the background and only used if SHA256SUMS carries a
valid Ed25519 signature by UPDATE_PUBLIC_KEY and the file matches its checksum. The private key
is a secret of the release workflow, so a release published by other means (a stolen GitHub
account, a tampered file) is never installed. The AppImage is replaced right away (the running
copy keeps working) and the new one starts on the next launch; on Windows the installer runs
when the window restarts or at the next start. The .deb is updated by APT from the project's
signed repository; the portable zip and source installations only get the notice.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import storage
from .common import WalletError, __version__, _json, debug
from .i18n import tr
from .storage import load_settings, save_settings

REPOSITORY = "CitComAI-Hub/atesta-id-wallet"
RELEASES_PAGE = f"https://github.com/{REPOSITORY}/releases"
LATEST_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
DOWNLOAD_PREFIX = f"{RELEASES_PAGE}/download/"
CHECK_INTERVAL = 24 * 3600
# Ed25519 key that signs SHA256SUMS (secret UPDATE_SIGNING_KEY of release.yml; docs/RELEASING.md).
UPDATE_PUBLIC_KEY = "c3vZ/S3X7r6jhD0VRH71gMD3Rk8oBJKfs+b/8rE24hk="
SUMS, SIGNATURE = "SHA256SUMS", "SHA256SUMS.sig"
MAX_DOWNLOAD = 400 * 1024 * 1024
FROZEN = bool(getattr(sys, "frozen", False))
SELF_UPDATING = ("appimage", "windows-installer")
VERSION_TAG = re.compile(r"v?\d{1,4}(\.\d{1,4}){1,3}")


@dataclass(frozen=True)
class Release:
    version: str
    url: str
    assets: tuple[tuple[str, str], ...] = ()  # (file name, download URL)

    def asset_url(self, name: str) -> str:
        for asset, url in self.assets:
            if asset == name:
                return url
        raise WalletError(tr("Version {version} has no file {name}.", version=self.version, name=name))


def parse_version(text: str) -> tuple[int, ...]:
    """'v0.6.0' -> (0, 6, 0); () if it does not look like a version."""
    match = re.match(r"v?(\d+(?:\.\d+)*)", (text or "").strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def _headers() -> dict[str, str]:
    return {"User-Agent": f"atesta-id-wallet/{__version__}"}


def latest_release(timeout: float = 10) -> Release:
    """Latest published version (/releases/latest already leaves out drafts and pre-releases)."""
    response = requests.get(LATEST_API, timeout=timeout,
                            headers={"Accept": "application/vnd.github+json", **_headers()})
    if response.status_code == 404:  # no published versions, or a private repository
        raise WalletError(tr("No published version was found at {url}", url=RELEASES_PAGE))
    if response.status_code in (403, 429) and response.headers.get("X-RateLimit-Remaining") == "0":
        # GitHub allows 60 anonymous requests per hour per IP address (shared behind a NAT)
        raise WalletError(tr("GitHub is limiting requests from this network; try again in an hour."))
    data = _json(response, "GET", LATEST_API)
    tag = str(data.get("tag_name") or "")
    # The version goes into file names and paths (asset_name): digits and dots only.
    if not VERSION_TAG.fullmatch(tag):
        raise WalletError(tr("Version {version} is not newer than this one.", version=tag[:40]))
    url = str(data.get("html_url") or "")
    # Only a page under the project's releases is opened in the browser, never another address.
    if not url.startswith(RELEASES_PAGE + "/"):
        url = RELEASES_PAGE
    assets = []
    for asset in data.get("assets") or []:
        if isinstance(asset, dict):
            name, link = str(asset.get("name") or ""), str(asset.get("browser_download_url") or "")
            if link.startswith(DOWNLOAD_PREFIX):  # files of this project only
                assets.append((name, link))
    return Release(tag.lstrip("v"), url, tuple(assets))


def newer_release(current: str = __version__) -> Release | None:
    release = latest_release()
    latest = parse_version(release.version)
    return release if latest and latest > parse_version(current) else None


# -- settings -----------------------------------------------------------------

def automatic_check_enabled() -> bool:
    return load_settings().get("update_check", True) is True


def set_automatic_check(enabled: bool) -> None:
    settings = load_settings()
    settings["update_check"] = enabled
    save_settings(settings)


def automatic_check_due(now: float | None = None) -> bool:
    settings = load_settings()
    last = settings.get("update_checked_at")
    last = last if isinstance(last, (int, float)) else 0
    return automatic_check_enabled() and (now or time.time()) - last >= CHECK_INTERVAL


def record_check(now: float | None = None) -> None:
    settings = load_settings()
    settings["update_checked_at"] = int(now or time.time())
    save_settings(settings)


# -- how this copy was installed --------------------------------------------

def install_kind() -> str:
    """appimage, windows-installer, windows-portable, deb, source or other."""
    if not FROZEN:
        return "source"
    folder = Path(sys.executable).resolve().parent
    if sys.platform == "win32":
        return "windows-installer" if (folder / "unins000.exe").exists() else "windows-portable"
    if sys.platform.startswith("linux"):
        if os.environ.get("APPIMAGE"):
            return "appimage"
        if folder == Path("/opt/atesta-id-wallet"):
            return "deb"
    return "other"


def can_update_itself() -> bool:
    return install_kind() in SELF_UPDATING


def asset_name(kind: str, version: str) -> str:
    if kind == "appimage":
        return f"Atesta_ID_Wallet-{version}-x86_64.AppImage"
    if kind == "windows-installer":
        return f"Atesta_ID_Wallet-{version}-windows-x64-setup.exe"
    raise WalletError(tr("This installation cannot update itself."))


# -- download and verification ----------------------------------------------

def updates_dir() -> Path:
    return storage.BASE_DIR / "updates"


def _pending_file() -> Path:
    return updates_dir() / "pending.json"


def _download(url: str, sink, limit: int, timeout: float = 30) -> None:
    if not url.startswith(DOWNLOAD_PREFIX):
        raise WalletError(tr("Refusing to download from {url}", url=url))
    with requests.get(url, stream=True, timeout=timeout, headers=_headers()) as response:
        if response.status_code != 200:
            raise WalletError(tr("Download failed ({status}): {url}", status=response.status_code, url=url))
        size = 0
        for chunk in response.iter_content(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise WalletError(tr("The download is larger than expected: {url}", url=url))
            sink(chunk)


def _download_bytes(url: str, limit: int = 64 * 1024) -> bytes:
    data = bytearray()
    _download(url, data.extend, limit)
    return bytes(data)


def verify_checksums(sums: bytes, signature: bytes, public_key: str | None = None) -> dict[str, str]:
    """{file name: sha256} of a SHA256SUMS whose detached signature (base64 Ed25519) is valid."""
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key or UPDATE_PUBLIC_KEY))
        key.verify(base64.b64decode(signature.strip(), validate=True), sums)
    except (InvalidSignature, ValueError, binascii.Error):
        raise WalletError(tr("The signature of the new version is not valid; it was not installed.")) from None
    checksums = {}
    for line in sums.decode("utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](\S+)", line.strip())
        if match:
            checksums[match.group(2)] = match.group(1)
    return checksums


def download_update(release: Release, kind: str | None = None) -> Path:
    """Downloads and verifies the new version for this installation, and gets it ready to install.

    AppImage: replaced right away (the next launch is the new version). Windows: the installer
    waits in updates/ for install_pending() (window restart or next start)."""
    kind = kind or install_kind()
    if not VERSION_TAG.fullmatch(release.version) or parse_version(release.version) <= parse_version(__version__):
        raise WalletError(tr("Version {version} is not newer than this one.", version=release.version))
    name = asset_name(kind, release.version)
    checksums = verify_checksums(_download_bytes(release.asset_url(SUMS)),
                                 _download_bytes(release.asset_url(SIGNATURE)))
    expected = checksums.get(name)
    if not expected:  # signed list of another version (replayed): its files have other names
        raise WalletError(tr("The signed list of version {version} does not include {name}.",
                             version=release.version, name=name))
    folder = updates_dir()
    shutil.rmtree(folder, ignore_errors=True)  # earlier downloads
    folder.mkdir(parents=True, exist_ok=True)
    target, partial = folder / name, folder / (name + ".part")
    digest = hashlib.sha256()
    with open(partial, "wb") as out:
        def write(chunk: bytes) -> None:
            digest.update(chunk)
            out.write(chunk)
        _download(release.asset_url(name), write, MAX_DOWNLOAD, timeout=60)
    if digest.hexdigest() != expected:
        partial.unlink(missing_ok=True)
        raise WalletError(tr("The downloaded file does not match the signed checksum; it was not installed."))
    os.replace(partial, target)
    if kind == "appimage":
        replace_appimage(target)
        shutil.rmtree(folder, ignore_errors=True)
    else:
        _pending_file().write_text(json.dumps({"version": release.version, "file": name, "sha256": expected}),
                                   encoding="utf-8")
    return target


def replace_appimage(new: Path, current: Path | None = None) -> None:
    """Puts the new AppImage in place of the running one, keeping its path (menu entry, links)."""
    current = current or Path(os.environ["APPIMAGE"])
    temporary = current.with_name(f".{current.name}.new")
    try:
        shutil.copyfile(new, temporary)
        shutil.copymode(current, temporary)  # executable, like the one it replaces
        os.replace(temporary, current)  # atomic; the running copy keeps its open file
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise WalletError(tr("Could not replace {path}: {error}", path=current, error=exc)) from None


def pending_update() -> dict | None:
    """The downloaded installer waiting to run, if it is still newer and intact."""
    try:
        pending = json.loads(_pending_file().read_text(encoding="utf-8"))
        path = updates_dir() / Path(str(pending["file"])).name
        if parse_version(str(pending["version"])) > parse_version(__version__) and path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() == pending["sha256"]:
                return {**pending, "path": path}
    except (OSError, ValueError, KeyError, TypeError):
        return None
    shutil.rmtree(updates_dir(), ignore_errors=True)  # installed already, or damaged
    return None


def install_pending() -> bool:
    """Windows: starts the downloaded installer (it closes the wallet and opens it again when done).

    True if it was started: the caller must then exit."""
    pending = pending_update() if install_kind() == "windows-installer" else None
    if not pending:
        return False
    _pending_file().unlink(missing_ok=True)  # one attempt: if it fails, the next check downloads it again
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        subprocess.Popen([str(pending["path"]), "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                          "/CLOSEAPPLICATIONS", "/LAUNCH=1"], creationflags=flags, close_fds=True)
    except OSError as exc:
        debug(f"Could not start the installer: {exc}")
        return False
    return True


def relaunch_command() -> list[str] | None:
    """Command that starts the (already replaced) application again, or None."""
    if install_kind() == "appimage":
        return [os.environ["APPIMAGE"]]
    return None

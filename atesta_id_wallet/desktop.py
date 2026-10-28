# -*- coding: utf-8 -*-
"""Integración con el escritorio: portapapeles, capturas con QR y enlaces (Linux, Windows, macOS)."""

from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .common import URI_SCHEMES, WalletError, debug, log
from .i18n import tr

DESKTOP_FILE = (
    Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    / "applications" / "atesta-id-wallet.desktop"
)
ICON_THEME_FILE = (
    Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    / "icons" / "hicolor" / "256x256" / "apps" / "atesta-id-wallet.png"
)
APP_ICON = Path(__file__).resolve().parent / "gui" / "icons" / "app-icon.png"
# Ejecutable de PyInstaller (AppImage, .deb o instalador de Windows) en vez de un paquete de Python.
FROZEN = bool(getattr(sys, "frozen", False))
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg")
QR_PREFIXES = ("openid4vp:", "openid-credential-offer:", "https://")


# ---------------------------------------------------------------------------
# QR
# ---------------------------------------------------------------------------


def decode_qr(image: Any) -> list[str]:
    """Textos de los códigos QR de una imagen de Pillow (zxing-cpp)."""
    import zxingcpp

    return [result.text for result in zxingcpp.read_barcodes(image) if result.text]


def _decode_qr_zbar(path: Path) -> list[str]:
    """Reserva si zxing-cpp no está disponible (instalaciones antiguas)."""
    try:
        result = subprocess.run(["zbarimg", "-q", "--raw", str(path)], capture_output=True, text=True, timeout=20)
    except FileNotFoundError as exc:
        raise WalletError(tr("QR codes cannot be read: install zxing-cpp and Pillow (pip install zxing-cpp pillow).")) from exc
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _wallet_qr(codes: list[str], source: str) -> str:
    links = [c for c in codes if c.startswith(QR_PREFIXES)]
    if not links:
        raise WalletError(tr("No OpenID QR code was found in {source}.", source=source))
    # Si en la imagen hay también un QR con una web cualquiera, se prefiere el del wallet.
    return next((c for c in links if _is_wallet_link(c)), links[0])


def decode_qr_image(path_text: str, *, quiet: bool = False) -> str:
    """Decodifica el QR de una imagen. Si se pasa una carpeta, usa la imagen más reciente."""
    path = Path(path_text).expanduser()
    if path.is_dir():
        images = [p for p in path.iterdir() if p.suffix.lower() in IMAGE_SUFFIXES]
        if not images:
            raise WalletError(tr("There are no images in {path}", path=path))
        path = max(images, key=lambda p: p.stat().st_mtime)
    if not quiet:
        log(tr("Reading the QR code from {path}", path=path))
    try:
        from PIL import Image

        with Image.open(path) as image:
            codes = decode_qr(image)
    except ImportError:
        codes = _decode_qr_zbar(path)
    except OSError as exc:
        raise WalletError(tr("Could not open the image {path}: {error}", path=path, error=exc)) from exc
    return _wallet_qr(codes, str(path))


# ---------------------------------------------------------------------------
# Portapapeles
# ---------------------------------------------------------------------------


def _clipboard_commands() -> list[list[str]]:
    if sys.platform == "win32":
        return [["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"]]
    if sys.platform == "darwin":
        return [["pbpaste"]]
    return [["wl-paste", "--no-newline"], ["xclip", "-o", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--output"]]


def _clipboard_bytes() -> bytes | None:
    """Contenido crudo del portapapeles: texto, o en Linux también la imagen (PNG)."""
    for command in _clipboard_commands():
        try:
            result = subprocess.run(command, capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return result.stdout
    return None


def _clipboard_image() -> Any:
    """Imagen del portapapeles en Windows/macOS (en Linux llega por _clipboard_bytes)."""
    if sys.platform not in ("win32", "darwin"):
        return None
    try:
        from PIL import Image, ImageGrab

        content = ImageGrab.grabclipboard()
    except Exception as exc:  # sin Pillow o portapapeles no accesible
        debug(f"Could not read an image from the clipboard: {exc}")
        return None
    return content if isinstance(content, Image.Image) else None


def _qr_from_bytes(data: bytes) -> str | None:
    try:
        from PIL import Image

        with Image.open(io.BytesIO(data)) as image:
            return _wallet_qr(decode_qr(image), tr("the clipboard"))
    except (ImportError, OSError, WalletError):
        return None


def clipboard_link() -> str | None:
    """Enlace del portapapeles, ya sea texto o una imagen con QR (Impr Pant la copia)."""
    data = _clipboard_bytes()
    if data and data.startswith((b"\x89PNG", b"\xff\xd8\xff")):  # PNG / JPEG
        link = _qr_from_bytes(data)
        if link:
            log(tr("Using the QR code of the image in the clipboard."))
        return link
    if data:
        text = data.decode("utf-8", errors="replace").strip()
        if _is_wallet_link(text):
            log(tr("Using the link in the clipboard."))
            return text
    image = _clipboard_image()
    if image is not None:
        try:
            link = _wallet_qr(decode_qr(image), tr("the clipboard"))
        except (ImportError, WalletError):
            return None
        log(tr("Using the QR code of the image in the clipboard."))
        return link
    return None


# ---------------------------------------------------------------------------
# Capturas de pantalla recientes
# ---------------------------------------------------------------------------


def _screenshot_dirs() -> list[Path]:
    home = Path.home()
    if sys.platform == "darwin":
        candidates = [home / "Desktop", home / "Pictures" / "Screenshots"]
        try:
            result = subprocess.run(["defaults", "read", "com.apple.screencapture", "location"],
                                    capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and result.stdout.strip():
                candidates.insert(0, Path(result.stdout.strip()).expanduser())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    else:
        pictures = [home / "Pictures", home / "Imágenes", home / "Billeder"]
        if sys.platform == "win32":
            onedrive = Path(os.environ.get("OneDrive") or home / "OneDrive")
            pictures += [onedrive / "Pictures", onedrive / "Imágenes", onedrive / "Billeder"]
        else:
            try:
                result = subprocess.run(["xdg-user-dir", "PICTURES"], capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and result.stdout.strip():
                    pictures.insert(0, Path(result.stdout.strip()))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        candidates = [base / sub if sub else base
                      for base in pictures for sub in ("Screenshots", "Capturas de pantalla", "Skærmbilleder", "")]
    dirs: list[Path] = []
    for candidate in candidates:
        if candidate.is_dir() and candidate not in dirs:
            dirs.append(candidate)
    return dirs


def _is_wallet_link(text: str) -> bool:
    text = text.strip().lower()
    return any(text.startswith(f"{s}:") or text.startswith(f"{s}%3a") for s in URI_SCHEMES)


def auto_detect_input(max_age: int = 300) -> str | None:
    """Enlace del portapapeles o QR de una captura de los últimos max_age segundos."""
    return clipboard_link() or screenshot_link(max_age)


def screenshot_link(max_age: float = 300) -> str | None:
    """QR de la captura de pantalla más reciente de los últimos max_age segundos."""
    now = time.time()
    recent: list[tuple[float, Path]] = []
    for directory in _screenshot_dirs():
        try:
            for path in directory.iterdir():
                if path.suffix.lower() in IMAGE_SUFFIXES:
                    mtime = path.stat().st_mtime
                    if now - mtime < max_age:
                        recent.append((mtime, path))
        except OSError:  # carpeta sin permiso o fichero borrado mientras se lista
            continue
    for _, image in sorted(recent, reverse=True):
        try:
            return decode_qr_image(str(image))
        except WalletError:
            continue
    return None


def detect_input(max_age: int = 300) -> str:
    """Enlace del portapapeles, o QR de una captura reciente, o lo que se pegue."""
    while True:
        found = auto_detect_input(max_age)
        if found:
            return found
        print(tr("There is no link in the clipboard and no recent screenshot with a QR code.\n"
                 "Take a screenshot of the QR code and press Enter, or paste the link / the image path."))
        entered = input("> ").strip().strip("'\"")
        if entered:
            return entered


def route_input(entry: str) -> tuple[str, list[str]]:
    """Decide el subcomando según el contenido: oferta -> issue, petición -> present."""
    entry = entry.strip().strip("'\"")
    if not _is_wallet_link(entry) and not entry.startswith(("http://", "https://")):
        path = Path(entry).expanduser()
        if path.exists():
            entry = decode_qr_image(str(path))
    lowered = entry.lower()
    if lowered.startswith(("openid-credential-offer:", "openid-credential-offer%3a")):
        return "issue", ["--offer", entry]
    if lowered.startswith(("openid4vp:", "openid4vp%3a")):
        return "present", ["--request", entry]
    raise WalletError(tr("Unrecognised input. Expected an openid-credential-offer:// or openid4vp:// link, "
                         "or an image with its QR code."))


# ---------------------------------------------------------------------------
# Manejador de enlaces openid4vp:// y openid-credential-offer://
# ---------------------------------------------------------------------------


def gui_available() -> bool:
    if FROZEN:  # cada ejecutable lleva solo sus módulos: la GUI es el otro ejecutable
        return _frozen_executable(True).exists()
    import importlib.util

    return importlib.util.find_spec("PySide6") is not None


def _frozen_executable(gui: bool) -> Path:
    """Los dos ejecutables empaquetados están en la misma carpeta."""
    name = "atesta-id-wallet-gui" if gui else "atesta-id-wallet"
    return Path(sys.executable).with_name(name + (".exe" if sys.platform == "win32" else ""))


def _launcher(gui: bool = False) -> list[str]:
    appimage = os.environ.get("APPIMAGE")  # ruta del .AppImage; su AppRun abre la GUI o, con 'cli', la terminal
    if FROZEN and appimage:
        return [appimage] if gui else [appimage, "cli"]
    if FROZEN:
        return [str(_frozen_executable(gui))]
    if gui:
        installed = shutil.which("atesta-id-wallet-gui")
        return [installed] if installed else [sys.executable, "-m", "atesta_id_wallet.gui"]
    installed = shutil.which("atesta-id-wallet")
    return [installed] if installed else [sys.executable, "-m", "atesta_id_wallet"]


def _desktop_exec(gui: bool = False) -> str:
    return " ".join(f'"{p}"' if " " in p else p for p in _launcher(gui))


def _windows_command(gui: bool = False) -> str:
    # La GUI no necesita --pause: el resultado se ve en la ventana.
    return " ".join(f'"{p}"' for p in _launcher(gui)) + (' "%1"' if gui else ' --pause "%1"')


def _install_icon() -> str:
    """Copia el icono de la aplicación al tema de iconos del usuario; si no hay, uno genérico."""
    if not APP_ICON.exists():
        return "dialog-password"
    ICON_THEME_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(APP_ICON, ICON_THEME_FILE)
    return "atesta-id-wallet"


def _install_linux(gui: bool) -> None:
    DESKTOP_FILE.parent.mkdir(parents=True, exist_ok=True)
    mime_types = "".join(f"x-scheme-handler/{s};" for s in URI_SCHEMES)
    exec_line = f"{_desktop_exec(gui)} %u" if gui else f"{_desktop_exec()} --pause %u"
    DESKTOP_FILE.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Atesta ID Wallet\n"
        "Comment=Verifiable credentials wallet (OpenID4VCI / OpenID4VP)\n"
        "Comment[es]=Wallet de credenciales verificables (OpenID4VCI / OpenID4VP)\n"
        "Comment[da]=Wallet til verificerbare legitimationer (OpenID4VCI / OpenID4VP)\n"
        f"Exec={exec_line}\n"
        f"Icon={_install_icon()}\n"
        f"Terminal={'false' if gui else 'true'}\n"
        "Categories=Utility;Security;\n"
        f"MimeType={mime_types}\n",
        encoding="utf-8",
    )
    for scheme in URI_SCHEMES:
        subprocess.run(["xdg-mime", "default", DESKTOP_FILE.name, f"x-scheme-handler/{scheme}"], check=False)
    subprocess.run(["update-desktop-database", str(DESKTOP_FILE.parent)], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(tr("✔ Installed {file}", file=DESKTOP_FILE))
    print(tr("  · 'Atesta ID Wallet' appears in the applications menu (graphical interface).") if gui else
          tr("  · 'Atesta ID Wallet' appears in the applications menu: it reads the clipboard or the latest screenshot."))


def _install_windows(gui: bool) -> None:
    """HKCU\\Software\\Classes\\<esquema>: no necesita permisos de administrador."""
    import winreg

    command = _windows_command(gui)
    for scheme in URI_SCHEMES:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{scheme}") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"URL:{scheme}")
            winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
            with winreg.CreateKey(key, r"shell\open\command") as cmd:
                winreg.SetValueEx(cmd, "", 0, winreg.REG_SZ, command)
    print(tr("✔ Links registered in HKCU\\Software\\Classes ({command})", command=command))


def _uninstall_windows() -> bool:
    import winreg

    removed = False
    for scheme in URI_SCHEMES:
        base = rf"Software\Classes\{scheme}"
        for sub in (r"\shell\open\command", r"\shell\open", r"\shell", ""):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + sub)
                removed = True
            except FileNotFoundError:
                pass
    return removed


def cmd_install_handler(args: argparse.Namespace | None) -> int:
    gui = gui_available() and not getattr(args, "terminal", False)
    if sys.platform == "win32":
        _install_windows(gui)
    elif sys.platform == "darwin":
        raise WalletError(tr("On macOS, openid4vp:// links need a packaged application (.app), which is not "
                             "available yet. Use 'atesta-id-wallet' with the link, the clipboard or a screenshot."))
    else:
        _install_linux(gui)
    print(tr("  · openid4vp:// and openid-credential-offer:// links will open with the wallet."))
    return 0


def cmd_uninstall_handler(_: argparse.Namespace) -> int:
    if sys.platform == "win32":
        print(tr("✔ Links removed from the registry.") if _uninstall_windows() else tr("The handler was not installed."))
    elif DESKTOP_FILE.exists():
        DESKTOP_FILE.unlink()
        ICON_THEME_FILE.unlink(missing_ok=True)
        subprocess.run(["update-desktop-database", str(DESKTOP_FILE.parent)], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(tr("✔ Removed {file}", file=DESKTOP_FILE))
    else:
        print(tr("The handler was not installed."))
    return 0

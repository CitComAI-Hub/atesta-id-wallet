# -*- coding: utf-8 -*-
"""
Aviso de versiones nuevas (GitHub Releases).

Solo se consulta GitHub si el usuario lo pide (Ajustes / `atesta-id-wallet update`) o activa la
comprobación automática (una vez al día como mucho). La petición no lleva datos del wallet:
GitHub solo ve la dirección IP y la versión en el User-Agent. No se descarga ni instala nada.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

import requests

from .common import WalletError, __version__, _json
from .i18n import tr
from .storage import load_settings, save_settings

REPOSITORY = "CitComAI-Hub/atesta-id-wallet"
RELEASES_PAGE = f"https://github.com/{REPOSITORY}/releases"
LATEST_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
CHECK_INTERVAL = 24 * 3600


@dataclass(frozen=True)
class Release:
    version: str
    url: str


def parse_version(text: str) -> tuple[int, ...]:
    """'v0.6.0' -> (0, 6, 0); () si no parece una versión."""
    match = re.match(r"v?(\d+(?:\.\d+)*)", (text or "").strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def latest_release(timeout: float = 10) -> Release:
    """Última versión publicada (/releases/latest ya excluye borradores y versiones previas)."""
    response = requests.get(LATEST_API, timeout=timeout, headers={
        "Accept": "application/vnd.github+json", "User-Agent": f"atesta-id-wallet/{__version__}"})
    if response.status_code == 404:  # sin versiones publicadas, o repositorio privado
        raise WalletError(tr("No published version was found at {url}", url=RELEASES_PAGE))
    data = _json(response, "GET", LATEST_API)
    tag = str(data.get("tag_name") or "")
    url = str(data.get("html_url") or "")
    # Solo se abre en el navegador una página de las releases del proyecto, nunca otra dirección.
    if not url.startswith(RELEASES_PAGE + "/"):
        url = RELEASES_PAGE
    return Release(tag.lstrip("v"), url)


def newer_release(current: str = __version__) -> Release | None:
    release = latest_release()
    latest = parse_version(release.version)
    return release if latest and latest > parse_version(current) else None


def automatic_check_enabled() -> bool:
    return load_settings().get("update_check") is True


def set_automatic_check(enabled: bool) -> None:
    settings = load_settings()
    settings["update_check"] = enabled
    save_settings(settings)


def automatic_check_due(now: float | None = None) -> bool:
    settings = load_settings()
    last = settings.get("update_checked_at")
    last = last if isinstance(last, (int, float)) else 0
    return settings.get("update_check") is True and (now or time.time()) - last >= CHECK_INTERVAL


def record_check(now: float | None = None) -> None:
    settings = load_settings()
    settings["update_checked_at"] = int(now or time.time())
    save_settings(settings)

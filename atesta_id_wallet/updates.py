# -*- coding: utf-8 -*-
"""
New-version notice (GitHub Releases).

GitHub is only asked when the user requests it (Settings / `atesta-id-wallet update`) or turns on
the automatic check (at most once a day). The request carries no wallet data: GitHub only sees
the IP address and the version in the User-Agent. Nothing is downloaded or installed.
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
    """'v0.6.0' -> (0, 6, 0); () if it does not look like a version."""
    match = re.match(r"v?(\d+(?:\.\d+)*)", (text or "").strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def latest_release(timeout: float = 10) -> Release:
    """Latest published version (/releases/latest already leaves out drafts and pre-releases)."""
    response = requests.get(LATEST_API, timeout=timeout, headers={
        "Accept": "application/vnd.github+json", "User-Agent": f"atesta-id-wallet/{__version__}"})
    if response.status_code == 404:  # no published versions, or a private repository
        raise WalletError(tr("No published version was found at {url}", url=RELEASES_PAGE))
    data = _json(response, "GET", LATEST_API)
    tag = str(data.get("tag_name") or "")
    url = str(data.get("html_url") or "")
    # Only a page under the project's releases is opened in the browser, never another address.
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

# -*- coding: utf-8 -*-
"""Common helpers: errors, messages, base64url/JWT and HTTP."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import sys
from typing import Any, Callable
from urllib.parse import SplitResult, quote, unquote, urlsplit

import requests

from .i18n import tr


__version__ = "0.9.0"
URI_SCHEMES = ("openid4vp", "openid-credential-offer")
SD_JWT_FORMATS = ("dc+sd-jwt", "vc+sd-jwt")
VERBOSE = False
# Where log()/debug() go: None = console; the GUI sets a function (message, is_debug).
LOG_HANDLER: Callable[[str, bool], None] | None = None


class WalletError(Exception):
    pass


class Cancelled(WalletError):
    """The user chose not to go on (not an error: it is not shown as one)."""

    def __init__(self, message: str | None = None):
        super().__init__(message or tr("Cancelled by the user."))


def log(message: str) -> None:
    if LOG_HANDLER:
        LOG_HANDLER(message, False)
    else:
        print(f"[wallet] {message}", flush=True)


def debug(message: str) -> None:
    if not VERBOSE:
        return
    if LOG_HANDLER:
        LOG_HANDLER(message, True)
    else:
        print(f"[wallet:debug] {message}", flush=True)


def confirm(question: str, *, default: bool = False, assume_yes: bool = False) -> bool:
    """Asks y/n. Without a terminal there is no consent: the answer is 'no' unless --yes."""
    if assume_yes:
        return True
    if not sys.stdin or not sys.stdin.isatty():
        raise WalletError(tr("{question} — interactive confirmation needed (or --yes).", question=question))
    hint = tr("[Y/n]") if default else tr("[y/N]")
    answer = input(f"{question} {hint} ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes", *tr("y,yes").split(",")}


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:  # e.g. an unbalanced '[' (IPv6 literal)
        return ""


# Second-level labels under which a country code hands out domains (example.co.uk, example.com.es).
_SECOND_LEVEL = {"ac", "co", "com", "edu", "gob", "gov", "net", "nom", "org"}
# Shared hosting where anyone gets a subdomain: "github.io" would name every site on it, so for these
# the full host is shown. (The proper source is the Public Suffix List; this covers the common ones.)
_SHARED_HOSTING = {
    "amazonaws.com", "appspot.com", "azurewebsites.net", "blogspot.com", "cloudfront.net", "duckdns.org",
    "firebaseapp.com", "fly.dev", "github.io", "gitlab.io", "glitch.me", "herokuapp.com", "netlify.app",
    "ngrok-free.app", "ngrok.app", "ngrok.io", "nip.io", "onrender.com", "pages.dev", "replit.dev",
    "sslip.io", "trycloudflare.com", "vercel.app", "web.app", "workers.dev",
}


def site_of(url: str) -> str:
    """
    The organisation's domain, to name an issuer that publishes no name: keycloak.city.example.eu
    -> city.example.eu is not it, example.eu is (the full host is still shown where trust is decided).
    """
    host = host_of(url)
    labels = host.split(".")
    if len(labels) <= 2 or host.replace(".", "").isdigit():
        return host
    keep = 3 if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL else 2
    site = ".".join(labels[-keep:])
    return host if site in _SHARED_HOSTING else site


def is_local_host(host: str | None) -> bool:
    """This computer or the local network: localhost, loopback, private and link-local addresses."""
    host = (host or "").lower().strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local or address.is_unspecified


def local_http_allowed() -> bool:
    """http://localhost only for development and the tests (ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP=1): otherwise a
    QR code could make the wallet call services on this computer."""
    return os.environ.get("ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP") == "1"


def split_url(url: str, what: str) -> SplitResult:
    """urlsplit for addresses that come from outside: WalletError instead of ValueError."""
    try:
        parts = urlsplit(url)
        parts.hostname  # noqa: B018  (parses the host: raises on e.g. an unbalanced '[')
        parts.port  # noqa: B018  (raises on a port that is not a number)
    except ValueError as exc:
        raise WalletError(tr("{what} is not a valid URL: {url}", what=what, url=url)) from exc
    return parts


def require_https(url: str, what: str) -> None:
    """HTTPS is required; http://localhost only with ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP=1."""
    parts = split_url(url, what)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")
                                   and local_http_allowed()):
        return
    raise WalletError(tr("{what} must use https: {url}", what=what, url=url))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def jwt_decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise WalletError(tr("The value is not a compact JWS (header.payload.signature)."))
    try:
        header, payload = json.loads(b64u_decode(parts[0])), json.loads(b64u_decode(parts[1]))
    except ValueError as exc:  # invalid base64 or JSON (binascii.Error and UnicodeDecodeError are ValueError)
        raise WalletError(tr("The value is not a compact JWS (header.payload.signature).")) from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise WalletError(tr("The value is not a compact JWS (header.payload.signature)."))
    return header, payload


def parse_json(text: str, what: str) -> Any:
    """json.loads with a readable WalletError if the received content is not JSON."""
    try:
        return json.loads(text)
    except ValueError as exc:
        raise WalletError(tr("{what} is not valid JSON.", what=what)) from exc


def _http_error(method: str, url: str, response: requests.Response) -> WalletError:
    body = response.text.strip()
    if len(body) > 800:
        body = body[:800] + "..."
    return WalletError(f"{method} {url} -> HTTP {response.status_code}: {body}")


def _json(response: requests.Response, method: str, url: str) -> dict[str, Any]:
    if response.status_code >= 400:
        raise _http_error(method, url, response)
    try:
        data = response.json()
    except ValueError as exc:
        raise WalletError(tr("{method} {url} did not return JSON: {body}", method=method, url=url,
                             body=response.text[:300])) from exc
    if not isinstance(data, dict):
        raise WalletError(tr("{method} {url} returned JSON that is not an object.", method=method, url=url))
    return data


def _last_deep_link(raw: str, scheme: str) -> str:
    """Tolerates duplicated pastes and spaces/line breaks in the middle."""
    raw = re.sub(r"\s+", "", raw.strip().strip("'\""))
    if raw.lower().startswith(quote(scheme, safe="").lower()):
        raw = unquote(raw)
    idx = raw.lower().rfind(scheme)
    if idx > 0:
        log(tr("Warning: the input contains '{scheme}' more than once; using the last one.", scheme=scheme))
        raw = raw[idx:]
    return raw


def humanize(identifier: str) -> str:
    """LegalPersonCredential -> Legal Person Credential; first_name -> First name."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|[_\-.]+", " ", identifier).strip()
    return spaced[:1].upper() + spaced[1:] if spaced else identifier

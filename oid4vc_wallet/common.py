# -*- coding: utf-8 -*-
"""Utilidades comunes: errores, mensajes, base64url/JWT y HTTP."""

from __future__ import annotations

import base64
import json
import re
import sys
from typing import Any, Callable
from urllib.parse import quote, unquote, urlsplit

import requests

from .i18n import tr


__version__ = "0.6.0"
URI_SCHEMES = ("openid4vp", "openid-credential-offer")
SD_JWT_FORMATS = ("dc+sd-jwt", "vc+sd-jwt")
VERBOSE = False
# Destino de log()/debug(): None = consola; la GUI pone una función (mensaje, es_debug).
LOG_HANDLER: Callable[[str, bool], None] | None = None


class WalletError(Exception):
    pass


class Cancelled(WalletError):
    """El usuario decidió no continuar (no es un error: no se muestra como tal)."""

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
    """Pregunta s/n. Sin terminal no se puede consentir: se responde 'no' salvo --yes."""
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
    return (urlsplit(url).hostname or "").lower()


def require_https(url: str, what: str) -> None:
    """HTTPS obligatorio salvo en localhost (pruebas)."""
    parts = urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")):
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
    except ValueError as exc:  # base64 o JSON inválidos (binascii.Error y UnicodeDecodeError son ValueError)
        raise WalletError(tr("The value is not a compact JWS (header.payload.signature).")) from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise WalletError(tr("The value is not a compact JWS (header.payload.signature)."))
    return header, payload


def parse_json(text: str, what: str) -> Any:
    """json.loads con un WalletError legible si el contenido recibido no es JSON."""
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
    """Tolera pegados duplicados y espacios/saltos de línea intercalados."""
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

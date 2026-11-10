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

from .i18n import N_, tr


__version__ = "0.12.0"
URI_SCHEMES = ("openid4vp", "openid-credential-offer")
SD_JWT_FORMATS = ("dc+sd-jwt", "vc+sd-jwt")
VERBOSE = False
# Where log()/debug() go: None = console; the GUI sets a function (message, is_debug).
LOG_HANDLER: Callable[[str, bool], None] | None = None


class WalletError(Exception):
    """
    A problem the flow cannot get past. The message is technical (it goes to the log and to the
    technical details); 'hint', when given, is what the window tells a non-technical user instead.
    """

    def __init__(self, message: str = "", *, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


class Cancelled(WalletError):
    """The user chose not to go on (not an error: it is not shown as one)."""

    def __init__(self, message: str | None = None):
        super().__init__(message or tr("Cancelled by the user."))


# Values that let someone else act as the user (codes, tokens, passwords) or carry personal data
# (credentials, presentations). Logs and technical details are meant to be pasted into a support
# request, so they never contain them.
SECRET_KEYS = ("pre-authorized_code", "code", "tx_code", "user_pin", "access_token", "refresh_token", "id_token",
               "code_verifier", "password", "client_secret", "issuer_state", "state", "session_state", "vp_token",
               "credential", "credentials")
REDACTED = "<redacted>"
_KEYS = "|".join(re.escape(k) for k in sorted(SECRET_KEYS, key=len, reverse=True))
_REDACTIONS = (
    # JSON and Python reprs: "code": "…" / 'code': '…' (also cut short by a [:200]).
    (re.compile(rf"""(?<![\w-])(["'])({_KEYS})\1(\s*:\s*)(["'])(?:(?!\4).)*\4?"""), rf"\1\2\1\3\4{REDACTED}\4"),
    # Query strings, fragments and form bodies: ?code=… &state=…
    (re.compile(rf"(?<![\w-])({_KEYS})=[^&#\s\"']*"), rf"\1={REDACTED}"),
    # Authorization and DPoP headers.
    (re.compile(r"(?i)\b(Bearer|DPoP)(\s+)[A-Za-z0-9._~+/=-]{16,}"), rf"\1\2{REDACTED}"),
    # Compact JWS/JWE and SD-JWT (credentials, proofs, tokens), whole or cut short.
    (re.compile(r"eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*){1,4}(?:~[A-Za-z0-9_.~-]*)?"), f"<JWT {REDACTED}>"),
)


def redact(text: str) -> str:
    """Removes secrets and personal data from text meant for logs and technical details."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


# Characters that change how a line is shown instead of being shown: C0/C1 controls (ESC starts the
# terminal sequences that move the cursor or erase the screen) and the bidirectional overrides, which
# make "evil.example" read as something else. Line breaks and tabs are kept.
_UNSAFE_CHARS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def printable(text: Any) -> str:
    """
    Text from outside (names, claim values, server errors) as it may be written to a terminal or a
    label: a verifier must not be able to erase the warning printed above its name.
    """
    return _UNSAFE_CHARS.sub("\ufffd", str(text))


def clean_text(value: Any, limit: int = 80) -> str | None:
    """A name published by an issuer, as one short line; None if it is not a usable text."""
    if not isinstance(value, str):
        return None
    text = " ".join(_UNSAFE_CHARS.sub(" ", value).split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text or None


def log(message: str) -> None:
    message = printable(redact(message))
    if LOG_HANDLER:
        LOG_HANDLER(message, False)
    else:
        print(f"[wallet] {message}", flush=True)


def debug(message: str) -> None:
    if not VERBOSE:
        return
    message = printable(redact(message))
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


class _Session(requests.Session):
    """
    A session that only talks HTTPS, also when it follows a redirect: every address the wallet is
    given is checked with require_https, and a server (or whoever answers in its name) could
    otherwise send the request on to http:// — metadata and keys read in clear text, or a service on
    this computer. Each hop of a followed redirect goes through send(); a redirect that is only
    read (allow_redirects=False, e.g. back to the wallet's loopback address) is not a request.
    """

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        require_https(request.url or "", tr("The address"))
        return super().send(request, **kwargs)


def new_session() -> requests.Session:
    """The HTTP session of a flow (see _Session)."""
    return _Session()


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


# Names of common claims (SD-JWT VC, OpenID Connect, Keycloak) in the user's language.
CLAIM_NAMES = {
    "given_name": N_("First name"), "firstName": N_("First name"), "first_name": N_("First name"),
    "family_name": N_("Last name"), "lastName": N_("Last name"), "last_name": N_("Last name"),
    "name": N_("Name"), "email": N_("Email"), "email_verified": N_("Email verified"),
    "username": N_("Username"), "preferred_username": N_("Username"),
    "birthdate": N_("Date of birth"), "birth_date": N_("Date of birth"),
    "phone_number": N_("Phone number"), "address": N_("Address"), "nationality": N_("Nationality"),
    "organization": N_("Organisation"), "organisation": N_("Organisation"),
    "legalName": N_("Legal name"), "legal_name": N_("Legal name"),
    "vatID": N_("VAT number"), "vat_id": N_("VAT number"),
    "role": N_("Role"), "roles": N_("Roles"), "groups": N_("Groups"),
}


def claim_label(name: str) -> str:
    """'given_name' -> 'First name' (translated); other claims as readable words."""
    known = CLAIM_NAMES.get(name)
    return tr(known) if known else humanize(name)

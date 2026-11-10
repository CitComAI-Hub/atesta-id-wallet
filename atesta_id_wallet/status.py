# -*- coding: utf-8 -*-
"""
Revocation of stored credentials: Token Status List (IETF draft-ietf-oauth-status-list).

A credential that can be revoked carries "status": {"status_list": {"idx": N, "uri": U}}. U serves a
JWT (typ statuslist+jwt) signed by the issuer, with a compressed array of 1, 2, 4 or 8 bits per
credential; entry N is this one's: 0 valid, 1 revoked (final), 2 suspended (may be lifted).

The list covers many credentials, so fetching it tells the issuer only that some holder looked; no
personal data is sent. The verifier checks the status itself: the wallet checks so that the user
knows, and so that it does not offer a credential that no longer works.
"""

from __future__ import annotations

import time
import zlib
from typing import Any
from urllib.parse import urljoin

import requests

from . import storage
from .common import WalletError, b64u_decode, debug, host_of, is_local_host, jwt_decode_unverified, log, \
    require_https
from .i18n import tr
from .jose import _verify_jws
from .sdjwt import SdJwt


STATES = {0: "valid", 1: "revoked", 2: "suspended"}
TOKEN_MAX_BYTES = 1024 * 1024  # the signed list as downloaded
LIST_MAX_BYTES = 16 * 1024 * 1024  # decompressed: 16 Mi entries of 8 bits (a zlib bomb stops here)
MAX_REDIRECTS = 3
# How long a check is good for when the list gives no 'ttl', and the bounds for one that does.
DEFAULT_RECHECK = 60 * 60
MIN_RECHECK = 5 * 60
MAX_RECHECK = 7 * 24 * 60 * 60


def automatic_enabled() -> bool:
    """Checked by itself (before presenting, and from time to time in the window); on by default."""
    return storage.load_settings().get("status_check") is not False


def set_automatic(enabled: bool) -> None:
    settings = storage.load_settings()
    settings["status_check"] = enabled
    storage.save_settings(settings)


class StatusError(WalletError):
    """The status could not be established (it says nothing about the credential being revoked)."""


def status_reference(sd: SdJwt) -> tuple[str, int] | None:
    """(uri, index) in the issuer's status list, or None if the credential has none."""
    status = sd.payload.get("status")
    if not isinstance(status, dict) or "status_list" not in status:
        return None
    ref = status["status_list"]
    if (not isinstance(ref, dict) or not isinstance(ref.get("uri"), str) or type(ref.get("idx")) is not int
            or ref["idx"] < 0):
        raise StatusError(tr("The credential's status reference is not valid."))
    return ref["uri"], ref["idx"]


def has_status(record: dict[str, Any]) -> bool:
    sd = record.get("_sd")
    try:
        return sd is not None and status_reference(sd) is not None
    except StatusError:
        return True  # malformed: checking it reports the problem


def decode_list(status_list: Any, uri: str = "") -> tuple[int, bytes]:
    """(bits per entry, decompressed bytes) of a 'status_list' claim."""
    def invalid(problem: str) -> StatusError:
        return StatusError(tr("The status list {uri} is not valid: {problem}.", uri=uri, problem=problem))

    if not isinstance(status_list, dict):
        raise invalid("'status_list' is not an object")
    bits, lst = status_list.get("bits"), status_list.get("lst")
    if type(bits) is not int or bits not in (1, 2, 4, 8):
        raise invalid("'bits' must be 1, 2, 4 or 8")
    if not isinstance(lst, str):
        raise invalid("'lst' is not a string")
    try:
        inflater = zlib.decompressobj()
        data = inflater.decompress(b64u_decode(lst), LIST_MAX_BYTES)
    except (ValueError, zlib.error) as exc:
        raise invalid(f"'lst' is not base64url ZLIB data ({exc})") from exc
    if inflater.unconsumed_tail:
        raise invalid("the list is too large")
    return bits, data


def status_at(bits: int, data: bytes, index: int, uri: str = "") -> int:
    """Entry 'index': entries fill each byte from its least significant bit."""
    position = index * bits
    if position // 8 >= len(data):
        raise StatusError(tr("The status list {uri} is not valid: {problem}.", uri=uri,
                             problem=f"index {index} is outside the list"))
    return (data[position // 8] >> (position % 8)) & ((1 << bits) - 1)


def fetch_token(session: requests.Session, uri: str, issuer: str) -> str:
    """Downloads the signed list (JWT form), following a few checked redirects."""
    url = uri
    for _ in range(MAX_REDIRECTS + 1):
        require_https(url, "status_list uri")
        # Not this computer or the local network: the address comes from the credential.
        if is_local_host(host_of(url)) and not is_local_host(host_of(issuer)):
            raise StatusError(tr("The status list {uri} is not valid: {problem}.", uri=uri,
                                 problem="it is on a local address"))
        with session.get(url, headers={"Accept": "application/statuslist+jwt"}, timeout=20, stream=True,
                         allow_redirects=False) as response:
            if response.is_redirect and response.headers.get("Location"):
                url = urljoin(url, response.headers["Location"])
                continue
            if response.status_code != 200:
                raise StatusError(f"GET {url} -> HTTP {response.status_code}")
            body = response.raw.read(TOKEN_MAX_BYTES + 1, decode_content=True)
        if len(body) > TOKEN_MAX_BYTES:
            raise StatusError(tr("The status list {uri} is not valid: {problem}.", uri=uri,
                                 problem="the response is too large"))
        return body.decode("ascii", errors="replace").strip()
    raise StatusError(tr("The status list {uri} is not valid: {problem}.", uri=uri, problem="too many redirects"))


def _issuer_metadata(session: requests.Session, issuer: str) -> dict[str, Any]:
    from .vci import _get_first_json, _well_known, authorization_server_metadata

    meta = _get_first_json(session, _well_known(issuer, "openid-credential-issuer"))
    if str(meta.get("credential_issuer", "")).rstrip("/") != issuer.rstrip("/"):
        raise WalletError(tr("The issuer metadata belongs to {other}, not to {issuer}.",
                             other=meta.get("credential_issuer"), issuer=issuer))
    return authorization_server_metadata(session, meta, issuer)


def verify_token(session: requests.Session, token: str, uri: str, record: dict[str, Any],
                 now: float | None = None) -> dict[str, Any]:
    """The payload of a status list token, once its type, subject, dates and signature are checked."""
    from .vci import issuer_keys

    now = time.time() if now is None else now

    def invalid(problem: str) -> StatusError:
        return StatusError(tr("The status list {uri} is not valid: {problem}.", uri=uri, problem=problem))

    try:
        header, payload = jwt_decode_unverified(token)
    except WalletError as exc:
        raise invalid("it is not a JWT") from exc
    if header.get("typ") != "statuslist+jwt":
        raise invalid(f"typ is {header.get('typ')!r}, not 'statuslist+jwt'")
    if payload.get("sub") != uri:  # a list for other credentials, served at this address
        raise invalid(f"its sub is {payload.get('sub')!r}")
    if not isinstance(payload.get("iat"), (int, float)):
        raise invalid("it has no iat")
    if isinstance(payload.get("exp"), (int, float)) and payload["exp"] < now:
        raise invalid("it has expired")
    sd: SdJwt = record["_sd"]
    issuer = str(record.get("issuer") or "")
    iss = str(sd.payload.get("iss") or issuer)
    keys, bound = issuer_keys(session, header, iss, issuer, lambda: _issuer_metadata(session, issuer))
    if not bound or not any(_verify_jws(token, key) for key in keys):
        raise StatusError(tr("The status list {uri} is not signed by the credential's issuer.", uri=uri))
    return payload


def _recheck_after(payload: dict[str, Any], now: float) -> float:
    ttl = payload.get("ttl")
    wait = min(MAX_RECHECK, max(MIN_RECHECK, ttl)) if isinstance(ttl, (int, float)) else DEFAULT_RECHECK
    exp = payload.get("exp")
    return min(now + wait, float(exp)) if isinstance(exp, (int, float)) else now + wait


def check(session: requests.Session, record: dict[str, Any], lists: dict[str, Any] | None = None,
          now: float | None = None) -> str | None:
    """
    Asks the issuer's status list and stores the answer in the credential: 'valid', 'revoked' or
    'suspended'; None if it has no status to check. StatusError (or a network error) if it cannot
    be established. 'lists' keeps the lists already downloaded (several credentials share one).
    """
    now = time.time() if now is None else now
    ref = status_reference(record["_sd"])
    if ref is None:
        return None
    uri, index = ref
    lists = {} if lists is None else lists
    if uri not in lists:
        token = fetch_token(session, uri, str(record.get("issuer") or ""))
        payload = verify_token(session, token, uri, record, now)
        lists[uri] = (*decode_list(payload.get("status_list"), uri), _recheck_after(payload, now))
    bits, data, next_check = lists[uri]
    value = status_at(bits, data, index, uri)
    state = STATES.get(value)
    if state is None:  # 3 and above: application-specific or reserved; not known to mean "valid"
        raise StatusError(tr("The status list {uri} is not valid: {problem}.", uri=uri,
                             problem=f"unknown status value {value}"))
    record["revocation"] = {"state": state, "checked_at": int(now), "next_check": int(next_check)}
    storage.save_record(record)
    debug(f"Status of {storage.credential_name(record)}: {state} ({uri} #{index})")
    return state


def due(record: dict[str, Any], now: float | None = None) -> bool:
    """It has a status list and the last check is out of date (a revocation is final: never again)."""
    if not has_status(record) or storage.revocation_state(record) == "revoked":
        return False
    next_check = (record.get("revocation") or {}).get("next_check")
    return not isinstance(next_check, (int, float)) or next_check <= (time.time() if now is None else now)


def refresh(session: requests.Session, records: list[dict[str, Any]], *, force: bool = False,
            failed: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """
    Checks the credentials that are due (all with a status list if 'force'). A failure is logged,
    added to 'failed' and leaves the previous state. Returns the credentials whose state changed.
    """
    lists: dict[str, Any] = {}
    changed = []
    for record in records:
        if not (due(record) or (force and has_status(record))):
            continue
        before = storage.revocation_state(record)
        try:
            state = check(session, record, lists)
        except (storage.vault.Locked, storage.vault.PasswordNeeded):
            raise  # the wallet locked meanwhile: nothing can be read or written
        except Exception as exc:  # noqa: BLE001  (whatever the list's server sends must not stop a presentation)
            log(tr("Warning: could not check whether '{credential}' has been revoked: {error}",
                   credential=storage.credential_name(record), error=exc))
            if failed is not None:
                failed.append(record)
            continue
        if storage.revocation_state(record) != before:
            changed.append(record)
            name = storage.credential_name(record)
            if state == "revoked":
                log(tr("'{credential}' has been revoked by its issuer.", credential=name))
            elif state == "suspended":
                log(tr("'{credential}' has been suspended by its issuer.", credential=name))
    return changed

# -*- coding: utf-8 -*-
"""OpenID4VCI: offers, login at the authorization server, and issuance."""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import requests
from cryptography.hazmat.primitives.asymmetric import ec

from .common import (
    Cancelled,
    SD_JWT_FORMATS,
    WalletError,
    _http_error,
    _json,
    _last_deep_link,
    humanize,
    b64u,
    b64u_decode,
    debug,
    host_of,
    is_local_host,
    log,
    site_of,
    parse_json,
    require_https,
    split_url,
)
from . import i18n
from .i18n import tr
from .jose import _dns_names, _verify_jws, _x5c_chain, jwk_to_public_key
from .sdjwt import parse_sd_jwt
from .storage import HolderKey, add_history, load_config, save_config, save_credential
from .ui import OfferSummary, Prompter, TerminalPrompter


PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
# The wallet's own OAuth client. An issuer that registers it (public, PKCE, redirect URI below; Keycloak
# accepts any port on 127.0.0.1, RFC 8252 §7.3) gets the login in the user's browser, so the password
# is never typed into the wallet. Elsewhere the wallet falls back to account-console and its own login.
WALLET_CLIENT_ID = "atesta-id-wallet"
LOOPBACK_REDIRECT = "http://127.0.0.1/callback"
DEFAULT_CLIENT_ID = "account-console"


class DPoP:
    """RFC 9449 proofs. The key lives only for one issuance: it binds the access token to this run."""

    def __init__(self) -> None:
        self.key = HolderKey(ec.generate_private_key(ec.SECP256R1()))
        self.nonces: dict[str, str] = {}  # htu -> last DPoP-Nonce (the AS and the issuer may differ)

    @staticmethod
    def _htu(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}{parts.path}"  # without query and fragment (§4.2)

    def proof(self, method: str, url: str, access_token: str | None = None) -> str:
        claims: dict[str, Any] = {
            "jti": b64u(secrets.token_bytes(16)),
            "htm": method,
            "htu": self._htu(url),
            "iat": int(time.time()),
        }
        nonce = self.nonces.get(self._htu(url))
        if nonce:
            claims["nonce"] = nonce
        if access_token:
            claims["ath"] = b64u(hashlib.sha256(access_token.encode("ascii")).digest())
        return self.key.sign_jwt({"typ": "dpop+jwt", "jwk": self.key.public_jwk}, claims)

    def remember(self, url: str, response: requests.Response) -> None:
        nonce = response.headers.get("DPoP-Nonce")
        if nonce:
            self.nonces[self._htu(url)] = nonce

    def post(self, session: requests.Session, url: str, *, access_token: str | None = None,
             headers: dict[str, str] | None = None, **kwargs: Any) -> requests.Response:
        """POST with a fresh proof; retries once if the server asks for a nonce (§8, §9)."""
        for attempt in range(2):
            response = session.post(url, headers={**(headers or {}), "DPoP": self.proof("POST", url, access_token)},
                                    **kwargs)
            self.remember(url, response)
            asks_nonce = "use_dpop_nonce" in response.text or "use_dpop_nonce" in response.headers.get(
                "WWW-Authenticate", "")
            if attempt == 0 and response.status_code in (400, 401) and asks_nonce and "DPoP-Nonce" in response.headers:
                debug("The server asked for a DPoP nonce; retrying.")
                continue
            return response
        return response


class _LoginReplay(Prompter):
    """
    Delegates to ui and keeps the last login of this issuance in memory, so that the retry of an
    offer tied to another wallet does not ask again. Replayed once, only to the same host; dropped
    when the issuance ends. Never written anywhere.
    """

    def __init__(self, ui: Prompter):
        self.ui = ui
        self.saved: tuple[str, str, str] | None = None  # host, username, password
        self.armed = False

    def login(self, host: str, username: str | None, *, ask_username: bool) -> tuple[str, str]:
        if self.armed and self.saved and self.saved[0] == host:
            self.armed = False
            return self.saved[1], self.saved[2]
        entered = self.ui.login(host, username, ask_username=ask_username)
        self.saved = (host, *entered)
        return entered

    def forget(self) -> None:
        self.saved, self.armed = None, False

    def review_offer(self, offer: OfferSummary) -> bool:
        return self.ui.review_offer(offer)

    def text(self, prompt: str, *, default: str | None = None) -> str:
        return self.ui.text(prompt, default=default)

    def secret(self, prompt: str) -> str:
        return self.ui.secret(prompt)

    def confirm(self, question: str, *, default: bool = False) -> bool:
        return self.ui.confirm(question, default=default)

    def notice(self, message: str) -> None:
        self.ui.notice(message)

    def wait_for_browser(self, host: str, url: str, wait: Callable[[threading.Event], str]) -> str:
        return self.ui.wait_for_browser(host, url, wait)

    def choose_credential(self, query_id: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        return self.ui.choose_credential(query_id, candidates)

    def consent(self, prepared: Any) -> bool:
        return self.ui.consent(prepared)


def _post(session: requests.Session, dpop: DPoP | None, url: str, *, access_token: str | None = None,
          **kwargs: Any) -> requests.Response:
    if dpop is None:
        return session.post(url, **kwargs)
    return dpop.post(session, url, access_token=access_token, **kwargs)


def supports_dpop(as_meta: dict[str, Any]) -> bool:
    algs = as_meta.get("dpop_signing_alg_values_supported")
    return isinstance(algs, list) and "ES256" in algs


def _well_known(base: str, suffix: str) -> list[str]:
    """RFC 8414 form (inserted after the host) and Keycloak's 'append' form."""
    parts = urlsplit(base.rstrip("/"))
    inserted = f"{parts.scheme}://{parts.netloc}/.well-known/{suffix}{parts.path}"
    appended = f"{base.rstrip('/')}/.well-known/{suffix}"
    return [inserted, appended] if inserted != appended else [inserted]


def _get_first_json(session: requests.Session, urls: list[str]) -> dict[str, Any]:
    last_error: Exception | None = None
    for url in urls:
        try:
            response = session.get(url, headers={"Accept": "application/json"}, timeout=20)
            data = _json(response, "GET", url)
            debug(f"Metadata from {url}")
            return data
        except (WalletError, requests.RequestException) as exc:
            last_error = exc
    raise WalletError(tr("Could not get the metadata ({urls}): {error}", urls=", ".join(urls), error=last_error))


def resolve_offer(session: requests.Session, raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if raw.startswith("{"):
        return _offer_object(parse_json(raw, "credential_offer"))
    raw = _last_deep_link(raw, "openid-credential-offer://")
    if raw.startswith(("http://", "https://")):
        offer_uri = raw
    else:
        params = parse_qs(split_url(raw, "openid-credential-offer").query, keep_blank_values=True)
        if "credential_offer" in params:
            return _offer_object(parse_json(params["credential_offer"][0], "credential_offer"))
        if "credential_offer_uri" not in params:
            raise WalletError(tr("The offer contains neither credential_offer nor credential_offer_uri."))
        offer_uri = params["credential_offer_uri"][0]
    require_https(offer_uri, "credential_offer_uri")
    log(tr("Downloading the offer: {uri}", uri=offer_uri))
    response = session.get(offer_uri, headers={"Accept": "application/json"}, timeout=20)
    return _json(response, "GET", offer_uri)


def _offer_object(offer: Any) -> dict[str, Any]:
    if not isinstance(offer, dict):
        raise WalletError(tr("credential_offer is not a JSON object."))
    return offer


def _pkce_pair() -> tuple[str, str]:
    verifier = b64u(secrets.token_bytes(32))
    challenge = b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class _Loopback:
    """
    Short-lived HTTP server on the loopback interface for a redirect_uri http://127.0.0.1[:PORT]/path.
    Without a port it takes a free one (RFC 8252 §7.3); redirect_uri is then the address to use.
    """

    def __init__(self, redirect_uri: str):
        parts = urlsplit(redirect_uri)
        path = parts.path or "/"
        result: dict[str, str] = {}
        self.result = result

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if urlsplit(self.path).path != path:  # e.g. /favicon.ico
                    self.send_response(404)
                    self.end_headers()
                    return
                result.setdefault("path", self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<h3>{html.escape(tr('Done. You can go back to the wallet.'))}</h3>".encode("utf-8"))

            def log_message(self, *args: Any) -> None:
                pass

        self.server = http.server.HTTPServer((parts.hostname or "127.0.0.1", parts.port or 0), Handler)
        self.server.timeout = 0.5
        netloc = f"{parts.hostname}:{self.server.server_port}"
        self.redirect_uri = f"{parts.scheme}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")
        result["base"] = f"{parts.scheme}://{netloc}"

    def wait(self, stop: threading.Event, timeout: int = 300) -> str:
        """The URL the browser was sent back to; Cancelled if stop is set, WalletError after timeout."""
        deadline = time.time() + timeout
        try:
            while "path" not in self.result and not stop.is_set() and time.time() < deadline:
                self.server.handle_request()
        finally:
            self.server.server_close()
        if "path" in self.result:
            return self.result["base"] + self.result["path"]
        if stop.is_set():
            raise Cancelled()
        raise WalletError(tr("Timed out waiting for the browser redirect."),
                          hint=tr("Signing in in the browser took too long. Start again from the page where you asked for the "
                                  "credential."))

    def close(self) -> None:
        self.server.server_close()


def _open_browser_quietly(url: str) -> None:
    """webbrowser inherits stdout/stderr and the browser writes over the prompt."""
    try:
        for stream in (sys.stdout, sys.stderr):
            if stream:
                stream.flush()
        saved = os.dup(1), os.dup(2)
    except (OSError, ValueError):
        # No console (the windowed builds on Windows and macOS have no stdout/stderr): nothing to protect.
        webbrowser.open(url)
        return
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        webbrowser.open(url)
        time.sleep(1.5)  # the browser launcher writes with a delay
    finally:
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for fd in (*saved, devnull):
            os.close(fd)


def _parse_forms(page: str) -> list[dict[str, Any]]:
    """Minimal HTML forms: action, inputs (name -> value) and buttons."""
    forms = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", page, re.S | re.I):
        attrs, inner = match.groups()
        action = re.search(r'action="([^"]*)"', attrs)
        form_id = re.search(r'id="([^"]*)"', attrs)
        inputs: dict[str, str] = {}
        buttons: dict[str, str] = {}
        for tag in re.finditer(r"<(input|button)\b([^>]*)>", inner, re.I):
            kind, tag_attrs = tag.group(1).lower(), tag.group(2)
            name = re.search(r'name="([^"]*)"', tag_attrs)
            if not name:
                continue
            value = re.search(r'value="([^"]*)"', tag_attrs)
            input_type = re.search(r'type="([^"]*)"', tag_attrs)
            target = buttons if kind == "button" or (input_type and input_type.group(1) == "submit") else inputs
            target[name.group(1)] = html.unescape(value.group(1)) if value else ""
        forms.append({
            "id": form_id.group(1) if form_id else "",
            "action": html.unescape(action.group(1)) if action else "",
            "inputs": inputs,
            "buttons": buttons,
        })
    return forms


def _page_error(page: str) -> str | None:
    for pattern in (
        r'id="input-error[^"]*"[^>]*>\s*([^<]+)',
        r'class="[^"]*kc-feedback-text[^"]*"[^>]*>\s*([^<]+)',
        r'id="kc-error-message"[^>]*>\s*<p[^>]*>\s*([^<]+)',
        r'class="[^"]*pf-v5-c-alert__title[^"]*"[^>]*>\s*([^<]+)',
    ):
        match = re.search(pattern, page, re.I)
        if match and match.group(1).strip():
            return html.unescape(match.group(1).strip())
    return None


def headless_login(session: requests.Session, auth_url: str, redirect_uri: str,
                   username: str | None, ui: Prompter | None = None, *,
                   suggested_username: str | None = None) -> tuple[str, str | None]:
    """
    Goes through the Keycloak login without a browser (username/password, OTP and
    consent screen) and returns the redirect URL with the code, without loading it,
    and the username that was used.

    username fixes the user (it is not asked); suggested_username is only offered.
    """
    ui = ui or TerminalPrompter()
    url, method, data = auth_url, "GET", None
    password_sent = False
    auth_host = host_of(auth_url)
    for _ in range(15):
        if method == "GET":
            response = session.get(url, allow_redirects=False, timeout=20)
        else:
            response = session.post(url, data=data, allow_redirects=False, timeout=20)
        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
            location = requests.compat.urljoin(url, response.headers["Location"])
            if location.startswith(redirect_uri):
                return location, username
            url, method, data = location, "GET", None
            continue
        if response.status_code >= 400:
            raise WalletError(tr("Keycloak returned HTTP {status} during login: {error}",
                                 status=response.status_code, error=_page_error(response.text) or response.text[:300]))

        page = response.text
        forms = [f for f in _parse_forms(page) if f["action"]]
        if not forms:
            raise WalletError(tr("Unexpected login page: {error}", error=_page_error(page) or page[:300]))
        form = next((f for f in forms if "password" in f["inputs"] or "username" in f["inputs"]
                     or "otp" in f["inputs"] or f["id"] == "kc-oauth"), forms[0])
        fields = dict(form["inputs"])
        target = requests.compat.urljoin(response.url, form["action"])
        if "password" in fields:
            if host_of(target) != auth_host:
                raise WalletError(tr(
                    "The login form would send the password to {target}, not to {host}. Aborting; if it is a "
                    "legitimate external identity provider, use --browser-login.", target=host_of(target), host=auth_host
                ), hint=tr("The sign-in page would send your password to another website, so the wallet stopped. "
                           "Nothing was sent."))
            require_https(target, tr("The login form"))  # never the password in clear text
            if password_sent:
                raise WalletError(tr("Login rejected: {error}", error=_page_error(page) or tr("wrong credentials")),
                                  hint=tr("The username or password is not correct. Start again and check them."))
            ask_username = "username" in fields and not username
            entered, fields["password"] = ui.login(
                auth_host, username or suggested_username, ask_username=ask_username
            )
            if "username" in fields:
                username = username or entered
                fields["username"] = username
            password_sent = True
        elif "otp" in fields:
            fields["otp"] = ui.text(tr("One-time code (OTP)"))
        elif "username" in fields:
            username = username or ui.text(tr("Keycloak username or email"), default=suggested_username)
            fields["username"] = username
        elif form["id"] == "kc-oauth" or "accept" in form["buttons"]:
            log(tr("Accepting the consent screen."))
            fields["accept"] = form["buttons"].get("accept", "Yes")
        else:
            error = _page_error(page)
            raise WalletError(tr("Keycloak shows a page the wallet cannot complete{error}. Try --browser-login.",
                                 error=f": {error}" if error else ""),
                              hint=tr("The sign-in page asks for something the wallet cannot fill in. Ask the "
                                      "organisation that gives the credential for help, and send them the technical "
                                      "details."))
        url, method, data = target, "POST", fields
    raise WalletError(tr("Too many pages during login."))


def authorization_code_flow(
    session: requests.Session,
    as_meta: dict[str, Any],
    *,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    issuer_state: str | None,
    authorization_details: list[dict[str, Any]] | None,
    open_browser: bool,
    browser_login: bool,
    username: str | None,
    ui: Prompter | None = None,
    suggested_username: str | None = None,
    dpop: DPoP | None = None,
) -> tuple[dict[str, Any], str | None]:
    """Returns the token and the username used to log in (if the login was done by the wallet)."""
    ui = ui or TerminalPrompter()
    if not as_meta.get("authorization_endpoint"):
        raise WalletError(tr("The authorization server metadata has no authorization_endpoint."))
    target = urlsplit(redirect_uri)
    # http://127.0.0.1 or localhost: the browser comes back to a server of the wallet (on a free port
    # if none is given), so the login happens in the browser and the wallet never sees the password.
    loopback = (_Loopback(redirect_uri) if target.scheme == "http" and target.hostname in ("localhost", "127.0.0.1")
                else None)
    if loopback:
        redirect_uri = loopback.redirect_uri
    try:
        callback_url, username, verifier, state = _authorize(
            session, as_meta, client_id=client_id, redirect_uri=redirect_uri, scopes=scopes,
            issuer_state=issuer_state, authorization_details=authorization_details, open_browser=open_browser,
            browser_login=browser_login, username=username, ui=ui, suggested_username=suggested_username,
            loopback=loopback,
        )
    finally:
        if loopback:
            loopback.close()
    return _redeem_code(session, as_meta, callback_url, state=state, verifier=verifier, client_id=client_id,
                        redirect_uri=redirect_uri, username=username, dpop=dpop)


def _authorize(
    session: requests.Session,
    as_meta: dict[str, Any],
    *,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    issuer_state: str | None,
    authorization_details: list[dict[str, Any]] | None,
    open_browser: bool,
    browser_login: bool,
    username: str | None,
    ui: Prompter,
    suggested_username: str | None,
    loopback: _Loopback | None,
) -> tuple[str, str | None, str, str]:
    """Authorization request; returns (callback URL or code, username, PKCE verifier, state)."""
    verifier, challenge = _pkce_pair()
    state = b64u(secrets.token_bytes(16))
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(["openid", *scopes]),
        "state": state,
        "nonce": b64u(secrets.token_bytes(16)),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if issuer_state:
        params["issuer_state"] = issuer_state
    if authorization_details:
        params["authorization_details"] = json.dumps(authorization_details, separators=(",", ":"))

    auth_url = as_meta["authorization_endpoint"] + "?" + urlencode(params, quote_via=quote)
    debug(f"Authorization URL: {auth_url}")

    if loopback:
        log(tr("Signing in to {host} in the browser.", host=host_of(auth_url)))
        if open_browser:
            _open_browser_quietly(auth_url)
        return ui.wait_for_browser(host_of(auth_url), auth_url, loopback.wait), None, verifier, state
    if not browser_login:
        log(tr("Signing in to Keycloak from the wallet (use --browser-login for the browser)."))
        callback_url, username = headless_login(
            session, auth_url, redirect_uri, username, ui, suggested_username=suggested_username
        )
    else:
        ui.notice(tr("Open this URL in the browser and sign in to Keycloak:\n\n{url}", url=auth_url))
        if open_browser:
            _open_browser_quietly(auth_url)
        ui.notice(tr(
            "After login the browser goes to a URL that starts with\n  {uri}?...code=...\n"
            "Copy it from the address bar and paste it here (if the page changes it right away, find it "
            "in the history with Ctrl+H). It expires in about a minute.", uri=redirect_uri
        ))
        callback_url = ""
        while not callback_url:
            callback_url = ui.text(tr("Paste the redirect URL (or just the code)")).strip()
    return callback_url, username, verifier, state


def _redeem_code(session: requests.Session, as_meta: dict[str, Any], callback_url: str, *, state: str,
                 verifier: str, client_id: str, redirect_uri: str, username: str | None,
                 dpop: DPoP | None) -> tuple[dict[str, Any], str | None]:
    """Checks the authorization response and exchanges its code for the token."""
    if "?" in callback_url or "#" in callback_url or "code=" in callback_url:
        parts = split_url(callback_url, "redirect_uri")
        query = parts.query or parts.fragment
        cb = parse_qs(query)
        if "error" in cb:
            raise WalletError(tr("The authorization server returned an error: {error} {description}",
                                 error=cb["error"][0], description=cb.get("error_description", [""])[0]))
        # Without state there is no way to know the response belongs to this request (CSRF / code injection).
        if cb.get("state", [""])[0] != state:
            raise WalletError(tr("The state parameter does not match; aborting for safety."))
        # RFC 9207: if the server says who is answering, it must be the one that was asked.
        if "iss" in cb and as_meta.get("issuer") and cb["iss"][0].rstrip("/") != as_meta["issuer"].rstrip("/"):
            raise WalletError(tr("The authorization response comes from {iss}, not from {expected}.",
                                 iss=cb["iss"][0], expected=as_meta["issuer"]))
        code = (cb.get("code") or [""])[0]
    else:
        code = callback_url
    if not code:
        raise WalletError(tr("No authorization code was received."))

    token_url = as_meta["token_endpoint"]
    response = _post(
        session,
        dpop,
        token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
        },
        timeout=20,
    )
    try:
        return _json(response, "POST", token_url), username
    except WalletError as exc:
        exc.username = username  # type: ignore[attr-defined]  # who signed in, if the caller retries
        raise


def wallet_client_available(session: requests.Session, as_meta: dict[str, Any]) -> bool:
    """
    Whether the authorization server knows the wallet's own client (WALLET_CLIENT_ID with a loopback
    redirect). Asked without cookies or credentials: Keycloak answers an unknown client or redirect_uri
    with an error page before any login, and a valid request with its login page.
    """
    endpoint = as_meta.get("authorization_endpoint")
    if not endpoint:
        return False
    _, challenge = _pkce_pair()
    probe = requests.Session()
    probe.headers.update(session.headers)
    probe.verify = session.verify
    params = {"response_type": "code", "client_id": WALLET_CLIENT_ID, "scope": "openid",
              "redirect_uri": LOOPBACK_REDIRECT.replace("127.0.0.1", "127.0.0.1:49152"),
              "state": b64u(secrets.token_bytes(16)), "code_challenge": challenge, "code_challenge_method": "S256"}
    try:
        response = probe.get(endpoint, params=params, allow_redirects=False, timeout=10)
    except requests.RequestException as exc:
        debug(f"Own client check failed: {exc}")
        return False
    finally:
        probe.close()
    # A redirect back to the wallet carries an error (the request was refused); any other one is a
    # login page elsewhere (e.g. an external identity provider).
    location = response.headers.get("Location", "")
    available = response.status_code == 200 or (response.is_redirect and not location.startswith("http://127.0.0.1"))
    debug(f"Own client '{WALLET_CLIENT_ID}' at the authorization server: HTTP {response.status_code}, "
          f"{'available' if available else 'not available'}")
    return available


def pre_authorized_flow(
    session: requests.Session,
    as_meta: dict[str, Any],
    grant: dict[str, Any],
    *,
    client_id: str | None,
    tx_code: str | None,
    ui: Prompter | None = None,
    dpop: DPoP | None = None,
) -> dict[str, Any]:
    if not isinstance(grant, dict) or not grant.get("pre-authorized_code"):
        raise WalletError(tr("The offer has no pre-authorized_code."))
    data = {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": grant["pre-authorized_code"]}
    if grant.get("tx_code") is not None or grant.get("user_pin_required"):
        if not tx_code:
            description = (grant.get("tx_code") or {}).get("description", "")
            tx_code = (ui or TerminalPrompter()).text(tr("Transaction code (tx_code) {description}",
                                                         description=description).strip())
        data["tx_code"] = tx_code
        data["user_pin"] = tx_code  # drafts antiguos
    if client_id:
        data["client_id"] = client_id
    token_url = as_meta["token_endpoint"]
    response = _post(session, dpop, token_url, data=data, timeout=20)
    return _json(response, "POST", token_url)


def _fetch_nonce(session: requests.Session, issuer_meta: dict[str, Any], token: dict[str, Any],
                 dpop: DPoP | None = None) -> str | None:
    endpoint = issuer_meta.get("nonce_endpoint")
    if endpoint:
        response = session.post(endpoint, timeout=20)
        if dpop is not None:
            dpop.remember(issuer_meta["credential_endpoint"], response)  # its DPoP nonce, if any, is for that
        return _json(response, "POST", endpoint).get("c_nonce")
    return token.get("c_nonce")


def request_credential(
    session: requests.Session,
    key: HolderKey,
    issuer_meta: dict[str, Any],
    token: dict[str, Any],
    configuration_id: str,
    *,
    proof_iss: str | None,
    dpop: DPoP | None = None,
) -> list[str]:
    issuer = issuer_meta["credential_issuer"]
    endpoint = issuer_meta["credential_endpoint"]
    # A DPoP-bound token is only accepted together with a proof made with the same key.
    if str(token.get("token_type", "")).lower() != "dpop":
        dpop = None
    headers = {
        "Authorization": f"{'DPoP' if dpop else token.get('token_type', 'Bearer')} {token['access_token']}",
        "Content-Type": "application/json",
    }

    # If the token carries credential_identifiers (authorization_details), they are used.
    identifier = None
    for detail in token.get("authorization_details") or []:
        if detail.get("credential_configuration_id") == configuration_id and detail.get(
            "credential_identifiers"
        ):
            identifier = detail["credential_identifiers"][0]

    nonce = _fetch_nonce(session, issuer_meta, token, dpop)
    legacy_proof = False
    for attempt in range(3):
        claims: dict[str, Any] = {"aud": issuer, "iat": int(time.time())}
        if nonce:
            claims["nonce"] = nonce
        if proof_iss:
            claims["iss"] = proof_iss
        proof = key.sign_jwt({"typ": "openid4vci-proof+jwt", "jwk": key.public_jwk}, claims)

        body: dict[str, Any] = (
            {"credential_identifier": identifier}
            if identifier
            else {"credential_configuration_id": configuration_id}
        )
        if legacy_proof:
            body["proof"] = {"proof_type": "jwt", "jwt": proof}
        else:
            body["proofs"] = {"jwt": [proof]}

        debug(f"POST {endpoint} {json.dumps(body)[:200]}")
        response = _post(session, dpop, endpoint, access_token=token["access_token"], headers=headers, json=body,
                         timeout=30)
        if response.status_code < 400:
            data = _json(response, "POST", endpoint)
            break
        error = {}
        try:
            error = response.json()
        except ValueError:
            pass
        if error.get("error") == "invalid_nonce" or error.get("c_nonce"):
            nonce = error.get("c_nonce") or _fetch_nonce(session, issuer_meta, token, dpop)
            log(tr("The issuer asked for a new nonce; retrying."))
            continue
        if not legacy_proof and "proof" in response.text.lower() and attempt == 0:
            legacy_proof = True
            log(tr("The issuer rejected 'proofs'; retrying with 'proof' (older draft)."))
            continue
        raise _http_error("POST", endpoint, response)
    else:
        raise WalletError(tr("Could not get the credential after several attempts."))

    if "transaction_id" in data and "credentials" not in data and "credential" not in data:
        raise WalletError(tr("The issuer answered with deferred issuance (transaction_id), which is not supported."),
                          hint=tr("The organisation will prepare this credential later, and this wallet cannot collect it "
                                  "that way yet."))
    credentials = data.get("credentials")
    if credentials is None and "credential" in data:
        credentials = [data["credential"]]
    out: list[str] = []
    for item in credentials or []:
        value = item.get("credential") if isinstance(item, dict) else item
        if isinstance(value, str):
            out.append(value)
        elif value is not None:
            out.append(json.dumps(value))
    if not out:
        raise WalletError(tr("Credential response without credentials: {data}", data=data))
    return out


@dataclass
class IssueOptions:
    client_id: str | None = None  # authorization_code; default: the one that worked, or account-console
    redirect_uri: str | None = None
    client_id_pre: str | None = None  # pre-authorized_code
    tx_code: str | None = None
    username: str | None = None
    authorization_details: bool = False
    force_auth_code: bool = False
    browser_login: bool = False
    open_browser: bool = True
    in_app_login: bool = False  # never the browser login with the wallet's own client
    dpop: bool = True  # only if the authorization server advertises it


@dataclass
class IssuedCredential:
    configuration_id: str
    path: Path
    claims: dict[str, Any] | None  # None if the format is not SD-JWT
    account: str | None = None  # the issuer account it was issued for, if the login said so


def account_of(token: dict[str, Any]) -> str | None:
    """
    'user (email)' from the id_token of the token response, to show which account signed in (in the
    browser it may be a session that was already open). Display only: it came straight from the token
    endpoint over TLS (OIDC Core §3.1.3.7), and nothing is decided with it.
    """
    id_token = token.get("id_token")
    if not isinstance(id_token, str) or id_token.count(".") != 2:
        return None
    try:
        claims = json.loads(b64u_decode(id_token.split(".")[1]))
    except (ValueError, binascii.Error):
        return None
    if not isinstance(claims, dict):
        return None
    names = [v for v in (claims.get("preferred_username") or claims.get("name"), claims.get("email"))
             if isinstance(v, str) and v.strip()]
    if len(names) == 2 and names[0].lower() == names[1].lower():
        names = names[:1]
    return f"{names[0]} ({names[1]})" if len(names) == 2 else (names[0] if names else None)


def authorization_server_metadata(session: requests.Session, issuer_meta: dict[str, Any],
                                  issuer: str) -> dict[str, Any]:
    """Metadata of the issuer's (first) authorization server, checked as RFC 8414 asks."""
    as_base = (issuer_meta.get("authorization_servers") or [issuer])[0]
    require_https(as_base, "authorization_server")
    as_meta = _get_first_json(
        session,
        _well_known(as_base, "oauth-authorization-server") + _well_known(as_base, "openid-configuration"),
    )
    # RFC 8414 §3.3: the metadata 'issuer' must be the server that was queried.
    if as_meta.get("issuer") and str(as_meta["issuer"]).rstrip("/") != as_base.rstrip("/"):
        raise WalletError(tr("The authorization server metadata belongs to {other}, not to {server}.",
                             other=as_meta["issuer"], server=as_base))
    if "token_endpoint" not in as_meta:
        raise WalletError(tr("The authorization server metadata has no token_endpoint."))
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if name in as_meta:
            require_https(str(as_meta[name]), name)
    return as_meta


def issue(session: requests.Session, raw_offer: str, options: IssueOptions, ui: Prompter) -> list[IssuedCredential]:
    """Accepts an OpenID4VCI offer and stores the received credentials in the active profile."""
    key = HolderKey.load_or_create()
    offer = resolve_offer(session, raw_offer)
    if "credential_offer" in offer and isinstance(offer["credential_offer"], dict):
        offer = offer["credential_offer"]
    debug(f"Offer: {json.dumps(offer)}")

    issuer = offer.get("credential_issuer")
    if not isinstance(issuer, str) or not issuer:
        raise WalletError(tr("The offer does not say which credential_issuer it comes from."))
    config_ids = offer.get("credential_configuration_ids") or offer.get("credentials") or []
    config_ids = [c for c in config_ids if isinstance(c, str)] if isinstance(config_ids, list) else []
    if not config_ids:
        raise WalletError(tr("The offer does not name any credential_configuration_ids."))
    require_https(issuer, "credential_issuer")
    log(tr("Issuer: {issuer}", issuer=issuer))
    log(tr("Offered credentials: {ids}", ids=", ".join(config_ids)))

    issuer_meta = _get_first_json(session, _well_known(issuer, "openid-credential-issuer"))
    # OpenID4VCI 1.0 §12.2: the metadata must be that of the offering issuer.
    if str(issuer_meta.get("credential_issuer", "")).rstrip("/") != issuer.rstrip("/"):
        raise WalletError(tr("The issuer metadata belongs to {other}, not to {issuer}.",
                             other=issuer_meta.get("credential_issuer"), issuer=issuer))
    if "credential_endpoint" not in issuer_meta:
        raise WalletError(tr("The issuer metadata has no credential_endpoint."))
    for name in ("credential_endpoint", "nonce_endpoint"):
        if name in issuer_meta:
            require_https(str(issuer_meta[name]), name)
    configs = issuer_meta.get("credential_configurations_supported") or {}
    if not isinstance(configs, dict):
        configs = {}
    published_name = pick_display(issuer_meta.get("display")).get("name")
    issuer_name = published_name or site_of(issuer)  # cards and history
    displays = {c: credential_display(configs.get(c, {}), c, issuer_name) for c in config_ids}
    # The review is where trust is decided: without a published name it shows the full host.
    summary = OfferSummary(issuer, published_name or host_of(issuer), [displays[c]["name"] for c in config_ids],
                           known=issuer in load_config().get("issuers", {}))
    if not ui.review_offer(summary):
        raise Cancelled()

    as_base = (issuer_meta.get("authorization_servers") or [issuer])[0]
    as_meta = authorization_server_metadata(session, issuer_meta, issuer)

    dpop = DPoP() if options.dpop and supports_dpop(as_meta) else None
    if dpop:
        debug("DPoP: the access token will be bound to a key of this issuance.")

    grants = offer.get("grants") or {}
    if PRE_AUTH_GRANT in grants and not options.force_auth_code:
        log(tr("Pre-authorized code flow."))
        token = pre_authorized_flow(
            session, as_meta, grants[PRE_AUTH_GRANT], client_id=options.client_id_pre, tx_code=options.tx_code,
            ui=ui, dpop=dpop,
        )
        proof_iss = options.client_id_pre
    else:
        issuer_config = load_config().get("issuers", {}).get(issuer, {})
        # A client chosen by the user (option or remembered) is kept; otherwise the wallet's own client
        # if this server has it (login in the browser), else account-console (login in the wallet).
        remembered = issuer_config.get("client_id")
        automatic = (None, DEFAULT_CLIENT_ID) + ((WALLET_CLIENT_ID,) if options.in_app_login else ())
        client_id = options.client_id or (remembered if remembered not in automatic else None)
        redirect_uri = options.redirect_uri or (issuer_config.get("redirect_uri") if client_id else None)
        if not client_id and not options.in_app_login and wallet_client_available(session, as_meta):
            client_id, redirect_uri = WALLET_CLIENT_ID, LOOPBACK_REDIRECT
        client_id = client_id or DEFAULT_CLIENT_ID
        redirect_uri = redirect_uri or f"{as_base.rstrip('/')}/account/oid4vci-callback"
        log(tr("Authorization code flow (client_id={client_id}).", client_id=client_id))
        scopes = [configs.get(c, {}).get("scope") for c in config_ids]
        details = None
        if options.authorization_details:
            details = [
                {"type": "openid_credential", "credential_configuration_id": c, "locations": [issuer]}
                for c in config_ids
            ]
        replay = _LoginReplay(ui)

        def login(http: requests.Session, issuer_state: str | None,
                  suggested: str | None = None) -> tuple[dict[str, Any], str | None]:
            return authorization_code_flow(
                http,
                as_meta,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scopes=[s for s in scopes if s],
                issuer_state=issuer_state,
                authorization_details=details,
                open_browser=options.open_browser,
                browser_login=options.browser_login,
                username=options.username,
                ui=replay,
                suggested_username=suggested or issuer_config.get("username"),
                dpop=dpop,
            )

        issuer_state = (grants.get("authorization_code") or {}).get("issuer_state")
        if issuer_state and client_id == WALLET_CLIENT_ID:
            # Offers are made by portals for their own client, not this one. Keycloak would refuse the
            # offer and, worse, keep its issuer_state in the browser's SSO session for this client, so
            # every later request would hit it too (prompt=login does not clear it). The same credentials
            # are asked for by scope: Keycloak issues what the account is entitled to, as for the offer.
            debug("Own client: the offer's issuer_state is not sent; the credentials are asked for by scope.")
            issuer_state = None
        try:
            token, username = login(session, issuer_state)
        except WalletError as exc:
            # Keycloak ties each offer to the OAuth client that created it (often another wallet's,
            # e.g. the PGTEC onboarding portal makes them for Lissi's client).
            bound = re.search(r"offer target client '([^']+)' different from login client", str(exc))
            if not bound or not issuer_state:
                raise
            # Same issuer and credentials the user just accepted, asked for without the offer: the
            # server authorizes by scope (the user must be entitled to them). In a new HTTP session:
            # Keycloak reuses the client session of an SSO login and keeps its issuer_state note, so
            # the retry would hit the same offer. The login of the first attempt is replayed.
            log(tr("The offer was made for another wallet ({client}); asking the issuer directly for the "
                   "same credential.", client=bound.group(1)))
            fresh = requests.Session()
            fresh.headers.update(session.headers)
            fresh.verify = session.verify
            replay.armed = True
            try:
                token, retry_username = login(fresh, None, getattr(exc, "username", None))
            except WalletError as retry_exc:
                raise WalletError(tr(
                    "This offer was made for another wallet (OAuth client '{client}') and the issuer did not "
                    "give the credential directly either: {error}", client=bound.group(1), error=retry_exc,
                ), hint=retry_exc.hint) from retry_exc
            username = getattr(exc, "username", None) or retry_username
        finally:
            replay.forget()  # the password does not outlive the login
        proof_iss = client_id
        # Remember what worked (never the password).
        config = load_config()
        remembered = {"client_id": client_id, "redirect_uri": redirect_uri}
        if username:
            remembered["username"] = username
        config.setdefault("issuers", {})[issuer] = remembered
        save_config(config)
    log(tr("Access token received."))
    account = account_of(token)
    if account:
        log(tr("Signed in as {account}.", account=account))
    debug(f"Token scope: {token.get('scope')}")

    issued: list[IssuedCredential] = []
    # Logos are fetched only now, once the user accepted the offer, and stored with the credential:
    # showing the wallet never contacts anyone.
    issuer_logo = _logo_uri(pick_display(issuer_meta.get("display")))
    logos = _Logos(session, issuer)
    for config_id in config_ids:
        logos.want(config_id, displays[config_id].get("logo_uri") or issuer_logo)
    for config_id in config_ids:
        fmt = configs.get(config_id, {}).get("format", "unknown")
        log(tr("Requesting {credential} ({format})…", credential=config_id, format=fmt))
        for raw_credential in request_credential(
            session, key, issuer_meta, token, config_id, proof_iss=proof_iss, dpop=dpop
        ):
            if fmt in SD_JWT_FORMATS:
                verify_issued_credential(session, raw_credential, key, issuer, as_meta)
            path = save_credential(raw_credential, fmt=fmt, issuer=issuer, configuration_id=config_id,
                                   display=_stored_display(displays[config_id], logos.get(config_id)))
            debug(f"Credential stored in {path}")
            claims = parse_sd_jwt(raw_credential).claims if fmt in SD_JWT_FORMATS else None
            issued.append(IssuedCredential(config_id, path, claims, account))
    config = load_config()
    config.setdefault("issuers", {}).setdefault(issuer, {})
    save_config(config)
    event = {"type": "issued", "party": issuer_name, "party_id": issuer,
             "credentials": [displays[c.configuration_id]["name"] for c in issued]}
    if account:
        event["account"] = account
    add_history(event)
    return issued


def known_issuer_for(session: requests.Session, wanted: list[str]) -> tuple[str, str, str] | None:
    """
    (issuer, credential_configuration_id, issuer name) of an issuer already used in this profile that
    offers one of the 'wanted' credential types (configuration id or vct), or None. Only public metadata
    is read; errors just mean "no".
    """
    wanted_set = {w for w in wanted if w}
    for issuer in list(load_config().get("issuers", {}))[:8]:
        try:
            require_https(issuer, "credential_issuer")
            meta = _get_first_json(session, _well_known(issuer, "openid-credential-issuer"))
        except (WalletError, requests.RequestException):
            continue
        configs = meta.get("credential_configurations_supported") or {}
        if not isinstance(configs, dict):
            continue
        for config_id, config in configs.items():
            vct = config.get("vct") if isinstance(config, dict) else None
            if config_id in wanted_set or (vct and vct in wanted_set):
                name = pick_display(meta.get("display")).get("name") or site_of(issuer)
                return issuer, config_id, name
    return None


def issue_from_issuer(session: requests.Session, issuer: str, config_ids: list[str], options: IssueOptions,
                      ui: Prompter) -> list[IssuedCredential]:
    """Wallet-initiated issuance (OpenID4VCI 1.0 §3.3.3): no offer, just the issuer and the credential."""
    issuer = issuer.strip().rstrip("/")
    require_https(issuer, "credential_issuer")
    if not config_ids:
        meta = _get_first_json(session, _well_known(issuer, "openid-credential-issuer"))
        available = sorted((meta.get("credential_configurations_supported") or {}).keys())
        if len(available) != 1:
            raise WalletError(tr("Choose a credential with --credential: {ids}",
                                 ids=", ".join(available) or "-"))
        config_ids = available
    # Authorization code without issuer_state: the server authorizes by scope (the user must be
    # entitled to the credential) and the token is not tied to any other wallet's offer.
    offer = {"credential_issuer": issuer, "credential_configuration_ids": config_ids,
             "grants": {"authorization_code": {}}}
    return issue(session, json.dumps(offer), options, ui)


def pick_display(displays: Any, locales: tuple[str, ...] | None = None) -> dict[str, Any]:
    """Picks the 'display' entry (OpenID4VCI) in the interface language (else English), or the first one."""
    if not isinstance(displays, list) or not displays:
        return {}
    locales = locales or tuple(dict.fromkeys((i18n.current(), "en")))
    for wanted in locales:
        for entry in displays:
            if isinstance(entry, dict) and str(entry.get("locale", "")).lower().startswith(wanted):
                return entry
    return displays[0] if isinstance(displays[0], dict) else {}


LOGO_MAX_BYTES = 256 * 1024
# Raster formats only, recognised by their first bytes; SVG is left out (scripts, external references).
_LOGO_TYPES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def _logo_type(data: bytes) -> str | None:
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return next((mime for magic, mime in _LOGO_TYPES if data.startswith(magic)), None)


def _logo_uri(entry: dict[str, Any]) -> str | None:
    logo = entry.get("logo") or {}
    uri = logo.get("uri") or logo.get("url") if isinstance(logo, dict) else None
    return uri if isinstance(uri, str) else None


def fetch_logo(session: requests.Session, uri: str, issuer: str = "") -> dict[str, str]:
    """{"logo": base64, "logo_type": mime} for a small raster image, or {} (a logo is never required)."""
    try:
        if uri.startswith("data:"):
            header, _, payload = uri[5:].partition(",")
            if not header.endswith(";base64") or len(payload) > LOGO_MAX_BYTES * 4 // 3 + 4:
                return {}
            data = base64.b64decode(payload, validate=True)
        else:
            require_https(uri, "logo")
            # Not this computer or the local network: the address comes from the issuer's metadata.
            if is_local_host(urlsplit(uri).hostname) and not is_local_host(urlsplit(issuer).hostname):
                debug(f"Logo on a local address ignored: {uri[:80]}")
                return {}
            with session.get(uri, timeout=10, stream=True, allow_redirects=False) as response:
                if response.status_code != 200:
                    return {}
                data = response.raw.read(LOGO_MAX_BYTES + 1, decode_content=True)
        mime = _logo_type(data)
        if len(data) > LOGO_MAX_BYTES or mime is None:
            debug(f"Logo ignored ({len(data)} bytes, not a small PNG/JPEG/GIF/WebP): {uri[:80]}")
            return {}
        return {"logo": base64.b64encode(data).decode("ascii"), "logo_type": mime}
    except (WalletError, requests.RequestException, binascii.Error, ValueError) as exc:
        debug(f"Logo not downloaded ({exc}): {uri[:80]}")
        return {}


def _stored_display(display: dict[str, Any], logo: dict[str, str]) -> dict[str, Any]:
    stored = {**display, **logo}
    if str(stored.get("logo_uri", "")).startswith("data:"):  # already decoded into "logo"
        del stored["logo_uri"]
    return stored


class _Logos:
    """Logo of each credential configuration, each address downloaded once."""

    def __init__(self, session: requests.Session, issuer: str):
        self.session = session
        self.issuer = issuer
        self.by_uri: dict[str, dict[str, str]] = {}
        self.by_config: dict[str, str] = {}

    def want(self, config_id: str, uri: str | None) -> None:
        if uri:
            self.by_config[config_id] = uri

    def get(self, config_id: str) -> dict[str, str]:
        uri = self.by_config.get(config_id)
        if not uri:
            return {}
        if uri not in self.by_uri:
            self.by_uri[uri] = fetch_logo(self.session, uri, self.issuer)
        return self.by_uri[uri]


def credential_display(config: dict[str, Any], config_id: str, issuer_name: str) -> dict[str, Any]:
    """Name and colours the issuer wants the credential shown with (if it publishes them)."""
    entry = pick_display(config.get("display") or (config.get("credential_metadata") or {}).get("display"))
    display = {"name": entry.get("name") or humanize(config_id), "issuer_name": issuer_name}
    for key in ("background_color", "text_color", "description"):
        if isinstance(entry.get(key), str):
            display[key] = entry[key]
    logo_uri = _logo_uri(entry)
    if logo_uri:
        display["logo_uri"] = logo_uri
    return display


def did_web_url(did: str) -> str:
    """did:web:host[%3Aport][:path:...] -> URL of the DID document."""
    parts = [unquote(p) for p in did.split(":")[2:]]
    if not parts or not parts[0]:
        raise WalletError(tr("Invalid did:web: {did}", did=did))
    if len(parts) == 1:
        return f"https://{parts[0]}/.well-known/did.json"
    return f"https://{parts[0]}/{'/'.join(parts[1:])}/did.json"


def _did_web_keys(session: requests.Session, did: str, kid: str | None) -> list[Any]:
    url = did_web_url(did)
    document = _json(session.get(url, headers={"Accept": "application/json"}, timeout=20), "GET", url)
    if document.get("id") != did:
        raise WalletError(tr("The document {url} belongs to {owner}, not to {did}.", url=url, owner=document.get("id"),
                             did=did))
    methods = [m for m in document.get("verificationMethod") or [] if m.get("publicKeyJwk")]
    if kid:
        wanted = {kid, did + kid if kid.startswith("#") else kid}
        methods = [m for m in methods if m.get("id") in wanted or m["publicKeyJwk"].get("kid") == kid] or methods
    return [k for k in (jwk_to_public_key(m["publicKeyJwk"]) for m in methods) if k is not None]


def issuer_keys(
    session: requests.Session, header: dict[str, Any], iss: str, issuer: str,
    as_meta: dict[str, Any] | Callable[[], dict[str, Any]],
) -> tuple[list[Any], bool]:
    """
    Candidate public keys for a JWT of the issuer 'iss' with this header, and whether they are known
    to belong to 'iss': x5c, did:web document, jwt-vc-issuer metadata or, as a last resort, the jwks
    of the authorization server that offered the credential ('as_meta', or a function that fetches it).
    """
    kid = header.get("kid")
    if header.get("x5c"):
        cert = _x5c_chain(header)[0]
        return [cert.public_key()], host_of(iss) in _dns_names(cert)
    if iss.startswith("did:web:"):
        try:
            keys = _did_web_keys(session, iss, kid)
            if keys:
                return keys, True
        except (WalletError, requests.RequestException) as exc:
            log(tr("Warning: could not resolve {iss}: {error}", iss=iss, error=exc))
    if iss.startswith("https://"):
        try:
            meta = _get_first_json(session, _well_known(iss, "jwt-vc-issuer"))
            jwks = meta.get("jwks") or (
                _json(session.get(meta["jwks_uri"], timeout=20), "GET", meta["jwks_uri"])
                if meta.get("jwks_uri") else None
            )
            if meta.get("issuer", iss) == iss and jwks:
                keys = [j for j in jwks.get("keys") or [] if not kid or j.get("kid") == kid]
                return [k for k in map(jwk_to_public_key, keys) if k is not None], True
        except (WalletError, requests.RequestException) as exc:
            debug(f"No jwt-vc-issuer metadata: {exc}")
    if callable(as_meta):
        as_meta = as_meta()
    if not as_meta.get("jwks_uri"):
        return [], False
    jwks = _json(session.get(as_meta["jwks_uri"], timeout=20), "GET", as_meta["jwks_uri"])
    keys = [j for j in jwks.get("keys") or [] if not kid or j.get("kid") == kid]
    bound = iss == issuer or host_of(iss) == host_of(issuer)
    return [k for k in map(jwk_to_public_key, keys) if k is not None], bound


def verify_issued_credential(
    session: requests.Session, raw: str, holder: HolderKey, issuer: str, as_meta: dict[str, Any]
) -> None:
    """Before storing: issuer signature and binding to the wallet key."""
    sd = parse_sd_jwt(raw)
    iss = sd.payload.get("iss") or issuer
    keys, bound = issuer_keys(session, sd.header, str(sd.payload.get("iss", "")), issuer, as_meta)
    if not keys:
        log(tr("Warning: the issuer's public key was not found; the signature could not be verified."))
    elif not any(_verify_jws(sd.issuer_jwt, k) for k in keys):
        raise WalletError(tr("The credential's signature does not match the issuer's keys; it is not stored."),
                          hint=tr("The credential received could not be checked, so it was not saved. Contact "
                                  "the organisation that gives it and send them the technical details."))
    elif bound:
        log(tr("Valid issuer signature ({iss}).", iss=iss))
    else:
        log(tr("Warning: the signature is valid with the keys of {host}, but they could not be tied to {iss}; "
               "the verifier may reject it.", host=host_of(issuer), iss=iss))
    cnf = (sd.payload.get("cnf") or {}).get("jwk")
    if cnf is None:
        log(tr("Warning: the credential is not bound to any key (no cnf); anyone who copies it can use it."))
    elif (cnf.get("x"), cnf.get("y")) != (holder.public_jwk["x"], holder.public_jwk["y"]):
        raise WalletError(tr("The credential is bound to another key, not this wallet's; it is not stored."),
                          hint=tr("The credential received could not be checked, so it was not saved. Contact "
                                  "the organisation that gives it and send them the technical details."))

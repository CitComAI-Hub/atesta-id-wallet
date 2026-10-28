# -*- coding: utf-8 -*-
"""OpenID4VCI: offers, login at the authorization server, and issuance."""

from __future__ import annotations

import hashlib
import html
import http.server
import json
import os
import re
import secrets
import sys
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import requests

from .common import (
    Cancelled,
    SD_JWT_FORMATS,
    WalletError,
    _http_error,
    _json,
    _last_deep_link,
    humanize,
    b64u,
    debug,
    host_of,
    log,
    parse_json,
    require_https,
)
from . import i18n
from .i18n import tr
from .jose import _dns_names, _verify_jws, _x5c_chain, jwk_to_public_key
from .sdjwt import SdJwt, parse_sd_jwt
from .storage import HolderKey, add_history, load_config, save_config, save_credential
from .ui import OfferSummary, Prompter, TerminalPrompter


PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


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
        params = parse_qs(urlsplit(raw).query, keep_blank_values=True)
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


def _wait_local_callback(redirect_uri: str, timeout: int = 300) -> str:
    """Short-lived HTTP server for redirect_uri http://localhost:PORT/..."""
    parts = urlsplit(redirect_uri)
    result: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if urlsplit(self.path).path != (parts.path or "/"):  # p. ej. /favicon.ico
                self.send_response(404)
                self.end_headers()
                return
            result["url"] = f"{parts.scheme}://{parts.netloc}{self.path}"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<h3>{tr('Done. You can go back to the wallet.')}</h3>".encode("utf-8"))

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.HTTPServer((parts.hostname or "127.0.0.1", parts.port or 80), Handler)
    server.timeout = 1
    deadline = time.time() + timeout
    while "url" not in result and time.time() < deadline:
        server.handle_request()
    server.server_close()
    if "url" not in result:
        raise WalletError(tr("Timed out waiting for the browser redirect."))
    return result["url"]


def _open_browser_quietly(url: str) -> None:
    """webbrowser inherits stdout/stderr and the browser writes over the prompt."""
    sys.stdout.flush()
    sys.stderr.flush()
    saved = os.dup(1), os.dup(2)
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
                ))
            require_https(target, tr("The login form"))  # never the password in clear text
            if password_sent:
                raise WalletError(tr("Login rejected: {error}", error=_page_error(page) or tr("wrong credentials")))
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
                                 error=f": {error}" if error else ""))
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
) -> tuple[dict[str, Any], str | None]:
    """Returns the token and the username used to log in (if the login was done by the wallet)."""
    ui = ui or TerminalPrompter()
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

    if not as_meta.get("authorization_endpoint"):
        raise WalletError(tr("The authorization server metadata has no authorization_endpoint."))
    auth_url = as_meta["authorization_endpoint"] + "?" + urlencode(params, quote_via=quote)
    debug(f"Authorization URL: {auth_url}")

    target = urlsplit(redirect_uri)
    local_redirect = target.scheme == "http" and target.hostname in ("localhost", "127.0.0.1")
    if not browser_login and not local_redirect:
        log(tr("Signing in to Keycloak from the wallet (use --browser-login for the browser)."))
        callback_url, username = headless_login(
            session, auth_url, redirect_uri, username, ui, suggested_username=suggested_username
        )
    else:
        ui.notice(tr("Open this URL in the browser and sign in to Keycloak:\n\n{url}", url=auth_url))
        if open_browser:
            _open_browser_quietly(auth_url)

    if local_redirect:
        log(tr("Waiting for the redirect at {uri}…", uri=redirect_uri))
        callback_url = _wait_local_callback(redirect_uri)
    elif browser_login:
        ui.notice(tr(
            "After login the browser goes to a URL that starts with\n  {uri}?...code=...\n"
            "Copy it from the address bar and paste it here (if the page changes it right away, find it "
            "in the history with Ctrl+H). It expires in about a minute.", uri=redirect_uri
        ))
        callback_url = ""
        while not callback_url:
            callback_url = ui.text(tr("Paste the redirect URL (or just the code)")).strip()

    if "?" in callback_url or "#" in callback_url or "code=" in callback_url:
        query = urlsplit(callback_url).query or urlsplit(callback_url).fragment
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
    response = session.post(
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
    return _json(response, "POST", token_url), username


def pre_authorized_flow(
    session: requests.Session,
    as_meta: dict[str, Any],
    grant: dict[str, Any],
    *,
    client_id: str | None,
    tx_code: str | None,
    ui: Prompter | None = None,
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
    response = session.post(token_url, data=data, timeout=20)
    return _json(response, "POST", token_url)


def _fetch_nonce(session: requests.Session, issuer_meta: dict[str, Any], token: dict[str, Any]) -> str | None:
    endpoint = issuer_meta.get("nonce_endpoint")
    if endpoint:
        response = session.post(endpoint, timeout=20)
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
) -> list[str]:
    issuer = issuer_meta["credential_issuer"]
    endpoint = issuer_meta["credential_endpoint"]
    headers = {
        "Authorization": f"{token.get('token_type', 'Bearer')} {token['access_token']}",
        "Content-Type": "application/json",
    }

    # If the token carries credential_identifiers (authorization_details), they are used.
    identifier = None
    for detail in token.get("authorization_details") or []:
        if detail.get("credential_configuration_id") == configuration_id and detail.get(
            "credential_identifiers"
        ):
            identifier = detail["credential_identifiers"][0]

    nonce = _fetch_nonce(session, issuer_meta, token)
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
        response = session.post(endpoint, headers=headers, json=body, timeout=30)
        if response.status_code < 400:
            data = _json(response, "POST", endpoint)
            break
        error = {}
        try:
            error = response.json()
        except ValueError:
            pass
        if error.get("error") == "invalid_nonce" or error.get("c_nonce"):
            nonce = error.get("c_nonce") or _fetch_nonce(session, issuer_meta, token)
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
        raise WalletError(tr("The issuer answered with deferred issuance (transaction_id), which is not supported."))
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


@dataclass
class IssuedCredential:
    configuration_id: str
    path: Path
    claims: dict[str, Any] | None  # None if the format is not SD-JWT


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
    issuer_name = pick_display(issuer_meta.get("display")).get("name") or host_of(issuer)
    displays = {c: credential_display(configs.get(c, {}), c, issuer_name) for c in config_ids}
    summary = OfferSummary(issuer, issuer_name, [displays[c]["name"] for c in config_ids],
                           known=issuer in load_config().get("issuers", {}))
    if not ui.review_offer(summary):
        raise Cancelled()

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

    grants = offer.get("grants") or {}
    if PRE_AUTH_GRANT in grants and not options.force_auth_code:
        log(tr("Pre-authorized code flow."))
        token = pre_authorized_flow(
            session, as_meta, grants[PRE_AUTH_GRANT], client_id=options.client_id_pre, tx_code=options.tx_code,
            ui=ui,
        )
        proof_iss = options.client_id_pre
    else:
        issuer_config = load_config().get("issuers", {}).get(issuer, {})
        client_id = options.client_id or issuer_config.get("client_id") or "account-console"
        redirect_uri = (
            options.redirect_uri
            or issuer_config.get("redirect_uri")
            or f"{as_base.rstrip('/')}/account/oid4vci-callback"
        )
        log(tr("Authorization code flow (client_id={client_id}).", client_id=client_id))
        scopes = [configs.get(c, {}).get("scope") for c in config_ids]
        details = None
        if options.authorization_details:
            details = [
                {"type": "openid_credential", "credential_configuration_id": c, "locations": [issuer]}
                for c in config_ids
            ]
        token, username = authorization_code_flow(
            session,
            as_meta,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=[s for s in scopes if s],
            issuer_state=(grants.get("authorization_code") or {}).get("issuer_state"),
            authorization_details=details,
            open_browser=options.open_browser,
            browser_login=options.browser_login,
            username=options.username,
            ui=ui,
            suggested_username=issuer_config.get("username"),
        )
        proof_iss = client_id
        # Remember what worked (never the password).
        config = load_config()
        remembered = {"client_id": client_id, "redirect_uri": redirect_uri}
        if username:
            remembered["username"] = username
        config.setdefault("issuers", {})[issuer] = remembered
        save_config(config)
    log(tr("Access token received."))
    debug(f"Token scope: {token.get('scope')}")

    issued: list[IssuedCredential] = []
    for config_id in config_ids:
        fmt = configs.get(config_id, {}).get("format", "unknown")
        log(tr("Requesting {credential} ({format})…", credential=config_id, format=fmt))
        for raw_credential in request_credential(
            session, key, issuer_meta, token, config_id, proof_iss=proof_iss
        ):
            if fmt in SD_JWT_FORMATS:
                verify_issued_credential(session, raw_credential, key, issuer, as_meta)
            path = save_credential(raw_credential, fmt=fmt, issuer=issuer, configuration_id=config_id,
                                   display=displays[config_id])
            debug(f"Credential stored in {path}")
            claims = parse_sd_jwt(raw_credential).claims if fmt in SD_JWT_FORMATS else None
            issued.append(IssuedCredential(config_id, path, claims))
    config = load_config()
    config.setdefault("issuers", {}).setdefault(issuer, {})
    save_config(config)
    add_history({"type": "issued", "party": issuer_name, "party_id": issuer,
                 "credentials": [displays[c.configuration_id]["name"] for c in issued]})
    return issued


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


def credential_display(config: dict[str, Any], config_id: str, issuer_name: str) -> dict[str, Any]:
    """Name and colours the issuer wants the credential shown with (if it publishes them)."""
    entry = pick_display(config.get("display") or (config.get("credential_metadata") or {}).get("display"))
    display = {"name": entry.get("name") or humanize(config_id), "issuer_name": issuer_name}
    for key in ("background_color", "text_color", "description"):
        if isinstance(entry.get(key), str):
            display[key] = entry[key]
    logo = entry.get("logo") or {}
    if isinstance(logo, dict) and isinstance(logo.get("uri") or logo.get("url"), str):
        display["logo_uri"] = logo.get("uri") or logo.get("url")
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


def _issuer_keys(
    session: requests.Session, sd: SdJwt, issuer: str, as_meta: dict[str, Any]
) -> tuple[list[Any], bool]:
    """
    Candidate public keys of the issuer, and whether they are known to belong to the
    credential's 'iss': x5c, did:web document, jwt-vc-issuer metadata or, as a last resort,
    the jwks of the authorization server that offered the credential.
    """
    iss = str(sd.payload.get("iss", ""))
    kid = sd.header.get("kid")
    if sd.header.get("x5c"):
        cert = _x5c_chain(sd.header)[0]
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
    keys, bound = _issuer_keys(session, sd, issuer, as_meta)
    if not keys:
        log(tr("Warning: the issuer's public key was not found; the signature could not be verified."))
    elif not any(_verify_jws(sd.issuer_jwt, k) for k in keys):
        raise WalletError(tr("The credential's signature does not match the issuer's keys; it is not stored."))
    elif bound:
        log(tr("Valid issuer signature ({iss}).", iss=iss))
    else:
        log(tr("Warning: the signature is valid with the keys of {host}, but they could not be tied to {iss}; "
               "the verifier may reject it.", host=host_of(issuer), iss=iss))
    cnf = (sd.payload.get("cnf") or {}).get("jwk")
    if cnf is None:
        log(tr("Warning: the credential is not bound to any key (no cnf); anyone who copies it can use it."))
    elif (cnf.get("x"), cnf.get("y")) != (holder.public_jwk["x"], holder.public_jwk["y"]):
        raise WalletError(tr("The credential is bound to another key, not this wallet's; it is not stored."))

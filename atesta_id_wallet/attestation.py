# -*- coding: utf-8 -*-
"""
Wallet attestation and key attestation, from a wallet provider (provider/ in this repository).

- Wallet attestation (OAuth 2.0 Attestation-Based Client Authentication, OpenID4VCI 1.0
  Appendix E, HAIP 1.0 §4.4.1): a Client Attestation JWT for a key made for one issuance, sent
  with a fresh proof of possession to the authorization server's PAR and token endpoints. Its
  `sub`, the same for every installation, is the client_id. One per issuance, so issuers cannot
  link two issuances by it.
- Key attestation (OpenID4VCI 1.0 Appendix D, HAIP 1.0 §4.5.1): one key-attestation+jwt covering
  every key of a batch, with the issuer's c_nonce, asked for only when the issuer requires it.

The provider is stateless: it is sent public keys and proofs that the wallet holds them, never
anything about the user or the credentials.
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

import requests

from . import storage
from .common import WalletError, _http_error, _json, b64u, debug, jwt_decode_unverified, log, require_https
from .i18n import tr
from .keys import HolderKey, Key

AUTH_METHOD = "attest_jwt_client_auth"
ATTESTATION_HEADER = "OAuth-Client-Attestation"
POP_HEADER = "OAuth-Client-Attestation-PoP"
CHALLENGE_HEADER = "OAuth-Client-Attestation-Challenge"
ENV_PROVIDER = "ATESTA_ID_WALLET_PROVIDER"


def provider_url() -> str | None:
    """The wallet provider: ATESTA_ID_WALLET_PROVIDER, else the setting; None if there is none."""
    url = os.environ.get(ENV_PROVIDER) or storage.load_settings().get("wallet_provider")
    return url.rstrip("/") if isinstance(url, str) and url else None


def set_provider_url(url: str | None) -> None:
    if url:
        require_https(url, "wallet provider")
    settings = storage.load_settings()
    if url:
        settings["wallet_provider"] = url.rstrip("/")
    else:
        settings.pop("wallet_provider", None)
    storage.save_settings(settings)


def required_by(as_meta: dict[str, Any]) -> bool:
    """Whether the authorization server takes wallet attestations as client authentication."""
    methods = as_meta.get("token_endpoint_auth_methods_supported")
    return isinstance(methods, list) and AUTH_METHOD in methods


def _no_provider(what: str) -> WalletError:
    return WalletError(
        tr("The issuer asks for {what}, and no wallet provider is set up (atesta-id-wallet provider URL).",
           what=what),
        hint=tr("This organisation only gives credentials to wallets vouched for by a wallet provider. Ask "
                "whoever supports the wallet in your organisation which one to use."))


class Provider:
    def __init__(self, session: requests.Session, url: str):
        require_https(url, "wallet provider")
        self.session, self.url = session, url

    def _post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.url + path
        try:
            response = self.session.post(url, json=body or {}, timeout=20)
        except requests.RequestException as exc:
            raise WalletError(tr("The wallet provider could not be reached: {error}", error=exc)) from exc
        if response.status_code >= 400:
            raise _http_error("POST", url, response)
        return _json(response, "POST", url)

    def nonce(self) -> str:
        nonce = self._post("/nonce").get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise WalletError(tr("The wallet provider gave no nonce."))
        return nonce

    def _request(self, key: Key, typ: str, nonce: str, **claims: Any) -> str:
        return key.sign_jwt({"typ": typ, "jwk": key.public_jwk},
                            {"aud": self.url, "nonce": nonce, "iat": int(time.time()), **claims})

    def wallet_attestation(self, key: Key) -> str:
        request = self._request(key, "wallet-attestation-request+jwt", self.nonce())
        attestation = self._post("/wallet-attestation", {"request": request}).get("wallet_attestation")
        header, claims = _decoded(attestation, "oauth-client-attestation+jwt")
        jwk = (claims.get("cnf") or {}).get("jwk") if isinstance(claims.get("cnf"), dict) else None
        if not isinstance(jwk, dict) or (jwk.get("x"), jwk.get("y")) != (key.public_jwk["x"], key.public_jwk["y"]):
            raise WalletError(tr("The wallet provider attested another key."))
        if not isinstance(claims.get("sub"), str) or not claims["sub"] or not header.get("x5c"):
            raise WalletError(tr("The wallet provider's attestation is not valid."))
        return str(attestation)

    def key_attestation(self, keys: list[Key], issuer_nonce: str | None) -> str:
        nonce = self.nonce()
        extra = {"issuer_nonce": issuer_nonce} if issuer_nonce else {}
        requests_ = [self._request(key, "key-attestation-request+jwt", nonce, **extra) for key in keys]
        attestation = self._post("/key-attestation", {"keys": requests_}).get("key_attestation")
        header, claims = _decoded(attestation, "key-attestation+jwt")
        attested = claims.get("attested_keys")
        mine = {(k.public_jwk["x"], k.public_jwk["y"]) for k in keys}
        if not isinstance(attested, list) or {(j.get("x"), j.get("y")) for j in attested
                                              if isinstance(j, dict)} != mine:
            raise WalletError(tr("The wallet provider attested other keys."))
        if issuer_nonce and claims.get("nonce") != issuer_nonce or not header.get("x5c"):
            raise WalletError(tr("The wallet provider's attestation is not valid."))
        return str(attestation)


def _decoded(token: Any, typ: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(token, str):
        raise WalletError(tr("The wallet provider's attestation is not valid."))
    try:
        header, claims = jwt_decode_unverified(token)
    except Exception as exc:
        raise WalletError(tr("The wallet provider's attestation is not valid.")) from exc
    if header.get("typ") != typ:
        raise WalletError(tr("The wallet provider's attestation is not valid."))
    return header, claims


class ClientAttestation:
    """A wallet attestation for one issuance and the proofs of possession sent with it."""

    def __init__(self, session: requests.Session, as_meta: dict[str, Any], url: str | None = None):
        url = url or provider_url()
        if not url:
            raise _no_provider(tr("a wallet attestation"))
        self.session, self.as_meta = session, as_meta
        self.key = HolderKey.generate()  # this issuance only: it links nothing else
        self.jwt = Provider(session, url).wallet_attestation(self.key)
        self.client_id = str(jwt_decode_unverified(self.jwt)[1]["sub"])
        self.challenge: str | None = None
        log(tr("Wallet attestation received from the wallet provider (client_id={client_id}).",
               client_id=self.client_id))

    def _challenge(self) -> str | None:
        if self.challenge:
            challenge, self.challenge = self.challenge, None  # one use each
            return challenge
        endpoint = self.as_meta.get("challenge_endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            return None
        response = self.session.post(endpoint, timeout=20)
        value = _json(response, "POST", endpoint).get("attestation_challenge")
        return value if isinstance(value, str) and value else None

    def headers(self) -> dict[str, str]:
        now = int(time.time())
        claims: dict[str, Any] = {"iss": self.client_id, "aud": self.as_meta.get("issuer", ""),
                                  "jti": b64u(secrets.token_bytes(16)), "iat": now, "exp": now + 300}
        challenge = self._challenge()
        if challenge:
            claims["challenge"] = challenge
        pop = self.key.sign_jwt({"typ": "oauth-client-attestation-pop+jwt"}, claims)
        return {ATTESTATION_HEADER: self.jwt, POP_HEADER: pop}

    def asks_challenge(self, response: requests.Response) -> bool:
        """A use_attestation_challenge error: the challenge it carries is used on the retry."""
        challenge = response.headers.get(CHALLENGE_HEADER)
        if response.status_code in (400, 401) and challenge and "use_attestation_challenge" in response.text:
            debug("The authorization server asked for an attestation challenge; retrying.")
            self.challenge = challenge
            return True
        return False


def key_attestation_needed(config: dict[str, Any]) -> tuple[bool, bool]:
    """(the issuer requires a key attestation, it only takes the 'attestation' proof type)."""
    types = config.get("proof_types_supported")
    types = types if isinstance(types, dict) else {}
    jwt = types.get("jwt") if isinstance(types.get("jwt"), dict) else None
    only_attestation = jwt is None and isinstance(types.get("attestation"), dict)
    required = only_attestation or (jwt is not None and "key_attestations_required" in jwt)
    return required, only_attestation


def key_attestation(session: requests.Session, keys: list[Key], issuer_nonce: str | None) -> str:
    url = provider_url()
    if not url:
        raise _no_provider(tr("a key attestation"))
    return Provider(session, url).key_attestation(keys, issuer_nonce)

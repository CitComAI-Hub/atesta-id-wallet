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

import hashlib
import os
import secrets
import time
from typing import Any

import requests

from . import storage
from .common import (
    WalletError, _http_error, _json, b64u, b64u_decode, debug, jwt_decode_unverified, log, require_https,
)
from .i18n import tr
from .keys import HardwareKey, HolderKey, Key, TpmEvidence, tpm_evidence

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


class ProviderError(WalletError):
    """The provider refused a request; error is its OAuth-style error code."""

    def __init__(self, message: str, error: str):
        super().__init__(message)
        self.error = error


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
            try:
                error = response.json().get("error")
            except (ValueError, AttributeError):
                error = None
            raise ProviderError(str(_http_error("POST", url, response)), str(error or ""))
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
        """
        One key attestation for the batch: with TPM evidence when every key is in a TPM that can
        give it (the provider then states key_storage), else without (if the evidence cannot be
        had or is refused, the issuance goes on as with keys in software).
        """
        evidence = _common_evidence(keys)
        if evidence is not None:
            for attempt in range(2):
                try:
                    credential = self.aik_credential(evidence, fresh=attempt > 0)
                    if credential is None:
                        break
                    attestation = self._key_attestation(keys, issuer_nonce, credential)
                    log(tr("The wallet provider confirmed that the keys are in this computer's security chip."))
                    return attestation
                except ProviderError as exc:
                    if exc.error == "invalid_aik_credential" and attempt == 0:
                        continue  # expired or from another provider key: enrol again
                    log(tr("The security chip's evidence was not accepted ({error}); the keys are attested "
                           "without it.", error=exc))
                except Exception as exc:  # the chip or its driver failed: the issuance goes on
                    log(tr("The security chip's evidence could not be had ({error}); the keys are attested "
                           "without it.", error=exc))
                break
        return self._key_attestation(keys, issuer_nonce, None)

    def _key_attestation(self, keys: list[Key], issuer_nonce: str | None, credential: str | None) -> str:
        nonce = self.nonce()
        extra: dict[str, Any] = {"issuer_nonce": issuer_nonce} if issuer_nonce else {}
        requests_ = []
        for key in keys:
            claims = dict(extra)
            if credential and isinstance(key, HardwareKey):
                certified = key.certify(hashlib.sha256(nonce.encode("ascii")).digest())
                if certified:
                    claims["tpm"] = dict(zip(("attest", "signature", "public"), (b64u(p) for p in certified)))
            requests_.append(self._request(key, "key-attestation-request+jwt", nonce, **claims))
        body: dict[str, Any] = {"keys": requests_}
        if credential:
            body["aik_credential"] = credential
        attestation = self._post("/key-attestation", body).get("key_attestation")
        header, claims = _decoded(attestation, "key-attestation+jwt")
        attested = claims.get("attested_keys")
        mine = {(k.public_jwk["x"], k.public_jwk["y"]) for k in keys}
        if not isinstance(attested, list) or {(j.get("x"), j.get("y")) for j in attested
                                              if isinstance(j, dict)} != mine:
            raise WalletError(tr("The wallet provider attested other keys."))
        if issuer_nonce and claims.get("nonce") != issuer_nonce or not header.get("x5c"):
            raise WalletError(tr("The wallet provider's attestation is not valid."))
        return str(attestation)


    def aik_credential(self, evidence: TpmEvidence, fresh: bool = False) -> str | None:
        """
        This provider's credential for the TPM's attestation key, kept in the settings (it names no
        user and no TPM). Enrolment: the EK certificate and the AIK go to the provider, which
        answers with a MakeCredential; only that TPM's ActivateCredential recovers its secret.
        None if the provider does not check TPM evidence.
        """
        settings = storage.load_settings()
        stored = settings.get("tpm_aik")
        kept: dict[str, Any] = stored if isinstance(stored, dict) else {}
        mine = kept.get(self.url) if isinstance(kept.get(self.url), dict) else None
        if mine and not fresh and isinstance(mine.get("exp"), int) and mine["exp"] > time.time() + 300:
            return str(mine["credential"])
        try:
            ek, aik = b64u(evidence.endorsement_certificate()), b64u(evidence.attestation_key())
            challenge = self._post("/tpm/enroll", {"ek_certificate": ek, "aik_public": aik})
        except ProviderError as exc:
            if exc.error == "tpm_not_supported":
                debug("The wallet provider does not check TPM evidence.")
                return None
            raise
        secret = evidence.activate(b64u_decode(challenge["credential_blob"]),
                                   b64u_decode(challenge["encrypted_secret"]))
        credential = self._post("/tpm/activate", {"ek_certificate": ek, "aik_public": aik,
                                                  "issued_at": challenge["issued_at"], "secret": b64u(secret)}
                                ).get("aik_credential")
        if not isinstance(credential, str):
            raise WalletError(tr("The wallet provider's attestation is not valid."))
        _, claims = jwt_decode_unverified(credential)
        kept[self.url] = {"credential": credential, "exp": int(claims.get("exp") or 0)}
        settings = storage.load_settings()
        settings["tpm_aik"] = kept
        storage.save_settings(settings)
        log(tr("This computer's security chip was enrolled with the wallet provider."))
        return credential


def _common_evidence(keys: list[Key]) -> TpmEvidence | None:
    """The TPM all the keys are in, if it can give evidence (a batch is all in one place or none)."""
    backends = {id(k.backend): k.backend for k in keys if isinstance(k, HardwareKey)}
    if len(backends) != 1 or not all(isinstance(k, HardwareKey) for k in keys):
        return None
    return tpm_evidence(next(iter(backends.values())))


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

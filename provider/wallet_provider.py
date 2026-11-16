#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Atesta wallet provider: issues wallet attestations and key attestations to Atesta ID Wallet.

A minimal, stateless WSGI service (only `cryptography` is needed):

  POST /nonce                {}                          -> {"nonce": N}
  POST /wallet-attestation   {"request": JWT}            -> {"wallet_attestation": JWT}
  POST /key-attestation      {"keys": [JWT, ...], "aik_credential"?: JWT} -> {"key_attestation": JWT}
  POST /tpm/enroll           {"ek_certificate", "aik_public"}            -> {"credential_blob", ...}
  POST /tpm/activate         {"ek_certificate", "aik_public", "issued_at", "secret"} -> {"aik_credential": JWT}
  GET  /health                                           -> {"status": "ok"}

Each request JWT is signed by the key it is about, with that key in its `jwk` header, and
carries {"aud": PROVIDER_URL, "nonce": N, "iat": ...}: whoever asks holds the key. A
key-attestation request may add "issuer_nonce" (the issuer's c_nonce), copied into the
attestation. Nothing is stored and nothing about the user is received.

What is attested: that the keys belong to a running Atesta ID Wallet that answered the nonce.
The wallet is open source, so that alone proves neither the computer nor the key storage. With
TPM evidence (tpm2.py) it also proves where the keys are:
  1. /tpm/enroll: the TPM's endorsement key certificate, chained to a manufacturer's root in
     WP_TPM_ROOTS, and the public area of an attestation key (AIK). The answer is a
     MakeCredential for that EK and AIK name; its secret is derived from WP_SECRET, so nothing
     is kept between the two calls.
  2. /tpm/activate: the secret ActivateCredential gave back proves the AIK is in that TPM; the
     answer is an AIK credential (tpm-aik+jwt, WP_AIK_TTL), which carries neither the EK nor
     anything else that identifies the TPM.
  3. /key-attestation: each key request may carry "tpm": {"attest", "signature", "public"}, a
     TPM2_Certify of that key by the AIK with SHA-256(nonce) as qualifying data. When every key
     has it, the attestation states WP_TPM_KEY_STORAGE as key_storage.

Configuration (environment):
  WP_URL       public base URL of this service (iss of the attestations, expected aud)
  WP_KEY       PEM file with the signing key (P-256)
  WP_CERTS     PEM file with the signing certificate first, then intermediates (not the root)
  WP_SECRET    secret for the nonces, the same in every worker and instance (e.g. openssl rand -hex 32)
  WP_WALLET_ID sub of the wallet attestations = the wallet's client_id (default atesta-id-wallet)
  WP_WALLET_NAME, WP_WALLET_LINK  shown by issuers (Appendix E wallet_name, wallet_link)
  WP_WALLET_TTL, WP_KEY_TTL       lifetime of the attestations in seconds (3600, 600)
  WP_TPM_ROOTS  folder with TPM manufacturers' root and intermediate certificates (e.g. the
                contents of Microsoft's TrustedTpm.cab); without it there is no TPM evidence
  WP_TPM_KEY_STORAGE  key_storage for keys with TPM evidence, comma separated (default
                iso_18045_moderate; empty: none stated)
  WP_AIK_TTL    lifetime of an AIK credential in seconds (30 days)

Run:  python wallet_provider.py serve [--port 8080]    (behind a TLS reverse proxy)
      python wallet_provider.py init DIR [--name NAME]  (a CA and a signing certificate, for tests)
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.x509.oid import NameOID

import tpm2

NONCE_TTL = 300
MAX_BODY = 64 * 1024
MAX_KEYS = 10  # a batch: the wallet asks for up to 5 copies
CLOCK_SKEW = 60


class Refused(Exception):
    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error, self.description, self.status = error, description, status


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def public_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    numbers = key.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big"))}


def jwk_key(jwk: Any) -> ec.EllipticCurvePublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise Refused("invalid_request", "the key must be a public P-256 JWK")
    try:
        x, y = b64u_decode(jwk["x"]), b64u_decode(jwk["y"])
        if len(x) != 32 or len(y) != 32:
            raise ValueError("coordinates")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
    except (KeyError, TypeError, ValueError) as exc:
        raise Refused("invalid_request", "the key is not a valid P-256 JWK") from exc


def sign_jwt(key: ec.EllipticCurvePrivateKey, header: dict[str, Any], claims: dict[str, Any]) -> str:
    signing_input = f"{b64u_json({'alg': 'ES256', **header})}.{b64u_json(claims)}".encode("ascii")
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return f"{signing_input.decode('ascii')}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def verified_request(token: Any, typ: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """A request JWT signed by the key in its own jwk header: (that JWK, claims)."""
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 8192:
        raise Refused("invalid_request", "a request must be a JWT")
    head, body, signature = token.split(".")
    try:
        header, claims = json.loads(b64u_decode(head)), json.loads(b64u_decode(body))
        raw = b64u_decode(signature)
    except ValueError as exc:
        raise Refused("invalid_request", "the request JWT cannot be read") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise Refused("invalid_request", "the request JWT cannot be read")
    if header.get("typ") != typ or header.get("alg") != "ES256":
        raise Refused("invalid_request", f"the request must be an ES256 JWT of type {typ}")
    key = jwk_key(header.get("jwk"))
    if len(raw) != 64:
        raise Refused("invalid_request", "bad signature")
    try:
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   f"{head}.{body}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise Refused("invalid_request", "the request is not signed by its key") from exc
    return public_jwk(key), claims


def verified_own(token: Any, typ: str, key: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    """The claims of a JWT this provider signed (an AIK credential it gave out earlier)."""
    try:
        head, body, signature = token.split(".")
        header, claims, raw = json.loads(b64u_decode(head)), json.loads(b64u_decode(body)), b64u_decode(signature)
        if header.get("typ") != typ or header.get("alg") != "ES256" or len(raw) != 64 or not isinstance(claims, dict):
            raise ValueError("not this kind of JWT")
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   f"{head}.{body}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except (AttributeError, ValueError, InvalidSignature) as exc:
        raise Refused("invalid_aik_credential", "not an AIK credential of this provider") from exc
    return claims


@dataclass
class Config:
    url: str
    key: ec.EllipticCurvePrivateKey
    certs: list[x509.Certificate]
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    wallet_id: str = "atesta-id-wallet"
    wallet_name: str = "Atesta ID Wallet"
    wallet_link: str = "https://github.com/CitComAI-Hub/atesta-id-wallet"
    wallet_ttl: int = 3600
    key_ttl: int = 600
    tpm_roots: list[x509.Certificate] = field(default_factory=list)
    tpm_key_storage: list[str] = field(default_factory=lambda: ["iso_18045_moderate"])
    aik_ttl: int = 30 * 86400

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = dict(os.environ if env is None else env)
        missing = [n for n in ("WP_URL", "WP_KEY", "WP_CERTS", "WP_SECRET") if not env.get(n)]
        if missing:
            raise SystemExit(f"Missing configuration: {', '.join(missing)} (see the module docstring)")
        key = serialization.load_pem_private_key(Path(env["WP_KEY"]).read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise SystemExit("WP_KEY must be a P-256 private key")
        certs = x509.load_pem_x509_certificates(Path(env["WP_CERTS"]).read_bytes())
        config = cls(url=env["WP_URL"].rstrip("/"), key=key, certs=certs)
        config.secret = env["WP_SECRET"].encode("utf-8")  # the same in every worker and instance
        for name, attr in (("WP_WALLET_ID", "wallet_id"), ("WP_WALLET_NAME", "wallet_name"),
                           ("WP_WALLET_LINK", "wallet_link")):
            if env.get(name):
                setattr(config, attr, env[name])
        for name, attr in (("WP_WALLET_TTL", "wallet_ttl"), ("WP_KEY_TTL", "key_ttl"), ("WP_AIK_TTL", "aik_ttl")):
            if env.get(name):
                setattr(config, attr, int(env[name]))
        config.tpm_roots = tpm2.load_roots(env.get("WP_TPM_ROOTS"))
        if env.get("WP_TPM_ROOTS") and not config.tpm_roots:
            raise SystemExit("WP_TPM_ROOTS has no certificates")
        if "WP_TPM_KEY_STORAGE" in env:
            config.tpm_key_storage = [v.strip() for v in env["WP_TPM_KEY_STORAGE"].split(",") if v.strip()]
        config.check()
        return config

    def check(self) -> None:
        """HAIP 1.0 §4.5.1: the signing certificate is in x5c, is not self-signed, and the root is not there."""
        if not self.certs:
            raise SystemExit("WP_CERTS has no certificate")
        leaf = self.certs[0].public_key()
        if not isinstance(leaf, ec.EllipticCurvePublicKey) or \
                leaf.public_numbers() != self.key.public_key().public_numbers():
            raise SystemExit("The first certificate of WP_CERTS is not that of WP_KEY")
        if any(c.subject == c.issuer for c in self.certs):
            raise SystemExit("WP_CERTS must not hold a self-signed (root) certificate: issuers have the root")

    @property
    def x5c(self) -> list[str]:
        return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii") for c in self.certs]


class Provider:
    def __init__(self, config: Config, clock: Callable[[], float] = time.time):
        self.config, self.clock = config, clock

    # Stateless nonces: time and randomness, authenticated with the secret. Within NONCE_TTL a
    # nonce could be used twice; it only proves that the request is recent (nothing is spent).
    def nonce(self) -> str:
        data = int(self.clock()).to_bytes(8, "big") + secrets.token_bytes(16)
        return b64u(data + hmac.new(self.config.secret, data, hashlib.sha256).digest()[:16])

    def _check_nonce(self, nonce: Any) -> None:
        try:
            raw = b64u_decode(nonce) if isinstance(nonce, str) else b""
        except ValueError:
            raw = b""
        data, tag = raw[:24], raw[24:]
        if len(raw) != 40 or not hmac.compare_digest(tag, hmac.new(self.config.secret, data,
                                                                    hashlib.sha256).digest()[:16]):
            raise Refused("invalid_nonce", "unknown nonce")
        if not 0 <= self.clock() - int.from_bytes(data[:8], "big") <= NONCE_TTL:
            raise Refused("invalid_nonce", "the nonce has expired")

    def _check_request(self, claims: dict[str, Any]) -> None:
        if claims.get("aud") != self.config.url:
            raise Refused("invalid_request", "the request is not for this provider (aud)")
        iat = claims.get("iat")
        if type(iat) is not int or abs(self.clock() - iat) > NONCE_TTL + CLOCK_SKEW:
            raise Refused("invalid_request", "the request has no recent iat")
        self._check_nonce(claims.get("nonce"))

    def _sign(self, typ: str, claims: dict[str, Any]) -> str:
        return sign_jwt(self.config.key, {"typ": typ, "x5c": self.config.x5c}, claims)

    def wallet_attestation(self, body: dict[str, Any]) -> dict[str, str]:
        jwk, claims = verified_request(body.get("request"), "wallet-attestation-request+jwt")
        self._check_request(claims)
        now = int(self.clock())
        # HAIP 1.0 §4.4.1: sub is the same for every instance; nothing identifies this one but the
        # key, which the wallet makes for one issuance.
        return {"wallet_attestation": self._sign("oauth-client-attestation+jwt", {
            "iss": self.config.url, "sub": self.config.wallet_id, "iat": now, "nbf": now - CLOCK_SKEW,
            "exp": now + self.config.wallet_ttl, "cnf": {"jwk": jwk},
            "wallet_name": self.config.wallet_name, "wallet_link": self.config.wallet_link,
        })}

    def key_attestation(self, body: dict[str, Any]) -> dict[str, str]:
        requests_ = body.get("keys")
        if not isinstance(requests_, list) or not 1 <= len(requests_) <= MAX_KEYS:
            raise Refused("invalid_request", f"'keys' must hold 1 to {MAX_KEYS} request JWTs")
        aik = self._aik(body["aik_credential"]) if body.get("aik_credential") is not None else None
        keys: list[dict[str, Any]] = []
        issuer_nonces = set()
        in_tpm = 0
        for request in requests_:
            jwk, claims = verified_request(request, "key-attestation-request+jwt")
            self._check_request(claims)
            if jwk in keys:
                raise Refused("invalid_request", "the same key twice")
            keys.append(jwk)
            issuer_nonces.add(claims.get("issuer_nonce"))
            if claims.get("tpm") is not None:
                if aik is None:
                    raise Refused("invalid_request", "TPM evidence needs an aik_credential")
                self._check_tpm_key(aik, claims["tpm"], jwk, claims["nonce"])
                in_tpm += 1
        if len(issuer_nonces) != 1:
            raise Refused("invalid_request", "every key must carry the same issuer_nonce")
        issuer_nonce = issuer_nonces.pop()
        if issuer_nonce is not None and (not isinstance(issuer_nonce, str) or len(issuer_nonce) > 512):
            raise Refused("invalid_request", "issuer_nonce must be a string")
        now = int(self.clock())
        claims = {"iss": self.config.url, "iat": now, "exp": now + self.config.key_ttl, "attested_keys": keys}
        if issuer_nonce:
            claims["nonce"] = issuer_nonce
        # One attestation for the whole batch: storage is stated only if it holds for every key.
        if in_tpm == len(keys) and self.config.tpm_key_storage:
            claims["key_storage"] = self.config.tpm_key_storage
        return {"key_attestation": self._sign("key-attestation+jwt", claims)}

    # TPM evidence (see the module docstring and tpm2.py).

    def _endorsement(self, body: dict[str, Any]) -> tuple[bytes, tpm2.Endorsement, tpm2.Public]:
        if not self.config.tpm_roots:
            raise Refused("tpm_not_supported", "this provider does not check TPM evidence")
        try:
            ek_der, aik_raw = b64u_decode(body["ek_certificate"]), b64u_decode(body["aik_public"])
            endorsement = tpm2.check_endorsement(ek_der, self.config.tpm_roots,
                                                 datetime.datetime.fromtimestamp(self.clock(), datetime.timezone.utc))
            aik = tpm2.parse_public(aik_raw)
            tpm2.check_aik(aik)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise Refused("invalid_request", "ek_certificate and aik_public must be base64url") from exc
        except tpm2.TpmError as exc:
            raise Refused("invalid_tpm_evidence", str(exc)) from exc
        return ek_der, endorsement, aik

    def _activation_secret(self, ek_der: bytes, aik: tpm2.Public, issued_at: int) -> bytes:
        data = b"atesta-aik" + hashlib.sha256(ek_der).digest() + aik.name + issued_at.to_bytes(8, "big")
        return hmac.new(self.config.secret, data, hashlib.sha256).digest()

    def tpm_enroll(self, body: dict[str, Any]) -> dict[str, Any]:
        ek_der, endorsement, aik = self._endorsement(body)
        issued_at = int(self.clock())
        blob, encrypted = tpm2.make_credential(endorsement.key, aik.name,
                                               self._activation_secret(ek_der, aik, issued_at))
        return {"credential_blob": b64u(blob), "encrypted_secret": b64u(encrypted), "issued_at": issued_at}

    def tpm_activate(self, body: dict[str, Any]) -> dict[str, str]:
        ek_der, endorsement, aik = self._endorsement(body)
        issued_at, secret = body.get("issued_at"), body.get("secret")
        if type(issued_at) is not int or not 0 <= self.clock() - issued_at <= NONCE_TTL:
            raise Refused("invalid_request", "the enrolment has expired; start again")
        try:
            given = b64u_decode(secret) if isinstance(secret, str) else b""
        except ValueError:
            given = b""
        if not hmac.compare_digest(given, self._activation_secret(ek_der, aik, issued_at)):
            raise Refused("invalid_tpm_evidence", "the secret was not recovered by that TPM")
        now = int(self.clock())
        # Nothing that identifies the TPM (no EK): only the AIK, which only this wallet holds.
        claims = {"iss": self.config.url, "iat": now, "exp": now + self.config.aik_ttl, "aik": b64u(aik.raw)}
        if endorsement.manufacturer:
            claims["tpm_manufacturer"] = endorsement.manufacturer
        return {"aik_credential": sign_jwt(self.config.key, {"typ": "tpm-aik+jwt"}, claims)}

    def _aik(self, credential: Any) -> tpm2.Public:
        """The AIK of an AIK credential this provider issued and that has not expired."""
        claims = verified_own(credential, "tpm-aik+jwt", self.config.key.public_key())
        if claims.get("iss") != self.config.url or not isinstance(claims.get("exp"), int) \
                or claims["exp"] < self.clock():
            raise Refused("invalid_aik_credential", "the AIK credential has expired; enrol again")
        try:
            return tpm2.parse_public(b64u_decode(claims["aik"]))
        except (KeyError, ValueError, tpm2.TpmError) as exc:
            raise Refused("invalid_aik_credential", "the AIK credential cannot be read") from exc

    def _check_tpm_key(self, aik: tpm2.Public, evidence: Any, jwk: dict[str, Any], nonce: str) -> None:
        try:
            attest, signature, public = (b64u_decode(evidence[n]) for n in ("attest", "signature", "public"))
            key = tpm2.certified_key(aik, attest, signature, public, hashlib.sha256(nonce.encode("ascii")).digest())
        except (KeyError, TypeError, ValueError) as exc:
            raise Refused("invalid_request", "tpm must hold attest, signature and public (base64url)") from exc
        except tpm2.TpmError as exc:
            raise Refused("invalid_tpm_evidence", str(exc)) from exc
        if public_jwk(key) != jwk:
            raise Refused("invalid_tpm_evidence", "the TPM certified another key")

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        """The WSGI application."""
        method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
        try:
            if method == "GET" and path == "/health":
                result: dict[str, Any] = {"status": "ok"}
            elif method != "POST":
                raise Refused("not_found", "not found", 404)
            else:
                handler = {"/nonce": lambda _body: {"nonce": self.nonce()},
                           "/wallet-attestation": self.wallet_attestation,
                           "/key-attestation": self.key_attestation,
                           "/tpm/enroll": self.tpm_enroll,
                           "/tpm/activate": self.tpm_activate}.get(path)
                if handler is None:
                    raise Refused("not_found", "not found", 404)
                result = handler(self._body(environ))
            status, payload = 200, result
        except Refused as exc:
            status, payload = exc.status, {"error": exc.error, "error_description": exc.description}
        data = json.dumps(payload).encode("utf-8")
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 413: "Payload Too Large"}.get(status, "Error")
        start_response(f"{status} {reason}", [("Content-Type", "application/json"), ("Cache-Control", "no-store"),
                                              ("Content-Length", str(len(data)))])
        return [data]

    @staticmethod
    def _body(environ: dict[str, Any]) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            raise Refused("invalid_request", "the request is too large", 413)
        raw = environ["wsgi.input"].read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except ValueError as exc:
            raise Refused("invalid_request", "the body must be JSON") from exc
        if not isinstance(body, dict):
            raise Refused("invalid_request", "the body must be a JSON object")
        return body


def create_app() -> Provider:
    """The WSGI application configured from the environment (gunicorn 'wallet_provider:create_app()')."""
    return Provider(Config.from_env())


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def init(folder: Path, name: str, days: int = 365) -> None:
    """A CA (ca.pem: what issuers trust) and a signing key and certificate issued by it."""
    folder.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name(f"{name} CA")).issuer_name(_name(f"{name} CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (folder / "ca.pem").write_bytes(ca.public_bytes(pem))
    (folder / "signer.pem").write_bytes(cert.public_bytes(pem))
    fd = os.open(folder / "signer.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # The CA key is not kept: a new signing certificate means a new CA (fine for tests; a real
    # deployment keeps its CA offline and issues the signing certificate from it).


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Atesta wallet provider")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="serve on HTTP (put a TLS reverse proxy in front)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    make = sub.add_parser("init", help="create a test CA (ca.pem) and signing key (signer.key, signer.pem)")
    make.add_argument("folder", type=Path)
    make.add_argument("--name", default="Atesta wallet provider")
    args = parser.parse_args(argv)
    if args.command == "init":
        init(args.folder, args.name)
        print(f"Created {args.folder}/ca.pem (give it to issuers), signer.key and signer.pem "
              f"(WP_KEY={args.folder}/signer.key WP_CERTS={args.folder}/signer.pem)")
        return 0
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    class Quiet(WSGIRequestHandler):
        def log_message(self, format: str, *values: Any) -> None:  # noqa: A002
            sys.stderr.write(f"{self.command} {self.path} {values[1] if len(values) > 1 else ''}\n")

    app = create_app()
    with make_server(args.host, args.port, app, handler_class=Quiet) as server:
        print(f"Wallet provider {app.config.url} on http://{args.host}:{args.port}", file=sys.stderr)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

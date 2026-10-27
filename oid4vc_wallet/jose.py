# -*- coding: utf-8 -*-
"""Firmas JWS, claves JWK/X.509 y cifrado JWE de respuestas."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import WalletError, b64u, b64u_decode, b64u_json, debug
from .i18n import tr


# Curva que exige cada algoritmo ES* (RFC 7518 §3.4): ES256 con P-384 no es una firma válida.
_ES_CURVES = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}


def _verify_jws(token: str, public_key: Any) -> bool:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = b64u_decode(sig_b64)
        alg = json.loads(b64u_decode(header_b64)).get("alg", "")
    except (ValueError, AttributeError):
        return False
    if not isinstance(alg, str):
        return False
    digest = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}.get(alg[-3:])
    if digest is None:
        return False
    try:
        if alg in _ES_CURVES and isinstance(public_key, ec.EllipticCurvePublicKey):
            size = (public_key.curve.key_size + 7) // 8
            if public_key.curve.name != _ES_CURVES[alg] or len(signature) != 2 * size:
                return False
            half = size
            der = encode_dss_signature(
                int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
            )
            public_key.verify(der, signing_input, ec.ECDSA(digest))
        elif alg in ("RS256", "RS384", "RS512") and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signing_input, padding.PKCS1v15(), digest)
        elif alg in ("PS256", "PS384", "PS512") and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                signing_input,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                digest,
            )
        else:
            return False
    except Exception:
        return False
    return True


def _verify_jws_with_cert(token: str, cert: x509.Certificate) -> bool:
    return _verify_jws(token, cert.public_key())


def jwk_to_public_key(jwk: dict[str, Any]) -> Any:
    try:
        return _jwk_to_public_key(jwk)
    except (KeyError, ValueError, TypeError) as exc:
        debug(f"Invalid JWK ({exc}); ignored.")
        return None


_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}


def _jwk_to_public_key(jwk: dict[str, Any]) -> Any:
    if jwk.get("kty") == "EC":
        curve = _CURVES.get(jwk.get("crv"))
        if curve is None:
            return None
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_decode(jwk["x"]), "big"), int.from_bytes(b64u_decode(jwk["y"]), "big"), curve()
        ).public_key()
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(
            int.from_bytes(b64u_decode(jwk["e"]), "big"), int.from_bytes(b64u_decode(jwk["n"]), "big")
        ).public_key()
    return None


def _x5c_chain(header: dict[str, Any]) -> list[x509.Certificate]:
    return [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header.get("x5c") or []]


def cert_fingerprint(cert: x509.Certificate) -> str:
    return b64u(hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest())


def _dns_names(cert: x509.Certificate) -> list[str]:
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [n.lower() for n in sans.get_values_for_type(x509.DNSName)]


def _concat_kdf(z: bytes, alg_id: str, apu: bytes, apv: bytes, key_bits: int) -> bytes:
    def len_prefixed(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    other_info = (
        len_prefixed(alg_id.encode("ascii"))
        + len_prefixed(apu)
        + len_prefixed(apv)
        + key_bits.to_bytes(4, "big")
    )
    out = b""
    counter = 1
    while len(out) * 8 < key_bits:
        out += hashlib.sha256(counter.to_bytes(4, "big") + z + other_info).digest()
        counter += 1
    return out[: key_bits // 8]


def encrypt_response_jwe(payload: dict[str, Any], request: dict[str, Any], *, apv: str | None) -> str:
    """JWE ECDH-ES (acuerdo directo) + AxxxGCM para response_mode direct_post.jwt."""
    meta = request.get("client_metadata") or {}
    keys = (meta.get("jwks") or {}).get("keys") or []
    # La clave del verificador debe servir para ECDH-ES (OpenID4VP 1.0 §8.3: el alg del JWE es el de la clave).
    jwk = next((k for k in keys if isinstance(k, dict) and k.get("kty") == "EC" and k.get("use", "enc") == "enc"
                and k.get("crv") in _CURVES and k.get("alg", "ECDH-ES") == "ECDH-ES"), None)
    if jwk is None:
        raise WalletError(tr("direct_post.jwt requires an EC encryption key in client_metadata.jwks."))
    enc_values = (
        meta.get("encrypted_response_enc_values_supported")
        or [meta.get("authorization_encrypted_response_enc") or "A128GCM"]
    )
    enc = next((e for e in enc_values if e in ("A128GCM", "A256GCM")), None)
    if enc is None:
        raise WalletError(tr("Unsupported response encryption algorithm: {values}", values=enc_values))
    key_bits = 128 if enc == "A128GCM" else 256

    curve = _CURVES[jwk["crv"]]()
    verifier_key = jwk_to_public_key(jwk)
    if verifier_key is None:
        raise WalletError(tr("direct_post.jwt requires an EC encryption key in client_metadata.jwks."))
    ephemeral = ec.generate_private_key(curve)
    z = ephemeral.exchange(ec.ECDH(), verifier_key)
    numbers = ephemeral.public_key().public_numbers()
    size = (curve.key_size + 7) // 8
    header: dict[str, Any] = {
        "alg": "ECDH-ES",
        "enc": enc,
        "epk": {
            "kty": "EC",
            "crv": jwk["crv"],
            "x": b64u(numbers.x.to_bytes(size, "big")),
            "y": b64u(numbers.y.to_bytes(size, "big")),
        },
    }
    if jwk.get("kid"):
        header["kid"] = jwk["kid"]
    if apv:
        header["apv"] = b64u(apv.encode("utf-8"))
    cek = _concat_kdf(z, enc, b"", apv.encode("utf-8") if apv else b"", key_bits)
    protected = b64u_json(header)
    iv = secrets.token_bytes(12)
    sealed = AESGCM(cek).encrypt(iv, json.dumps(payload).encode("utf-8"), protected.encode("ascii"))
    return f"{protected}..{b64u(iv)}.{b64u(sealed[:-16])}.{b64u(sealed[-16:])}"

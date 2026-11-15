# -*- coding: utf-8 -*-
"""
COSE_Sign1 (RFC 9052) and CWT claims (RFC 8392): what the wallet reads in CBOR, signed by an issuer
(status lists in CWT form; the mso_mdoc issuer signature).
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import cbor2

from .jose import verify_signature

# Header parameters (RFC 9052 §3.1, RFC 9360 §2).
ALG, KID, TYP, X5CHAIN = 1, 4, 16, 33
# COSE algorithm identifiers -> the JOSE name verify_signature knows (RFC 9053, RFC 8812).
ALGORITHMS = {-7: "ES256", -35: "ES384", -36: "ES512", -37: "PS256", -38: "PS384", -39: "PS512",
              -257: "RS256", -258: "RS384", -259: "RS512"}
SIGN1_TAG = 18
MAX_BYTES = 1024 * 1024  # a COSE structure larger than this is not read


class CoseError(ValueError):
    """Not a COSE_Sign1 the wallet can read."""


@dataclass
class Sign1:
    protected: Mapping[Any, Any]
    unprotected: Mapping[Any, Any]
    payload: bytes | None  # None: detached
    signature: bytes
    protected_raw: bytes = field(repr=False)

    def header(self, label: int) -> Any:
        """A header parameter, from the protected bucket first."""
        return self.protected.get(label, self.unprotected.get(label))

    @property
    def x5chain(self) -> list[bytes]:
        """The certificates (DER), leaf first; one certificate may come alone instead of in an array."""
        chain = self.header(X5CHAIN)
        chain = [chain] if isinstance(chain, bytes) else chain
        if chain is None:
            return []
        if not isinstance(chain, (list, tuple)) or not chain or not all(isinstance(c, bytes) for c in chain):
            raise CoseError("x5chain is not a certificate or an array of certificates")
        return list(chain)

    def jose_header(self) -> dict[str, Any]:
        """The same information as a JWS header (alg, kid, x5c), to reuse the issuer key lookup."""
        header: dict[str, Any] = {"alg": algorithm(self)}
        kid = self.header(KID)
        if isinstance(kid, bytes):
            try:
                kid = kid.decode("utf-8")
            except UnicodeDecodeError:
                kid = None
        if isinstance(kid, str):
            header["kid"] = kid
        if self.x5chain:
            header["x5c"] = [base64.b64encode(c).decode("ascii") for c in self.x5chain]
        return header


def algorithm(sign1: Sign1) -> str | None:
    """The JOSE name of the signature algorithm, which must be in the protected header."""
    alg = sign1.protected.get(ALG)
    return ALGORITHMS.get(alg) if type(alg) is int else None


def loads(data: bytes | bytearray) -> Any:
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_BYTES:
        raise CoseError("not CBOR data of a reasonable size")
    try:
        return cbor2.loads(bytes(data))
    except (cbor2.CBORDecodeError, ValueError, RecursionError, OverflowError) as exc:
        raise CoseError(f"not valid CBOR ({exc})") from exc


def decode_sign1(data: bytes | Any) -> Sign1:
    """A COSE_Sign1, tagged (18) or not, from its CBOR bytes or already decoded."""
    obj = loads(data) if isinstance(data, (bytes, bytearray)) else data
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != SIGN1_TAG:
            raise CoseError(f"CBOR tag {obj.tag}, not COSE_Sign1 (18)")
        obj = obj.value
    if not isinstance(obj, (list, tuple)) or len(obj) != 4:  # a tagged array decodes as a tuple
        raise CoseError("a COSE_Sign1 is an array of four elements")
    protected_raw, unprotected, payload, signature = obj
    if not isinstance(protected_raw, bytes) or not isinstance(unprotected, Mapping) \
            or not (payload is None or isinstance(payload, bytes)) or not isinstance(signature, bytes):
        raise CoseError("the elements of the COSE_Sign1 have the wrong types")
    protected = loads(protected_raw) if protected_raw else {}
    if not isinstance(protected, Mapping):
        raise CoseError("the protected header is not a map")
    return Sign1(protected, unprotected, payload, signature, protected_raw)


def verify_sign1(sign1: Sign1, public_key: Any, *, payload: bytes | None = None, external_aad: bytes = b"") -> bool:
    """The signature with this key (RFC 9052 §4.4); 'payload' for a detached one. The algorithm must be protected."""
    content = sign1.payload if payload is None else payload
    if content is None:
        return False
    to_be_signed = cbor2.dumps(["Signature1", sign1.protected_raw, external_aad, content])
    return verify_signature(algorithm(sign1), sign1.signature, to_be_signed, public_key)

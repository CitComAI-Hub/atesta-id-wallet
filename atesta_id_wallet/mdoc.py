# -*- coding: utf-8 -*-
"""
ISO/IEC 18013-5 mdoc (format "mso_mdoc" in OpenID4VCI and OpenID4VP): reading what an issuer
signed, and presenting it with a device signature.

An issuer sends IssuerSigned: the data elements, each in an IssuerSignedItem (digestID, random,
elementIdentifier, elementValue) wrapped as CBOR tag 24, and issuerAuth, a COSE_Sign1 over the
Mobile Security Object (MSO). The MSO has a digest of every item, the docType, the validity dates
and the device key: the public key of the copy, which signs every presentation.

A presentation (DeviceResponse) carries the items the user agreed to share, the same issuerAuth,
and a device signature over the SessionTranscript, which for OpenID4VP binds it to the verifier's
client_id, nonce, response_uri and, when the answer is encrypted, its encryption key (OpenID4VP
1.0 Appendix B.2.6.1). Nothing but these items is revealed: the other digests in the MSO are salted.
"""

from __future__ import annotations

import datetime
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

from . import cose
from .common import WalletError, b64u, b64u_decode
from .i18n import tr

FORMAT = "mso_mdoc"
DIGESTS = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
ENCODED_CBOR = 24  # tag of "bstr .cbor": an item encoded on its own (RFC 8949 §3.4.5.1)
MAX_ITEMS = 1000


class MdocError(WalletError):
    """Not an mdoc the wallet can read, or one whose digests do not match."""


@dataclass
class Mdoc:
    raw: str  # base64url of the IssuerSigned CBOR, as stored
    doctype: str
    issuer_auth: cose.Sign1 = field(repr=False)
    issuer_auth_cbor: Any = field(repr=False)  # issuerAuth as received, sent again in presentations
    mso: Mapping[str, Any] = field(repr=False)
    # namespace -> element identifier -> the item as received (tag 24), to present it unchanged
    items: dict[str, dict[str, cbor2.CBORTag]] = field(repr=False)
    claims: dict[str, dict[str, Any]]  # namespace -> element -> value as JSON (OpenID4VP 1.0 §6.3)
    payload: dict[str, Any]  # what the rest of the wallet reads from a credential: dates, status, key
    header: dict[str, Any] = field(repr=False)  # issuerAuth's alg, kid, x5c, as a JWS header

    @property
    def display_claims(self) -> dict[str, Any]:
        """
        The elements without their namespace (one namespace is the usual case; a clash keeps it), and
        binary ones (a portrait, a signature image) as their size instead of pages of base64.
        """
        merged: dict[str, Any] = {}
        for namespace, elements in self.claims.items():
            for name, value in elements.items():
                original = cbor2.loads(self.items[namespace][name].value).get("elementValue")
                if isinstance(original, bytes):
                    value = f"({len(original)} bytes)"
                merged[f"{namespace}.{name}" if name in merged else name] = value
        return merged

    @property
    def disclosures(self) -> list[tuple[str, str]]:
        """Every element, all of them selectively disclosable."""
        return [(namespace, name) for namespace, elements in self.items.items() for name in elements]

    @property
    def device_key(self) -> ec.EllipticCurvePublicKey:
        return cose_key_to_public(self.mso["deviceKeyInfo"]["deviceKey"])


def to_json(value: Any) -> Any:
    """A CBOR value as JSON (OpenID4VP 1.0 §6.3): dates as ISO text, byte strings as base64url."""
    if isinstance(value, cbor2.CBORTag):
        return to_json(value.value)
    if isinstance(value, datetime.datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return b64u(bytes(value))
    if isinstance(value, Mapping):
        return {str(k): to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_json(v) for v in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def cose_key_to_public(key: Any) -> ec.EllipticCurvePublicKey:
    """An EC2 COSE_Key (RFC 9053 §7.1.1) on P-256, P-384 or P-521."""
    curves: dict[int, Callable[[], ec.EllipticCurve]] = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1}
    if not isinstance(key, Mapping) or key.get(1) != 2 or type(key.get(-1)) is not int or key[-1] not in curves:
        raise MdocError(tr("The mdoc's device key is not a supported EC key."))
    x, y = key.get(-2), key.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise MdocError(tr("The mdoc's device key is not a supported EC key."))
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                             curves[key[-1]]()).public_key()
    except ValueError as exc:
        raise MdocError(tr("The mdoc's device key is not a supported EC key.")) from exc


def _timestamp(value: Any) -> float | None:
    if isinstance(value, cbor2.CBORTag):
        value = value.value
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime.datetime):
        return (value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)).timestamp()
    return None


def _embedded(value: Any, what: str) -> Any:
    """The content of a tag-24 item (bstr .cbor)."""
    if not isinstance(value, cbor2.CBORTag) or value.tag != ENCODED_CBOR or not isinstance(value.value, bytes):
        raise MdocError(tr("The mdoc is not valid: {problem}.", problem=f"{what} is not an encoded CBOR item"))
    try:
        return cose.loads(value.value)
    except cose.CoseError as exc:
        raise MdocError(tr("The mdoc is not valid: {problem}.", problem=f"{what}: {exc}")) from exc


def parse_mdoc(raw: str) -> Mdoc:
    """
    An IssuerSigned (base64url CBOR) whose items match the digests of its MSO. The issuer's
    signature is checked by the caller, with the issuer's keys (vci.verify_issued_mdoc).
    """
    try:
        return _parse_mdoc(raw)
    except (TypeError, KeyError, AttributeError, OverflowError) as exc:  # a shape not foreseen: still not valid
        raise MdocError(tr("The mdoc is not valid: {problem}.", problem=f"{type(exc).__name__}: {exc}")) from exc


def _parse_mdoc(raw: str) -> Mdoc:
    def invalid(problem: str) -> MdocError:
        return MdocError(tr("The mdoc is not valid: {problem}.", problem=problem))

    try:
        issuer_signed = cose.loads(b64u_decode(raw.strip()))
    except (ValueError, cose.CoseError) as exc:
        raise invalid(f"not base64url CBOR ({exc})") from exc
    if not isinstance(issuer_signed, Mapping) or "issuerAuth" not in issuer_signed:
        raise invalid("no issuerAuth")
    try:
        issuer_auth = cose.decode_sign1(issuer_signed["issuerAuth"])
        header = issuer_auth.jose_header()
    except cose.CoseError as exc:
        raise invalid(f"issuerAuth: {exc}") from exc
    if issuer_auth.payload is None:
        raise invalid("issuerAuth has no MSO")
    try:
        mso = _embedded(cose.loads(issuer_auth.payload), "the MSO")
    except cose.CoseError as exc:
        raise invalid(f"the MSO: {exc}") from exc
    if not isinstance(mso, Mapping):
        raise invalid("the MSO is not a map")
    doctype, digest_alg, value_digests = mso.get("docType"), mso.get("digestAlgorithm"), mso.get("valueDigests")
    validity, key_info = mso.get("validityInfo"), mso.get("deviceKeyInfo")
    if not isinstance(doctype, str) or not doctype:
        raise invalid("the MSO has no docType")
    if not isinstance(digest_alg, str) or digest_alg not in DIGESTS:
        raise invalid(f"digestAlgorithm {digest_alg!r} is not supported")
    if not isinstance(value_digests, Mapping) or not isinstance(validity, Mapping) \
            or not isinstance(key_info, Mapping):
        raise invalid("the MSO lacks valueDigests, validityInfo or deviceKeyInfo")
    cose_key_to_public(key_info.get("deviceKey"))

    namespaces = issuer_signed.get("nameSpaces") or {}
    if not isinstance(namespaces, Mapping):
        raise invalid("nameSpaces is not a map")
    items: dict[str, dict[str, cbor2.CBORTag]] = {}
    claims: dict[str, dict[str, Any]] = {}
    count = 0
    for namespace, entries in namespaces.items():
        digests = value_digests.get(namespace)
        if not isinstance(namespace, str) or not isinstance(entries, (list, tuple)) or not isinstance(digests, Mapping):
            raise invalid(f"namespace {namespace!r} has no digests in the MSO")
        for entry in entries:
            count += 1
            if count > MAX_ITEMS:
                raise invalid("too many data elements")
            item = _embedded(entry, "an IssuerSignedItem")
            if not isinstance(item, Mapping) or not isinstance(item.get("elementIdentifier"), str) \
                    or type(item.get("digestID")) is not int or not isinstance(item.get("random"), bytes) \
                    or "elementValue" not in item:
                raise invalid("an IssuerSignedItem lacks digestID, random, elementIdentifier or elementValue")
            # The digest covers the tag-24 item exactly as the issuer encoded it.
            expected = digests.get(item["digestID"])
            if not isinstance(expected, bytes) or DIGESTS[digest_alg](cbor2.dumps(entry)).digest() != expected:
                raise invalid(f"the digest of {namespace}/{item['elementIdentifier']} does not match the MSO")
            name = item["elementIdentifier"]
            if name in items.setdefault(namespace, {}):
                raise invalid(f"{namespace}/{name} appears twice")
            items[namespace][name] = entry
            claims.setdefault(namespace, {})[name] = to_json(item["elementValue"])
    device_key = cose_key_to_public(key_info["deviceKey"])
    numbers, size = device_key.public_numbers(), (device_key.curve.key_size + 7) // 8
    crv = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}[device_key.curve.name]
    payload: dict[str, Any] = {
        "doctype": doctype,
        "cnf": {"jwk": {"kty": "EC", "crv": crv, "x": b64u(numbers.x.to_bytes(size, "big")),
                        "y": b64u(numbers.y.to_bytes(size, "big"))}},
    }
    for name, key in (("iat", "signed"), ("nbf", "validFrom"), ("exp", "validUntil")):
        stamp = _timestamp(validity.get(key))
        if stamp is not None:
            payload[name] = int(stamp)
    if "exp" not in payload:
        raise invalid("validityInfo has no validUntil")
    if isinstance(mso.get("status"), Mapping):
        payload["status"] = to_json(mso["status"])
    return Mdoc(raw.strip(), doctype, issuer_auth, issuer_signed["issuerAuth"], mso, items, claims, payload, header)


def disclosed_claims(mdoc: Mdoc, requested_paths: list[list[Any]] | None) -> list[tuple[str, Any, bool]]:
    """(element, value, selective) of what the verifier will see; every element is selective."""
    return [(name if len(mdoc.claims) == 1 else f"{namespace}.{name}", mdoc.claims[namespace][name], True)
            for namespace, name in selected_elements(mdoc, requested_paths)]


def selected_elements(mdoc: Mdoc, requested_paths: list[list[Any]] | None) -> list[tuple[str, str]]:
    """The elements a request names ([namespace, element], OpenID4VP 1.0 §7.2); None: all of them."""
    if requested_paths is None:
        return mdoc.disclosures
    chosen = []
    for path in requested_paths:
        if len(path) == 2 and isinstance(path[0], str) and isinstance(path[1], str) \
                and path[1] in mdoc.items.get(path[0], {}) and (path[0], path[1]) not in chosen:
            chosen.append((path[0], path[1]))
    return chosen


def session_transcript(client_id: str, nonce: str, jwk_thumbprint: bytes | None, response_uri: str) -> list[Any]:
    """SessionTranscript for OpenID4VP over redirects (OpenID4VP 1.0 Appendix B.2.6.1)."""
    info = cbor2.dumps([client_id, nonce, jwk_thumbprint, response_uri])
    return [None, None, ["OpenID4VPHandover", hashlib.sha256(info).digest()]]


def device_response(mdoc: Mdoc, key: Any, requested_paths: list[list[Any]] | None, transcript: list[Any]) -> str:
    """
    A DeviceResponse (ISO 18013-5 §8.3.2.1.2.2) with the selected items and a device signature
    (ES256 with the copy's key) over the transcript; base64url, as OpenID4VP puts it in vp_token.
    """
    namespaces: dict[str, list[cbor2.CBORTag]] = {}
    for namespace, name in selected_elements(mdoc, requested_paths):
        namespaces.setdefault(namespace, []).append(mdoc.items[namespace][name])
    device_namespaces = cbor2.CBORTag(ENCODED_CBOR, cbor2.dumps({}))
    authentication = cbor2.dumps(["DeviceAuthentication", transcript, mdoc.doctype, device_namespaces])
    to_sign = cbor2.CBORTag(ENCODED_CBOR, authentication)
    protected = cbor2.dumps({cose.ALG: -7})
    signature = key.sign_raw(cbor2.dumps(["Signature1", protected, b"", cbor2.dumps(to_sign)]))
    issuer_signed: dict[str, Any] = {"issuerAuth": mdoc.issuer_auth_cbor}
    if namespaces:
        issuer_signed = {"nameSpaces": namespaces, **issuer_signed}
    document = {
        "docType": mdoc.doctype,
        "issuerSigned": issuer_signed,
        "deviceSigned": {"nameSpaces": device_namespaces,
                         "deviceAuth": {"deviceSignature": [protected, {}, None, signature]}},
    }
    return b64u(cbor2.dumps({"version": "1.0", "documents": [document], "status": 0}))

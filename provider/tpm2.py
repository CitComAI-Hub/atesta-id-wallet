# -*- coding: utf-8 -*-
"""
TPM 2.0 evidence for the wallet provider (TPM 2.0 Library, Part 1 §24 and Part 2), with nothing
but `cryptography`:

- the endorsement key (EK) certificate, chained to a TPM manufacturer's root;
- MakeCredential: a secret only the TPM that holds that EK can recover (ActivateCredential), and
  only for a key whose name is the attestation key's (AIK): so the AIK is in that TPM;
- TPM2_Certify by the AIK of a holder key: its public area, and that it was made in the TPM and
  cannot leave it (fixedTPM, fixedParent, sensitiveDataOrigin).

The structures are the TPM's own (big-endian, TPM2B = 2-byte size + bytes), the same on every
platform: the wallet unpacks whatever its platform wraps them in (CNG's PCP blobs on Windows).
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:  # where CFB lives since cryptography 47; MakeCredential needs it (TPM 2.0 Part 1 §24.4)
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # older versions
    from cryptography.hazmat.primitives.ciphers.modes import CFB

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_CERTIFY = 0x8017
ALG_RSA, ALG_ECC, ALG_NULL, ALG_SHA1, ALG_SHA256, ALG_SHA384 = 0x0001, 0x0023, 0x0010, 0x0004, 0x000B, 0x000C
ALG_RSASSA, ALG_RSAES, ALG_ECDSA, ALG_ECDAA, ALG_AES, ALG_CFB = 0x0014, 0x0015, 0x0018, 0x001A, 0x0006, 0x0043
ECC_NIST_P256 = 0x0003
# objectAttributes
FIXED_TPM, FIXED_PARENT, SENSITIVE_DATA_ORIGIN = 0x00000002, 0x00000010, 0x00000020
RESTRICTED, DECRYPT, SIGN = 0x00010000, 0x00020000, 0x00040000
NON_EXPORTABLE = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN
HASHES: dict[int, Callable[[], hashes.HashAlgorithm]] = {ALG_SHA1: hashes.SHA1, ALG_SHA256: hashes.SHA256,
                                                        ALG_SHA384: hashes.SHA384}
# TCG EK Credential Profile: the TPM's manufacturer, model and version in the EK certificate's SAN.
OID_MANUFACTURER, OID_MODEL, OID_VERSION = "2.23.133.2.1", "2.23.133.2.2", "2.23.133.2.3"


class TpmError(Exception):
    """The evidence is malformed or does not prove what it should."""


class Reader:
    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise TpmError("truncated TPM structure")
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int(struct.unpack(">H", self.take(2))[0])

    def u32(self) -> int:
        return int(struct.unpack(">I", self.take(4))[0])

    def u64(self) -> int:
        return int(struct.unpack(">Q", self.take(8))[0])

    def tpm2b(self) -> bytes:
        return self.take(self.u16())

    def end(self) -> None:
        if self.at != len(self.data):
            raise TpmError("trailing bytes after a TPM structure")


def tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


@dataclass
class Public:
    """A TPMT_PUBLIC: what the TPM says about a key, and what its name is made of."""
    raw: bytes
    type: int
    name_alg: int
    attributes: int
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey

    @property
    def name(self) -> bytes:
        if self.name_alg not in HASHES:
            raise TpmError("unsupported name algorithm")
        digest = hashes.Hash(HASHES[self.name_alg]())
        digest.update(self.raw)
        return struct.pack(">H", self.name_alg) + digest.finalize()

    def has(self, attributes: int) -> bool:
        return self.attributes & attributes == attributes


def _skip_symmetric(r: Reader) -> None:
    if r.u16() != ALG_NULL:
        r.u16()  # keyBits
        r.u16()  # mode


def parse_public(data: bytes) -> Public:
    """A TPMT_PUBLIC (a TPM2B_PUBLIC's size prefix is taken off when it is there)."""
    if len(data) >= 2 and int.from_bytes(data[:2], "big") == len(data) - 2:
        data = data[2:]
    r = Reader(data)
    kind, name_alg, attributes = r.u16(), r.u16(), r.u32()
    r.tpm2b()  # authPolicy
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    if kind == ALG_RSA:
        _skip_symmetric(r)
        if r.u16() not in (ALG_NULL, ALG_RSAES):
            r.u16()  # the scheme's hash
        r.u16()  # keyBits
        exponent = r.u32() or 65537
        modulus = int.from_bytes(r.tpm2b(), "big")
        key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    elif kind == ALG_ECC:
        _skip_symmetric(r)
        scheme = r.u16()
        if scheme != ALG_NULL:
            r.u16()  # the scheme's hash
            if scheme == ALG_ECDAA:
                r.u16()  # count
        curve = r.u16()
        if r.u16() != ALG_NULL:  # kdf
            r.u16()
        x, y = r.tpm2b(), r.tpm2b()
        if curve != ECC_NIST_P256 or len(x) > 32 or len(y) > 32:
            raise TpmError("only P-256 ECC keys are supported")
        try:
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                ec.SECP256R1()).public_key()
        except ValueError as exc:
            raise TpmError("the ECC point is not on the curve") from exc
    else:
        raise TpmError("unsupported key type")
    r.end()
    return Public(data, kind, name_alg, attributes, key)


@dataclass
class Certify:
    """A TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY."""
    extra_data: bytes
    name: bytes  # of the certified key


def parse_certify(data: bytes) -> Certify:
    r = Reader(data)
    if r.u32() != TPM_GENERATED_VALUE:
        raise TpmError("not made by a TPM (magic)")
    if r.u16() != TPM_ST_ATTEST_CERTIFY:
        raise TpmError("not a TPM2_Certify attestation")
    r.tpm2b()  # qualifiedSigner
    extra = r.tpm2b()
    r.u64(), r.u32(), r.u32(), r.u8()  # clockInfo
    r.u64()  # firmwareVersion
    name = r.tpm2b()
    r.tpm2b()  # qualifiedName
    r.end()
    return Certify(extra, name)


def verify_signature(signer: Public, signature: bytes, data: bytes) -> None:
    """
    The signature over data by a signing key (the AIK): raw (RSASSA-PKCS1-v1_5 bytes, or ECDSA
    r || s) or a TPMT_SIGNATURE, SHA-256.
    """
    raw = signature
    if len(signature) > 6 and int.from_bytes(signature[:2], "big") in (ALG_RSASSA, ALG_ECDSA):
        r = Reader(signature)
        alg, hash_alg = r.u16(), r.u16()
        if hash_alg != ALG_SHA256:
            raise TpmError("only SHA-256 attestation signatures are supported")
        if alg == ALG_RSASSA:
            raw = r.tpm2b()
        else:
            raw = r.tpm2b().rjust(32, b"\0") + r.tpm2b().rjust(32, b"\0")
        r.end()
    try:
        if isinstance(signer.key, rsa.RSAPublicKey):
            signer.key.verify(raw, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            if len(raw) != 64:
                raise TpmError("bad ECDSA signature")
            signer.key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                              data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise TpmError("the attestation is not signed by the attestation key") from exc


def check_aik(aik: Public) -> None:
    """An attestation key: made in the TPM, cannot leave it, signs only what the TPM produces."""
    if not aik.has(NON_EXPORTABLE | RESTRICTED | SIGN) or aik.has(DECRYPT):
        raise TpmError("the attestation key is not a restricted signing key fixed to the TPM")
    if aik.name_alg != ALG_SHA256:
        raise TpmError("the attestation key's name algorithm must be SHA-256")


def certified_key(aik: Public, attest: bytes, signature: bytes, public: bytes,
                  qualifying: bytes) -> ec.EllipticCurvePublicKey:
    """
    The holder key that the AIK certified (TPM2_Certify) for this request: signed by the AIK, with
    the qualifying data asked for (the TPM may get it hashed: CNG passes SHA-1 or SHA-256 of it),
    a P-256 signing key made in the TPM that cannot leave it.
    """
    verify_signature(aik, signature, attest)
    certified = parse_certify(attest)
    accepted = {qualifying, hashlib.sha1(qualifying, usedforsecurity=False).digest(),  # what CNG may pass on
                hashlib.sha256(qualifying).digest()}
    if certified.extra_data not in accepted:
        raise TpmError("the attestation is for another request (qualifying data)")
    key = parse_public(public)
    if not hmac.compare_digest(certified.name, key.name):
        raise TpmError("the attestation is about another key")
    if key.type != ALG_ECC or not key.has(NON_EXPORTABLE | SIGN) or key.has(RESTRICTED):
        raise TpmError("the key is not a P-256 signing key made in the TPM and fixed to it")
    assert isinstance(key.key, ec.EllipticCurvePublicKey)
    return key.key


def kdfa(hash_alg: str, key: bytes, label: bytes, context_u: bytes, context_v: bytes,
         bits: int) -> bytes:
    """KDFa of TPM 2.0 Part 1 §11.4.10.2 (SP 800-108 counter mode with HMAC)."""
    out, counter = b"", 0
    while len(out) * 8 < bits:
        counter += 1
        mac = hmac.new(key, digestmod=hash_alg)
        mac.update(struct.pack(">I", counter) + label + b"\0" + context_u + context_v + struct.pack(">I", bits))
        out += mac.digest()
    return out[:bits // 8]


def make_credential(ek: rsa.RSAPublicKey, aik_name: bytes, secret: bytes) -> tuple[bytes, bytes]:
    """
    TPM2_MakeCredential for an RSA EK of the default templates (SHA-256, AES-128-CFB): returns
    (TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET). Only ActivateCredential in the TPM with that EK, on
    the key with that name, gives the secret back.
    """
    if len(secret) > 32:
        raise TpmError("the secret is too long")
    seed = secrets.token_bytes(32)
    encrypted_seed = ek.encrypt(seed, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                   label=b"IDENTITY\0"))
    sym_key = kdfa("sha256", seed, b"STORAGE", aik_name, b"", 128)
    encryptor = Cipher(algorithms.AES(sym_key), CFB(b"\0" * 16)).encryptor()
    enc_identity = encryptor.update(tpm2b(secret)) + encryptor.finalize()
    hmac_key = kdfa("sha256", seed, b"INTEGRITY", b"", b"", 256)
    integrity = hmac.new(hmac_key, enc_identity + aik_name, "sha256").digest()
    return tpm2b(tpm2b(integrity) + enc_identity), tpm2b(encrypted_seed)


def _load_certificates(data: bytes) -> list[x509.Certificate]:
    if b"-----BEGIN" in data:
        return list(x509.load_pem_x509_certificates(data))
    return [x509.load_der_x509_certificate(data)]


def load_roots(folder: Path | str | None) -> list[x509.Certificate]:
    """TPM manufacturers' root and intermediate certificates: .pem, .crt, .cer or .der files."""
    if not folder:
        return []
    found: list[x509.Certificate] = []
    for path in sorted(Path(folder).rglob("*")):
        if path.is_file() and path.suffix.lower() in (".pem", ".crt", ".cer", ".der"):
            try:
                found += _load_certificates(path.read_bytes())
            except ValueError:
                continue  # not a certificate: ignored
    return found


@dataclass
class Endorsement:
    key: rsa.RSAPublicKey
    manufacturer: str  # e.g. "id:494E5443" (INTC), from the certificate when it says


def check_endorsement(ek_der: bytes, anchors: list[x509.Certificate], now: datetime.datetime | None = None
                      ) -> Endorsement:
    """
    The EK certificate, chained up to one of the anchors (roots, with the manufacturers'
    intermediates in the same list). EK certificates often carry extensions general-purpose
    validators refuse, so the chain is walked here: names, signatures and validity.
    """
    try:
        cert = x509.load_der_x509_certificate(ek_der)
    except ValueError as exc:
        raise TpmError("the EK certificate cannot be read") from exc
    now = now or datetime.datetime.now(datetime.timezone.utc)
    chain, current = [cert], cert
    for _ in range(6):
        if current.not_valid_after_utc < now or current.not_valid_before_utc > now:
            raise TpmError("a certificate in the EK chain is not valid now")
        issuers = [a for a in anchors if a.subject == current.issuer]
        issuer = None
        for candidate in issuers:
            try:
                current.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature):
                continue
            issuer = candidate
            break
        if issuer is None:
            raise TpmError("the EK certificate does not chain to a known TPM manufacturer")
        if issuer.subject == issuer.issuer:  # a root
            break
        chain.append(issuer)
        current = issuer
    else:
        raise TpmError("the EK certificate chain is too long")
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        raise TpmError("only RSA 2048 endorsement keys are supported")
    manufacturer = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for name in san.get_values_for_type(x509.DirectoryName):
            for attribute in name:
                if attribute.oid.dotted_string == OID_MANUFACTURER:
                    manufacturer = str(attribute.value)
    except x509.ExtensionNotFound:
        pass
    return Endorsement(key, manufacturer)


# -*- coding: utf-8 -*-
"""
Keys in the TPM 2.0 on Windows, through CNG and its Microsoft Platform Crypto Provider (ncrypt.dll,
called with ctypes: nothing to install). Keys are per user, made in the TPM and not exportable:
only their public part leaves it.

TPM evidence for the wallet provider (attestation.py): the endorsement key certificate, an
attestation key (AIK, an identity key of the PCP), ActivateCredential on it, and TPM2_Certify of a
holder key by it (NCryptCreateClaim). The PCP wraps the TPM's structures in blobs of its own
(PCP_KEY_ATTESTATION_BLOB, PCP_KEY_BLOB_WIN8); they are unwrapped here, so the provider only
sees the TPM's.
"""

from __future__ import annotations

import ctypes
import struct
from ctypes import POINTER, Structure, byref, c_long, c_size_t, c_ulong, c_void_p, c_wchar_p, create_string_buffer
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .i18n import tr

PROVIDER = "Microsoft Platform Crypto Provider"
ALGORITHM = "ECDSA_P256"
PUBLIC_BLOB = "ECCPUBLICBLOB"
P256_PUBLIC_MAGIC = 0x31534345  # BCRYPT_ECDSA_PUBLIC_P256_MAGIC ("ECS1")
NTE_BAD_KEYSET = 0x80090016  # no key with that name
NTE_NO_MORE_ITEMS = 0x8009002A
NCRYPT_SILENT_FLAG = 0x40  # never show a window: an operation that needs one fails instead
AIK_NAME = "atesta-id-wallet-aik"  # one per user, shared by the profiles (not a holder key: no profile prefix)
KEY_USAGE_POLICY = "PCP_KEY_USAGE_POLICY"
PCP_IDENTITY_KEY = 0x00000008  # NCRYPT_PCP_IDENTITY_KEY: an AIK
ID_BINDING = "PCP_TPM12_IDBINDING"  # for TPM 2.0: TPM2B_PUBLIC || TPM2B_CREATION_DATA || TPM2B_ATTEST || sig
ID_ACTIVATION = "PCP_TPM12_IDACTIVATION"  # set: TPM2B_ID_OBJECT || TPM2B_ENCRYPTED_SECRET; get: the secret
EK_CERTIFICATES = ("PCP_RSA_EKCERT", "PCP_EKCERT", "PCP_RSA_EKNVCERT", "PCP_EKNVCERT")
CLAIM_AUTHORITY_AND_SUBJECT = 0x00000003  # NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT
BUFFER_KEYATTESTATION_NONCE = 41  # NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE
KEY_ATTESTATION_MAGIC = 0x5344414B  # PCP_KEY_ATTESTATION_BLOB ("KADS")

HANDLE = c_size_t  # NCRYPT_HANDLE is a ULONG_PTR
DWORD = c_ulong


class _KeyName(Structure):
    _fields_ = [("pszName", c_wchar_p), ("pszAlgid", c_wchar_p), ("dwLegacyKeySpec", DWORD), ("dwFlags", DWORD)]


class _Buffer(Structure):
    _fields_ = [("cbBuffer", c_ulong), ("BufferType", c_ulong), ("pvBuffer", c_void_p)]


class _BufferDesc(Structure):
    _fields_ = [("ulVersion", c_ulong), ("cBuffers", c_ulong), ("pBuffers", POINTER(_Buffer))]


class CngError(Exception):
    def __init__(self, function: str, status: int):
        self.status = status & 0xFFFFFFFF
        super().__init__(f"{function}: 0x{self.status:08X}")


class _NCrypt:
    def __init__(self) -> None:
        dll = ctypes.WinDLL("ncrypt.dll")  # type: ignore[attr-defined]
        signatures = {
            "NCryptOpenStorageProvider": (POINTER(HANDLE), c_wchar_p, DWORD),
            "NCryptIsAlgSupported": (HANDLE, c_wchar_p, DWORD),
            "NCryptCreatePersistedKey": (HANDLE, POINTER(HANDLE), c_wchar_p, c_wchar_p, DWORD, DWORD),
            "NCryptFinalizeKey": (HANDLE, DWORD),
            "NCryptOpenKey": (HANDLE, POINTER(HANDLE), c_wchar_p, DWORD, DWORD),
            "NCryptExportKey": (HANDLE, HANDLE, c_wchar_p, c_void_p, c_void_p, DWORD, POINTER(DWORD), DWORD),
            "NCryptSignHash": (HANDLE, c_void_p, c_void_p, DWORD, c_void_p, DWORD, POINTER(DWORD), DWORD),
            "NCryptDeleteKey": (HANDLE, DWORD),
            "NCryptFreeObject": (HANDLE,),
            "NCryptEnumKeys": (HANDLE, c_wchar_p, POINTER(POINTER(_KeyName)), POINTER(c_void_p), DWORD),
            "NCryptFreeBuffer": (c_void_p,),
            "NCryptGetProperty": (HANDLE, c_wchar_p, c_void_p, DWORD, POINTER(DWORD), DWORD),
            "NCryptSetProperty": (HANDLE, c_wchar_p, c_void_p, DWORD, DWORD),
            "NCryptCreateClaim": (HANDLE, HANDLE, DWORD, POINTER(_BufferDesc), c_void_p, DWORD, POINTER(DWORD),
                                  DWORD),
        }
        self._functions: dict[str, Any] = {}
        for name, args in signatures.items():
            function = getattr(dll, name)
            function.argtypes, function.restype = args, c_long
            self._functions[name] = function

    def status(self, name: str, *args: object) -> int:
        """Calls a function and returns its SECURITY_STATUS (0: success)."""
        return int(self._functions[name](*args)) & 0xFFFFFFFF

    def call(self, name: str, *args: object) -> int:
        status = self.status(name, *args)
        if status:
            raise CngError(name, status)
        return status


class PlatformTpm:
    name = "windows-tpm"

    def __init__(self) -> None:
        self._ncrypt: _NCrypt | None = None
        self._provider: HANDLE | None = None

    @property
    def label(self) -> str:
        return tr("this computer's security chip (TPM)")

    def _open(self) -> tuple[_NCrypt, HANDLE]:
        if self._ncrypt is None or self._provider is None:
            ncrypt = _NCrypt()
            provider = HANDLE()
            ncrypt.call("NCryptOpenStorageProvider", byref(provider), PROVIDER, 0)
            self._ncrypt, self._provider = ncrypt, provider
        return self._ncrypt, self._provider

    def available(self) -> bool:
        ncrypt, provider = self._open()
        ncrypt.call("NCryptIsAlgSupported", provider, ALGORITHM, 0)  # TPM 2.0: a 1.2 chip has no ECC
        return True

    def _key(self, key_name: str) -> HANDLE | None:
        ncrypt, provider = self._open()
        key = HANDLE()
        try:
            ncrypt.call("NCryptOpenKey", provider, byref(key), key_name, 0, NCRYPT_SILENT_FLAG)
        except CngError as exc:
            if exc.status == NTE_BAD_KEYSET:
                return None
            raise
        return key

    def _public(self, ncrypt: _NCrypt, key: HANDLE) -> ec.EllipticCurvePublicKey:
        size = DWORD()
        ncrypt.call("NCryptExportKey", key, 0, PUBLIC_BLOB, None, None, 0, byref(size), 0)
        blob = create_string_buffer(size.value)
        ncrypt.call("NCryptExportKey", key, 0, PUBLIC_BLOB, None, blob, size.value, byref(size), 0)
        data = blob.raw[:size.value]
        magic, length = int.from_bytes(data[0:4], "little"), int.from_bytes(data[4:8], "little")
        if magic != P256_PUBLIC_MAGIC or length != 32 or len(data) != 8 + 64:
            raise CngError("NCryptExportKey (unexpected key)", 0xFFFFFFFF)
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + data[8:])

    def create(self, key_name: str) -> ec.EllipticCurvePublicKey:
        ncrypt, provider = self._open()
        key = HANDLE()
        ncrypt.call("NCryptCreatePersistedKey", provider, byref(key), ALGORITHM, key_name, 0, 0)
        try:
            ncrypt.call("NCryptFinalizeKey", key, NCRYPT_SILENT_FLAG)
            public = self._public(ncrypt, key)
        except CngError:
            if ncrypt.status("NCryptDeleteKey", key, 0):  # on success it frees the handle too
                ncrypt.status("NCryptFreeObject", key)
            raise
        ncrypt.status("NCryptFreeObject", key)
        return public

    def public_key(self, key_name: str) -> ec.EllipticCurvePublicKey | None:
        key = self._key(key_name)
        if key is None:
            return None
        ncrypt, _ = self._open()
        try:
            return self._public(ncrypt, key)
        finally:
            ncrypt.status("NCryptFreeObject", key)

    def sign(self, key_name: str, digest: bytes) -> bytes:
        key = self._key(key_name)
        if key is None:
            raise CngError("NCryptOpenKey", NTE_BAD_KEYSET)
        ncrypt, _ = self._open()
        try:
            signature, size = create_string_buffer(64), DWORD()
            ncrypt.call("NCryptSignHash", key, None, digest, len(digest), signature, 64, byref(size),
                        NCRYPT_SILENT_FLAG)
            return signature.raw[:size.value]  # ECDSA in CNG: r || s already
        finally:
            ncrypt.status("NCryptFreeObject", key)

    def delete(self, key_name: str) -> None:
        key = self._key(key_name)
        if key is None:
            return
        ncrypt, _ = self._open()
        ncrypt.call("NCryptDeleteKey", key, NCRYPT_SILENT_FLAG)  # frees the handle on success

    def names(self) -> list[str]:
        ncrypt, provider = self._open()
        found: list[str] = []
        state = c_void_p()
        try:
            while True:
                item = POINTER(_KeyName)()
                status = ncrypt.status("NCryptEnumKeys", provider, None, byref(item), byref(state),
                                       NCRYPT_SILENT_FLAG)
                if status & 0xFFFFFFFF == NTE_NO_MORE_ITEMS:
                    break
                if status:
                    raise CngError("NCryptEnumKeys", status)
                try:
                    if item.contents.pszName:
                        found.append(item.contents.pszName)
                finally:
                    ncrypt.status("NCryptFreeBuffer", item)
        finally:
            if state:
                ncrypt.status("NCryptFreeBuffer", state)
        return found

    # TPM evidence (keys.TpmEvidence).

    def _property(self, handle: HANDLE, name: str) -> bytes:
        ncrypt, _ = self._open()
        size = DWORD()
        ncrypt.call("NCryptGetProperty", handle, name, None, 0, byref(size), NCRYPT_SILENT_FLAG)
        out = create_string_buffer(size.value)
        ncrypt.call("NCryptGetProperty", handle, name, out, size.value, byref(size), NCRYPT_SILENT_FLAG)
        return out.raw[:size.value]

    def endorsement_certificate(self) -> bytes:
        """The EK certificate (DER): in the TPM's NV memory, or fetched by Windows for firmware TPMs."""
        _, provider = self._open()
        for name in EK_CERTIFICATES:
            try:
                data = self._property(provider, name)
            except CngError:
                continue
            start = data.find(b"\x30\x82")  # a DER certificate, wherever the property puts it
            if start >= 0:
                length = int.from_bytes(data[start + 2:start + 4], "big") + 4
                return data[start:start + length]
        raise CngError("NCryptGetProperty (EK certificate)", NTE_BAD_KEYSET)

    def _aik(self) -> HANDLE:
        key = self._key(AIK_NAME)
        if key is not None:
            return key
        ncrypt, provider = self._open()
        key = HANDLE()
        ncrypt.call("NCryptCreatePersistedKey", provider, byref(key), "RSA", AIK_NAME, 0, 0)
        try:
            usage = DWORD(PCP_IDENTITY_KEY)
            ncrypt.call("NCryptSetProperty", key, KEY_USAGE_POLICY, byref(usage), 4, 0)
            ncrypt.call("NCryptFinalizeKey", key, NCRYPT_SILENT_FLAG)
        except CngError:
            if ncrypt.status("NCryptDeleteKey", key, 0):
                ncrypt.status("NCryptFreeObject", key)
            raise
        return key

    def attestation_key(self) -> bytes:
        """The AIK's TPMT_PUBLIC (made the first time), from the head of its identity binding."""
        ncrypt, _ = self._open()
        key = self._aik()
        try:
            binding = self._property(key, ID_BINDING)
        finally:
            ncrypt.status("NCryptFreeObject", key)
        size = int.from_bytes(binding[:2], "big")
        if size < 10 or 2 + size > len(binding):
            raise CngError("NCryptGetProperty (identity binding)", NTE_BAD_KEYSET)
        return binding[2:2 + size]

    def activate(self, credential_blob: bytes, encrypted_secret: bytes) -> bytes:
        """TPM2_ActivateCredential on the AIK: the secret, if the credential was made for this TPM."""
        ncrypt, _ = self._open()
        key = self._aik()
        try:
            data = credential_blob + encrypted_secret
            ncrypt.call("NCryptSetProperty", key, ID_ACTIVATION, data, len(data), 0)
            return self._property(key, ID_ACTIVATION)
        finally:
            ncrypt.status("NCryptFreeObject", key)

    def certify(self, key_name: str, qualifying: bytes) -> tuple[bytes, bytes, bytes]:
        """TPM2_Certify of a holder key by the AIK: (TPMS_ATTEST, signature, TPMT_PUBLIC of the key)."""
        ncrypt, _ = self._open()
        key, aik = self._key(key_name), None
        if key is None:
            raise CngError("NCryptOpenKey", NTE_BAD_KEYSET)
        try:
            aik = self._aik()
            nonce = create_string_buffer(qualifying, len(qualifying))
            buffer = _Buffer(len(qualifying), BUFFER_KEYATTESTATION_NONCE, ctypes.cast(nonce, c_void_p))
            desc = _BufferDesc(0, 1, ctypes.pointer(buffer))
            size = DWORD()
            ncrypt.call("NCryptCreateClaim", key, aik, CLAIM_AUTHORITY_AND_SUBJECT, byref(desc), None, 0,
                        byref(size), 0)
            out = create_string_buffer(size.value)
            ncrypt.call("NCryptCreateClaim", key, aik, CLAIM_AUTHORITY_AND_SUBJECT, byref(desc), out, size.value,
                        byref(size), 0)
            return unwrap_key_attestation(out.raw[:size.value])
        finally:
            ncrypt.status("NCryptFreeObject", key)
            if aik is not None:
                ncrypt.status("NCryptFreeObject", aik)


def unwrap_key_attestation(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """
    PCP_KEY_ATTESTATION_BLOB: {Magic "KADS", Platform, HeaderSize, cbKeyAttest, cbSignature,
    cbKeyBlob} (little-endian), then the TPMS_ATTEST, the AIK's signature and the key's
    PCP_KEY_BLOB_WIN8, whose public part (at its cbHeader, cbPublic bytes) is a TPM2B_PUBLIC.
    """
    if len(blob) < 24:
        raise CngError("NCryptCreateClaim (short claim)", NTE_BAD_KEYSET)
    magic, _platform, header, attest_size, signature_size, key_size = struct.unpack("<6I", blob[:24])
    if magic != KEY_ATTESTATION_MAGIC or header + attest_size + signature_size + key_size > len(blob):
        raise CngError("NCryptCreateClaim (not a key attestation)", NTE_BAD_KEYSET)
    attest = blob[header:header + attest_size]
    signature = blob[header + attest_size:header + attest_size + signature_size]
    key_blob = blob[header + attest_size + signature_size:header + attest_size + signature_size + key_size]
    if len(key_blob) < 20:
        raise CngError("NCryptCreateClaim (short key blob)", NTE_BAD_KEYSET)
    key_header, public_size = struct.unpack("<I", key_blob[4:8])[0], struct.unpack("<I", key_blob[16:20])[0]
    public = key_blob[key_header:key_header + public_size]
    if len(public) != public_size or public_size < 4:
        raise CngError("NCryptCreateClaim (no public part)", NTE_BAD_KEYSET)
    if int.from_bytes(public[:2], "big") == len(public) - 2:
        public = public[2:]  # TPM2B_PUBLIC -> TPMT_PUBLIC
    return attest, signature, public

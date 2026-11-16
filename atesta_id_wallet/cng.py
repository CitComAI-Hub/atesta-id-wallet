# -*- coding: utf-8 -*-
"""
Keys in the TPM 2.0 on Windows, through CNG and its Microsoft Platform Crypto Provider (ncrypt.dll,
called with ctypes: nothing to install). Keys are per user, made in the TPM and not exportable:
only their public part leaves it.
"""

from __future__ import annotations

import ctypes
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

HANDLE = c_size_t  # NCRYPT_HANDLE is a ULONG_PTR
DWORD = c_ulong


class _KeyName(Structure):
    _fields_ = [("pszName", c_wchar_p), ("pszAlgid", c_wchar_p), ("dwLegacyKeySpec", DWORD), ("dwFlags", DWORD)]


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

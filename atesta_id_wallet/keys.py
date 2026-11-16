# -*- coding: utf-8 -*-
"""
Holder keys: in software (a PEM stored, encrypted, with each copy of a credential) or in this
computer's security chip (TPM 2.0), where they are made and used but cannot be read out.

A hardware key is stored as a reference, {"backend": NAME, "name": KEY_NAME}: the credential
can only be presented on the computer that made it. Its name starts with the profile's prefix,
so emptying or removing a profile deletes its keys even if its credentials can no longer be read.
"""

from __future__ import annotations

import hashlib
import secrets
import sys
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .common import WalletError, b64u, b64u_json, debug, log
from .i18n import tr

KEY_PREFIX = "atesta-id-wallet"  # hardware key names: atesta-id-wallet:PROFILE:RANDOM


class Key:
    """What every holder key does: a P-256 public key and ES256 signatures."""

    hardware = False

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        raise NotImplementedError

    def sign_raw(self, data: bytes) -> bytes:
        """ES256 signature as r || s (JWS and COSE alike)."""
        raise NotImplementedError

    def stored(self) -> str | dict[str, str]:
        """What is kept with the credential to find this key again."""
        raise NotImplementedError

    def discard(self) -> None:
        """Deletes the key where it lives (nothing to do for a software key: it goes with its file)."""

    @property
    def public_jwk(self) -> dict[str, str]:
        numbers = self.public_key.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }

    def sign_jwt(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        header = {"alg": "ES256", **header}
        signing_input = f"{b64u_json(header)}.{b64u_json(payload)}".encode("ascii")
        return f"{signing_input.decode('ascii')}.{b64u(self.sign_raw(signing_input))}"


class HolderKey(Key):
    """A P-256 key in software, bound to one copy of a credential (cnf), or used for one DPoP run."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self.private_key = private_key

    @classmethod
    def generate(cls) -> "HolderKey":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: str | bytes) -> "HolderKey":
        key = serialization.load_pem_private_key(pem.encode("ascii") if isinstance(pem, str) else pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise WalletError(tr("The credential's key is not a P-256 key."))
        return cls(key)

    def pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()

    def sign_raw(self, data: bytes) -> bytes:
        r, s = decode_dss_signature(self.private_key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def stored(self) -> str:
        return self.pem().decode("ascii")


class Backend(Protocol):
    """A place that makes and keeps P-256 keys that cannot be read out (TPM, smart card...)."""

    name: str  # stored with each key: "windows-tpm"
    label: str  # shown to the user

    def available(self) -> bool: ...
    def create(self, key_name: str) -> ec.EllipticCurvePublicKey: ...
    def public_key(self, key_name: str) -> ec.EllipticCurvePublicKey | None: ...  # None: not on this computer
    def sign(self, key_name: str, digest: bytes) -> bytes: ...  # SHA-256 digest in, r || s out
    def delete(self, key_name: str) -> None: ...
    def names(self) -> list[str]: ...  # this application's keys


class HardwareKey(Key):
    hardware = True

    def __init__(self, backend: Backend, key_name: str, public_key: ec.EllipticCurvePublicKey):
        self.backend, self.key_name, self._public_key = backend, key_name, public_key

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key

    def sign_raw(self, data: bytes) -> bytes:
        return self.backend.sign(self.key_name, hashlib.sha256(data).digest())

    def stored(self) -> dict[str, str]:
        return {"backend": self.backend.name, "name": self.key_name}

    def discard(self) -> None:
        self.backend.delete(self.key_name)


def _platform_backends() -> list[Backend]:
    if sys.platform == "win32":
        from . import cng

        return [cng.PlatformTpm()]
    return []


BACKENDS: list[Backend] = _platform_backends()
_available: dict[str, bool] = {}


def hardware_backend() -> Backend | None:
    """The first back-end this computer has (checked once per run), or None."""
    for backend in BACKENDS:
        if backend.name not in _available:
            try:
                _available[backend.name] = backend.available()
            except Exception as exc:  # a driver that fails is the same as no chip
                debug(f"{backend.name} not available: {exc}")
                _available[backend.name] = False
        if _available[backend.name]:
            return backend
    return None


def _backend(name: Any) -> Backend | None:
    return next((b for b in BACKENDS if b.name == name), None)


def new_key(profile: str, hardware: bool) -> Key:
    """A key for one copy: in the chip if asked for and there is one, in software otherwise."""
    backend = hardware_backend() if hardware else None
    if backend is not None:
        key_name = f"{KEY_PREFIX}:{profile}:{secrets.token_hex(12)}"
        try:
            key = HardwareKey(backend, key_name, backend.create(key_name))
            if backend.name not in _checked:
                # The first key of each run signs once before a credential is bound to it: a chip
                # (or driver) whose signatures do not verify would leave credentials unusable.
                try:
                    _check(key)
                except Exception:
                    key.discard()
                    _available[backend.name] = False
                    raise
                _checked.add(backend.name)
            return key
        except Exception as exc:
            log(tr("The key could not be made in {chip} ({error}); it is kept in software instead.",
                   chip=backend.label, error=exc))
    return HolderKey.generate()


_checked: set[str] = set()


def _check(key: Key) -> None:
    signature = key.sign_raw(b"atesta-id-wallet key check")
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    key.public_key.verify(encode_dss_signature(r, s), b"atesta-id-wallet key check", ec.ECDSA(hashes.SHA256()))


def load(stored: Any) -> Key:
    """The key a copy was stored with (see Key.stored)."""
    if isinstance(stored, str):
        return HolderKey.from_pem(stored)
    if not isinstance(stored, dict) or not isinstance(stored.get("name"), str):
        raise WalletError(tr("The credential is not bound to any key of this wallet, so it cannot be presented."))
    backend = _backend(stored.get("backend"))
    public = None
    if backend is not None and hardware_backend() is backend:
        public = backend.public_key(stored["name"])
    if public is None:
        raise WalletError(tr("The key of this credential is in the security chip of another computer, so it cannot "
                             "be presented here."),
                          hint=tr("Ask the organisation that gave it to you for the credential again, on this "
                                  "computer."))
    return HardwareKey(backend, stored["name"], public)  # type: ignore[arg-type]


def is_here(stored: Any) -> bool:
    """Whether the key can be used on this computer (a software key always can)."""
    if isinstance(stored, str):
        return True
    try:
        load(stored)
    except WalletError:
        return False
    return True


def discard(stored: Any) -> None:
    """Deletes a stored hardware key, if it is on this computer; failures are only logged."""
    if not isinstance(stored, dict):
        return
    backend = _backend(stored.get("backend"))
    if backend is None or hardware_backend() is not backend or not isinstance(stored.get("name"), str):
        return
    try:
        backend.delete(stored["name"])
    except Exception as exc:
        debug(f"Could not delete the key {stored['name']}: {exc}")


def discard_profile(profile: str) -> None:
    """Deletes every hardware key of a profile (emptied or removed), readable credentials or not."""
    prefix = f"{KEY_PREFIX}:{profile}:"
    backend = hardware_backend()
    if backend is None:
        return
    try:
        names = [n for n in backend.names() if n.startswith(prefix)]
    except Exception as exc:
        debug(f"Could not list the keys of {backend.name}: {exc}")
        return
    for name in names:
        discard({"backend": backend.name, "name": name})

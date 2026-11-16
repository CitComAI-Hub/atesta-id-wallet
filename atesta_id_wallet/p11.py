# -*- coding: utf-8 -*-
"""
Keys on a PKCS#11 token (keys.Backend): the TPM on Linux through tpm2-pkcs11, smart cards and USB
tokens through OpenSC or their maker's module (YubiKey: ykcs11). The user chooses the module (a
.so, .dll or .dylib) and, if it has several, the token; keys are made on the token, not
extractable, and found again by their label (atesta-id-wallet:PROFILE:RANDOM, as in the TPM).

Signing needs the token's user PIN. It is asked for the first time it is needed (keys.ask_pin:
the CLI or the window), kept in memory only while the wallet is open, and forgotten when it locks
(forget_pins) or the PIN is refused. Public keys are read without it.
"""

from __future__ import annotations

import secrets
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric import ec

from .common import WalletError, debug
from .i18n import tr

# Where distributions and makers put the usual modules (shown to help choose; any path works).
KNOWN_MODULES = [
    "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so", "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
    "/usr/lib64/pkcs11/libtpm2_pkcs11.so", "/usr/lib/pkcs11/libtpm2_pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so", "/usr/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so", "/usr/lib64/libykcs11.so", "/usr/local/lib/libykcs11.dylib",
    "C:\\Windows\\System32\\opensc-pkcs11.dll", "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll",
]

_pins: dict[str, str] = {}  # token serial -> PIN, in memory only
_libraries: dict[str, Any] = {}  # a module is loaded once per process (C_Initialize)
_lock = threading.RLock()  # one operation at a time: many modules are not thread-safe


def forget_pins() -> None:
    _pins.clear()


def known_modules() -> list[str]:
    return [m for m in KNOWN_MODULES if Path(m).is_file()]


def _library(module: str) -> Any:
    import pkcs11  # optional at run time: without it, no token (keys stay in the TPM or in software)

    if module not in _libraries:
        _libraries[module] = pkcs11.lib(module)
    return _libraries[module]


def tokens(module: str) -> list[str]:
    """The labels of the initialised tokens the module offers now."""
    import pkcs11

    with _lock:
        found = []
        for slot in _library(module).get_slots(token_present=True):
            token = slot.get_token()
            if token.flags & pkcs11.TokenFlag.TOKEN_INITIALIZED:
                found.append(str(token.label).strip())
        return found


def _point(public: Any) -> ec.EllipticCurvePublicKey:
    """CKA_EC_POINT: a DER OCTET STRING with the uncompressed point (some modules give it bare)."""
    from pkcs11 import Attribute

    raw = bytes(public[Attribute.EC_POINT])
    if len(raw) == 67 and raw[:2] == b"\x04\x41":
        raw = raw[2:]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


class Pkcs11Token:
    """keys.Backend on one token of a PKCS#11 module."""
    name = "pkcs11"
    cache_availability = False  # a token can be plugged in or out at any time

    def __init__(self, module: str, token_label: str | None, ask_pin: Callable[[str], str] | None):
        self.module, self.token_label, self.ask_pin = module, token_label or None, ask_pin

    @property
    def label(self) -> str:
        return tr("the security device «{token}»", token=self.token_label or Path(self.module).name)

    def _token(self) -> Any:
        import pkcs11

        library = _library(self.module)
        if self.token_label:
            return library.get_token(token_label=self.token_label)
        for slot in library.get_slots(token_present=True):
            token = slot.get_token()
            if token.flags & pkcs11.TokenFlag.TOKEN_INITIALIZED:
                return token
        raise pkcs11.exceptions.NoSuchToken()

    def available(self) -> bool:
        with _lock:
            try:
                self._token()
            except Exception as exc:
                debug(f"PKCS#11 token not available: {exc}")
                return False
            return True

    def _open(self, *, login: bool, write: bool = False) -> Any:
        """A session on the token; logged in with the PIN (asked for once) when login is True."""
        import pkcs11

        token = self._token()
        if not login:
            return token.open(rw=write)
        serial = bytes(token.serial).hex() if isinstance(token.serial, bytes) else str(token.serial)
        for attempt in range(2):
            pin = _pins.get(serial)
            if pin is None:
                if self.ask_pin is None:
                    raise WalletError(tr("The PIN of {token} is needed, and it cannot be asked for here.",
                                         token=self.label))
                pin = self.ask_pin(tr("PIN of {token}", token=self.label))
            try:
                session = token.open(rw=write, user_pin=pin)
            except pkcs11.exceptions.PinIncorrect as exc:
                _pins.pop(serial, None)
                if attempt == 0 and self.ask_pin is not None:
                    continue
                raise WalletError(tr("The PIN of {token} is not correct.", token=self.label)) from exc
            except pkcs11.exceptions.PinLocked as exc:
                _pins.pop(serial, None)
                raise WalletError(tr("The PIN of {token} is blocked: unblock it with the tool of the token's "
                                     "maker.", token=self.label)) from exc
            _pins[serial] = pin
            return session
        raise WalletError(tr("The PIN of {token} is not correct.", token=self.label))

    def _find(self, session: Any, key_name: str, kind: Any) -> Any:
        from pkcs11 import Attribute

        found = list(session.get_objects({Attribute.CLASS: kind, Attribute.LABEL: key_name}))
        return found[0] if found else None

    def create(self, key_name: str) -> ec.EllipticCurvePublicKey:
        from pkcs11 import Attribute, KeyType
        from pkcs11.util.ec import encode_named_curve_parameters

        with _lock, self._open(login=True, write=True) as session:
            parameters = session.create_domain_parameters(
                KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")}, local=True)
            public, _ = parameters.generate_keypair(
                store=True, label=key_name, id=secrets.token_bytes(16),
                public_template={Attribute.VERIFY: True},
                private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                                  Attribute.PRIVATE: True})
            return _point(public)

    def public_key(self, key_name: str) -> ec.EllipticCurvePublicKey | None:
        from pkcs11 import ObjectClass

        with _lock:
            try:
                with self._open(login=False) as session:
                    public = self._find(session, key_name, ObjectClass.PUBLIC_KEY)
                    return _point(public) if public is not None else None
            except WalletError:
                raise
            except Exception as exc:  # no token (or another one): not here
                debug(f"PKCS#11: {exc}")
                return None

    def sign(self, key_name: str, digest: bytes) -> bytes:
        from pkcs11 import Mechanism, ObjectClass

        with _lock, self._open(login=True) as session:
            private = self._find(session, key_name, ObjectClass.PRIVATE_KEY)
            if private is None:
                raise WalletError(tr("The key of this credential is not on {token}.", token=self.label))
            signature = bytes(private.sign(digest, mechanism=Mechanism.ECDSA))  # r || s
            if len(signature) != 64:
                raise WalletError(tr("The signature from {token} is not a P-256 one.", token=self.label))
            return signature

    def delete(self, key_name: str) -> None:
        from pkcs11 import Attribute

        with _lock, self._open(login=True, write=True) as session:
            for item in list(session.get_objects({Attribute.LABEL: key_name})):
                item.destroy()

    def names(self) -> list[str]:
        from pkcs11 import Attribute, ObjectClass

        with _lock, self._open(login=False) as session:
            return [str(o[Attribute.LABEL]) for o in session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY})]


_configured: dict[tuple[str, str], Pkcs11Token] = {}


def configured(settings: dict[str, Any], ask_pin: Callable[[str], str] | None) -> list[Pkcs11Token]:
    """The token chosen in the settings ({"pkcs11": {"module", "token"}}), if any."""
    chosen = settings.get("pkcs11")
    if not isinstance(chosen, dict) or not isinstance(chosen.get("module"), str):
        return []
    key = (chosen["module"], str(chosen.get("token") or ""))
    if key not in _configured:
        _configured[key] = Pkcs11Token(chosen["module"], chosen.get("token") or None, ask_pin)
    _configured[key].ask_pin = ask_pin
    return [_configured[key]]


def library_installed() -> bool:
    try:
        import pkcs11  # noqa: F401
    except ImportError:
        return False
    return True


def module_suffix() -> str:
    return {"win32": "*.dll", "darwin": "*.dylib *.so"}.get(sys.platform, "*.so")

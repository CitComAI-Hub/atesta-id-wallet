# -*- coding: utf-8 -*-
"""
Encryption of the profile data at rest.

Every profile has a random 256-bit data key. Its files are encrypted with AES-256-GCM under that
key and bound to their name inside the profile, so one file cannot be swapped for another. The
data key itself is kept in one of two ways (vault.json in the profile says which):

  * keyring: in the operating system keyring (Secret Service on Linux, Credential Manager on
    Windows, Keychain on macOS). It opens with the user's session, without questions;
  * password: wrapped with a key derived (scrypt) from the wallet password. Nothing can be read
    until the user types it (app lock), not even by programs running as the same user.

Without a usable keyring a password is required: the data is never stored in clear text.
Unlocked keys stay in memory (per profile folder) until lock() is called.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import WalletError, b64u, b64u_decode
from .i18n import tr

FILE_MAGIC = b"ATESTAF1"  # encrypted file, format 1
KEYRING_SERVICE = "atesta-id-wallet"
VAULT_FILE = "vault.json"
MIN_PASSWORD = 8
SCRYPT = {"n": 2**15, "r": 8, "p": 1}

_keys: dict[Path, bytes] = {}  # unlocked data keys, by profile folder


class Locked(WalletError):
    """The profile is protected by a password that has not been typed yet."""

    def __init__(self) -> None:
        super().__init__(tr("The wallet is locked."))


class PasswordNeeded(WalletError):
    """There is no keyring to keep the data key: the user must choose a wallet password."""

    def __init__(self) -> None:
        super().__init__(tr("There is no system keyring to protect the wallet: choose a wallet password."))


class WrongPassword(WalletError):
    def __init__(self) -> None:
        super().__init__(tr("Wrong wallet password."))


def keyring_available() -> bool:
    try:
        import keyring
        from keyring.backends import fail, null
    except ImportError:
        return False
    backend = keyring.get_keyring()
    return not isinstance(backend, (fail.Keyring, null.Keyring)) and getattr(backend, "priority", 1) > 0


def _meta_path(profile: Path) -> Path:
    return profile / VAULT_FILE


def load_meta(profile: Path) -> dict[str, Any] | None:
    try:
        meta = json.loads(_meta_path(profile).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise WalletError(tr("{path} is damaged: {error}", path=_meta_path(profile), error=exc)) from exc
    if not isinstance(meta, dict) or meta.get("mode") not in ("keyring", "password"):
        raise WalletError(tr("{path} is damaged: {error}", path=_meta_path(profile), error="mode"))
    return meta


def _save_meta(profile: Path, meta: dict[str, Any]) -> None:
    from .storage import write_private  # storage uses this module for its files

    write_private(_meta_path(profile), json.dumps(meta, indent=2))


def mode(profile: Path) -> str | None:
    """'keyring', 'password' or None (no data key yet)."""
    meta = load_meta(profile)
    return meta["mode"] if meta else None


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise WalletError(tr("Use a password with at least {n} characters.", n=MIN_PASSWORD))


def _derive(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, **SCRYPT).derive(password.encode("utf-8"))


def _protect(vault_id: str, key: bytes, password: str | None) -> dict[str, Any]:
    """vault.json content for 'key' kept in the keyring (password None) or wrapped with the password."""
    meta: dict[str, Any] = {"version": 1, "id": vault_id}
    if password is None:
        import keyring

        keyring.set_password(KEYRING_SERVICE, vault_id, b64u(key))
        meta["mode"] = "keyring"
    else:
        _check_password(password)
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        wrapped = AESGCM(_derive(password, salt)).encrypt(nonce, key, vault_id.encode("ascii"))
        meta.update(mode="password", kdf={"name": "scrypt", "salt": b64u(salt), **SCRYPT},
                    wrapped_key=b64u(nonce + wrapped))
    return meta


def create(profile: Path, password: str | None = None) -> None:
    """New data key for a profile without one; in the keyring unless a password is given."""
    if load_meta(profile) is not None:
        raise WalletError(tr("The profile is already encrypted."))
    if password is None and not keyring_available():
        raise PasswordNeeded()
    key, vault_id = secrets.token_bytes(32), secrets.token_hex(16)
    _save_meta(profile, _protect(vault_id, key, password))
    _keys[profile] = key


def unlock(profile: Path, password: str | None = None) -> None:
    meta = load_meta(profile)
    if meta is None:
        create(profile, password)
        return
    if meta["mode"] == "keyring":
        import keyring

        stored = keyring.get_password(KEYRING_SERVICE, meta["id"]) if keyring_available() else None
        if not stored:
            raise WalletError(tr("The key of this profile is not in the system keyring (was the folder copied from "
                                 "another computer?). Restore a backup into a new profile instead."))
        _keys[profile] = b64u_decode(stored)
        return
    if password is None:
        raise Locked()
    blob = b64u_decode(meta["wrapped_key"])
    kek = _derive(password, b64u_decode(meta["kdf"]["salt"]))
    try:
        _keys[profile] = AESGCM(kek).decrypt(blob[:12], blob[12:], meta["id"].encode("ascii"))
    except InvalidTag as exc:
        raise WrongPassword() from exc


def lock(profile: Path | None = None) -> None:
    if profile is None:
        _keys.clear()
    else:
        _keys.pop(profile, None)


def is_open(profile: Path) -> bool:
    """True if the profile can be read now (unlocked, or its key opens with the session)."""
    if profile in _keys:
        return True
    meta = load_meta(profile)
    if meta is None:
        return keyring_available()  # the key will be created in the keyring on the first write
    if meta["mode"] == "password":
        return False
    try:
        unlock(profile)
    except WalletError:  # not in the keyring: unlock() explains it when asked
        return False
    return True


def set_password(profile: Path, password: str | None) -> None:
    """Protects the (unlocked) data key with a new password, or moves it to the keyring (None)."""
    key = _key(profile)
    meta = load_meta(profile)
    if password is None and not keyring_available():
        raise PasswordNeeded()
    new = _protect(meta["id"], key, password)
    _save_meta(profile, new)
    if meta["mode"] == "keyring" and new["mode"] == "password":
        _forget_keyring(meta["id"])


def destroy(profile: Path) -> None:
    """Removes the profile key from the keyring (the profile folder is being deleted)."""
    meta = load_meta(profile)
    if meta and meta["mode"] == "keyring":
        _forget_keyring(meta["id"])
    lock(profile)


def _forget_keyring(vault_id: str) -> None:
    try:
        import keyring
        from keyring.errors import PasswordDeleteError

        keyring.delete_password(KEYRING_SERVICE, vault_id)
    except (ImportError, PasswordDeleteError):
        pass


def _key(profile: Path) -> bytes:
    if profile not in _keys:
        meta = load_meta(profile)
        if meta is None or meta["mode"] == "keyring":
            unlock(profile)  # creates the key (keyring) or reads it from the keyring
        else:
            raise Locked()
    return _keys[profile]


def encrypt(profile: Path, name: str, data: bytes) -> bytes:
    """name: path inside the profile ('credentials/x.enc'); a file only decrypts under its own name."""
    nonce = secrets.token_bytes(12)
    return FILE_MAGIC + nonce + AESGCM(_key(profile)).encrypt(nonce, data, FILE_MAGIC + name.encode("utf-8"))


def decrypt(profile: Path, name: str, blob: bytes) -> bytes:
    if not blob.startswith(FILE_MAGIC):
        raise WalletError(tr("{name} is not an encrypted wallet file.", name=name))
    nonce, sealed = blob[len(FILE_MAGIC):len(FILE_MAGIC) + 12], blob[len(FILE_MAGIC) + 12:]
    try:
        return AESGCM(_key(profile)).decrypt(nonce, sealed, FILE_MAGIC + name.encode("utf-8"))
    except InvalidTag as exc:
        raise WalletError(tr("{name} is damaged or does not belong to this profile.", name=name)) from exc

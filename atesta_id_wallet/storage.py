# -*- coding: utf-8 -*-
"""Profiles, credentials (each copy with its own holder key) and configuration on disk."""

from __future__ import annotations

import io
import json
import os
import secrets
import re
import shutil
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import keys, mdoc, vault
from .common import SD_JWT_FORMATS, WalletError, debug, host_of, humanize, log, site_of
from .keys import HolderKey  # noqa: F401  (imported from here by the rest of the wallet)
from .i18n import tr
from .sdjwt import SdJwt, parse_sd_jwt


def _default_base_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "atesta-id-wallet"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "atesta-id-wallet"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "atesta-id-wallet"


BASE_DIR = Path(os.environ.get("ATESTA_ID_WALLET_HOME") or _default_base_dir())
PROFILES_DIR = BASE_DIR / "profiles"
DEFAULT_PROFILE = "default"

# Paths of the active profile; set_profile() changes them.
PROFILE = DEFAULT_PROFILE
DATA_DIR = PROFILES_DIR / DEFAULT_PROFILE
CRED_DIR = DATA_DIR / "credentials"
CONFIG_FILE = DATA_DIR / "config.enc"
TRUST_DIR = DATA_DIR / "trusted_cas"
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


# Copies of a credential asked from an issuer that supports batch issuance (OpenID4VCI 1.0 §8.2).
# Each copy is bound to a key of its own, so two verifiers cannot link two presentations by the
# issuer's signature or the key; once every copy has been used, they are used again in turn.
MAX_COPIES = 5


def hardware_keys_enabled() -> bool:
    """New keys in this computer's security chip, when it has one; on by default (see keys.py)."""
    return load_settings().get("hardware_keys") is not False


def set_hardware_keys(enabled: bool) -> None:
    settings = load_settings()
    settings["hardware_keys"] = enabled
    save_settings(settings)


def new_holder_key() -> keys.Key:
    """A key for one copy of a credential of the active profile."""
    return keys.new_key(PROFILE, hardware_keys_enabled())


def profile_dir(name: str) -> Path:
    """Every profile lives in profiles/NAME; the root only holds settings.json."""
    if not PROFILE_NAME_RE.match(name):
        raise WalletError(tr("Invalid profile name: '{name}' (letters, digits, '_', '.', '-').", name=name))
    return PROFILES_DIR / name


def set_profile(name: str) -> None:
    global PROFILE, DATA_DIR, CRED_DIR, CONFIG_FILE, TRUST_DIR
    PROFILE = name
    DATA_DIR = profile_dir(name)
    CRED_DIR = DATA_DIR / "credentials"
    CONFIG_FILE = DATA_DIR / "config.enc"
    TRUST_DIR = DATA_DIR / "trusted_cas"


def settings_file() -> Path:
    """Application settings, shared by all profiles (e.g. the language)."""
    return BASE_DIR / "settings.json"


def load_settings() -> dict[str, Any]:
    try:
        settings = json.loads(settings_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return settings if isinstance(settings, dict) else {}  # hand-edited or damaged: the defaults


def save_settings(settings: dict[str, Any]) -> None:
    write_private(settings_file(), json.dumps(settings, indent=2, ensure_ascii=False))


def list_profiles() -> list[str]:
    names = [DEFAULT_PROFILE]
    if PROFILES_DIR.is_dir():
        names += sorted(p.name for p in PROFILES_DIR.iterdir()
                        if p.is_dir() and p.name != DEFAULT_PROFILE and PROFILE_NAME_RE.match(p.name))
    return names


def ensure_data_dir(path: Path | None = None) -> None:
    """Creates the folder 0700, and also its parents up to the data folder (profiles/, the root)."""
    path = path or DATA_DIR
    folders = [path]
    while BASE_DIR in folders[-1].parents:
        folders.append(folders[-1].parent)
    for folder in reversed(folders):
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(folder, 0o700)


def write_private(path: Path, content: str | bytes) -> None:
    """
    Writes with 0600 permissions from the start (no window with the default umask) and
    atomically: an interruption halfway does not leave an empty config file, which would forget
    the pinned verifier certificates.
    """
    ensure_data_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content.encode("utf-8") if isinstance(content, str) else content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# Wrong wallet passwords: a few are free, then each one doubles the wait (15 s, 30 s, ... 15 min).
# This slows down guessing in the wallet itself; whoever copies the files attacks scrypt offline
# instead (see docs/SECURITY.md).
FREE_ATTEMPTS = 3
FIRST_WAIT = 15
MAX_WAIT = 15 * 60


class TooManyAttempts(WalletError):
    def __init__(self, seconds: int) -> None:
        self.seconds = seconds
        super().__init__(tr("Too many wrong passwords. Try again in {seconds} s.", seconds=seconds))


def _failures() -> dict[str, Any]:
    failures = load_settings().get("unlock_failures")
    entry = failures.get(PROFILE) if isinstance(failures, dict) else None
    if not isinstance(entry, dict):
        return {}
    try:  # a hand-edited or damaged settings.json must not stop the wallet from opening
        return {"count": int(entry.get("count", 0)), "until": float(entry.get("until", 0))}
    except (TypeError, ValueError):
        return {}


def _save_failures(entry: dict[str, Any] | None) -> None:
    settings = load_settings()
    failures = settings.get("unlock_failures")
    if not isinstance(failures, dict):
        failures = {}
    if entry:
        failures[PROFILE] = entry
    else:
        failures.pop(PROFILE, None)
    if failures:
        settings["unlock_failures"] = failures
    else:
        settings.pop("unlock_failures", None)
    save_settings(settings)


def unlock_wait() -> int:
    """Seconds left before the wallet password of the active profile may be tried again."""
    return max(0, int(float(_failures().get("until", 0)) - time.time() + 0.999))


def attempts_before_wait() -> int:
    """Wrong passwords still allowed before the next one makes the user wait."""
    return max(0, FREE_ATTEMPTS - int(_failures().get("count", 0)))


def unlock(password: str | None = None) -> None:
    """Unlocks the active profile (or creates its key, protected by 'password' if given)."""
    wait = unlock_wait()
    if wait and vault.mode(DATA_DIR) == "password":
        raise TooManyAttempts(wait)
    try:
        vault.unlock(DATA_DIR, password)
    except vault.WrongPassword:
        count = int(_failures().get("count", 0)) + 1
        entry: dict[str, Any] = {"count": count}
        if count > FREE_ATTEMPTS:
            entry["until"] = time.time() + min(MAX_WAIT, FIRST_WAIT * 2 ** (count - FREE_ATTEMPTS - 1))
        _save_failures(entry)
        raise
    if _failures():
        _save_failures(None)


def vault_state() -> str:
    """Active profile: 'open' (readable), 'locked' (needs the wallet password) or 'new' (no keyring: a
    wallet password must be chosen before storing anything)."""
    if vault.is_open(DATA_DIR):
        return "open"
    return "new" if vault.mode(DATA_DIR) is None else "locked"


def _secret_name(path: Path) -> str:
    return path.relative_to(DATA_DIR).as_posix()


def write_secret(path: Path, data: bytes) -> None:
    """Encrypted (see vault) and atomic write of a file of the active profile."""
    write_private(path, vault.encrypt(DATA_DIR, _secret_name(path), data))


def read_secret(path: Path) -> bytes:
    return vault.decrypt(DATA_DIR, _secret_name(path), path.read_bytes())


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        config = json.loads(read_secret(CONFIG_FILE))
    except ValueError:
        return {}
    return config if isinstance(config, dict) else {}


def save_config(config: dict[str, Any]) -> None:
    if not CONFIG_FILE.exists():
        # A configuration this version starts has no plain CAs of an older one to move: a .pem found
        # later was put there by someone else (see _migrate_plain_cas).
        config = {CAS_ENCRYPTED: True, **config}
    write_secret(CONFIG_FILE, json.dumps(config, indent=2, ensure_ascii=False).encode("utf-8"))


def save_credential(copies: list[tuple[str, keys.Key | None]], *, fmt: str, issuer: str, configuration_id: str,
                    display: dict[str, Any] | None = None) -> Path:
    """Stores one credential: its copies, each with the key it is bound to (None: not bound to any)."""
    if not copies:
        raise WalletError(tr("Credential response without credentials: {data}", data="[]"))
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", configuration_id)[:80]
    stamp = time.strftime("%Y%m%dT%H%M%S")
    path = CRED_DIR / f"{stamp}_{safe_id}.enc"
    suffix = 1
    while path.exists():  # several credentials in the same second (several configurations)
        suffix += 1
        path = CRED_DIR / f"{stamp}_{safe_id}_{suffix}.enc"
    record = {
        "format": fmt,
        "issuer": issuer,
        "credential_configuration_id": configuration_id,
        "stored_at": int(time.time()),
        "instances": [{"credential": raw, "key": key.stored() if key else None, "uses": 0}
                      for raw, key in copies],
    }
    if display:
        record["display"] = display  # name and colours published by the issuer
    write_secret(path, json.dumps(record, indent=2, ensure_ascii=False).encode("utf-8"))
    return path


def has_credentials() -> bool:
    return CRED_DIR.is_dir() and any(CRED_DIR.glob("*.enc"))


def load_credentials() -> list[dict[str, Any]]:
    """
    The stored credentials, newest first. Each one shows the copy to use next: record["_sd"] and
    record["_instance"] (see refresh_state). Credentials stored by versions before 0.14, bound to
    one key for the whole profile, have no 'instances' and are ignored.
    """
    if not CRED_DIR.exists():
        return []
    records = []
    for path in sorted(CRED_DIR.glob("*.enc"), reverse=True):  # newest first
        try:
            record = json.loads(read_secret(path))
        except (vault.Locked, vault.PasswordNeeded):
            raise
        except (OSError, ValueError, WalletError) as exc:  # damaged file: ignored
            debug(f"Could not read {path}: {exc}")
            continue
        instances = record.get("instances") if isinstance(record, dict) else None
        if not isinstance(instances, list) or not instances or not all(isinstance(i, dict) for i in instances):
            debug(f"Ignored {path}: not a credential of this version")
            continue
        record["_path"] = str(path)
        parse = parse_sd_jwt if record.get("format") in SD_JWT_FORMATS else \
            mdoc.parse_mdoc if record.get("format") == mdoc.FORMAT else None
        if parse is not None:
            try:
                for instance in instances:
                    instance["_sd"] = parse(instance["credential"])  # an SdJwt or an Mdoc
            except Exception as exc:  # damaged credential: ignored
                debug(f"Could not parse {path}: {exc}")
                continue
        refresh_state(record)
        records.append(record)
    return records


def _instance_state(instance: dict[str, Any]) -> str | None:
    state = (instance.get("revocation") or {}).get("state")
    return state if state in ("revoked", "suspended") else None


def refresh_state(record: dict[str, Any]) -> None:
    """
    Sets what the rest of the wallet reads from a credential with several copies:
    - record["revocation"]: revoked or suspended only when every copy is (a suspension wins over a
      revocation: it may be lifted); otherwise 'valid', with the oldest check and the nearest
      next check of the copies still in use. Absent if no copy has been checked.
    - record["_instance"], record["_sd"]: the copy to present next, the least used of those not
      revoked or suspended (the first on a tie).
    """
    instances = record["instances"]
    live = [i for i in instances if _instance_state(i) is None]
    record.pop("revocation", None)
    if not live:
        states = [_instance_state(i) for i in instances]
        worst = "suspended" if "suspended" in states else "revoked"
        record["revocation"] = dict(next(i["revocation"] for i in instances if _instance_state(i) == worst))
    elif any(isinstance(i.get("revocation"), dict) for i in live):
        checks = [i.get("revocation") or {} for i in live]
        record["revocation"] = {
            "state": "valid",
            "checked_at": min(int(c.get("checked_at") or 0) for c in checks),
            "next_check": min(int(c.get("next_check") or 0) for c in checks),
        }
    pool = live or instances
    chosen = min(pool, key=lambda i: i.get("uses") if isinstance(i.get("uses"), int) else 0)
    record["_instance"] = next(n for n, i in enumerate(instances) if i is chosen)
    record["_sd"] = chosen.get("_sd")


def holder_key(record: dict[str, Any]) -> keys.Key:
    """The key of the copy to present next (the one record["_sd"] shows)."""
    return keys.load(record["instances"][record["_instance"]].get("key"))


def hardware_bound(record: dict[str, Any]) -> bool:
    """Whether the credential's copies are bound to keys in a security chip (they stay on this computer)."""
    return any(isinstance(i.get("key"), dict) for i in record["instances"])


def bound_elsewhere(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The credentials none of whose keys are on this computer (e.g. restored from another one)."""
    return [r for r in records if hardware_bound(r) and not any(keys.is_here(i.get("key")) for i in r["instances"])]


def mark_used(record: dict[str, Any]) -> None:
    """Counts a presentation of the current copy and moves on to the next one."""
    instance = record["instances"][record["_instance"]]
    instance["uses"] = (instance.get("uses") if isinstance(instance.get("uses"), int) else 0) + 1
    save_record(record)
    refresh_state(record)


def credential_name(record: dict[str, Any]) -> str:
    """Display name: the one the issuer publishes, or the credential type (vct)."""
    sd: SdJwt | None = record.get("_sd")
    claims = sd.claims if sd else {}
    published = (record.get("display") or {}).get("name")
    if published:
        return str(published)
    kind = str(claims.get("vct") or record.get("credential_configuration_id") or record.get("format"))
    return humanize(kind.rstrip("/").rsplit("/", 1)[-1]) if " " not in kind else kind


def credential_holder(record: dict[str, Any]) -> str:
    """The value that best identifies the holder (email, username, name...), if any."""
    sd: SdJwt | None = record.get("_sd")
    claims = sd.display_claims if sd else {}
    for names in (("given_name", "family_name"), ("firstName", "lastName")):
        if all(isinstance(claims.get(k), str) for k in names):
            return " ".join(claims[k] for k in names)
    return next((str(claims[k]) for k in ("name", "email", "username", "preferred_username", "given_name",
                                          "firstName") if isinstance(claims.get(k), (str, int))), "")


def credential_issuer_name(record: dict[str, Any]) -> str:
    issuer = record.get("issuer", "")
    name = (record.get("display") or {}).get("issuer_name")
    if not name or name == host_of(issuer):  # no published name (older versions stored the host)
        name = site_of(issuer)
    return str(name or issuer or "?")


def credential_label(record: dict[str, Any]) -> str:
    """One line that identifies the credential to the user."""
    kind = credential_name(record)
    who = credential_holder(record)
    stored = time.strftime("%Y-%m-%d", time.localtime(record.get("stored_at", 0)))
    issuer = credential_issuer_name(record)
    label = tr("{credential} from {issuer}, stored on {date}", credential=kind, issuer=issuer, date=stored)
    if who:
        label += f" ({who})"
    if revocation_state(record) == "revoked":
        label += "  " + tr("[REVOKED]")
    elif revocation_state(record) == "suspended":
        label += "  " + tr("[SUSPENDED]")
    elif is_expired(record):
        label += "  " + tr("[EXPIRED]")
    return label


def delete_credential(record: dict[str, Any]) -> None:
    Path(record["_path"]).unlink(missing_ok=True)
    for instance in record["instances"]:
        keys.discard(instance.get("key"))


def save_record(record: dict[str, Any]) -> bool:
    """
    Writes a loaded credential back (e.g. with its revocation state or its uses). Only into the
    active profile: a background check that finishes after a profile switch must not write with
    another profile's key. Returns whether it was written. What refresh_state derives is not stored.
    """
    path = Path(record["_path"])
    if path.parent != CRED_DIR or not path.exists():
        return False
    data = {k: v for k, v in record.items() if not k.startswith("_") and k != "revocation"}
    data["instances"] = [{k: v for k, v in i.items() if not k.startswith("_")} for i in record["instances"]]
    write_secret(path, json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))
    return True


def is_expired(record: dict[str, Any]) -> bool:
    sd: SdJwt | None = record.get("_sd")
    exp = sd.payload.get("exp") if sd else None
    return isinstance(exp, (int, float)) and exp < time.time()


def revocation_state(record: dict[str, Any]) -> str | None:
    """'revoked' or 'suspended' if the issuer's status list said so at the last check, else None."""
    state = (record.get("revocation") or {}).get("state")
    return state if state in ("revoked", "suspended") else None


def is_usable(record: dict[str, Any]) -> bool:
    """It can be presented: readable, not expired, not revoked or suspended (as last checked)."""
    return record.get("_sd") is not None and not is_expired(record) and revocation_state(record) is None


EXPIRES_SOON_DAYS = 30


def validity(record: dict[str, Any], now: float | None = None) -> tuple[str, float | None]:
    """
    (state, date): 'revoked' or 'suspended' (date of the check that said so) if the issuer's status
    list said so; otherwise from the credential's own dates: 'valid' (until date, or None if it does
    not expire), 'expiring' (within EXPIRES_SOON_DAYS), 'expired', 'not-yet' (valid from date).
    'valid' does not mean that the status was checked: see status.py.
    """
    now = time.time() if now is None else now
    revoked = revocation_state(record)
    if revoked:
        checked = (record.get("revocation") or {}).get("checked_at")
        return revoked, float(checked) if isinstance(checked, (int, float)) else None
    sd: SdJwt | None = record.get("_sd")
    payload = sd.payload if sd else {}
    exp, nbf = payload.get("exp"), payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now:
        return "not-yet", float(nbf)
    if isinstance(exp, (int, float)):
        if exp < now:
            return "expired", float(exp)
        if exp - now < EXPIRES_SOON_DAYS * 86400:
            return "expiring", float(exp)
        return "valid", float(exp)
    return "valid", None


# What makes up a profile (holder_key.enc: the single key of versions before 0.14, still wiped).
PROFILE_ITEMS = ("holder_key.enc", "credentials", "config.enc", "trusted_cas", "history.enc", vault.VAULT_FILE)


def history_file() -> Path:
    return DATA_DIR / "history.enc"


def _history_text() -> str:
    path = history_file()
    return read_secret(path).decode("utf-8") if path.exists() else ""


def add_history(event: dict[str, Any]) -> None:
    """Adds an event (issued / presented / declined) to the history of the active profile."""
    event = {"time": int(time.time()), **event}
    text = _history_text() + json.dumps(event, ensure_ascii=False) + "\n"
    write_secret(history_file(), text.encode("utf-8"))


def load_history() -> list[dict[str, Any]]:
    """History events, newest first."""
    lines = _history_text().splitlines()
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events[::-1]


def _wipe_profile(path: Path) -> None:
    """Empties a profile, its encryption key included (also the way out of a forgotten password)."""
    keys.discard_profile(path.name)
    vault.destroy(path)
    for item in PROFILE_ITEMS:
        target = path / item
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()


BACKUP_MAGIC = b"ATESTAB1"  # Atesta backup, format 1


def _backup_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def profile_is_empty() -> bool:
    return not has_credentials()


def write_backup(out: Path, password: str) -> None:
    """Encrypted backup (scrypt + AES-256-GCM) of the active profile, the credentials' keys included."""
    if not has_credentials():
        raise WalletError(tr("The profile '{profile}' is empty; there is nothing to back up.", profile=PROFILE))
    vault.check_new_password(password)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in _backup_entries():
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
            tar.addfile(info, io.BytesIO(data))
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    sealed = AESGCM(_backup_key(password, salt)).encrypt(nonce, buffer.getvalue(), BACKUP_MAGIC)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(BACKUP_MAGIC + salt + nonce + sealed)


def _backup_entries() -> list[tuple[str, bytes]]:
    """
    The profile decrypted, with plain names (credentials/X.json, each with its keys...): the backup
    has its own password, and the profile key (in the keyring) does not travel to another computer.
    """
    entries: list[tuple[str, bytes]] = []
    for path, name in ((CONFIG_FILE, "config.json"), (history_file(), "history.jsonl")):
        if path.exists():
            entries.append((name, read_secret(path)))
    if CRED_DIR.is_dir():
        entries += [(f"credentials/{p.stem}.json", read_secret(p)) for p in sorted(CRED_DIR.glob("*.enc"))]
    entries += [(f"trusted_cas/{path.name[:-4]}", pem) for path, pem in trusted_ca_files()]
    return entries


def _restore_target(name: str) -> tuple[Path, bool] | None:
    """Where a backup entry goes in the profile, and whether it is encrypted; None if unexpected."""
    simple = {"config.json": CONFIG_FILE, "history.jsonl": history_file()}
    if name in simple:
        return simple[name], True
    folder, _, file = name.partition("/")
    if "/" in file or not re.fullmatch(r"[A-Za-z0-9_.-]+", file or "") or file.startswith("."):
        return None
    if folder == "credentials" and file.endswith(".json"):
        return CRED_DIR / f"{file[:-5]}.enc", True
    if folder == "trusted_cas" and file.endswith(".pem"):
        return TRUST_DIR / f"{file}.enc", True
    return None


def restore_backup(path: Path, password: str) -> int:
    """Restores a backup into the active profile, which must be empty; returns the number of credentials."""
    if not profile_is_empty():
        raise WalletError(tr("The profile '{profile}' already has data. Restore into a new profile or empty it.",
                             profile=PROFILE))
    data = path.read_bytes()
    if not data.startswith(BACKUP_MAGIC):
        raise WalletError(tr("The file is not an atesta-id-wallet backup."))
    salt, nonce, sealed = data[8:24], data[24:36], data[36:]
    try:
        plain = AESGCM(_backup_key(password, salt)).decrypt(nonce, sealed, BACKUP_MAGIC)
    except Exception as exc:
        raise WalletError(tr("Wrong password or damaged backup.")) from exc

    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        members = tar.getmembers()
        if "holder_key.pem" in {m.name for m in members}:  # one key per profile: before 0.14
            raise WalletError(tr("This backup was made by a version before 0.14 and cannot be restored. Ask "
                                 "the issuers for your credentials again."))
        # Everything is checked before anything is written.
        entries = []
        for member in members:
            found = _restore_target(member.name) if member.isfile() else None
            if found is None:
                raise WalletError(tr("Unexpected entry in the backup: {name}", name=member.name))
            entries.append((member, *found))
        for member, target, encrypted in entries:
            stream = tar.extractfile(member)
            if stream is None:
                raise WalletError(tr("Unexpected entry in the backup: {name}", name=member.name))
            data = stream.read()
            if encrypted:
                write_secret(target, data)
            else:
                write_private(target, data)
    return len(load_credentials())


def read_ca_file(source: Path) -> list[Any]:
    """Certificates in a PEM file, or WalletError if it cannot be read."""
    from cryptography import x509

    try:
        certs = x509.load_pem_x509_certificates(source.read_bytes())
    except (OSError, ValueError) as exc:
        raise WalletError(tr("Could not read the PEM certificate {file}: {error}", file=source, error=exc)) from exc
    return certs


# Trusted CAs decide which verifiers are shown as trusted, and a trusted verifier is not asked to
# confirm the risk: they are encrypted like the rest of the profile (trusted_cas/NAME.pem.enc), so a
# certificate dropped into the folder by another program is not believed.
CA_SUFFIX = ".pem.enc"
CAS_ENCRYPTED = "trusted_cas_encrypted"  # config flag: the plain .pem files of older versions were moved


def _migrate_plain_cas() -> None:
    """
    Older versions kept the CAs as plain .pem files: encrypted once, then plain files are ignored.
    Only in a profile whose encrypted configuration was written by an older version: without it
    (a new profile, or config.enc deleted by another program) a plain .pem is not believed, or a
    program that cannot read the wallet could delete config.enc and have its own CA trusted.
    """
    if not CONFIG_FILE.exists():
        return
    config = load_config()
    if config.get(CAS_ENCRYPTED) is True:
        return
    for path in sorted(TRUST_DIR.glob("*.pem")) if TRUST_DIR.is_dir() else []:
        write_secret(path.with_name(path.name + ".enc"), path.read_bytes())
        path.unlink()
    config[CAS_ENCRYPTED] = True
    save_config(config)


def trusted_ca_files() -> list[tuple[Path, bytes]]:
    """(file, PEM) of each CA trusted in the active profile; files that do not decrypt are left out."""
    _migrate_plain_cas()
    found = []
    for path in sorted(TRUST_DIR.glob("*" + CA_SUFFIX)) if TRUST_DIR.is_dir() else []:
        try:
            found.append((path, read_secret(path)))
        except WalletError as exc:
            log(tr("Warning: {file} is not a valid PEM certificate: {error}", file=path.name, error=exc))
    plain = list(TRUST_DIR.glob("*.pem")) if TRUST_DIR.is_dir() else []
    for path in plain:
        log(tr("Warning: {file} is not a valid PEM certificate: {error}", file=path.name,
               error="not added with the wallet; ignored"))
    return found


def ca_file(name: str) -> Path:
    """The file of a trusted CA from its name as listed ('ca', 'ca.pem' or 'ca.pem.enc')."""
    base = Path(name).name
    for suffix in (".enc", ".pem"):
        base = base[: -len(suffix)] if base.endswith(suffix) else base
    return TRUST_DIR / f"{base}{CA_SUFFIX}"


def add_trusted_ca(source: Path) -> Path:
    """Copies the PEM to the profile's trusted_cas/ without overwriting another CA with the same file name."""
    certs = read_ca_file(source)
    pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs).encode("ascii")
    existing = dict(trusted_ca_files())
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", source.stem)[:60].lstrip(".") or "ca"
    target, suffix = TRUST_DIR / f"{stem}{CA_SUFFIX}", 1
    while target.exists() and existing.get(target) != pem:
        suffix += 1
        target = TRUST_DIR / f"{stem}_{suffix}{CA_SUFFIX}"
    write_secret(target, pem)
    return target


def create_profile(name: str) -> None:
    path = profile_dir(name)
    if path.exists():
        raise WalletError(tr("The profile '{name}' already exists.", name=name))
    ensure_data_dir(path)


def remove_profile(name: str) -> None:
    if name == DEFAULT_PROFILE:
        raise WalletError(tr("The 'default' profile cannot be removed; empty it with 'atesta-id-wallet reset'."))
    path = profile_dir(name)
    if not path.is_dir():
        raise WalletError(tr("The profile '{name}' does not exist.", name=name))
    keys.discard_profile(name)
    vault.destroy(path)
    shutil.rmtree(path)

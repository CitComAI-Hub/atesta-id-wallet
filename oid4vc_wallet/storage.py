# -*- coding: utf-8 -*-
"""Perfiles, clave del holder, credenciales y configuración en disco."""

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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import SD_JWT_FORMATS, WalletError, b64u, b64u_json, debug, host_of, humanize, log
from .i18n import tr
from .sdjwt import SdJwt, parse_sd_jwt


def _default_base_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "oid4vc-wallet"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "oid4vc-wallet"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "oid4vc-wallet"


BASE_DIR = Path(os.environ.get("OID4VC_WALLET_HOME") or _default_base_dir())
PROFILES_DIR = BASE_DIR / "profiles"
DEFAULT_PROFILE = "default"
LEGACY_DATA_DIR = Path(__file__).resolve().parent.parent / "wallet_data"  # versiones de un solo script

# Rutas del perfil activo; set_profile() las cambia.
PROFILE = DEFAULT_PROFILE
DATA_DIR = BASE_DIR
KEY_FILE = DATA_DIR / "holder_key.pem"
CRED_DIR = DATA_DIR / "credentials"
CONFIG_FILE = DATA_DIR / "config.json"
TRUST_DIR = DATA_DIR / "trusted_cas"
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class HolderKey:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self.private_key = private_key

    @classmethod
    def load_or_create(cls, path: Path | None = None) -> "HolderKey":
        path = path or KEY_FILE
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise WalletError(tr("{path} does not contain an EC key.", path=path))
            return cls(key)
        ensure_data_dir()
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        log(tr("New holder key generated in {path}", path=path))
        return cls(key)

    @property
    def public_jwk(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }

    def sign_jwt(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        header = {"alg": "ES256", **header}
        signing_input = f"{b64u_json(header)}.{b64u_json(payload)}".encode("ascii")
        der = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing_input.decode('ascii')}.{b64u(signature)}"


def profile_dir(name: str) -> Path:
    """El perfil 'default' vive en la raíz (compatibilidad con la 0.1); el resto en profiles/."""
    if name == DEFAULT_PROFILE:
        return BASE_DIR
    if not PROFILE_NAME_RE.match(name):
        raise WalletError(tr("Invalid profile name: '{name}' (letters, digits, '_', '.', '-').", name=name))
    return PROFILES_DIR / name


def set_profile(name: str) -> None:
    global PROFILE, DATA_DIR, KEY_FILE, CRED_DIR, CONFIG_FILE, TRUST_DIR
    PROFILE = name
    DATA_DIR = profile_dir(name)
    KEY_FILE = DATA_DIR / "holder_key.pem"
    CRED_DIR = DATA_DIR / "credentials"
    CONFIG_FILE = DATA_DIR / "config.json"
    TRUST_DIR = DATA_DIR / "trusted_cas"


def settings_file() -> Path:
    """Ajustes de la aplicación, comunes a todos los perfiles (p. ej. el idioma)."""
    return BASE_DIR / "settings.json"


def load_settings() -> dict[str, Any]:
    try:
        return json.loads(settings_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(settings: dict[str, Any]) -> None:
    write_private(settings_file(), json.dumps(settings, indent=2, ensure_ascii=False))


def list_profiles() -> list[str]:
    names = [DEFAULT_PROFILE]
    if PROFILES_DIR.is_dir():
        names += sorted(p.name for p in PROFILES_DIR.iterdir() if p.is_dir() and PROFILE_NAME_RE.match(p.name))
    return names


def ensure_data_dir(path: Path | None = None) -> None:
    path = path or DATA_DIR
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def write_private(path: Path, text: str) -> None:
    """
    Escribe con permisos 0600 desde el principio (no hay ventana con el umask por defecto) y de
    forma atómica: un corte a mitad no deja un config.json vacío, que haría olvidar los
    certificados fijados de los verificadores.
    """
    ensure_data_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def harden_permissions() -> None:
    """
    Corrige permisos de datos creados por la 0.1 (con el umask por defecto). Solo toca lo que
    es del wallet: $OID4VC_WALLET_HOME puede apuntar a una carpeta con otras cosas.
    """
    if not BASE_DIR.is_dir():
        return
    profiles = [BASE_DIR]
    if PROFILES_DIR.is_dir() and not PROFILES_DIR.is_symlink():
        os.chmod(PROFILES_DIR, 0o700)
        profiles += [p for p in PROFILES_DIR.iterdir() if p.is_dir() and not p.is_symlink()]
    targets = [BASE_DIR / "settings.json"]
    for profile in profiles:
        os.chmod(profile, 0o700)
        targets += [profile / item for item in PROFILE_ITEMS]
    for target in targets:
        if target.is_symlink() or not target.exists():
            continue
        if target.is_dir():
            os.chmod(target, 0o700)
            for child in target.iterdir():
                if child.is_file() and not child.is_symlink():
                    os.chmod(child, 0o600)
        else:
            os.chmod(target, 0o600)


def migrate_legacy_data() -> None:
    """Copia ./wallet_data (versiones anteriores del script) al directorio de datos."""
    if BASE_DIR.exists() or not LEGACY_DATA_DIR.is_dir():
        return
    shutil.copytree(LEGACY_DATA_DIR, BASE_DIR)
    log(tr("Data copied from {old} to {new}", old=LEGACY_DATA_DIR, new=BASE_DIR))


def load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(config: dict[str, Any]) -> None:
    write_private(CONFIG_FILE, json.dumps(config, indent=2, ensure_ascii=False))


def save_credential(raw: str, *, fmt: str, issuer: str, configuration_id: str,
                    display: dict[str, Any] | None = None) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", configuration_id)[:80]
    stamp = time.strftime("%Y%m%dT%H%M%S")
    path = CRED_DIR / f"{stamp}_{safe_id}.json"
    suffix = 1
    while path.exists():  # varias credenciales en el mismo segundo (lotes, varias configuraciones)
        suffix += 1
        path = CRED_DIR / f"{stamp}_{safe_id}_{suffix}.json"
    record = {
        "format": fmt,
        "issuer": issuer,
        "credential_configuration_id": configuration_id,
        "stored_at": int(time.time()),
        "credential": raw,
    }
    if display:
        record["display"] = display  # nombre y colores publicados por el emisor
    write_private(path, json.dumps(record, indent=2, ensure_ascii=False))
    return path


def load_credentials() -> list[dict[str, Any]]:
    if not CRED_DIR.exists():
        return []
    records = []
    for path in sorted(CRED_DIR.glob("*.json"), reverse=True):  # más reciente primero
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        record["_path"] = str(path)
        if record.get("format") in SD_JWT_FORMATS:
            try:
                record["_sd"] = parse_sd_jwt(record["credential"])
            except Exception as exc:  # credencial corrupta: se ignora
                debug(f"Could not parse {path}: {exc}")
                continue
        records.append(record)
    return records


def credential_name(record: dict[str, Any]) -> str:
    """Nombre para mostrar: el que publica el emisor, o el tipo (vct) de la credencial."""
    sd: SdJwt | None = record.get("_sd")
    claims = sd.claims if sd else {}
    published = (record.get("display") or {}).get("name")
    if published:
        return str(published)
    kind = str(claims.get("vct") or record.get("credential_configuration_id") or record.get("format"))
    return humanize(kind.rstrip("/").rsplit("/", 1)[-1]) if " " not in kind else kind


def credential_holder(record: dict[str, Any]) -> str:
    """El dato que mejor identifica al titular (email, usuario, nombre...), si lo hay."""
    sd: SdJwt | None = record.get("_sd")
    claims = sd.claims if sd else {}
    for keys in (("given_name", "family_name"), ("firstName", "lastName")):
        if all(isinstance(claims.get(k), str) for k in keys):
            return " ".join(claims[k] for k in keys)
    return next((str(claims[k]) for k in ("name", "email", "username", "preferred_username", "given_name",
                                          "firstName") if isinstance(claims.get(k), (str, int))), "")


def credential_issuer_name(record: dict[str, Any]) -> str:
    return str((record.get("display") or {}).get("issuer_name") or host_of(record.get("issuer", ""))
               or record.get("issuer", "?"))


def credential_label(record: dict[str, Any]) -> str:
    """Una línea para identificar la credencial ante el usuario."""
    kind = credential_name(record)
    who = credential_holder(record)
    stored = time.strftime("%Y-%m-%d", time.localtime(record.get("stored_at", 0)))
    issuer = credential_issuer_name(record)
    label = tr("{credential} from {issuer}, stored on {date}", credential=kind, issuer=issuer, date=stored)
    if who:
        label += f" ({who})"
    if is_expired(record):
        label += "  " + tr("[EXPIRED]")
    return label


def delete_credential(record: dict[str, Any]) -> None:
    Path(record["_path"]).unlink(missing_ok=True)


def is_expired(record: dict[str, Any]) -> bool:
    sd: SdJwt | None = record.get("_sd")
    exp = sd.payload.get("exp") if sd else None
    return isinstance(exp, (int, float)) and exp < time.time()


# Lo que forma un perfil (el perfil 'default' comparte directorio con profiles/).
PROFILE_ITEMS = ("holder_key.pem", "credentials", "config.json", "trusted_cas", "history.jsonl")


def history_file() -> Path:
    return DATA_DIR / "history.jsonl"


def add_history(event: dict[str, Any]) -> None:
    """Añade un evento (issued / presented / declined) al historial del perfil activo."""
    event = {"time": int(time.time()), **event}
    path = history_file()
    ensure_data_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")


def load_history() -> list[dict[str, Any]]:
    """Eventos del historial, del más reciente al más antiguo."""
    try:
        lines = history_file().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events[::-1]


def _wipe_profile(path: Path) -> None:
    for item in PROFILE_ITEMS:
        target = path / item
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()


BACKUP_MAGIC = b"OID4VCW1"


def _backup_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def profile_is_empty() -> bool:
    return not KEY_FILE.exists() and not load_credentials()


def write_backup(out: Path, password: str) -> None:
    """Copia cifrada (scrypt + AES-256-GCM) del perfil activo, clave incluida."""
    if not KEY_FILE.exists():
        raise WalletError(tr("The profile '{profile}' is empty; there is nothing to back up.", profile=PROFILE))
    if len(password) < 8:
        raise WalletError(tr("Use a password with at least 8 characters."))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for item in PROFILE_ITEMS:
            if (DATA_DIR / item).exists():
                tar.add(DATA_DIR / item, arcname=item)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    sealed = AESGCM(_backup_key(password, salt)).encrypt(nonce, buffer.getvalue(), BACKUP_MAGIC)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(BACKUP_MAGIC + salt + nonce + sealed)


def restore_backup(path: Path, password: str) -> int:
    """Restaura una copia en el perfil activo, que debe estar vacío; devuelve cuántas credenciales hay."""
    if not profile_is_empty():
        raise WalletError(tr("The profile '{profile}' already has data. Restore into a new profile or empty it.",
                             profile=PROFILE))
    data = path.read_bytes()
    if not data.startswith(BACKUP_MAGIC):
        raise WalletError(tr("The file is not an oid4vc-wallet backup."))
    salt, nonce, sealed = data[8:24], data[24:36], data[36:]
    try:
        plain = AESGCM(_backup_key(password, salt)).decrypt(nonce, sealed, BACKUP_MAGIC)
    except Exception as exc:
        raise WalletError(tr("Wrong password or damaged backup.")) from exc

    ensure_data_dir()
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if (member.name.startswith("/") or ".." in parts or not parts or parts[0] not in PROFILE_ITEMS
                    or not (member.isfile() or member.isdir())):
                raise WalletError(tr("Unexpected entry in the backup: {name}", name=member.name))
        for member in tar.getmembers():
            target = DATA_DIR / member.name
            if member.isdir():
                ensure_data_dir(target)
            else:
                write_private(target, tar.extractfile(member).read().decode("utf-8"))
    return len(load_credentials())


def read_ca_file(source: Path) -> list[Any]:
    """Certificados de un PEM, o WalletError si no se puede leer."""
    from cryptography import x509

    try:
        certs = x509.load_pem_x509_certificates(source.read_bytes())
    except (OSError, ValueError) as exc:
        raise WalletError(tr("Could not read the PEM certificate {file}: {error}", file=source, error=exc)) from exc
    return certs


def add_trusted_ca(source: Path) -> Path:
    """Copia el PEM a trusted_cas/ del perfil sin pisar otra CA que tenga el mismo nombre de fichero."""
    certs = read_ca_file(source)
    pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs)
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", source.stem)[:60] or "ca"
    target, suffix = TRUST_DIR / f"{stem}.pem", 1
    while target.exists() and target.read_text(encoding="utf-8") != pem:
        suffix += 1
        target = TRUST_DIR / f"{stem}_{suffix}.pem"
    write_private(target, pem)
    return target


def create_profile(name: str) -> None:
    path = profile_dir(name)
    if path.exists():
        raise WalletError(tr("The profile '{name}' already exists.", name=name))
    ensure_data_dir(path)


def remove_profile(name: str) -> None:
    if name == DEFAULT_PROFILE:
        raise WalletError(tr("The 'default' profile cannot be removed; empty it with 'oid4vc-wallet reset'."))
    path = profile_dir(name)
    if not path.is_dir():
        raise WalletError(tr("The profile '{name}' does not exist.", name=name))
    shutil.rmtree(path)

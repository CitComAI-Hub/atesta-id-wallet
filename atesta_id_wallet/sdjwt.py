# -*- coding: utf-8 -*-
"""SD-JWT VC parsing and disclosure selection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .common import WalletError, b64u, b64u_decode, jwt_decode_unverified
from .i18n import tr


@dataclass
class Disclosure:
    encoded: str
    digest: str
    salt: str
    name: str | None
    value: Any
    path: list[Any] = field(default_factory=list)


@dataclass
class SdJwt:
    raw: str
    issuer_jwt: str
    header: dict[str, Any]
    payload: dict[str, Any]
    disclosures: list[Disclosure]
    claims: dict[str, Any]

    @property
    def hash_alg(self) -> str:
        return str(self.payload.get("_sd_alg", "sha-256")).lower()


def _sd_digest(encoded: str, alg: str = "sha-256") -> str:
    algorithms = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512}
    if alg not in algorithms:
        raise WalletError(tr("Unsupported _sd_alg: {alg}", alg=alg))
    return b64u(algorithms[alg](encoded.encode("ascii")).digest())


def parse_sd_jwt(raw: str) -> SdJwt:
    raw = raw.strip()
    parts = raw.split("~")
    issuer_jwt = parts[0]
    header, payload = jwt_decode_unverified(issuer_jwt)
    alg = str(payload.get("_sd_alg", "sha-256")).lower()

    by_digest: dict[str, Disclosure] = {}
    for encoded in parts[1:]:
        if not encoded or encoded.count(".") == 2:  # empty or KB-JWT
            continue
        try:
            decoded = json.loads(b64u_decode(encoded))
        except ValueError as exc:
            raise WalletError(tr("Disclosure with an invalid format.")) from exc
        if not isinstance(decoded, list):
            raise WalletError(tr("Disclosure with an invalid format."))
        if len(decoded) == 3 and isinstance(decoded[1], str) and decoded[1] not in ("_sd", "..."):
            salt, name, value = decoded
        elif len(decoded) == 2:
            salt, value = decoded
            name = None
        else:
            raise WalletError(tr("Disclosure with an invalid format."))
        digest = _sd_digest(encoded, alg)
        if digest in by_digest:  # the SD-JWT specification requires rejecting repeated disclosures
            raise WalletError(tr("The SD-JWT contains the same disclosure twice."))
        by_digest[digest] = Disclosure(encoded, digest, salt, name, value)
    used: set[str] = set()

    def take(digest: Any) -> Disclosure | None:
        disclosure = by_digest.get(digest) if isinstance(digest, str) else None
        if disclosure is not None:
            if digest in used:  # a digest that appears twice in the payload
                raise WalletError(tr("The SD-JWT references the same disclosure twice."))
            used.add(digest)
        return disclosure

    def resolve(node: Any, path: list[Any]) -> Any:
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, value in node.items():
                if key in ("_sd", "_sd_alg"):
                    continue
                out[key] = resolve(value, path + [key])
            for digest in node.get("_sd", []) or []:
                disclosure = take(digest)
                if disclosure is None or disclosure.name is None:
                    continue
                if disclosure.name in out:  # it cannot replace a claim the issuer made visible
                    raise WalletError(tr("A disclosure overwrites the claim '{name}'.", name=disclosure.name))
                disclosure.path = path + [disclosure.name]
                out[disclosure.name] = resolve(disclosure.value, disclosure.path)
            return out
        if isinstance(node, list):
            out_list: list[Any] = []
            for item in node:
                if isinstance(item, dict) and set(item) == {"..."}:
                    disclosure = take(item["..."])
                    if disclosure is None or disclosure.name is not None:
                        continue
                    disclosure.path = path + [len(out_list)]
                    out_list.append(resolve(disclosure.value, disclosure.path))
                else:
                    out_list.append(resolve(item, path + [len(out_list)]))
            return out_list
        return node

    claims = resolve(payload, [])
    return SdJwt(raw, issuer_jwt, header, payload, list(by_digest.values()), claims)


def _path_is_prefix(prefix: list[Any], full: list[Any]) -> bool:
    if len(prefix) > len(full):
        return False
    return all(p is None or p == f for p, f in zip(prefix, full))


def select_disclosures(sd_jwt: SdJwt, requested_paths: list[list[Any]] | None) -> list[Disclosure]:
    if requested_paths is None:
        return list(sd_jwt.disclosures)
    return [
        d
        for d in sd_jwt.disclosures
        if d.path  # an orphan disclosure (no path) is never revealed
        and any(_path_is_prefix(d.path, p) or _path_is_prefix(p, d.path) for p in requested_paths)
    ]


# Technical claims that are not personal data; the rest is shown when asking for consent.
TECHNICAL_CLAIMS = {"_sd", "_sd_alg", "cnf", "iss", "iat", "exp", "nbf", "vct", "vct#integrity", "status"}


def disclosed_claims(sd_jwt: SdJwt, requested_paths: list[list[Any]] | None) -> list[tuple[str, Any, bool]]:
    """(path, value, selective?) of what the verifier will see, without repeating nested paths."""
    selected = select_disclosures(sd_jwt, requested_paths)
    paths = [d.path for d in selected if d.path]
    out: list[tuple[str, Any, bool]] = []
    for key, value in sd_jwt.payload.items():
        if key not in TECHNICAL_CLAIMS:
            out.append((key, _without_digests(value), False))
    for path in paths:
        if any(other != path and _path_is_prefix(other, path) for other in paths):
            continue  # already included in a parent claim (e.g. array elements)
        _, value = _claim_at(sd_jwt.claims, path)
        out.append((".".join(map(str, path)), value, True))
    return out


def _without_digests(value: Any) -> Any:
    """A visible claim as the verifier sees it, without the digests (_sd, '...') of what is not revealed."""
    if isinstance(value, dict):
        return {k: _without_digests(v) for k, v in value.items() if k not in ("_sd", "_sd_alg")}
    if isinstance(value, list):
        return [_without_digests(v) for v in value if not (isinstance(v, dict) and set(v) == {"..."})]
    return value


def _claim_at(claims: Any, path: list[Any]) -> tuple[bool, Any]:
    node = claims
    for step in path:
        if step is None and isinstance(node, list):
            return (len(node) > 0, node)
        if isinstance(step, int) and isinstance(node, list) and 0 <= step < len(node):
            node = node[step]
        elif isinstance(step, str) and isinstance(node, dict) and step in node:
            node = node[step]
        else:
            return False, None
    return True, node

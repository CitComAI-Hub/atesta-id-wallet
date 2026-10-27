# -*- coding: utf-8 -*-
"""
Lo que los flujos de emisión y presentación necesitan preguntar al usuario.

Los módulos de protocolo (vci, vp) no hablan con el usuario directamente: reciben un
Prompter. TerminalPrompter pregunta por consola; la GUI implementa el mismo interfaz
con diálogos.
"""

from __future__ import annotations

import getpass
import json
import sys
from dataclasses import dataclass
from typing import Any

from .common import WalletError, confirm
from .i18n import N_, tr
from .sdjwt import disclosed_claims
from .storage import credential_label

TRUST_TEXT = {  # se traducen al mostrarlos: tr(TRUST_TEXT[nivel])
    "trusted": N_("✔ verified identity (certificate from a trusted CA)"),
    "pinned": N_("✔ same certificate as last time (not issued by a trusted CA)"),
    "new": N_("⚠ FIRST TIME: self-signed certificate or unknown CA; nobody vouches for who it claims to be"),
    "changed": N_("⚠⚠ THE CERTIFICATE HAS CHANGED since last time: this could be an impersonation"),
    "unverified": N_("⚠⚠ UNVERIFIED IDENTITY: the request is not signed or uses an unsupported scheme"),
}
RISKY_TRUST = ("changed", "unverified")


def short_value(value: Any, limit: int = 80) -> str:
    if isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value):
        text = ", ".join(map(str, value))
    else:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class OfferSummary:
    """Lo que se muestra antes de aceptar una oferta de credencial."""
    issuer: str  # URL del credential_issuer
    issuer_name: str  # nombre publicado por el emisor (display) o su dominio
    credentials: list[str]  # nombres de las credenciales ofrecidas
    known: bool  # ya se ha usado este emisor antes


@dataclass
class ConsentItem:
    label: str  # credencial que se usa
    claims: list[tuple[str, str]]  # (ruta, valor abreviado) que verá el verificador


def consent_items(matches: list[Any]) -> list[ConsentItem]:
    """Resumen de lo que se va a revelar, para la consola o la GUI."""
    return [
        ConsentItem(
            credential_label(m.record),
            [(path, short_value(value)) for path, value, _ in disclosed_claims(m.record["_sd"], m.paths)],
        )
        for m in matches
    ]


class Prompter:
    """
    Interfaz; cada método puede lanzar WalletError para cancelar el flujo.

    text/secret/confirm/notice/choose_credential/consent son obligatorios; review_offer y
    login tienen una implementación por defecto basada en ellos (la GUI los sustituye por
    pantallas propias).
    """

    def review_offer(self, offer: OfferSummary) -> bool:
        if offer.known:
            return True
        return self.confirm(tr("This is the first time you use the issuer {issuer}. Continue?", issuer=offer.issuer_name))

    def login(self, host: str, username: str | None, *, ask_username: bool) -> tuple[str, str]:
        """Usuario (si ask_username, con username como sugerencia) y contraseña para host."""
        if ask_username:
            username = self.text(tr("Keycloak username or email"), default=username)
        return username or "", self.secret(tr("Password for {host}", host=host))

    def text(self, prompt: str, *, default: str | None = None) -> str:
        raise NotImplementedError

    def secret(self, prompt: str) -> str:
        raise NotImplementedError

    def confirm(self, question: str, *, default: bool = False) -> bool:
        raise NotImplementedError

    def notice(self, message: str) -> None:
        """Instrucciones que el usuario debe leer (p. ej. una URL que abrir en el navegador)."""
        raise NotImplementedError

    def choose_credential(self, query_id: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        raise NotImplementedError

    def consent(self, prepared: Any) -> bool:
        """prepared es un vp.PreparedPresentation; True solo si el usuario acepta enviarlo."""
        raise NotImplementedError


class TerminalPrompter(Prompter):
    def __init__(self, assume_yes: bool = False):
        self.assume_yes = assume_yes

    def text(self, prompt: str, *, default: str | None = None) -> str:
        shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
        return input(shown).strip() or (default or "")

    def secret(self, prompt: str) -> str:
        return getpass.getpass(f"{prompt}: ")

    def confirm(self, question: str, *, default: bool = False) -> bool:
        return confirm(question, default=default, assume_yes=self.assume_yes)

    def notice(self, message: str) -> None:
        print("\n" + message + "\n")

    def choose_credential(self, query_id: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        if len(candidates) == 1 or self.assume_yes or not sys.stdin.isatty():
            return candidates[0]
        print("\n" + tr("Several credentials match '{query}':", query=query_id))
        for index, record in enumerate(candidates, 1):
            print(f"  {index}. {credential_label(record)}")
        while True:
            answer = input(tr("Which one? [1-{count}, Enter = 1] ", count=len(candidates))).strip() or "1"
            if answer.isdigit() and 1 <= int(answer) <= len(candidates):
                return candidates[int(answer) - 1]

    def consent(self, prepared: Any) -> bool:
        identity = prepared.identity
        print("\n" + "=" * 70)
        print(tr("Verifier: {name}", name=identity.name))
        print(f"  {tr(TRUST_TEXT[identity.trust])}")
        print(tr("The data will be sent to: {uri}", uri=prepared.response_uri))
        print("\n" + tr("Data that will be disclosed:"))
        for item in consent_items(prepared.matches):
            print(f"  · {item.label}")
            for path, value in item.claims:
                print(f"      {path}: {value}")
        print("=" * 70)
        if identity.trust in RISKY_TRUST and self.assume_yes:
            raise WalletError(tr("Data is not sent to an unverified verifier without confirmation (remove --yes)."))
        return self.confirm(tr("Send this data?"), default=False)

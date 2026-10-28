# -*- coding: utf-8 -*-
"""
What the issuance and presentation flows need to ask the user.

The protocol modules (vci, vp) never talk to the user directly: they receive a Prompter.
TerminalPrompter asks in the console; the GUI implements the same interface with panels.
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

TRUST_TEXT = {  # translated when shown: tr(TRUST_TEXT[level])
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
    """What is shown before accepting a credential offer."""
    issuer: str  # credential_issuer URL
    issuer_name: str  # name published by the issuer (display) or its domain
    credentials: list[str]  # names of the offered credentials
    known: bool  # this issuer has been used before


@dataclass
class ConsentItem:
    label: str  # credential being used
    claims: list[tuple[str, str]]  # (path, shortened value) the verifier will see


def consent_items(matches: list[Any]) -> list[ConsentItem]:
    """Summary of what will be disclosed, for the console or the GUI."""
    return [
        ConsentItem(
            credential_label(m.record),
            [(path, short_value(value)) for path, value, _ in disclosed_claims(m.record["_sd"], m.paths)],
        )
        for m in matches
    ]


class Prompter:
    """
    Interface; every method may raise WalletError to cancel the flow.

    text/secret/confirm/notice/choose_credential/consent are required; review_offer and login
    have a default implementation built on them (the GUI replaces them with its own screens).
    """

    def review_offer(self, offer: OfferSummary) -> bool:
        if offer.known:
            return True
        return self.confirm(tr("This is the first time you use the issuer {issuer}. Continue?", issuer=offer.issuer_name))

    def login(self, host: str, username: str | None, *, ask_username: bool) -> tuple[str, str]:
        """Username (if ask_username, with username as a suggestion) and password for host."""
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
        """Instructions the user must read (e.g. a URL to open in the browser)."""
        raise NotImplementedError

    def choose_credential(self, query_id: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        raise NotImplementedError

    def consent(self, prepared: Any) -> bool:
        """prepared is a vp.PreparedPresentation; True only if the user agrees to send it."""
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

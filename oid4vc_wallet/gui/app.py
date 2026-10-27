# -*- coding: utf-8 -*-
"""
Ventana principal.

Los flujos (emisión, presentación) se ejecutan en un hilo aparte. Cuando necesitan
preguntar algo, GuiPrompter pide a la ventana un panel y espera; la ventana muestra
el panel sin bloquear y responde cuando el usuario decide.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
from PySide6.QtCore import QBuffer, QIODevice, QLocale, QObject, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import common, i18n, storage, updates
from ..common import Cancelled, WalletError, __version__
from ..desktop import (
    APP_ICON,
    IMAGE_SUFFIXES,
    _is_wallet_link,
    _qr_from_bytes,
    _screenshot_dirs,
    cmd_install_handler,
    decode_qr_image,
    route_input,
)
from ..i18n import tr, tr_n
from ..storage import (
    DEFAULT_PROFILE,
    HolderKey,
    add_trusted_ca,
    create_profile,
    credential_name,
    delete_credential,
    harden_permissions,
    list_profiles,
    load_config,
    load_credentials,
    load_settings,
    migrate_legacy_data,
    profile_is_empty,
    read_ca_file,
    remove_profile,
    restore_backup,
    save_config,
    save_settings,
    set_profile,
    write_backup,
)
from ..ui import OfferSummary, Prompter, consent_items
from ..vci import IssueOptions, issue
from ..vp import NoMatchingCredential, build_response, prepare_presentation, record_declined, send_presentation
from . import theme
from .pages import ActivityPage, CredentialPage, SettingsPage, WalletPage
from .sheets import (
    ChooseSheet,
    ConfirmSheet,
    ConsentSheet,
    LoginSheet,
    OfferSheet,
    Overlay,
    ProgressSheet,
    ResultSheet,
    ScanSheet,
    TextSheet,
)
from .widgets import CredentialCard, IconBubble, Toast, esc, label


# ---------------------------------------------------------------------------
# Puente entre el hilo de trabajo y la interfaz
# ---------------------------------------------------------------------------


@dataclass
class Ask:
    kind: str
    args: tuple
    done: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    cancelled: bool = False

    def answer(self, value: Any) -> None:
        self.result = value
        self.done.set()

    def cancel(self) -> None:
        self.cancelled = True
        self.done.set()


class Bridge(QObject):
    ask = Signal(object)
    logged = Signal(str, bool)
    finished = Signal(object, object)  # (callback, resultado)
    failed = Signal(object, str)  # (excepción, traza)
    update_checked = Signal(object, bool)  # (Release, None o excepción; automática)


class GuiPrompter(Prompter):
    def __init__(self, bridge: Bridge):
        self.bridge = bridge

    def _ask(self, kind: str, *args: Any) -> Any:
        request = Ask(kind, args)
        self.bridge.ask.emit(request)
        request.done.wait()
        if request.cancelled:
            raise Cancelled()
        return request.result

    def review_offer(self, offer: OfferSummary) -> bool:
        return self._ask("offer", offer)

    def login(self, host: str, username: str | None, *, ask_username: bool) -> tuple[str, str]:
        return self._ask("login", host, username, ask_username)

    def text(self, prompt: str, *, default: str | None = None) -> str:
        return self._ask("text", prompt, default)

    def secret(self, prompt: str) -> str:
        return self._ask("secret", prompt)

    def confirm(self, question: str, *, default: bool = False) -> bool:
        return self._ask("confirm", question)

    def notice(self, message: str) -> None:
        self._ask("notice", message)

    def choose_credential(self, query_id: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        return candidates[0] if len(candidates) == 1 else self._ask("choose", query_id, candidates)

    def consent(self, prepared: Any) -> bool:
        return self._ask("consent", prepared)


# ---------------------------------------------------------------------------
# Ventana
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.bridge = Bridge()
        self.bridge.ask.connect(self._on_ask)
        self.bridge.logged.connect(self._on_log)
        self.bridge.finished.connect(self._on_finished)
        self.bridge.failed.connect(self._on_failed)
        self.bridge.update_checked.connect(self._on_update_checked)
        self.prompter = GuiPrompter(self.bridge)
        self.busy = False
        self.records: list[dict[str, Any]] = []
        self.log_text = ""
        self.last_result: tuple[bool, str] | None = None  # (éxito, título) del último flujo; para los tests
        self._watch: dict[str, Any] | None = None  # estado mientras se espera un QR
        # Enlaces ya procesados (con éxito o no): Escanear no debe volver a coger el QR anterior,
        # que sigue en el portapapeles o en las capturas recientes.
        self._consumed: set[str] = set()
        self._page_name = "wallet"
        self.available_release: updates.Release | None = None

        self.setWindowTitle("OID4VC Wallet")
        self.setMinimumSize(920, 640)
        self.resize(1100, 740)
        QGuiApplication.clipboard().dataChanged.connect(self._watch_tick)
        self._watch_timer = QTimer(self)
        self._watch_timer.timeout.connect(self._watch_tick)
        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(lambda *_: self.apply_theme())
        self.apply_theme()

    # -- construcción ---------------------------------------------------------

    def apply_theme(self) -> None:
        t = theme.current()
        app = QApplication.instance()
        app.setPalette(theme.palette(t))
        app.setStyleSheet(theme.stylesheet(t))
        self._build()

    def _build(self) -> None:
        central = QWidget()
        row = QHBoxLayout(central)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(self._sidebar())
        self.stack = QStackedWidget()
        self.wallet_page = WalletPage(self)
        self.activity_page = ActivityPage(self)
        self.settings_page = SettingsPage(self)
        for page in (self.wallet_page, self.activity_page, self.settings_page):
            self.stack.addWidget(page)
        self.detail_page: CredentialPage | None = None
        row.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        self.overlay = Overlay(central)
        self.toast = Toast(central)
        self.reload()
        self._go(self._page_name)

    def _sidebar(self) -> QWidget:
        t = theme.current()
        bar = QWidget()
        bar.setObjectName("sidebar")
        bar.setAttribute(Qt.WA_StyledBackground)
        bar.setFixedWidth(232)
        column = QVBoxLayout(bar)
        column.setContentsMargins(18, 24, 18, 20)
        column.setSpacing(4)

        brand = QHBoxLayout()
        brand.setSpacing(10)
        brand.addWidget(IconBubble("wallet", t.on_accent, t.accent, 38))
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(label("OID4VC Wallet", "appName"))
        names.addWidget(label(tr("Verifiable credentials"), "appTagline", wrap=True))
        brand.addLayout(names, 1)
        column.addLayout(brand)
        column.addSpacing(28)

        self.nav = QButtonGroup(self)
        self.nav_buttons: dict[str, QPushButton] = {}
        for key, text, icon in (("wallet", tr("Wallet"), "wallet"), ("activity", tr("Activity"), "history"),
                                ("settings", tr("Settings"), "settings")):
            nav = QPushButton(f"  {text}")
            nav.setObjectName("navButton")
            nav.setCheckable(True)
            nav.setCursor(Qt.PointingHandCursor)
            nav.setIcon(theme.icon(icon, t.text_muted, 18))
            nav.toggled.connect(lambda on, b=nav, i=icon: b.setIcon(theme.icon(i, t.accent if on else t.text_muted, 18)))
            nav.clicked.connect(lambda _=False, k=key: self._go(k))
            self.nav.addButton(nav)
            self.nav_buttons[key] = nav
            column.addWidget(nav)
        column.addStretch()

        column.addWidget(label(tr("Profile").upper(), "sidebarCaption"))
        column.addSpacing(4)
        self.profile_combo = QComboBox()
        self.profile_combo.setToolTip(tr("Each profile is a separate identity"))
        self.profile_combo.addItems(list_profiles())
        self.profile_combo.setCurrentText(storage.PROFILE)
        self.profile_combo.currentTextChanged.connect(self.switch_profile)
        column.addWidget(self.profile_combo)
        return bar

    # -- navegación -----------------------------------------------------------

    def _go(self, name: str) -> None:
        self._page_name = name
        page = {"wallet": self.wallet_page, "activity": self.activity_page, "settings": self.settings_page}[name]
        page.refresh()
        self.stack.setCurrentWidget(page)
        self.nav_buttons[name].setChecked(True)
        if self.detail_page is not None:
            self.stack.removeWidget(self.detail_page)
            self.detail_page.deleteLater()
            self.detail_page = None

    def show_wallet(self) -> None:
        self._go("wallet")

    def open_credential(self, record: dict[str, Any]) -> None:
        if self.detail_page is not None:
            self.stack.removeWidget(self.detail_page)
            self.detail_page.deleteLater()
        self.detail_page = CredentialPage(self, record)
        self.stack.addWidget(self.detail_page)
        self.stack.setCurrentWidget(self.detail_page)

    def reload(self) -> None:
        self.records = load_credentials()
        current = self.stack.currentWidget() if hasattr(self, "stack") else None
        if current is not None and hasattr(current, "refresh"):
            current.refresh()

    def switch_profile(self, name: str) -> None:
        if not name or name == storage.PROFILE:
            return
        if self.busy:  # no cambiar de identidad a mitad de un flujo
            self._sync_profile_widgets()
            return
        set_profile(name)
        _remember_profile(name)
        self._sync_profile_widgets()
        self.reload()
        self._go(self._page_name)
        self.toast.show_message(tr("Profile «{name}»", name=name))

    def _sync_profile_widgets(self) -> None:
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItems(list_profiles())
        self.profile_combo.setCurrentText(storage.PROFILE)
        self.profile_combo.blockSignals(False)

    # -- paneles --------------------------------------------------------------

    def _sheet(self, sheet: Any) -> None:
        self.overlay.show_sheet(sheet)

    def _close_sheet(self) -> None:
        self._stop_watch()
        self.overlay.close_sheet()

    def _result(self, ok: bool, title: str, body: str, **kwargs: Any) -> None:
        self.last_result = (ok, title)
        self._sheet(ResultSheet(ok, title, body, self._close_sheet, **kwargs))

    def _confirm(self, title: str, body: str, action: Callable[[], None], *, confirm_text: str | None = None,
                 danger: bool = False, icon: str = "info") -> None:
        def answer(ok: bool) -> None:
            self._close_sheet()
            if ok:
                action()
        self._sheet(ConfirmSheet(title, body, answer, confirm_text=confirm_text, danger=danger, icon=icon))

    def _ask_text_then(self, title: str, body: str, action: Callable[[str], None], *, secret: bool = False,
                       placeholder: str = "", icon: str = "key-round", confirm_text: str | None = None) -> None:
        def answer(value: str | None) -> None:
            self._close_sheet()
            if value is not None:
                action(value)
        self._sheet(TextSheet(title, body, answer, secret=secret, placeholder=placeholder, icon=icon,
                              confirm_text=confirm_text))

    # -- leer un QR o enlace ----------------------------------------------------

    def scan(self) -> None:
        if self.busy:
            return
        found = self._fresh(self._clipboard_link()) or self._new_screenshot_link(time.time() - 300, set())
        if found:
            self.process(found)
            return
        self._watch = {"since": time.time(), "seen": set(), "clipboard": self._clipboard_signature()}
        self._sheet(ScanSheet(self.open_image, self.paste_link, self._close_sheet))
        self._watch_timer.start(1200)

    def _stop_watch(self) -> None:
        self._watch = None
        self._watch_timer.stop()

    def _watch_tick(self) -> None:
        if self._watch is None or self.busy:
            return
        found = None
        signature = self._clipboard_signature()
        if signature != self._watch["clipboard"]:
            self._watch["clipboard"] = signature
            found = self._fresh(self._clipboard_link())
        found = found or self._new_screenshot_link(self._watch["since"] - 2, self._watch["seen"])
        if found:
            self._stop_watch()
            self.process(found)

    @staticmethod
    def _clipboard_signature() -> str:
        data = QGuiApplication.clipboard().mimeData()
        if data is None:
            return ""
        return "|".join(data.formats()) + (data.text()[:200] if data.hasText() else "")

    @staticmethod
    def _clipboard_link() -> str | None:
        data = QGuiApplication.clipboard().mimeData()
        if data is None:
            return None
        if data.hasText() and _is_wallet_link(data.text()):
            return data.text().strip()
        if data.hasImage():
            image = QGuiApplication.clipboard().image()
            if not image.isNull():
                buffer = QBuffer()
                buffer.open(QIODevice.WriteOnly)
                image.save(buffer, "PNG")
                return _qr_from_bytes(bytes(buffer.data()))
        return None

    def _fresh(self, link: str | None) -> str | None:
        return link if link and link.strip() not in self._consumed else None

    def _new_screenshot_link(self, since: float, seen: set[Path]) -> str | None:
        """QR de una captura guardada después de 'since' que aún no se haya mirado."""
        candidates = []
        for directory in _screenshot_dirs():
            try:
                candidates += [p for p in directory.iterdir()
                               if p.suffix.lower() in IMAGE_SUFFIXES and p not in seen and p.stat().st_mtime >= since]
            except OSError:
                continue
        for image in sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True):
            seen.add(image)
            try:
                link = self._fresh(decode_qr_image(str(image), quiet=True))
            except WalletError:
                continue
            if link:
                return link
        return None

    def open_image(self) -> None:
        self._stop_watch()
        path, _ = QFileDialog.getOpenFileName(self, tr("Image with the QR code"), str(Path.home()),
                                              tr("Images (*.png *.jpg *.jpeg)"))
        if not path:
            return self._close_sheet()
        try:
            self.process(decode_qr_image(path, quiet=True))
        except WalletError as exc:
            self._result(False, tr("No QR code found"), esc(exc))

    def paste_link(self) -> None:
        self._stop_watch()
        self._ask_text_then(tr("Paste link"), tr("Paste the <b>openid4vp://</b> or <b>openid-credential-offer://</b> "
                                                 "link the website gave you."), self.process,
                            placeholder="openid4vp://…", icon="link")

    # -- flujos ---------------------------------------------------------------

    def process(self, entry: str) -> None:
        if self.busy:
            self.toast.show_message(tr("Finish the current step first"))
            return
        self._stop_watch()
        try:
            command, extra = route_input(entry)
        except WalletError as exc:
            return self._result(False, tr("This is not a wallet QR code"), esc(exc))
        raw = extra[1]
        self._consumed.add(raw.strip())
        if command == "issue":
            self._run(tr("Receiving the credential…"),
                      lambda: issue(requests.Session(), raw, IssueOptions(), self.prompter), self._issued)
        else:
            self._run(tr("Reading the request…"), lambda: self._present(raw), self._presented)

    def _present(self, raw: str) -> tuple[Any, str | None]:
        session = requests.Session()
        prepared = prepare_presentation(session, raw, load_credentials(), choose=self.prompter.choose_credential)
        if not self.prompter.consent(prepared):
            record_declined(prepared)
            raise Cancelled()
        body = build_response(prepared, HolderKey.load_or_create())
        return prepared, send_presentation(session, prepared, body)

    def _issued(self, issued: list[Any]) -> None:
        self.reload()
        self._go("wallet")
        added = [r for r in self.records if any(Path(r["_path"]) == c.path for c in issued)]
        names = ", ".join(credential_name(r) for r in added) or tr("the credential")
        card = CredentialCard(added[0], width=280, interactive=False) if added else None
        self._result(True, tr("Credential added"), tr("<b>{names}</b> is now in your wallet.", names=esc(names)),
                     extra=card)

    def _presented(self, result: tuple[Any, str | None]) -> None:
        prepared, redirect_uri = result
        count = sum(len(item.claims) for item in consent_items(prepared.matches))
        self.reload()
        self._result(True, tr("Data shared"),
                     tr_n("You shared {n} piece of data with <b>{verifier}</b>. Go back to the browser: the sign-in "
                          "will complete by itself.", "You shared {n} pieces of data with <b>{verifier}</b>. Go back "
                          "to the browser: the sign-in will complete by itself.", count,
                          verifier=esc(prepared.identity.name)),
                     icon="send")
        if redirect_uri:  # send_presentation solo devuelve direcciones web
            webbrowser.open(redirect_uri)

    def _run(self, title: str, task: Callable[[], Any], on_done: Callable[[Any], None]) -> None:
        self.busy = True
        self.last_result = None
        self._progress_title = title
        self._show_progress()

        def work() -> None:
            try:
                result = task()
            except Exception as exc:  # se muestra en la ventana; la traza va al registro técnico
                self.bridge.failed.emit(exc, traceback.format_exc())
            else:
                self.bridge.finished.emit(on_done, result)

        threading.Thread(target=work, daemon=True).start()

    def _show_progress(self, detail: str = "") -> None:
        self._sheet(ProgressSheet(self._progress_title, detail))

    @Slot(object, object)
    def _on_finished(self, callback: Callable[[Any], None], result: Any) -> None:
        self.busy = False
        callback(result)

    @Slot(object, str)
    def _on_failed(self, exc: Exception, trace: str) -> None:
        self.busy = False
        self.reload()
        if isinstance(exc, Cancelled):
            self._close_sheet()
            self.toast.show_message(tr("Cancelled: nothing was sent"))
            return
        if isinstance(exc, NoMatchingCredential):
            return self._result(False, tr("You do not have the requested credential"),
                                tr("<b>{verifier}</b> asks for: {wanted}. Get it from its issuer first and try again.",
                                   verifier=esc(exc.verifier or tr("The verifier")),
                                   wanted=esc(", ".join(exc.wanted))),
                                icon="wallet", tone="warn", details=exc.detail)
        if isinstance(exc, requests.RequestException):
            return self._result(False, tr("Could not connect"), tr("Check your internet connection. ({error})",
                                                                   error=esc(exc)))
        if isinstance(exc, WalletError):
            return self._result(False, tr("Could not complete it"), esc(exc))
        self._on_log(trace, True)
        self._result(False, tr("Unexpected error"), esc(f"{type(exc).__name__}: {exc}"), details=trace)

    @Slot(str, bool)
    def _on_log(self, message: str, is_debug: bool) -> None:
        self.log_text += ("· " if is_debug else "") + message + "\n"
        sheet = self.overlay.sheet
        if self.busy and not is_debug and isinstance(sheet, ProgressSheet):
            sheet.set_detail(message)

    # -- preguntas del flujo ------------------------------------------------------

    @Slot(object)
    def _on_ask(self, request: Ask) -> None:
        self.raise_()
        self.activateWindow()
        try:
            getattr(self, f"_ask_{request.kind}")(request)
        except Exception:  # un fallo al mostrar el panel no debe dejar el hilo esperando
            self._on_log(traceback.format_exc(), True)
            request.cancel()

    def _reply(self, request: Ask) -> Callable[[Any], None]:
        """Callback para un panel: None cancela; cualquier otro valor responde y vuelve al progreso."""
        def reply(value: Any) -> None:
            self._show_progress()
            if value is None:
                request.cancel()
            else:
                request.answer(value)
        return reply

    def _ask_offer(self, request: Ask) -> None:
        reply = self._reply(request)
        self._sheet(OfferSheet(request.args[0], lambda ok: reply(True) if ok else reply(None)))

    def _ask_login(self, request: Ask) -> None:
        host, username, ask_username = request.args
        self._sheet(LoginSheet(host, username, ask_username, self._reply(request)))

    def _ask_text(self, request: Ask) -> None:
        prompt, default = request.args
        if "tx_code" in prompt:
            title, body = tr("Transaction code"), tr("The issuer has sent you a code (by email, SMS or on its website) "
                                                     "to collect the credential.")
        else:
            title, body = prompt, ""
        reply = self._reply(request)
        self._sheet(TextSheet(title, body, lambda v: reply(v.strip() if v is not None else None),
                              default=default or ""))

    def _ask_secret(self, request: Ask) -> None:
        reply = self._reply(request)
        self._sheet(TextSheet(request.args[0], "", reply, secret=True, icon="lock"))

    def _ask_confirm(self, request: Ask) -> None:
        reply = self._reply(request)
        self._sheet(ConfirmSheet(request.args[0], "", lambda ok: reply(ok)))

    def _ask_notice(self, request: Ask) -> None:
        reply = self._reply(request)
        self._sheet(ResultSheet(True, tr("Notice"), esc(request.args[0]), lambda: reply(True), icon="info",
                                tone="accent"))

    def _ask_choose(self, request: Ask) -> None:
        query_id, candidates = request.args
        self._sheet(ChooseSheet(query_id, candidates, self._reply(request)))

    def _ask_consent(self, request: Ask) -> None:
        reply = self._reply(request)
        self._sheet(ConsentSheet(request.args[0], lambda ok: reply(ok)))

    # -- acciones de las páginas ----------------------------------------------------

    def confirm_delete(self, record: dict[str, Any]) -> None:
        def delete() -> None:
            delete_credential(record)
            self.reload()
            self._go("wallet")
            self.toast.show_message(tr("Credential deleted"))
        self._confirm(tr("Delete this credential?"),
                      tr("<b>{credential}</b> will be deleted from this computer. To get it back you will have to ask "
                         "the issuer again (or restore a backup).", credential=esc(credential_name(record))), delete,
                      confirm_text=tr("Delete"), danger=True, icon="trash-2")

    def new_profile(self) -> None:
        def create(name: str) -> None:
            try:
                create_profile(name.strip())
            except WalletError as exc:
                return self._result(False, tr("Could not create the profile"), esc(exc))
            set_profile(name.strip())
            _remember_profile(name.strip())
            self._sync_profile_widgets()
            self.reload()
            self._go(self._page_name)
            self.toast.show_message(tr("Profile «{name}» created", name=name.strip()))
        self._ask_text_then(tr("New profile"), tr("A profile is a separate identity, with its own key and credentials "
                                                  "(for example, «work»)."), create, placeholder=tr("Profile name"),
                            icon="users", confirm_text=tr("Create"))

    def delete_profile(self) -> None:
        name = storage.PROFILE
        if name == DEFAULT_PROFILE:
            return self._result(False, tr("It cannot be removed"), tr("The «default» profile cannot be removed."),
                                icon="info", tone="accent")

        def delete() -> None:
            remove_profile(name)
            set_profile(DEFAULT_PROFILE)
            _remember_profile(DEFAULT_PROFILE)
            self._sync_profile_widgets()
            self.reload()
            self._go(self._page_name)
            self.toast.show_message(tr("Profile «{name}» removed", name=name))
        self._confirm(tr("Remove the profile «{name}»?", name=esc(name)), tr("Its key and all its credentials will be "
                      "deleted. This cannot be undone."), delete, confirm_text=tr("Remove"), danger=True, icon="trash-2")

    def backup(self) -> None:
        if not storage.KEY_FILE.exists():
            return self._result(False, tr("Nothing to back up"), tr("This profile has no credentials yet."),
                                icon="info", tone="accent")
        path, _ = QFileDialog.getSaveFileName(self, tr("Save encrypted backup"),
                                              str(Path.home() / f"oid4vc-wallet-{storage.PROFILE}.bak"))
        if not path:
            return

        def first(password: str) -> None:
            if len(password) < 8:
                return self._result(False, tr("Password too short"), tr("Use at least 8 characters."))

            def second(repeated: str) -> None:
                if repeated != password:
                    return self._result(False, tr("The passwords do not match"), tr("Try again."))
                try:
                    write_backup(Path(path), password)
                except (WalletError, OSError) as exc:
                    return self._result(False, tr("Could not create the backup"), esc(exc))
                self._result(True, tr("Backup created"), tr("Saved in {path}. Keep it outside this computer: it "
                                                            "cannot be opened without the password.", path=esc(path)),
                             icon="archive")
            self._ask_text_then(tr("Repeat the password"), "", second, secret=True, icon="lock")
        self._ask_text_then(tr("Backup password"), tr("It encrypts the backup. You will need this password to restore "
                                                      "it; it cannot be recovered if you forget it."), first,
                            secret=True, icon="lock")

    def restore(self) -> None:
        if not profile_is_empty():
            return self._result(False, tr("This profile already has data"),
                                tr("Create a new profile in Settings → Profile and restore the backup into it."),
                                icon="info", tone="accent")
        path, _ = QFileDialog.getOpenFileName(self, tr("Restore backup"), str(Path.home()),
                                              tr("Backups (*.bak);;All files (*)"))
        if not path:
            return

        def restore_with(password: str) -> None:
            try:
                count = restore_backup(Path(path), password)
            except (WalletError, OSError) as exc:
                return self._result(False, tr("Could not restore"), esc(exc))
            self.reload()
            self._result(True, tr("Backup restored"), tr_n("{n} credential recovered.", "{n} credentials recovered.",
                                                           count), icon="archive-restore")
        self._ask_text_then(tr("Backup password"), "", restore_with, secret=True, icon="lock",
                            confirm_text=tr("Restore"))

    def add_ca(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, tr("CA certificate (PEM)"), str(Path.home()),
                                              tr("Certificates (*.pem *.crt);;All files (*)"))
        if not path:
            return
        try:
            certs = read_ca_file(Path(path))
        except WalletError as exc:
            return self._result(False, tr("Invalid certificate"), esc(exc))

        def add() -> None:
            try:
                add_trusted_ca(Path(path))
            except (WalletError, OSError) as exc:
                return self._result(False, tr("Invalid certificate"), esc(exc))
            self.reload()
            self.toast.show_message(tr("Authority added"))
        subjects = "<br>".join(esc(c.subject.rfc4514_string()) for c in certs)
        self._confirm(tr("Trust this authority?"), tr("Verifiers with certificates issued by:<br><b>{subjects}</b><br>"
                                                      "will be shown as trusted.", subjects=subjects), add,
                      confirm_text=tr("Trust"), icon="shield-check")

    def forget_verifiers(self) -> None:
        def forget() -> None:
            config = load_config()
            config["verifiers"] = {}
            save_config(config)
            self.reload()
            self.toast.show_message(tr("Verifiers forgotten"))
        self._confirm(tr("Forget the verifiers?"), tr("Next time they will appear as new, and a change of certificate "
                                                      "cannot be detected."), forget, confirm_text=tr("Forget"))

    def set_language(self, preference: str) -> None:
        """Guarda el idioma elegido en Ajustes y reconstruye la ventana con él."""
        settings = load_settings()
        settings["language"] = preference
        save_settings(settings)
        i18n.set_language(i18n.resolve(preference, QLocale.system().name()))
        self._build()
        self.toast.show_message(tr("Language: {language}", language=i18n.LANGUAGES[i18n.current()]))


    def register_links(self) -> None:
        try:
            cmd_install_handler(None)
        except (WalletError, OSError) as exc:
            return self._result(False, tr("Could not register the links"), esc(exc))
        self.toast.show_message(tr("Links registered: they will open this application"))

    # -- versiones nuevas -------------------------------------------------------

    def check_for_updates(self, *, automatic: bool = False) -> None:
        """Pregunta a GitHub en segundo plano; la automática solo avisa si hay una versión nueva."""
        def work() -> None:
            try:
                result: Any = updates.newer_release()
            except (requests.RequestException, WalletError) as exc:
                result = exc
            self.bridge.update_checked.emit(result, automatic)

        threading.Thread(target=work, daemon=True).start()

    def _on_update_checked(self, result: Any, automatic: bool) -> None:
        updates.record_check()
        if isinstance(result, Exception):
            common.debug(f"Update check failed: {result}")
            if not automatic:
                self._result(False, tr("Could not check for new versions"), esc(result))
            return
        if result is None:
            if not automatic:
                self.toast.show_message(tr("This is the latest version ({version})", version=__version__))
            return
        self.available_release = result
        if self._page_name == "settings":
            self.settings_page.refresh()
        if automatic:
            self.toast.show_message(tr("Version {version} is available: see Settings", version=result.version), 6000)
        else:
            self._confirm(tr("Version {version} is available", version=result.version),
                          tr("You have version {current}. Open the download page?", current=__version__),
                          self.open_release, confirm_text=tr("Download"), icon="download")

    def open_release(self) -> None:
        webbrowser.open(self.available_release.url if self.available_release else updates.RELEASES_PAGE)

    def set_update_check(self, enabled: bool) -> None:
        updates.set_automatic_check(enabled)
        if enabled and updates.automatic_check_due():
            self.check_for_updates(automatic=True)


def _remember_profile(name: str) -> None:
    """La ventana se abre la próxima vez con el último perfil elegido."""
    settings = load_settings()
    if settings.get("profile") != name:
        settings["profile"] = name
        save_settings(settings)


def _choose_startup_profile(requested: str | None) -> str:
    profiles = list_profiles()
    requested = requested or os.environ.get("OID4VC_WALLET_PROFILE")
    if requested and requested not in profiles:
        raise WalletError(tr("The profile '{name}' does not exist.", name=requested))
    remembered = load_settings().get("profile")
    return requested or (remembered if remembered in profiles else DEFAULT_PROFILE)


# ---------------------------------------------------------------------------
# Una sola ventana: un enlace abierto con el wallet ya en marcha va a esa ventana
# ---------------------------------------------------------------------------


def _instance_name() -> str:
    """
    Socket local por usuario. En Linux/macOS es una ruta en un directorio privado (0700) para que
    otro usuario no pueda ocupar el nombre y recibir los enlaces; en Windows, una tubería con nombre.
    """
    if sys.platform == "win32":
        # Las tuberías con nombre son globales: con un nombre adivinable, otro usuario del equipo podría
        # crearla antes y recibir los enlaces. El sufijo aleatorio se guarda en la carpeta del usuario.
        token_file = storage.BASE_DIR / "gui-instance"
        try:
            token = token_file.read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            token = secrets.token_hex(16)
            storage.write_private(token_file, token)
        return f"oid4vc-wallet-{token}"
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    candidates = [Path(runtime) / "oid4vc-wallet-gui.sock"] if runtime and Path(runtime).is_dir() else []
    candidates.append(storage.BASE_DIR / "gui.sock")
    for path in candidates:
        if len(str(path).encode()) < 100:  # límite de longitud de los sockets Unix (sun_path)
            if path.parent == storage.BASE_DIR:
                storage.ensure_data_dir(storage.BASE_DIR)
            return str(path)
    return f"oid4vc-wallet-{os.getuid()}"  # en el directorio temporal; Qt lo crea solo para este usuario


def forward_to_running_instance(entry: str | None, name: str | None = None) -> bool:
    """True si ya hay una ventana abierta y se le ha pasado el enlace (o la orden de mostrarse)."""
    socket = QLocalSocket()
    socket.connectToServer(name or _instance_name())
    if not socket.waitForConnected(500):
        return False
    socket.write(((entry or "") + "\n").encode("utf-8"))
    socket.flush()
    socket.waitForBytesWritten(1000)
    socket.disconnectFromServer()
    return True


def listen_for_instances(window: MainWindow, name: str | None = None) -> QLocalServer:
    name = name or _instance_name()
    server = QLocalServer(window)
    server.setSocketOptions(QLocalServer.UserAccessOption)
    if not server.listen(name):
        QLocalServer.removeServer(name)  # socket huérfano de una ventana que se cerró mal
        if not server.listen(name):  # sin ventana única no pasa nada grave: cada enlace abre otra
            common.debug(f"Single-instance socket unavailable ({name}): {server.errorString()}")

    def on_connection() -> None:
        socket = server.nextPendingConnection()
        if socket is None:
            return
        buffer = bytearray()

        def on_data() -> None:
            buffer.extend(bytes(socket.readAll()))
            if b"\n" not in buffer:
                return
            entry = bytes(buffer).split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
            socket.disconnectFromServer()
            window.showNormal()
            window.raise_()
            window.activateWindow()
            if entry:
                window.process(entry)

        socket.readyRead.connect(on_data)
        socket.disconnected.connect(socket.deleteLater)
        if socket.bytesAvailable():
            on_data()

    server.newConnection.connect(on_connection)
    return server


def main(argv: list[str] | None = None) -> int:
    i18n.set_language(i18n.resolve(load_settings().get("language"), QLocale.system().name()))
    parser = argparse.ArgumentParser(prog="oid4vc-wallet-gui", description=tr("OpenID4VC wallet (graphical interface)."))
    parser.add_argument("entry", nargs="?", help=tr("openid4vp:// or openid-credential-offer:// link, or an image"))
    parser.add_argument("--profile", help=tr("Profile to use"))
    parser.add_argument("--verbose", action="store_true", help=tr("Log the protocol details"))
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    QGuiApplication.setApplicationDisplayName("OID4VC Wallet")
    QGuiApplication.setDesktopFileName("oid4vc-wallet")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    if args.smoke_test:
        return smoke_test()
    if forward_to_running_instance(args.entry):
        return 0
    app.setStyle("Fusion")
    app.setWindowIcon(QIcon(str(APP_ICON)) if APP_ICON.exists() else
                      QIcon(theme.icon_pixmap("wallet", theme.current().accent, 64)))
    migrate_legacy_data()
    harden_permissions()
    common.VERBOSE = args.verbose
    try:
        set_profile(_choose_startup_profile(args.profile))
    except WalletError as exc:
        print(tr("ERROR: {error}", error=exc), file=sys.stderr)
        return 1

    window = MainWindow()
    common.LOG_HANDLER = window.bridge.logged.emit
    window._instance_server = listen_for_instances(window)
    window.show()
    if args.entry:
        QTimer.singleShot(0, lambda: window.process(args.entry))
    if updates.automatic_check_due():
        window.check_for_updates(automatic=True)
    return app.exec()


def smoke_test() -> int:
    """
    Comprueba que un ejecutable empaquetado trae lo necesario (lo usa la CI): Qt con SVG, iconos,
    catálogos, zxing-cpp, Pillow y cryptography. Usa $OID4VC_WALLET_HOME si se le da uno vacío y
    devuelve 0 o 1, sin diálogos (en Windows la GUI no tiene consola donde escribir).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from PIL import Image
        from PySide6.QtCore import QByteArray
        from PySide6.QtSvg import QSvgRenderer

        from ..desktop import decode_qr

        for code in i18n.LANGUAGES:
            i18n.load_catalog(code)
        icons = sorted(theme.ICON_DIR.glob("*.svg"))
        if not icons or not all(QSvgRenderer(QByteArray(path.read_bytes())).isValid() for path in icons):
            raise RuntimeError("SVG icons missing or unreadable")
        if not APP_ICON.exists():
            raise RuntimeError(f"missing {APP_ICON}")
        decode_qr(Image.new("RGB", (64, 64), "white"))
        ec.generate_private_key(ec.SECP256R1())
        window = MainWindow()
        window.show()
        QApplication.processEvents()
        window.close()
        return 0
    except Exception:
        if sys.stderr is not None:
            traceback.print_exc()
        return 1

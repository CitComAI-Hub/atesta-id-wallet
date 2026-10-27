# -*- coding: utf-8 -*-
"""Páginas de la ventana: Cartera, detalle de credencial, Actividad y Ajustes."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QLocale, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from .. import common, i18n, storage, updates
from ..common import __version__, host_of, humanize
from ..i18n import N_, tr, tr_n
from ..storage import (
    credential_holder,
    credential_issuer_name,
    credential_name,
    is_expired,
    list_profiles,
    load_config,
    load_history,
    load_settings,
)
from ..trust import load_trust_anchors
from . import theme
from .widgets import (
    CredentialCard,
    EmptyState,
    FlowLayout,
    IconBubble,
    Panel,
    clear_layout,
    button,
    hline,
    key_value_row,
    label,
    pill,
    relative_time,
    short_date,
)

if TYPE_CHECKING:
    from .app import MainWindow


def _scroll_page(content: QWidget) -> QScrollArea:
    content.setObjectName("scrollContent")
    scroll = QScrollArea()
    scroll.setObjectName("page")
    scroll.setWidget(content)
    scroll.setWidgetResizable(True)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    return scroll


def _header(title: str, subtitle: str = "") -> tuple[QWidget, QHBoxLayout]:
    header = QWidget()
    row = QHBoxLayout(header)
    row.setContentsMargins(0, 0, 0, 0)
    text = QVBoxLayout()
    text.setSpacing(2)
    text.addWidget(label(title, "pageTitle"))
    sub = label(subtitle, "pageSubtitle")
    text.addWidget(sub)
    header.subtitle = sub  # type: ignore[attr-defined]
    row.addLayout(text, 1)
    return header, row


class Page(QWidget):
    def __init__(self, window: MainWindow):
        super().__init__()
        self.window_ = window
        self.setObjectName("page")
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(36, 32, 36, 24)
        self.root.setSpacing(20)

    def refresh(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Cartera
# ---------------------------------------------------------------------------


class WalletPage(Page):
    def __init__(self, window: MainWindow):
        super().__init__(window)
        self.header, row = _header(tr("Wallet"))
        row.setContentsMargins(18, 0, 18, 0)  # alineada con las tarjetas (que dejan sitio a su sombra)
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Search"))
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(220)
        self.search.addAction(theme.icon("search", theme.current().text_muted, 16), QLineEdit.LeadingPosition)
        self.search.textChanged.connect(self.refresh)
        row.addWidget(self.search, alignment=Qt.AlignVCenter)
        self.scan_button = button(tr("Scan QR"), "primary", "scan-line")
        self.scan_button.setToolTip(tr("Read a QR code or a link to receive a credential or to sign in"))
        self.scan_button.clicked.connect(window.scan)
        row.addSpacing(8)
        row.addWidget(self.scan_button, alignment=Qt.AlignVCenter)
        self.root.addWidget(self.header)
        self.root.setSpacing(6)

        self.grid_host = QWidget()
        self.grid = FlowLayout(self.grid_host, spacing=24)
        self.grid.setContentsMargins(18, 14, 18, 36)  # sitio para la sombra de las tarjetas
        self.scroll = _scroll_page(self.grid_host)
        self.root.addWidget(self.scroll, 1)

        self.empty = EmptyState(
            "plus", tr("Your wallet is empty"),
            tr("Ask an issuer for a credential (for example, in your Keycloak account: Verifiable Credentials → "
               "Issue to wallet) and scan the QR code it shows you."),
            action=self._empty_action(),
        )
        self.root.addWidget(self.empty, 1)
        self.no_results = EmptyState("search", tr("No results"), tr("No credential matches the search."))
        self.root.addWidget(self.no_results, 1)

    def _empty_action(self) -> Any:
        action = button(tr("Scan QR"), "primary", "scan-line")
        action.clicked.connect(self.window_.scan)
        return action

    def refresh(self) -> None:
        clear_layout(self.grid)
        records = self.window_.records
        query = self.search.text().strip().lower()
        shown = [r for r in records if not query or query in " ".join(
            (credential_name(r), credential_issuer_name(r), credential_holder(r))).lower()]
        for record in shown:
            card = CredentialCard(record)
            card.clicked.connect(lambda r=record: self.window_.open_credential(r))
            self.grid.addWidget(card)
        count = len(records)
        self.header.subtitle.setText(tr_n("{n} credential · profile {profile}", "{n} credentials · profile {profile}",
                                          count, profile=storage.PROFILE))
        self.search.setVisible(count > 0)
        self.scroll.setVisible(bool(shown))
        self.empty.setVisible(not records)
        self.no_results.setVisible(bool(records) and not shown)


# ---------------------------------------------------------------------------
# Detalle de una credencial
# ---------------------------------------------------------------------------


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Claims anidados como filas 'Dirección › Calle'."""
    if isinstance(value, dict):
        rows = []
        for key, item in value.items():
            if key in ("_sd", "_sd_alg", "cnf", "iss", "vct", "iat", "exp", "nbf", "status", "vct#integrity"):
                continue
            rows += _flatten(item, f"{prefix} › {humanize(str(key))}" if prefix else humanize(str(key)))
        return rows
    if isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            return [(prefix, ", ".join(map(str, value)))]
        rows = []
        for index, item in enumerate(value, 1):
            rows += _flatten(item, f"{prefix} {index}")
        return rows
    return [(prefix, str(value))]


def _issuer_text(record: dict[str, Any]) -> str:
    name, host = credential_issuer_name(record), host_of(record.get("issuer", ""))
    return name if name == host else f"{name} ({host})"


def _date(timestamp: Any) -> str:
    return short_date(timestamp) if isinstance(timestamp, (int, float)) else "—"


class CredentialPage(Page):
    def __init__(self, window: MainWindow, record: dict[str, Any]):
        super().__init__(window)
        self.record = record
        back = button(tr("Wallet"), "ghost", "chevron-left")
        back.clicked.connect(window.show_wallet)
        self.root.addWidget(back, alignment=Qt.AlignLeft)

        content = QWidget()
        columns = QHBoxLayout(content)
        columns.setContentsMargins(0, 0, 0, 0)
        columns.setSpacing(32)

        left = QVBoxLayout()
        left.setSpacing(16)
        left.addWidget(CredentialCard(record, width=340, interactive=False))
        left.addWidget(label(credential_name(record), "pageTitle", wrap=True))
        left.addWidget(label(tr("Issued by {issuer}", issuer=credential_issuer_name(record)), "pageSubtitle", wrap=True))
        if is_expired(record):
            t = theme.current()
            left.addWidget(pill(tr("EXPIRED"), t.danger, t.danger_soft), alignment=Qt.AlignLeft)
        left.addSpacing(8)
        delete = button(tr("Delete credential"), "danger", "trash-2")
        delete.clicked.connect(lambda: window.confirm_delete(record))
        left.addWidget(delete, alignment=Qt.AlignLeft)
        left.addStretch()
        columns.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(12)
        sd = record.get("_sd")
        rows = _flatten(sd.claims if sd else {})
        right.addWidget(label(tr("Data"), "sectionTitle"))
        data = Panel((20, 6, 20, 6))
        for index, (key, value) in enumerate(rows):
            data.body.addWidget(key_value_row(key, value, last=index == len(rows) - 1))
        if not rows:
            data.body.addWidget(label(tr("This credential contains no readable data."), "pageSubtitle"))
        right.addWidget(data)

        right.addSpacing(8)
        right.addWidget(label(tr("Details"), "sectionTitle"))
        payload = sd.payload if sd else {}
        details = [
            (tr("Issuer"), _issuer_text(record)),
            (tr("Type"), str(payload.get("vct") or record.get("credential_configuration_id") or "—")),
            (tr("Received"), _date(record.get("stored_at"))),
            (tr("Valid until"), _date(payload.get("exp")) if payload.get("exp") else tr("Does not expire")),
            (tr("Bound to this wallet's key"), tr("Yes") if (payload.get("cnf") or {}).get("jwk") else tr("No")),
            (tr("Selective disclosure"), tr_n("{n} piece of data that is only shared when you approve it",
                                              "{n} pieces of data that are only shared when you approve them, one by one",
                                              len(sd.disclosures) if sd else 0)),
        ]
        info = Panel((20, 6, 20, 6))
        for index, (key, value) in enumerate(details):
            info.body.addWidget(key_value_row(key, value, last=index == len(details) - 1))
        right.addWidget(info)
        right.addStretch()
        columns.addLayout(right, 1)

        self.root.addWidget(_scroll_page(content), 1)


# ---------------------------------------------------------------------------
# Actividad
# ---------------------------------------------------------------------------

EVENT_STYLE = {  # icono, tono, plantilla del título
    "issued": ("download", "accent", N_("You received {credentials} from {party}")),
    "presented": ("send", "ok", N_("You shared data with {party}")),
    "declined": ("ban", "danger", N_("You declined the request from {party}")),
}


class ActivityPage(Page):
    def __init__(self, window: MainWindow):
        super().__init__(window)
        self.header, _ = _header(tr("Activity"), tr("Which credentials you received and which data you shared, and with "
                                                     "whom."))
        self.root.addWidget(self.header)
        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(0)
        self.scroll = _scroll_page(self.list_host)
        self.root.addWidget(self.scroll, 1)
        self.empty = EmptyState("history", tr("No activity yet"),
                                tr("Here you will see every credential you receive and every time you share (or "
                                   "decline to share) your data."))
        self.root.addWidget(self.empty, 1)

    def refresh(self) -> None:
        clear_layout(self.list_layout)
        events = load_history()
        self.scroll.setVisible(bool(events))
        self.empty.setVisible(not events)
        if not events:
            return
        panel = Panel((20, 4, 20, 4))
        for index, event in enumerate(events):
            panel.body.addWidget(self._row(event))
            if index < len(events) - 1:
                panel.body.addWidget(hline())
        self.list_layout.addWidget(panel)
        self.list_layout.addStretch()

    def _row(self, event: dict[str, Any]) -> QWidget:
        t = theme.current()
        icon, tone, template = EVENT_STYLE.get(event.get("type"), ("info", "accent", "{party}"))
        color, soft = {"accent": (t.accent, t.accent_soft), "ok": (t.success, t.success_soft),
                       "danger": (t.danger, t.danger_soft)}[tone]
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 14, 0, 14)
        layout.setSpacing(14)
        layout.addWidget(IconBubble(icon, color, soft, 40), alignment=Qt.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(3)
        credentials = ", ".join(event.get("credentials") or []) or tr("a credential")
        text.addWidget(label(tr(template, party=event.get("party", "?"), credentials=credentials),
                             "sectionTitle", wrap=True))
        if event.get("claims"):
            names = ", ".join(humanize(c.split(".")[-1]) for c in event["claims"])
            text.addWidget(label(tr("Data: {names}", names=names) if event.get("type") == "presented"
                                 else tr("Requested data: {names}", names=names), "caption", wrap=True))
        elif event.get("type") == "issued":
            text.addWidget(label(host_of(event.get("party_id", "")), "caption"))
        layout.addLayout(text, 1)
        layout.addWidget(label(relative_time(event.get("time", 0)), "caption"), alignment=Qt.AlignTop)
        return row


# ---------------------------------------------------------------------------
# Ajustes
# ---------------------------------------------------------------------------


def _setting(title: str, description: str, *controls: QWidget) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 14, 0, 14)
    layout.setSpacing(16)
    text = QVBoxLayout()
    text.setSpacing(2)
    text.addWidget(label(title, "sectionTitle"))
    if description:
        text.addWidget(label(description, "caption", wrap=True))
    layout.addLayout(text, 1)
    for control in controls:
        layout.addWidget(control, alignment=Qt.AlignVCenter)
    return row


class SettingsPage(Page):
    def __init__(self, window: MainWindow):
        super().__init__(window)
        header, _ = _header(tr("Settings"))
        self.root.addWidget(header)
        self.content = QWidget()
        self.column = QVBoxLayout(self.content)
        self.column.setContentsMargins(0, 0, 8, 24)
        self.column.setSpacing(10)
        self.root.addWidget(_scroll_page(self.content), 1)

    def refresh(self) -> None:
        clear_layout(self.column)
        w = self.window_

        general = [_setting(tr("Language"), tr("Automatic uses the language of your system."), self._language_combo())]
        if sys.platform != "darwin":  # en macOS hace falta un .app (ver desktop.cmd_install_handler)
            general.append(_setting(tr("Wallet links"), tr("Open openid4vp:// and openid-credential-offer:// links "
                                                           "(QR codes on web pages) with this application."),
                                    self._action(tr("Register"), w.register_links, "link")))
        self._section(tr("General"), general)
        self._section(tr("Profile"), [
            _setting(tr("Active profile"), tr("Each profile is a separate identity, with its own key and credentials."),
                     self._profile_combo()),
            _setting(tr("New profile"), tr("For example, a personal one and a work one."),
                     self._action(tr("Create…"), w.new_profile, "plus")),
            _setting(tr("Remove this profile"), tr("Deletes its key and its credentials. This cannot be undone."),
                     self._action(tr("Remove…"), w.delete_profile, "trash-2", "danger")),
        ])
        self._section(tr("Backup"), [
            _setting(tr("Create an encrypted backup"), tr("It includes the wallet key: without it the credentials are "
                     "useless. Keep it outside this computer."), self._action(tr("Create…"), w.backup, "archive")),
            _setting(tr("Restore a backup"), tr("It is restored into the active profile, which must be empty."),
                     self._action(tr("Restore…"), w.restore, "archive-restore")),
        ])
        anchors = load_trust_anchors()
        verifiers = load_config().get("verifiers", {})
        anchor_text = ", ".join(c.subject.rfc4514_string() for c in anchors) or tr("None yet.")
        self._section(tr("Trust"), [
            _setting(tr("Verifier authorities"), tr("Verifiers with certificates from these CAs are shown as trusted. "
                                                    "{authorities}", authorities=anchor_text),
                     self._action(tr("Add CA…"), w.add_ca, "shield-check")),
            _setting(tr("Remembered verifiers"),
                     tr_n("{n} verifier whose certificate is remembered since its first use; you will be warned if "
                          "it changes.", "{n} verifiers whose certificate is remembered since their first use; you "
                          "will be warned if it changes.", len(verifiers)),
                     self._action(tr("Forget all"), w.forget_verifiers, enabled=bool(verifiers))),
        ])
        verbose = QCheckBox()
        verbose.setChecked(common.VERBOSE)
        verbose.toggled.connect(lambda on: setattr(common, "VERBOSE", on))
        log = QPlainTextEdit(w.log_text)
        log.setReadOnly(True)
        log.setMinimumHeight(160)
        log.setPlaceholderText(tr("No technical activity in this session."))
        self._section(tr("Advanced"), [
            _setting(tr("Protocol details"), tr("Log the OpenID4VC requests and responses (for debugging)."),
                     verbose),
            log,
        ])
        auto_update = QCheckBox()
        auto_update.setChecked(updates.automatic_check_enabled())
        auto_update.toggled.connect(w.set_update_check)
        about = [
            _setting(f"OID4VC Wallet {__version__}", "OpenID4VCI 1.0 + OpenID4VP · SD-JWT VC\n"
                     + tr("Data: {path}", path=storage.DATA_DIR)),
            _setting(tr("New versions"), tr("Check once a day whether a newer version has been published on GitHub. "
                                            "Nothing about your wallet is sent."),
                     auto_update, self._action(tr("Check now"), w.check_for_updates)),
        ]
        if w.available_release:
            about.append(_setting(tr("Version {version} is available", version=w.available_release.version),
                                  tr("Install it over this one; your credentials and settings are kept."),
                                  self._action(tr("Download"), w.open_release, "download", "primary")))
        self._section(tr("About"), about)
        self.column.addStretch()

    def _section(self, title: str, rows: list[QWidget]) -> None:
        self.column.addSpacing(8)
        self.column.addWidget(label(title.upper(), "sidebarCaption"))
        panel = Panel((20, 2, 20, 2))
        for index, row in enumerate(rows):
            panel.body.addWidget(row)
            if index < len(rows) - 1 and not isinstance(row, QPlainTextEdit):
                panel.body.addWidget(hline())
        if isinstance(rows[-1], QPlainTextEdit):
            panel.body.addSpacing(14)
        self.column.addWidget(panel)

    def _action(self, text: str, slot: Any, icon: str | None = None, kind: str | None = None,
                enabled: bool = True) -> QWidget:
        widget = button(text, kind, icon)
        widget.clicked.connect(slot)
        widget.setEnabled(enabled)
        return widget

    def _language_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItem(tr("Automatic ({language})", language=i18n.LANGUAGES[i18n.system_language(
            QLocale.system().name())]), i18n.AUTO)
        for code, name in i18n.LANGUAGES.items():
            combo.addItem(name, code)
        combo.setCurrentIndex(max(0, combo.findData(load_settings().get("language", i18n.AUTO))))
        combo.setMinimumWidth(180)
        combo.currentIndexChanged.connect(lambda _index: self.window_.set_language(combo.currentData()))
        return combo

    def _profile_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItems(list_profiles())
        combo.setCurrentText(storage.PROFILE)
        combo.setMinimumWidth(160)
        combo.currentTextChanged.connect(self.window_.switch_profile)
        return combo

# -*- coding: utf-8 -*-
"""Window pages: Wallet, credential details, Activity and Settings."""

from __future__ import annotations

import sys
import time
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

from .. import common, i18n, status, storage, updates, vault
from ..common import __version__, claim_label, host_of, site_of
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
    app_logo,
    clear_layout,
    button,
    hline,
    key_value_row,
    keyboard_focus_ring,
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
    sub = label(subtitle, "pageSubtitle", wrap=True)  # long translations in a small window
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
# Wallet
# ---------------------------------------------------------------------------


class WalletPage(Page):
    def __init__(self, window: MainWindow):
        super().__init__(window)
        self.header, row = _header(tr("Wallet"))
        row.setContentsMargins(18, 0, 18, 0)  # aligned with the cards (which leave room for their shadow)
        self.search = QLineEdit()
        self.search.setObjectName("search")  # recognised by its icon and text: subtle edge (theme.input_border)
        self.search.setPlaceholderText(tr("Search"))
        self.search.setAccessibleName(tr("Search credentials"))
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(220)
        glass = self.search.addAction(theme.icon("search", theme.current().text_muted, 16), QLineEdit.LeadingPosition)
        glass.setText(tr("Search credentials"))
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
        self.grid.setContentsMargins(18, 14, 18, 36)  # room for the cards' shadow
        self.scroll = _scroll_page(self.grid_host)
        self.root.addWidget(self.scroll, 1)

        self.empty = EmptyState(
            "plus", tr("Your wallet is empty"),
            tr("Open the page of the organisation that gives you the credential, such as the link in your welcome "
               "email. In your account page, it is under Verifiable Credentials → Issue to wallet. Then press Scan "
               "QR and take a screenshot of the QR code."),
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
        shown.sort(key=is_expired)  # the ones that still work first (stable: newest first)
        for record in shown:
            card = CredentialCard(record)
            card.clicked.connect(lambda r=record: self.window_.open_credential(r))
            self.grid.addWidget(card)
        count = len(records)
        text = tr_n("{n} credential", "{n} credentials", count)
        if len(list_profiles()) > 1:
            text = tr_n("{n} credential · profile {profile}", "{n} credentials · profile {profile}", count,
                        profile=storage.PROFILE)
        self.header.subtitle.setText(text)
        self.search.setVisible(count > 0)
        self.scroll.setVisible(bool(shown))
        self.empty.setVisible(not records)
        self.no_results.setVisible(bool(records) and not shown)


class LockPage(Page):
    """Shown instead of the pages while the profile is locked (or needs a wallet password first)."""

    def __init__(self, window: MainWindow):
        super().__init__(window)
        self.state: QWidget | None = None

    def refresh(self) -> None:
        if self.state is not None:
            self.state.hide()
            self.state.deleteLater()
        new = storage.vault_state() == "new"
        action = button(tr("Choose a password…") if new else tr("Unlock…"), "primary", "lock")
        action.clicked.connect(self.window_.unlock)
        if new:
            state = EmptyState("lock", tr("Protect your wallet"),
                               tr("There is no system keyring on this computer to keep the wallet key. Choose a "
                                  "wallet password: everything in the profile «{profile}» is encrypted with it.",
                                  profile=storage.PROFILE), action=action)
        else:
            state = EmptyState("lock", tr("The wallet is locked"),
                               tr("The profile «{profile}» is encrypted. Type the wallet password to open it.",
                                  profile=storage.PROFILE), action=action)
        self.state = state
        self.root.addWidget(state, 1)


# ---------------------------------------------------------------------------
# Credential details
# ---------------------------------------------------------------------------


# Shown elsewhere (dates, issuer, key) or meaningless to a person: never among the data.
HIDDEN_CLAIMS = {"_sd", "_sd_alg", "cnf", "iss", "vct", "iat", "exp", "nbf", "status", "vct#integrity"}
# Identifiers and internals (token id, subject id, the DID a role applies to...): under "Technical details".
TECHNICAL_CLAIMS = {"jti", "sub", "sid", "target", "id", "kid", "nonce", "@context", "@type"}


def _flatten(value: Any, prefix: str = "", technical: bool = False) -> list[tuple[str, str, bool]]:
    """Nested claims as ('Address › Street', value, technical) rows."""
    if isinstance(value, dict):
        shown = [k for k in value if k not in HIDDEN_CLAIMS and k not in TECHNICAL_CLAIMS]
        if shown == ["names"] and prefix:  # FIWARE roles {names, target}: "Roles: a, b", the target is technical
            rows = _flatten(value["names"], prefix, technical)
            return rows + [r for k in value if k in TECHNICAL_CLAIMS
                           for r in _flatten(value[k], f"{prefix} › {claim_label(k)}", True)]
        rows = []
        for key, item in value.items():
            if key in HIDDEN_CLAIMS:
                continue
            name = claim_label(str(key))
            rows += _flatten(item, f"{prefix} › {name}" if prefix else name, technical or key in TECHNICAL_CLAIMS)
        return rows
    if isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            return [(prefix, ", ".join(map(str, value)), technical)]
        if len(value) == 1:  # "Roles › Names", not "Roles 1 › Names"
            return _flatten(value[0], prefix, technical)
        rows = []
        for index, item in enumerate(value, 1):
            rows += _flatten(item, f"{prefix} {index}", technical)
        return rows
    return [(prefix, str(value), technical)]


def validity_text(record: dict[str, Any]) -> tuple[str, str]:
    """(tone, text) of the credential's validity: revoked or suspended at the last check, or its own dates."""
    state, when = storage.validity(record)
    if state == "revoked":
        return "danger", tr("Revoked by {issuer}", issuer=credential_issuer_name(record))
    if state == "suspended":
        return "warn", tr("Suspended by {issuer}", issuer=credential_issuer_name(record))
    if state == "expired":
        return "danger", tr("Expired on {date}", date=short_date(when))
    if state == "not-yet":
        return "warn", tr("Not valid until {date}", date=short_date(when))
    if state == "expiring":
        days = max(1, round((when - time.time()) / 86400))
        return "warn", tr_n("Expires in {n} day ({date})", "Expires in {n} days ({date})", days, date=short_date(when))
    if when is None:
        return "ok", tr("Valid · does not expire")
    return "ok", tr("Valid until {date}", date=short_date(when))


def _issuer_text(record: dict[str, Any]) -> str:
    issuer = record.get("issuer", "")
    name, host = credential_issuer_name(record), host_of(issuer)
    return host if name in (host, site_of(issuer)) else f"{name} ({host})"


def _date(timestamp: Any) -> str:
    return short_date(timestamp) if isinstance(timestamp, (int, float)) else "—"


def _not_before(timestamp: float) -> str:
    """nbf: a credential that cannot be used yet says so."""
    if timestamp > time.time():
        return tr("{date} (not valid yet)", date=short_date(timestamp))
    return short_date(timestamp)


def _revocation_text(record: dict[str, Any]) -> str:
    """What the wallet knows about the credential being revoked, and since when."""
    if not status.has_status(record):
        return tr("Not offered by {issuer}", issuer=credential_issuer_name(record))
    checked = (record.get("revocation") or {}).get("checked_at")
    if not isinstance(checked, (int, float)):
        return tr("Not checked yet")
    state = storage.revocation_state(record)
    if state == "revoked":
        return tr("Revoked (checked on {date})", date=short_date(checked))
    if state == "suspended":
        return tr("Suspended (checked on {date})", date=short_date(checked))
    return tr("Not revoked (checked on {date})", date=short_date(checked))


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
        card = CredentialCard(record, width=340, interactive=False)
        left.addWidget(card)
        # The card already shows the name: under it, what matters next — is it valid, and who gave it.
        tone, text = validity_text(record)
        t = theme.current()
        colour, soft = {"ok": (t.success, t.success_soft), "warn": (t.warning, t.warning_soft),
                        "danger": (t.danger, t.danger_soft)}[tone]
        state_pill = pill(text, colour, soft)
        state_pill.setAccessibleName(text)
        left.addWidget(state_pill, alignment=Qt.AlignLeft)
        left.addWidget(label(tr("Issued by {issuer}", issuer=credential_issuer_name(record)), "pageSubtitle", wrap=True))
        left.addSpacing(8)
        delete = button(tr("Delete credential"), "danger", "trash-2")
        delete.clicked.connect(lambda: window.confirm_delete(record))
        left.addWidget(delete, alignment=Qt.AlignLeft)
        left.addStretch()
        columns.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(12)
        sd = record.get("_sd")
        flat = _flatten(sd.claims if sd else {})
        rows = [(k, v) for k, v, technical in flat if not technical]
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
            (tr("Issued by"), _issuer_text(record)),

            *([(tr("Issued"), _date(payload["iat"]))] if isinstance(payload.get("iat"), (int, float)) else []),
            (tr("Received"), _date(record.get("stored_at"))),
            *([(tr("Valid from"), _not_before(payload["nbf"]))] if isinstance(payload.get("nbf"), (int, float)) else []),
            (tr("Valid until"), _date(payload.get("exp")) if payload.get("exp") else tr("Does not expire")),
            (tr("Revocation check"), _revocation_text(record)),
            (tr("Protection against copies"),
             tr("Only this wallet can use it") if (payload.get("cnf") or {}).get("jwk")
             else tr("None: anyone with a copy could use it")),
            (tr("Shared only with your approval"), tr_n("{n} piece of data", "{n} pieces of data",
                                                       len(sd.disclosures) if sd else 0)),
        ]
        info = Panel((20, 6, 20, 6))
        for index, (key, value) in enumerate(details):
            info.body.addWidget(key_value_row(key, value, last=index == len(details) - 1))
        right.addWidget(info)

        # Identifiers and internals: there to copy for support, folded away from everybody else.
        technical = [(tr("Technical type"), str(payload.get("vct") or record.get("credential_configuration_id") or "—")),
                     *[(k, v) for k, v, is_technical in flat if is_technical]]
        self.technical = Panel((20, 6, 20, 6))
        for index, (key, value) in enumerate(technical):
            self.technical.body.addWidget(key_value_row(key, value, last=index == len(technical) - 1))
        self.technical.hide()
        toggle = button(tr("Show technical details"), "ghost", "chevron-down")
        toggle.setStyleSheet("padding-left: 0px;")
        toggle.clicked.connect(lambda: (self.technical.setVisible(not self.technical.isVisible()),
                                        toggle.setText(tr("Hide technical details") if self.technical.isVisible()
                                                       else tr("Show technical details"))))
        right.addWidget(toggle, alignment=Qt.AlignLeft)
        right.addWidget(self.technical)
        right.addStretch()
        columns.addLayout(right, 1)

        self.root.addWidget(_scroll_page(content), 1)


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------

EVENT_STYLE = {  # icon, tone, title template
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
        self.contact: str | None = None  # party_id whose history is shown, or None for everything
        self.contact_bar = QWidget()
        bar = QVBoxLayout(self.contact_bar)
        bar.setContentsMargins(0, 0, 0, 12)
        bar.setSpacing(8)
        back = button(tr("All activity"), "ghost", "chevron-left")
        back.setStyleSheet("padding-left: 0px;")  # flush with the card and the list below
        back.clicked.connect(lambda: self.show_contact(None))
        bar.addWidget(back, alignment=Qt.AlignLeft)
        card = Panel((20, 14, 20, 14))
        row = QHBoxLayout()
        row.setSpacing(14)
        t = theme.current()
        row.addWidget(IconBubble("users", t.accent, t.accent_soft, 40), alignment=Qt.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(2)
        self.contact_title = label("", "sectionTitle", wrap=True)
        self.contact_summary = label("", "caption", wrap=True, selectable=True)
        text.addWidget(self.contact_title)
        text.addWidget(self.contact_summary)
        row.addLayout(text, 1)
        card.body.addLayout(row)
        bar.addWidget(card)
        self.root.addWidget(self.contact_bar)
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

    def show_contact(self, party_id: str | None) -> None:
        self.contact = party_id
        self.refresh()

    def refresh(self) -> None:
        clear_layout(self.list_layout)
        events = load_history()
        if self.contact is not None:
            events = [e for e in events if e.get("party_id") == self.contact]
        self.contact_bar.setVisible(self.contact is not None)
        if self.contact is not None and events:
            kinds = [e.get("type") for e in events]
            name, place = _party_name(events[0]), _party_place(events[0])
            self.contact_title.setText(name)
            parts = [text for n, text in (
                (kinds.count("issued"), tr_n("{n} credential received", "{n} credentials received", kinds.count("issued"))),
                (kinds.count("presented"), tr_n("shared once", "shared {n} times", kinds.count("presented"))),
                (kinds.count("declined"), tr_n("declined once", "declined {n} times", kinds.count("declined"))),
            ) if n]
            self.contact_summary.setText("\n".join(p for p in (place if place != name else "", " · ".join(parts)) if p))
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
        party = _party_name(event)
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
        text.addWidget(label(tr(template, party=party, credentials=credentials),
                             "sectionTitle", wrap=True))
        if event.get("claims"):
            names = ", ".join(claim_label(c.split(".")[-1]) for c in event["claims"])
            text.addWidget(label(tr("Data: {names}", names=names) if event.get("type") == "presented"
                                 else tr("Requested data: {names}", names=names), "caption", wrap=True))
        elif event.get("type") == "issued":
            text.addWidget(label(host_of(event.get("party_id", "")), "caption"))
        layout.addLayout(text, 1)
        layout.addWidget(label(relative_time(event.get("time", 0)), "caption"), alignment=Qt.AlignTop)
        if self.contact is None and event.get("party_id"):
            row.setCursor(Qt.PointingHandCursor)
            row.setToolTip(tr("Show everything with {party}", party=party))
            row.setFocusPolicy(Qt.StrongFocus)
            keyboard_focus_ring(row)
            row.setObjectName("activityRow")
            row.setAttribute(Qt.WA_StyledBackground)
            row.setAccessibleName(tr(template, party=party, credentials=credentials))
            row.setAccessibleDescription(tr("Show everything with {party}", party=party))
            row.mousePressEvent = lambda _e, pid=event["party_id"]: self.show_contact(pid)
            row.keyPressEvent = lambda e, pid=event["party_id"], r=row: (
                self.show_contact(pid) if e.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space)
                else QWidget.keyPressEvent(r, e))
        return row


def _party_name(event: dict[str, Any]) -> str:
    party = event.get("party", "?")
    if event.get("type") == "issued" and party == host_of(event.get("party_id", "")):
        return site_of(event["party_id"])  # older events stored the host of issuers with no name
    return party


def _party_place(event: dict[str, Any]) -> str:
    """Where the contact is: the host of an issuer, the client_id of a verifier."""
    party_id = str(event.get("party_id", ""))
    if "://" in party_id:
        return host_of(party_id)
    scheme, _, value = party_id.partition(":")  # verifier client_id: x509_san_dns:host, x509_hash:...
    return value if scheme == "x509_san_dns" else party_id


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def _setting(title: str, description: str, *controls: QWidget, leading: QWidget | None = None) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 14, 0, 14)
    layout.setSpacing(16)
    if leading is not None:
        layout.addWidget(leading, alignment=Qt.AlignVCenter)
    text = QVBoxLayout()
    text.setSpacing(2)
    text.addWidget(label(title, "sectionTitle"))
    if description:
        text.addWidget(label(description, "caption", wrap=True))
    layout.addLayout(text, 1)
    for control in controls:
        if not control.accessibleName() and not getattr(control, "text", lambda: "")():
            control.setAccessibleName(title)
        if description and not control.accessibleDescription():
            control.setAccessibleDescription(description)
        keyboard_focus_ring(control)
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

        general = [_setting(tr("Language"), tr("Automatic uses the language of your system."), self._language_combo()),
                   _setting(tr("Theme"), tr("Automatic follows the light or dark mode of your system."),
                            self._theme_combo())]
        if sys.platform != "darwin":  # macOS needs a .app (see desktop.cmd_install_handler)
            what = tr("Let buttons and links on web pages open this application, instead of scanning their QR code.")
            owner = w.links_state()
            links = {"us": tr("Registered: buttons and links on web pages open this application."),
                     "other": tr("Another application opens them now.") + " " + what,
                     "none": tr("Not registered yet.") + " " + what}.get(owner or "", what)
            general.append(_setting(tr("Wallet links"), links,
                                    self._action(tr("Register again") if owner == "us" else tr("Register"),
                                                 lambda: w.register_links(), "link")))
        self._section(tr("General"), general)
        self._section(tr("Profile"), [
            _setting(tr("Active profile"), tr("Each profile is a separate identity, with its own key and credentials."),
                     self._profile_combo()),
            _setting(tr("New profile"), tr("For example, a personal one and a work one."),
                     self._action(tr("Create…"), w.new_profile, "plus")),
            _setting(tr("Remove this profile"), tr("Deletes its key and its credentials. This cannot be undone."),
                     self._action(tr("Remove…"), w.delete_profile, "trash-2", "danger")),
        ])
        if vault.mode(storage.DATA_DIR) == "password":
            remove = [self._action(tr("Remove"), w.remove_wallet_password)] if vault.keyring_available() else []
            security = [
                _setting(tr("Wallet password"), tr("The data of this profile is encrypted with a key protected by "
                                                   "your password. It is asked for when the wallet opens and after "
                                                   "{n} minutes without use.", n=w.AUTO_LOCK_MINUTES),
                         self._action(tr("Change…"), w.set_wallet_password, "key-round"), *remove),
                _setting(tr("Lock now"), tr("Closes the wallet until the password is typed again."),
                         self._action(tr("Lock"), w.lock_now, "lock")),
            ]
        else:
            security = [
                _setting(tr("Wallet password"), tr("The data of this profile is encrypted; its key is kept in the "
                                                   "system keyring and opens with your session. A password adds an "
                                                   "app lock: it is asked for whenever the wallet opens."),
                         self._action(tr("Set…"), w.set_wallet_password, "key-round")),
            ]
        status_check = QCheckBox()
        status_check.setChecked(status.automatic_enabled())
        status_check.toggled.connect(w.set_status_check)
        security.append(_setting(
            tr("Revoked credentials"),
            tr("Ask the organisations that gave you your credentials whether they have cancelled them, before you "
               "use them and from time to time. The question carries nothing about you or about the credential."),
            status_check, self._action(tr("Check now"), w.check_revocations)))
        self._section(tr("Security"), security)
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
            _setting(f"Atesta ID Wallet {__version__}", "OpenID4VCI 1.0 + OpenID4VP · SD-JWT VC\n"
                     + tr("Data: {path}", path=storage.DATA_DIR), leading=app_logo(40)),
            _setting(tr("New versions"), tr("Check once a day for a new version on GitHub and, where the wallet can "
                                            "update itself, download it. Nothing about your wallet is sent."),
                     auto_update, self._action(tr("Check now"), w.check_for_updates)),
            _setting(tr("Licenses"), tr("Open source software this application is built with."),
                     self._action(tr("Show"), w.show_licenses, "info")),
        ]
        if w.update_ready:
            about.append(_setting(tr("Version {version} is ready", version=w.update_ready),
                                  tr("Restart the wallet to use it; your credentials and settings are kept."),
                                  self._action(tr("Restart"), w.restart_to_update, "download", "primary")))
        elif w.available_release:
            about.append(_setting(tr("Version {version} is available", version=w.available_release.version),
                                  tr("It arrives with the system updates (Software Updater, or 'sudo apt upgrade').")
                                  if updates.install_kind() == "deb" else
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
        widget.setMinimumWidth(132)  # the actions of Settings line up in one column
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

    def _theme_combo(self) -> QComboBox:
        combo = QComboBox()
        for code, name in (("auto", tr("Automatic")), ("light", tr("Light")), ("dark", tr("Dark"))):
            combo.addItem(name, code)
        combo.setCurrentIndex(max(0, combo.findData(theme.preference)))
        combo.setMinimumWidth(180)
        combo.currentIndexChanged.connect(lambda _index: self.window_.set_theme(combo.currentData()))
        return combo

    def _profile_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItems(list_profiles())
        combo.setCurrentText(storage.PROFILE)
        combo.setMinimumWidth(160)
        combo.currentTextChanged.connect(self.window_.switch_profile)
        return combo

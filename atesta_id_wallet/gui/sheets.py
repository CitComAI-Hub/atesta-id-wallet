# -*- coding: utf-8 -*-
"""
Overlay panels ("sheets") that walk through the flows inside the window:
offer, login, consent, progress, result, waiting for a QR code...
"""

from __future__ import annotations

import sys
from typing import Any, Callable

from PySide6.QtCore import QEvent, QObject, QSize, Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..common import host_of, humanize
from ..i18n import N_, tr, tr_n
from ..storage import credential_holder, credential_issuer_name, credential_name
from ..ui import OfferSummary, consent_items
from . import theme
from .widgets import IconBubble, Spinner, button, esc, fade_in, label

# (icon, style, title, explanation) per verifier trust level.
TRUST_COPY = {
    "trusted": ("shield-check", "ok", N_("Trusted verifier"),
                N_("Its certificate is issued by an authority you trust.")),
    "pinned": ("shield-check", "ok", N_("Known verifier"),
               N_("You have shared data with it before and its certificate has not changed.")),
    "new": ("shield-alert", "warn", N_("First time with this verifier"),
            N_("No trusted authority vouches for its identity. Check that the domain is the one you expect.")),
    "changed": ("shield-x", "danger", N_("Its certificate has changed"),
                N_("This may be a legitimate renewal or an impersonation. Do not continue if you are not sure.")),
    "unverified": ("shield-x", "danger", N_("Unverified identity"),
                   N_("The request is not signed: anyone could pretend to be this verifier.")),
}


class Overlay(QWidget):
    """Dimmed backdrop that covers the window and shows a centred panel."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("overlay")
        self.setAttribute(Qt.WA_StyledBackground)
        self.hide()
        self.sheet: Sheet | None = None
        self._layout = QVBoxLayout(self)
        self._layout.setAlignment(Qt.AlignCenter)
        parent.installEventFilter(self)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if watched is self.parentWidget() and event.type() == QEvent.Resize:
            self.setGeometry(self.parentWidget().rect())
        return False

    def _discard(self) -> None:
        # deleteLater only acts back in the event loop: hide it now so it is not seen underneath.
        old = self.sheet
        self._layout.removeWidget(old)
        old.hide()
        old.setParent(None)
        old.deleteLater()
        self.sheet = None

    def show_sheet(self, sheet: Sheet) -> None:
        if self.sheet is not None:
            self._discard()
        self.sheet = sheet
        self._layout.addWidget(sheet, alignment=Qt.AlignCenter)
        self.setGeometry(self.parentWidget().rect())
        if not self.isVisible():
            self.show()
            fade_in(self)
        else:
            fade_in(sheet, 120)
        self.raise_()
        sheet.focus()

    def close_sheet(self) -> None:
        if self.sheet is not None:
            self._discard()
        self.hide()

    def keyPressEvent(self, event: Any) -> None:  # noqa: N802
        if event.key() == Qt.Key_Escape and self.sheet is not None and self.sheet.on_escape:
            self.sheet.on_escape()
        else:
            super().keyPressEvent(event)


class Sheet(QFrame):
    """Panel with icon, title, text, content and buttons."""

    def __init__(self, *, width: int = 460, icon: str | None = None, tone: str = "accent",
                 title: str = "", body: str = ""):
        super().__init__()
        self.setObjectName("sheet")
        self.setFixedWidth(width)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Maximum)
        self.on_escape: Callable[[], None] | None = None
        self._focus: QWidget | None = None
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(28, 28, 28, 24)
        self.layout_.setSpacing(12)
        if icon:
            t = theme.current()
            color, soft = {
                "accent": (t.accent, t.accent_soft), "ok": (t.success, t.success_soft),
                "warn": (t.warning, t.warning_soft), "danger": (t.danger, t.danger_soft),
            }[tone]
            self.layout_.addWidget(IconBubble(icon, color, soft, 52))
            self.layout_.addSpacing(4)
        if title:
            self.title = label(title, "sheetTitle", wrap=True)
            self.layout_.addWidget(self.title)
        if body:  # rich text: whoever builds it escapes external values with esc()
            self.body = label(body, "sheetBody", wrap=True, rich=True)
            self.layout_.addWidget(self.body)

    def _height(self) -> int:
        # With several lines of text the height depends on the width; Qt's default sizeHint
        # computes it with another width and cut the text.
        layout = self.layout_
        if layout.hasHeightForWidth():
            return layout.totalHeightForWidth(self.width())
        return layout.totalSizeHint().height()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(self.width(), self._height())

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return self.sizeHint()

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.layout_.addWidget(widget, stretch)
        return widget

    def add_buttons(self, *buttons: QPushButton) -> None:
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addStretch()
        for widget in buttons:
            row.addWidget(widget)
        self.layout_.addSpacing(8)
        self.layout_.addLayout(row)

    def focus(self) -> None:
        if self._focus is not None:
            self._focus.setFocus()


# ---------------------------------------------------------------------------
# Status panels
# ---------------------------------------------------------------------------


class ProgressSheet(Sheet):
    def __init__(self, title: str, detail: str = ""):
        super().__init__(width=420)
        self.layout_.setAlignment(Qt.AlignHCenter)
        spinner = Spinner(44)
        self.layout_.addWidget(spinner, alignment=Qt.AlignHCenter)
        heading = label(title, "sheetTitle", wrap=True)
        heading.setAlignment(Qt.AlignCenter)
        self.layout_.addWidget(heading)
        self.detail = label(detail, "sheetBody", wrap=True)
        self.detail.setAlignment(Qt.AlignCenter)
        self.detail.setMinimumHeight(40)
        self.layout_.addWidget(self.detail)

    def set_detail(self, text: str) -> None:
        self.detail.setText(text)


class ResultSheet(Sheet):
    def __init__(self, ok: bool, title: str, body: str, on_close: Callable[[], None], *,
                 details: str = "", icon: str | None = None, tone: str | None = None,
                 extra: QWidget | None = None):
        super().__init__(icon=icon or ("circle-check" if ok else "circle-x"),
                         tone=tone or ("ok" if ok else "danger"), title=title, body=body)
        if extra is not None:
            self.layout_.addSpacing(6)
            self.layout_.addWidget(extra, alignment=Qt.AlignHCenter)
        if details:
            text = label(details, "caption", wrap=True, selectable=True)
            text.hide()
            toggle = button(tr("Show technical details"), "ghost")
            toggle.clicked.connect(lambda: (text.setVisible(not text.isVisible()), toggle.hide()))
            self.add(toggle)
            self.add(text)
        close = button(tr("Done") if ok else tr("Close"), "primary")
        close.clicked.connect(on_close)
        close.setDefault(True)
        self.add_buttons(close)
        self.on_escape = on_close
        self._focus = close


# ---------------------------------------------------------------------------
# Questions from the flow
# ---------------------------------------------------------------------------


class ConfirmSheet(Sheet):
    def __init__(self, title: str, body: str, on_answer: Callable[[bool], None], *,
                 confirm_text: str | None = None, danger: bool = False, icon: str = "info"):
        super().__init__(icon=icon, tone="danger" if danger else "accent", title=title, body=body)
        confirm_text = confirm_text or tr("Continue")
        cancel = button(tr("Cancel"))
        cancel.clicked.connect(lambda: on_answer(False))
        accept = button(confirm_text, "dangerFilled" if danger else "primary")
        accept.clicked.connect(lambda: on_answer(True))
        self.add_buttons(cancel, accept)
        self.on_escape = lambda: on_answer(False)
        self._focus = cancel if danger else accept


class TextSheet(Sheet):
    def __init__(self, title: str, body: str, on_answer: Callable[[str | None], None], *,
                 default: str = "", placeholder: str = "", secret: bool = False, icon: str = "key-round",
                 confirm_text: str | None = None):
        super().__init__(icon=icon, title=title, body=body)
        confirm_text = confirm_text or tr("Continue")
        self.field = QLineEdit(default)
        self.field.setPlaceholderText(placeholder)
        if secret:
            self.field.setEchoMode(QLineEdit.Password)
        self.add(self.field)
        cancel = button(tr("Cancel"))
        cancel.clicked.connect(lambda: on_answer(None))
        accept = button(confirm_text, "primary")
        accept.clicked.connect(lambda: on_answer(self.field.text()))
        self.field.returnPressed.connect(accept.click)
        self.add_buttons(cancel, accept)
        self.on_escape = lambda: on_answer(None)
        self._focus = self.field


class LoginSheet(Sheet):
    def __init__(self, host: str, username: str | None, ask_username: bool,
                 on_answer: Callable[[tuple[str, str] | None], None]):
        super().__init__(icon="lock", title=tr("Sign in"),
                         body=tr("Enter your username and password for <b>{host}</b>. The password is only sent to "
                                 "that domain and is never stored.", host=esc(host)))
        form = QVBoxLayout()
        form.setSpacing(6)
        self.user = QLineEdit(username or "")
        self.user.setPlaceholderText(tr("Username or email"))
        self.password = QLineEdit()
        self.password.setPlaceholderText(tr("Password"))
        self.password.setEchoMode(QLineEdit.Password)
        if ask_username:
            form.addWidget(label(tr("Username"), "claimName"))
            form.addWidget(self.user)
            form.addSpacing(6)
        else:
            self.add(label(tr("Username: <b>{username}</b>", username=esc(username)), "sheetBody", rich=True))
        form.addWidget(label(tr("Password"), "claimName"))
        form.addWidget(self.password)
        self.layout_.addLayout(form)
        cancel = button(tr("Cancel"))
        cancel.clicked.connect(lambda: on_answer(None))
        accept = button(tr("Sign in"), "primary")
        accept.clicked.connect(lambda: on_answer((self.user.text().strip(), self.password.text())))
        self.user.returnPressed.connect(self.password.setFocus)
        self.password.returnPressed.connect(accept.click)
        self.add_buttons(cancel, accept)
        self.on_escape = lambda: on_answer(None)
        self._focus = self.password if (username or not ask_username) else self.user


class OfferSheet(Sheet):
    def __init__(self, offer: OfferSummary, on_answer: Callable[[bool], None]):
        super().__init__(icon="download", title=tr_n("{issuer} wants to give you a credential",
                                                     "{issuer} wants to give you these credentials",
                                                     len(offer.credentials), issuer=offer.issuer_name))
        t = theme.current()
        for name in offer.credentials:
            row = QFrame()
            row.setObjectName("claimBox")
            layout = QHBoxLayout(row)
            layout.setContentsMargins(14, 12, 14, 12)
            layout.addWidget(IconBubble("id-card", t.accent, t.surface, 36))
            layout.addWidget(label(name, "sectionTitle", wrap=True), 1)
            self.add(row)
        self.add(label(tr("Issuer: {issuer}", issuer=host_of(offer.issuer)), "caption", selectable=True))
        if not offer.known:
            self.add(_notice("warn", "shield-alert", tr("This is the first time you use this issuer"),
                             tr("Accept only if you were asking for this credential on its website.")))
        decline = button(tr("Decline"))
        decline.clicked.connect(lambda: on_answer(False))
        accept = button(tr("Accept"), "primary")
        accept.clicked.connect(lambda: on_answer(True))
        self.add_buttons(decline, accept)
        self.on_escape = lambda: on_answer(False)
        self._focus = accept


class ChooseSheet(Sheet):
    def __init__(self, query_id: str, candidates: list[dict[str, Any]],
                 on_answer: Callable[[dict[str, Any] | None], None]):
        super().__init__(icon="wallet", title=tr("Which credential do you want to use?"),
                         body=tr("Several credentials in your wallet match this request."))
        group = QButtonGroup(self)
        for index, record in enumerate(candidates):
            box = QFrame()
            box.setObjectName("claimBox")
            layout = QHBoxLayout(box)
            layout.setContentsMargins(12, 10, 12, 10)
            radio = QRadioButton()
            radio.setChecked(index == 0)
            group.addButton(radio, index)
            layout.addWidget(radio)
            text = QVBoxLayout()
            text.setSpacing(0)
            text.addWidget(label(credential_name(record), "sectionTitle"))
            details = " · ".join(p for p in (credential_holder(record), credential_issuer_name(record)) if p)
            text.addWidget(label(details, "caption"))
            layout.addLayout(text, 1)
            box.mousePressEvent = lambda _e, r=radio: r.setChecked(True)  # the whole row is clickable
            self.add(box)
        cancel = button(tr("Cancel"))
        cancel.clicked.connect(lambda: on_answer(None))
        accept = button(tr("Use this one"), "primary")
        accept.clicked.connect(lambda: on_answer(candidates[group.checkedId()]))
        self.add_buttons(cancel, accept)
        self.on_escape = lambda: on_answer(None)
        self._focus = accept


class ConsentSheet(Sheet):
    """Who asks for which data and where it goes. Declining is the default."""

    def __init__(self, prepared: Any, on_answer: Callable[[bool], None]):
        identity = prepared.identity
        icon, tone, trust_title, trust_text = TRUST_COPY[identity.trust]
        super().__init__(width=540, icon=icon, tone=tone, title=tr("{verifier} is asking for your data",
                                                                   verifier=identity.name))
        self.add(_notice(tone, icon, tr(trust_title), tr(trust_text)))

        content = QWidget()
        content.setObjectName("scrollContent")
        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(10)
        total = 0
        for match, item in zip(prepared.matches, consent_items(prepared.matches)):
            box = QFrame()
            box.setObjectName("claimBox")
            grid = QGridLayout(box)
            grid.setContentsMargins(16, 14, 16, 14)
            grid.setHorizontalSpacing(16)
            grid.setVerticalSpacing(8)
            source = f"{credential_name(match.record)} · {credential_issuer_name(match.record)}"
            grid.addWidget(label(source, "caption", wrap=True), 0, 0, 1, 2)
            for row, (path, value) in enumerate(item.claims, start=1):
                name = " › ".join(humanize(part) for part in path.split("."))
                grid.addWidget(label(name, "claimName"), row, 0, Qt.AlignTop)
                grid.addWidget(label(value, "rowValue", wrap=True, selectable=True), row, 1)
            grid.setColumnStretch(1, 1)
            column.addWidget(box)
            total += len(item.claims)
        scroll = QScrollArea()
        scroll.setWidget(content)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        surface = theme.current().surface
        scroll.setStyleSheet(f"QScrollArea {{ background: {surface}; }}")
        content.setStyleSheet(f"QWidget#scrollContent {{ background: {surface}; }}")
        scroll.setMinimumHeight(min(content.sizeHint().height() + 4, 300))
        self.add(label(tr_n("You will share {n} piece of data:", "You will share {n} pieces of data:", total),
                       "sectionTitle"))
        self.add(scroll)
        destination = label(tr("It will be sent to {host}", host=host_of(prepared.response_uri)), "caption",
                            selectable=True)
        destination.setToolTip(prepared.response_uri)
        self.add(destination)

        decline = button(tr("Decline"))
        decline.clicked.connect(lambda: on_answer(False))
        self.share = button(tr("Share"), "primary", "send")
        self.share.clicked.connect(lambda: on_answer(True))
        if tone == "danger":
            self.risk = QCheckBox(tr("I understand the risk and want to share the data anyway"))
            self.risk.toggled.connect(self.share.setEnabled)
            self.share.setEnabled(False)
            self.add(self.risk)
        self.add_buttons(decline, self.share)
        self.on_escape = lambda: on_answer(False)
        self._focus = decline


class ScanSheet(Sheet):
    """Waits for a QR code to appear (screenshot or clipboard); the window detects it by itself."""

    def __init__(self, on_image: Callable[[], None], on_paste: Callable[[], None], on_cancel: Callable[[], None]):
        super().__init__(icon="scan-line", title=tr("Waiting for a QR code"))
        shortcut = {"win32": tr("<b>Win + Shift + S</b>"), "darwin": tr("<b>Cmd + Ctrl + Shift + 4</b>")}.get(
            sys.platform, tr("<b>Print Screen</b>"))
        body = label(tr("Take a screenshot of the QR code with {shortcut} or copy the link. We will detect it "
                        "automatically.", shortcut=shortcut), "sheetBody", wrap=True, rich=True)
        self.add(body)
        waiting = QHBoxLayout()
        waiting.addWidget(Spinner(22))
        waiting.addWidget(label(tr("Looking in the clipboard and in your screenshots…"), "caption"), 1)
        self.layout_.addLayout(waiting)
        image = button(tr("Open image…"), icon="image")
        image.clicked.connect(on_image)
        paste = button(tr("Paste link…"), icon="link")
        paste.clicked.connect(on_paste)
        cancel = button(tr("Cancel"), "ghost")
        cancel.clicked.connect(on_cancel)
        row = QHBoxLayout()
        row.addWidget(image)
        row.addWidget(paste)
        row.addStretch()
        row.addWidget(cancel)
        self.layout_.addSpacing(8)
        self.layout_.addLayout(row)
        self.on_escape = on_cancel


def _notice(tone: str, icon: str, title: str, text: str) -> QWidget:
    """Coloured notice (green, amber or red) with icon, title and explanation."""
    t = theme.current()
    color = {"ok": t.success, "warn": t.warning, "danger": t.danger, "accent": t.accent}[tone]
    box = QFrame()
    box.setObjectName({"ok": "trust_ok", "warn": "trust_warn", "danger": "trust_danger"}.get(tone, "trust_ok"))
    box.setAttribute(Qt.WA_StyledBackground)
    layout = QHBoxLayout(box)
    layout.setContentsMargins(12, 10, 12, 10)
    layout.setSpacing(10)
    glyph = label()
    glyph.setPixmap(theme.icon_pixmap(icon, color, 20))
    layout.addWidget(glyph, alignment=Qt.AlignTop)
    text_box = QVBoxLayout()
    text_box.setSpacing(2)
    heading = label(title, wrap=True)
    heading.setStyleSheet(f"color: {color}; font-weight: 700; background: transparent;")
    detail = label(text, wrap=True)
    detail.setStyleSheet(f"color: {color}; background: transparent;")
    text_box.addWidget(heading)
    text_box.addWidget(detail)
    layout.addLayout(text_box, 1)
    return box

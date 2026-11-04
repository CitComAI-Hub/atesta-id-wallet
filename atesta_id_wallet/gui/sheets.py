# -*- coding: utf-8 -*-
"""
Overlay panels ("sheets") that walk through the flows inside the window:
offer, login, consent, progress, result, waiting for a QR code...
"""

from __future__ import annotations

import sys
from typing import Any, Callable

from PySide6.QtCore import QEvent, QObject, QSize, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
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

from ..common import claim_label, host_of
from ..i18n import N_, tr, tr_n
from ..storage import credential_holder, credential_issuer_name, credential_name, is_expired
from ..ui import OfferSummary, consent_items
from . import theme
from .widgets import (
    APP_ICON_NAME,
    IconBubble,
    Spinner,
    app_logo,
    button,
    esc,
    fade_in,
    keyboard_focus_ring,
    label,
    password_field,
)

# (icon, style, title, explanation) per verifier trust level.
TRUST_COPY = {
    "trusted": ("shield-check", "ok", N_("Trusted service"),
                N_("An authority your wallet trusts confirms who this service is.")),
    "pinned": ("shield-check", "ok", N_("Known service"),
               N_("You have shared data with it before, and it is still the same service.")),
    "new": ("shield-alert", "warn", N_("First time with this service"),
            N_("Nobody has confirmed who this service is. Share only if you recognise the address below and you "
               "were signing in there.")),
    "changed": ("shield-x", "danger", N_("This service's identity has changed"),
                N_("It may simply have renewed its certificate, or someone may be pretending to be it. Do not "
                   "share unless you are sure.")),
    "unverified": ("shield-x", "danger", N_("Identity not confirmed"),
                   N_("The request is not signed: anyone could pretend to be this service.")),
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
        focused = QApplication.focusWidget()
        if focused is not None and old.isAncestorOf(focused):
            # Otherwise Qt hands the focus to the next widget in the chain (the first sidebar button).
            self.parentWidget().setFocus()
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
        # Hidden on the next turn of the event loop, and only if no other panel came in the meantime: a
        # flow that goes from one panel to the next keeps the dimmed backdrop instead of flashing it.
        QTimer.singleShot(0, self, self._hide_if_empty)  # cancelled if the overlay is destroyed first

    def _hide_if_empty(self) -> None:
        if self.sheet is None:
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
        if icon == APP_ICON_NAME:
            self.layout_.addWidget(app_logo(52))
            self.layout_.addSpacing(4)
        elif icon:
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
        """In a row, right-aligned; one under the other, full width, when the row does not fit (long translations)."""
        margins = self.layout_.contentsMargins()
        available = self.width() - margins.left() - margins.right()
        needed = sum(b.sizeHint().width() for b in buttons) + 10 * (len(buttons) - 1)
        self.layout_.addSpacing(8)
        if needed <= available:
            row = QHBoxLayout()
            row.setSpacing(10)
            row.addStretch()
            for widget in buttons:
                row.addWidget(widget)
            self.layout_.addLayout(row)
            return
        column = QVBoxLayout()
        column.setSpacing(8)
        for widget in reversed(buttons):  # the main action (last in the row) on top
            column.addWidget(widget)
        self.layout_.addLayout(column)

    def focus(self) -> None:
        """The focus goes inside the panel, or Tab would go on through the page behind it (no ring: not the keyboard)."""
        target = self._focus or next(iter(self._focus_chain()), None)
        (target or self).setFocus(Qt.OtherFocusReason)  # nothing to press (progress): the panel holds it

    def _focus_chain(self) -> list[QWidget]:
        chain = [w for w in self.findChildren(QWidget)
                 if w.isVisibleTo(self) and w.isEnabled() and w.focusPolicy() & Qt.TabFocus
                 and not (isinstance(w, QRadioButton) and not w.isChecked())]  # one stop per group of options
        return sorted(chain, key=lambda w: (w.mapTo(self, w.rect().topLeft()).y() // 8,
                                            w.mapTo(self, w.rect().topLeft()).x()))

    def focusNextPrevChild(self, forward: bool) -> bool:  # noqa: N802
        """Tab and Shift+Tab go round the panel's own controls, never to the page behind it (WCAG 2.4.3)."""
        chain = self._focus_chain()
        if not chain:
            return True
        current = QApplication.focusWidget()
        index = chain.index(current) if current in chain else -1
        target = chain[(index + (1 if forward else -1)) % len(chain)]
        target.setFocus(Qt.TabFocusReason if forward else Qt.BacktabFocusReason)
        return True


# ---------------------------------------------------------------------------
# Status panels
# ---------------------------------------------------------------------------


class ProgressSheet(Sheet):
    def __init__(self, title: str, detail: str = ""):
        super().__init__(width=420)
        spinner = Spinner(44)
        self.layout_.addWidget(spinner, alignment=Qt.AlignHCenter)
        heading = label(title, "sheetTitle", wrap=True)
        heading.setAlignment(Qt.AlignCenter)
        self.layout_.addWidget(heading)
        self.detail = label(detail, "sheetBody", wrap=True)
        self.detail.setAlignment(Qt.AlignCenter)
        self.detail.setVisible(bool(detail))
        self.layout_.addWidget(self.detail)

    def set_detail(self, text: str) -> None:
        self.detail.setText(text)
        self.detail.setVisible(bool(text))


class ResultSheet(Sheet):
    def __init__(self, ok: bool, title: str, body: str, on_close: Callable[[], None], *,
                 details: str = "", icon: str | None = None, tone: str | None = None,
                 extra: QWidget | None = None, action: tuple[str, Callable[[], None]] | None = None,
                 secondary: tuple[str, Callable[[], None]] | None = None):
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
        close = button(tr("Done") if ok else tr("Close"), None if action else "primary")
        close.clicked.connect(on_close)
        if secondary:  # a discreet way out, e.g. undo what just happened
            other = button(secondary[0], "ghost")
            other.clicked.connect(secondary[1])
            self.add(other)
        if action:
            act = button(action[0], "primary")
            act.clicked.connect(action[1])
            act.setDefault(True)
            self.add_buttons(close, act)
            self._focus = act
        else:
            close.setDefault(True)
            self.add_buttons(close)
            self._focus = close
        self.on_escape = on_close


# ---------------------------------------------------------------------------
# Questions from the flow
# ---------------------------------------------------------------------------


class ConfirmSheet(Sheet):
    def __init__(self, title: str, body: str, on_answer: Callable[[bool], None], *,
                 confirm_text: str | None = None, danger: bool = False, icon: str = "info",
                 cancel_text: str | None = None, step: str = ""):
        super().__init__(icon=icon, tone="danger" if danger else "accent", title=title, body=body)
        if step:
            self.add(label(step, "caption"))
        confirm_text = confirm_text or tr("Continue")
        cancel = button(cancel_text or tr("Cancel"))
        cancel.clicked.connect(lambda: on_answer(False))
        accept = button(confirm_text, "dangerFilled" if danger else "primary")
        accept.clicked.connect(lambda: on_answer(True))
        self.add_buttons(cancel, accept)
        self.on_escape = lambda: on_answer(False)
        self._focus = cancel if danger else accept


class BrowserSheet(Sheet):
    """While the user signs in in the browser (already opened by the wallet): only cancel, plus a way
    to open the page again if the browser did not come up."""

    def __init__(self, host: str, on_open_again: Callable[[], None], on_cancel: Callable[[], None]):
        super().__init__(icon="lock", title=tr("Continue in your browser"),
                         body=tr("Sign in to <b>{host}</b> in the browser window that has just opened. The wallet "
                                 "carries on by itself when you finish; your password stays in the browser.",
                                 host=esc(host)))
        self.add(label(tr("Waiting for the browser…"), "caption"))
        again = button(tr("Did it not open? Open it again"), "ghost")
        again.clicked.connect(on_open_again)
        cancel = button(tr("Cancel"))
        cancel.clicked.connect(on_cancel)
        self.add_buttons(again, cancel)
        self.on_escape = on_cancel
        self._focus = cancel


class TextSheet(Sheet):
    def __init__(self, title: str, body: str, on_answer: Callable[[str | None], None], *,
                 default: str = "", placeholder: str = "", secret: bool = False, icon: str = "key-round",
                 confirm_text: str | None = None):
        super().__init__(icon=icon, title=title, body=body)
        confirm_text = confirm_text or tr("Continue")
        if secret:
            self.field = password_field(placeholder)
            self.field.setText(default)
        else:
            self.field = QLineEdit(default)
            self.field.setPlaceholderText(placeholder)
        self.field.setAccessibleName(title)  # the panel's title is the field's label
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
        self.password = password_field(tr("Password"))
        self.user.setAccessibleName(tr("Username"))
        self.password.setAccessibleName(tr("Password"))
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
        self.add(label(tr("Website: {host}", host=host_of(offer.issuer)), "caption", selectable=True))
        if not offer.known:
            self.add(_notice("warn", "shield-alert", tr("First credential from {issuer}", issuer=offer.issuer_name),
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
        candidates = sorted(candidates, key=is_expired)  # a valid one is preselected (stable: newest first)
        for index, record in enumerate(candidates):
            box = QFrame()
            box.setObjectName("claimBox")
            layout = QHBoxLayout(box)
            layout.setContentsMargins(12, 10, 12, 10)
            radio = keyboard_focus_ring(QRadioButton())
            radio.setAccessibleName(credential_name(record))
            radio.setChecked(index == 0)
            group.addButton(radio, index)
            layout.addWidget(radio)
            text = QVBoxLayout()
            text.setSpacing(0)
            text.addWidget(label(credential_name(record), "sectionTitle"))
            radio.setAccessibleDescription(" · ".join(p for p in (credential_holder(record),
                                                                   credential_issuer_name(record)) if p))
            details = " · ".join(p for p in (credential_holder(record), credential_issuer_name(record),
                                             tr("Expired") if is_expired(record) else "") if p)
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
                name = " › ".join(claim_label(part) for part in path.split("."))
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
        destination = label(tr("It will be sent to {host}", host=host_of(prepared.response_uri)), "sheetBody",
                            selectable=True)
        destination.setToolTip(prepared.response_uri)
        self.add(destination)

        decline = button(tr("Decline"))
        decline.clicked.connect(lambda: on_answer(False))
        self.share = button(tr("Share"), "primary", "send")
        self.share.clicked.connect(lambda: on_answer(True))
        if tone == "danger":
            # A QCheckBox never wraps its text: the box, and a label beside it that wraps and also ticks it.
            text = tr("I understand the risk and want to share the data anyway")
            self.risk = keyboard_focus_ring(QCheckBox())
            self.risk.setAccessibleName(text)
            self.risk.toggled.connect(self.share.setEnabled)
            words = label(text, wrap=True)
            words.setCursor(Qt.PointingHandCursor)
            words.mousePressEvent = lambda _e: self.risk.toggle()
            risk_row = QWidget()
            row = QHBoxLayout(risk_row)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(8)
            row.addWidget(self.risk, alignment=Qt.AlignTop)
            row.addWidget(words, 1)
            self.share.setEnabled(False)
            self.add(risk_row)
        self.add_buttons(decline, self.share)
        self.on_escape = lambda: on_answer(False)
        self._focus = decline


# Third-party software in the application (the frozen builds also carry the Python runtime, PSF).
THIRD_PARTY = (
    ("Qt for Python (PySide6)", "LGPL-3.0", "https://doc.qt.io/qtforpython/"),
    ("cryptography", "Apache-2.0 OR BSD-3-Clause", "https://github.com/pyca/cryptography"),
    ("requests", "Apache-2.0", "https://github.com/psf/requests"),
    ("keyring", "MIT", "https://github.com/jaraco/keyring"),
    ("zxing-cpp", "Apache-2.0", "https://github.com/zxing-cpp/zxing-cpp"),
    ("Pillow", "MIT-CMU", "https://github.com/python-pillow/Pillow"),
    ("Lucide icons", "ISC", "https://lucide.dev"),
    ("Python", "PSF-2.0", "https://www.python.org"),
)


class LicensesSheet(Sheet):
    def __init__(self, on_close: Callable[[], None]):
        super().__init__(icon="info", title=tr("Licenses"),
                         body=tr("Atesta ID Wallet is built with this open source software."))
        box = QFrame()
        box.setObjectName("claimBox")
        rows = QVBoxLayout(box)
        rows.setContentsMargins(14, 10, 14, 10)
        rows.setSpacing(6)
        for name, licence, url in THIRD_PARTY:
            line = QHBoxLayout()
            line.addWidget(label(name, "claimName"), 1)
            line.addWidget(label(licence, "caption"))
            rows.addLayout(line)
            rows.addWidget(label(url, "caption", selectable=True))
        self.add(box)
        close = button(tr("Close"), "primary")
        close.clicked.connect(on_close)
        self.add_buttons(close)
        self.on_escape = on_close
        self._focus = close


class ScanSheet(Sheet):
    """Waits for a QR code to appear (screenshot or clipboard); the window detects it by itself."""

    def __init__(self, on_image: Callable[[], None], on_paste: Callable[[], None], on_cancel: Callable[[], None]):
        super().__init__(icon="scan-line", title=tr("Waiting for a QR code"))
        shortcut = {"win32": tr("<b>Win + Shift + S</b>"), "darwin": tr("<b>Cmd + Ctrl + Shift + 4</b>")}.get(
            sys.platform, tr("<b>Print Screen</b>"))
        body = label(tr("Take a screenshot of the QR code with {shortcut}, or copy the link. The wallet finds it by "
                        "itself.", shortcut=shortcut), "sheetBody", wrap=True, rich=True)
        self.add(body)
        waiting = QHBoxLayout()
        waiting.addWidget(Spinner(22))
        waiting.addWidget(label(tr("Looking in the clipboard and in your screenshots…"), "caption", wrap=True), 1)
        self.layout_.addLayout(waiting)
        image = button(tr("Open image…"), icon="image")
        image.clicked.connect(on_image)
        paste = button(tr("Paste link…"), icon="link")
        paste.clicked.connect(on_paste)
        cancel = button(tr("Cancel"), "ghost")
        cancel.clicked.connect(on_cancel)
        self.add_buttons(cancel, paste, image)
        self.on_escape = on_cancel
        self._focus = image


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

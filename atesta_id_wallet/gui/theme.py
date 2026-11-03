# -*- coding: utf-8 -*-
"""Interface colours, style sheet and icons (light and dark theme)."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer

ICON_DIR = Path(__file__).resolve().parent / "icons"


@dataclass(frozen=True)
class Theme:
    dark: bool
    window: str
    surface: str
    surface_alt: str
    border: str
    text: str
    text_muted: str
    accent: str
    accent_hover: str
    accent_soft: str
    on_accent: str
    success: str
    success_soft: str
    warning: str
    warning_soft: str
    danger: str
    danger_soft: str
    on_danger: str
    # Edge of a text field and of a checkbox: 3:1 (WCAG 1.4.11), the only sign of where to type or tick.
    # Fields that are recognised by something else (the search field by its icon and text, a drop-down
    # by its arrow) keep the subtle 'border' at rest, and the accent on hover and with the focus.
    input_border: str
    border_hover: str  # a field under the pointer: a step lighter (darker), not yet the accent
    backdrop: str


LIGHT = Theme(
    dark=False,
    window="#f4f5f9", surface="#ffffff", surface_alt="#eef0f6", border="#e1e4ec",
    text="#141824", text_muted="#5d6577",
    accent="#5b5bd6", accent_hover="#4b4bc4", accent_soft="#ebebfc", on_accent="#ffffff",
    success="#17773f", success_soft="#e1f5e9",  # text on the soft colours: at least 4.5:1 (WCAG AA)
    warning="#8a5a00", warning_soft="#fff3d1",
    danger="#b03030", danger_soft="#fde6e6", on_danger="#ffffff",
    input_border="#7b8293", border_hover="#c0c4cf",
    backdrop="rgba(16, 19, 30, 110)",
)
DARK = Theme(
    dark=True,
    window="#0f1117", surface="#181b24", surface_alt="#212532", border="#2b3040",
    text="#e9ebf1", text_muted="#9aa2b4",
    accent="#8b8bf5", accent_hover="#a0a0ff", accent_soft="#262650", on_accent="#0f1117",
    success="#4cc58a", success_soft="#163526",
    warning="#f0c062", warning_soft="#3a2f13",
    danger="#f08a8a", danger_soft="#3d1c1f", on_danger="#0f1117",
    input_border="#6f7689", border_hover="#4c5263",
    backdrop="rgba(0, 0, 0, 150)",
)

# Card gradients when the issuer publishes no colour (white text on all of them).
CARD_GRADIENTS = (
    ("#2a3b8f", "#5468d4"),  # indigo
    ("#0f4f55", "#1d8a84"),  # verde azulado
    ("#45297a", "#7a4bc4"),  # violeta
    ("#6e2638", "#bd4b62"),  # granate
    ("#1e3c2c", "#3c7a53"),  # verde
    ("#272c38", "#525a6e"),  # pizarra
)


THEMES = ("auto", "light", "dark")
# Settings → General → Theme ("theme" in settings.json); "auto" follows the system.
preference = "auto"


def system_is_dark() -> bool:
    forced = os.environ.get("ATESTA_ID_WALLET_THEME", "").lower()
    if forced in ("light", "dark"):
        return forced == "dark"
    if preference in ("light", "dark"):
        return preference == "dark"
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorScheme"):
        return hints.colorScheme() == Qt.ColorScheme.Dark
    return QGuiApplication.palette().window().color().lightness() < 128


def current() -> Theme:
    return DARK if system_is_dark() else LIGHT


def card_colors(record: dict) -> tuple[QColor, QColor, QColor]:
    """(start, end, text) of a card gradient: the issuer's if it publishes one, otherwise a stable one."""
    display = record.get("display") or {}
    base = QColor(display.get("background_color") or "")
    if base.isValid():
        text = QColor(display.get("text_color") or "")
        if not text.isValid():
            text = QColor("#141824") if base.lightness() > 150 else QColor("#ffffff")
        return base.darker(115), base.lighter(125), text
    seed = str(record.get("issuer", "")) + str(record.get("credential_configuration_id", ""))
    index = int(hashlib.sha256(seed.encode()).hexdigest(), 16) % len(CARD_GRADIENTS)
    start, end = CARD_GRADIENTS[index]
    return QColor(start), QColor(end), QColor("#ffffff")


@lru_cache(maxsize=512)
def _svg(name: str) -> bytes:
    return (ICON_DIR / f"{name}.svg").read_bytes()


def icon_pixmap(name: str, color: str, size: int = 20, stroke: float | None = None, gap: int = 0) -> QPixmap:
    """Coloured Lucide icon (the SVGs use currentColor); 'gap' leaves that much transparent room on its right."""
    data = _svg(name).replace(b"currentColor", color.encode())
    if stroke is not None:
        data = data.replace(b'stroke-width="2"', f'stroke-width="{stroke}"'.encode())
    ratio = QGuiApplication.primaryScreen().devicePixelRatio() if QGuiApplication.primaryScreen() else 1.0
    pixmap = QPixmap(int((size + gap) * ratio), int(size * ratio))
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    QSvgRenderer(QByteArray(data)).render(painter, QRectF(0, 0, size * ratio, size * ratio))
    painter.end()
    pixmap.setDevicePixelRatio(ratio)
    return pixmap


def icon(name: str, color: str, size: int = 20, gap: int = 0) -> QIcon:
    return QIcon(icon_pixmap(name, color, size, gap=gap))


# Room between the icon of a button and its text: Qt leaves a fixed 4 px, the sidebar and the search
# field about 10. The icon carries the rest as transparent pixels (the text stays the button's text).
BUTTON_ICON_GAP = 6


def palette(t: Theme) -> QPalette:
    """Palette for the native widgets the style sheet does not cover (menus, pickers...)."""
    p = QPalette()
    roles = {
        QPalette.Window: t.window, QPalette.WindowText: t.text, QPalette.Base: t.surface,
        QPalette.AlternateBase: t.surface_alt, QPalette.Text: t.text, QPalette.Button: t.surface,
        QPalette.ButtonText: t.text, QPalette.Highlight: t.accent, QPalette.HighlightedText: t.on_accent,
        QPalette.ToolTipBase: t.surface, QPalette.ToolTipText: t.text, QPalette.PlaceholderText: t.text_muted,
        QPalette.Link: t.accent,
    }
    for role, color in roles.items():
        p.setColor(role, QColor(color))
    p.setColor(QPalette.Disabled, QPalette.Text, QColor(t.text_muted))
    p.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(t.text_muted))
    return p


@lru_cache(maxsize=1)
def _private_tmp() -> Path:
    """Temporary folder of this process: in the shared /tmp another user could place the file first."""
    import atexit
    import shutil
    import tempfile

    path = Path(tempfile.mkdtemp(prefix="atesta-id-wallet-"))
    atexit.register(shutil.rmtree, path, True)
    return path


def _arrow_file(color: str) -> str:
    """Coloured chevron on disk: the style sheet only takes images by path."""
    path = _private_tmp() / f"chevron-{color.strip('#')}.svg"
    if not path.exists():
        path.write_bytes(_svg("chevron-down").replace(b"currentColor", color.encode()))
    return path.as_posix()


def _icon_file(name: str, color: str) -> str:
    """A coloured icon on disk, for the style sheet (it only takes images by path)."""
    path = _private_tmp() / f"{name}-{color.strip('#')}.svg"
    if not path.exists():
        path.write_bytes(_svg(name).replace(b"currentColor", color.encode()))
    return path.as_posix()


def stylesheet(t: Theme) -> str:
    arrow = _arrow_file(t.text_muted)
    check = _icon_file("check", t.on_accent)
    return f"""
* {{ outline: none; }}
QWidget {{ color: {t.text}; font-size: 14px; }}
QMainWindow, #page, QScrollArea, QScrollArea > QWidget > QWidget#scrollContent {{ background: {t.window}; }}
QScrollArea {{ border: none; }}
QToolTip {{ background: {t.surface}; color: {t.text}; border: 1px solid {t.border}; padding: 6px; }}

#sidebar {{ background: {t.surface}; border-right: 1px solid {t.border}; }}
#appName {{ font-size: 16px; font-weight: 700; }}
#navButton {{
    text-align: left; padding: 10px 12px; border: none; border-radius: 10px;
    color: {t.text_muted}; font-weight: 600; background: transparent;
}}
#navButton:hover {{ background: {t.surface_alt}; color: {t.text}; }}
#navButton:checked {{ background: {t.accent_soft}; color: {t.accent}; }}
#sidebarCaption {{ color: {t.text_muted}; font-size: 12px; font-weight: 700; letter-spacing: 0.6px; }}

#pageTitle {{ font-size: 26px; font-weight: 700; }}
#pageSubtitle, .muted {{ color: {t.text_muted}; }}
#sectionTitle {{ font-size: 15px; font-weight: 700; }}
#caption {{ color: {t.text_muted}; font-size: 13px; }}

#panel {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 14px; }}
#row {{ border-bottom: 1px solid {t.border}; }}
#rowLabel {{ color: {t.text_muted}; font-size: 12px; font-weight: 600; }}
#rowValue {{ font-size: 14px; }}

QPushButton {{
    background: {t.surface}; color: {t.text}; border: 1px solid {t.border};
    border-radius: 10px; padding: 9px 16px; font-weight: 600;
}}
QPushButton:hover {{ background: {t.surface_alt}; }}
QPushButton:disabled {{ color: {t.text_muted}; background: {t.surface_alt}; }}
QPushButton#primary {{ background: {t.accent}; color: {t.on_accent}; border: 1px solid {t.accent}; }}
QPushButton#primary:hover {{ background: {t.accent_hover}; border-color: {t.accent_hover}; }}
QPushButton#primary:disabled {{ background: {t.surface_alt}; color: {t.text_muted}; border-color: {t.border}; }}
QPushButton#danger {{ color: {t.danger}; }}
QPushButton#danger:hover {{ background: {t.danger_soft}; border-color: {t.danger_soft}; }}
QPushButton#dangerFilled {{ background: {t.danger}; color: {t.on_danger}; border: 1px solid {t.danger}; }}
QPushButton#ghost {{ background: transparent; border: none; color: {t.text_muted}; padding: 6px 10px; }}
QPushButton#ghost:hover {{ background: {t.surface_alt}; color: {t.text}; }}
/* Focus ring (WCAG 2.4.7), only when the focus came from the keyboard: widgets.keyboard_focus_ring. */
QPushButton[keyboardFocus="true"] {{ border: 2px solid {t.accent}; padding: 8px 15px; }}
QPushButton#primary[keyboardFocus="true"], QPushButton#dangerFilled[keyboardFocus="true"] {{
    border: 2px solid {t.text};
}}
QPushButton#ghost[keyboardFocus="true"] {{ border: 2px solid {t.accent}; padding: 4px 8px; }}
#navButton[keyboardFocus="true"] {{ border: 2px solid {t.accent}; padding: 8px 10px; }}
QComboBox[keyboardFocus="true"] {{ border-color: {t.accent}; }}
QCheckBox[keyboardFocus="true"], QRadioButton[keyboardFocus="true"] {{
    border: 2px solid {t.accent}; border-radius: 6px;
}}
#activityRow[keyboardFocus="true"] {{ background: {t.accent_soft}; border-radius: 10px; }}

QLineEdit {{
    background: {t.surface}; border: 1px solid {t.input_border}; border-radius: 10px;
    padding: 9px 12px; selection-background-color: {t.accent};
}}
/* Fields: subtle at rest, a step stronger under the pointer, the accent (1 px) where you type. */
QLineEdit:hover {{ border-color: {t.text_muted}; }}
QLineEdit:focus {{ border-color: {t.accent}; }}
QLineEdit#search {{ border-color: {t.border}; }}
QLineEdit#search:hover {{ border-color: {t.border_hover}; }}
QLineEdit#search:focus {{ border-color: {t.accent}; }}
QComboBox {{
    background: {t.surface}; border: 1px solid {t.border}; border-radius: 10px; padding: 7px 12px;
}}
QComboBox:hover {{ border-color: {t.border_hover}; }}
QComboBox:on {{ border-color: {t.accent}; }}
QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox::down-arrow {{ image: url("{arrow}"); width: 14px; height: 14px; }}
QComboBox QAbstractItemView {{
    background: {t.surface}; border: 1px solid {t.border}; selection-background-color: {t.accent_soft};
    selection-color: {t.text}; padding: 4px;
}}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 18px; height: 18px; border: 2px solid {t.input_border}; border-radius: 5px; background: {t.surface};
}}
QCheckBox::indicator:checked {{ background: {t.accent}; border-color: {t.accent}; image: url("{check}"); }}
QRadioButton::indicator {{
    width: 16px; height: 16px; border: 2px solid {t.input_border}; border-radius: 10px; background: {t.surface};
}}
QRadioButton::indicator:checked {{ border: 5px solid {t.accent}; width: 10px; height: 10px; }}
QPlainTextEdit {{
    background: {t.surface_alt}; border: 1px solid {t.border}; border-radius: 10px; padding: 8px;
    font-family: monospace; font-size: 12px;
}}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t.border}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {t.text_muted}; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{
    background: none; height: 0; width: 0;
}}
QScrollBar:horizontal {{ height: 0; }}

#overlay {{ background: {t.backdrop}; }}
#sheet {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 18px; }}
#sheetTitle {{ font-size: 20px; font-weight: 700; }}
#sheetBody {{ color: {t.text_muted}; }}
#trust_ok {{ background: {t.success_soft}; color: {t.success}; border-radius: 10px; padding: 10px 12px; }}
#trust_warn {{ background: {t.warning_soft}; color: {t.warning}; border-radius: 10px; padding: 10px 12px; }}
#trust_danger {{ background: {t.danger_soft}; color: {t.danger}; border-radius: 10px; padding: 10px 12px; }}
#claimBox {{ background: {t.surface_alt}; border-radius: 12px; }}
#claimName {{ color: {t.text_muted}; font-size: 12px; font-weight: 600; }}
#toast {{ background: {t.text}; color: {t.window}; border-radius: 10px; padding: 10px 16px; font-weight: 600; }}
#pill {{ border-radius: 9px; padding: 2px 8px; font-size: 12px; font-weight: 700; }}
"""

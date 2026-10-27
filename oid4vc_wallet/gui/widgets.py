# -*- coding: utf-8 -*-
"""Componentes visuales reutilizables."""

from __future__ import annotations

import html
import time
from typing import Any

from PySide6.QtCore import (
    QDateTime,
    QEasingCurve,
    QLocale,
    QPoint,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLayout,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
    QWidgetItem,
)

from .. import i18n
from ..i18n import tr
from ..storage import credential_holder, credential_issuer_name, credential_name, is_expired
from . import theme


def esc(text: Any) -> str:
    """Texto para insertar en un texto enriquecido (cuerpo de los paneles): sin HTML y con sus saltos de línea."""
    return html.escape(str(text)).replace("\n", "<br>")


def label(text: str = "", name: str | None = None, *, wrap: bool = False, selectable: bool = False,
          rich: bool = False) -> QLabel:
    """
    Texto plano salvo rich=True. Qt interpreta como HTML cualquier texto que lo parezca, y aquí se
    muestran nombres y datos que vienen de emisores y verificadores: un verificador podría
    pintar su nombre de verde. Con rich=True, los valores externos se pasan por esc().
    """
    widget = QLabel()
    widget.setTextFormat(Qt.RichText if rich else Qt.PlainText)
    widget.setText(text)
    if name:
        widget.setObjectName(name)
    widget.setWordWrap(wrap)
    if selectable:
        widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return widget


def button(text: str, kind: str | None = None, icon: str | None = None) -> QPushButton:
    widget = QPushButton(text)
    if kind:
        widget.setObjectName(kind)
    widget.setCursor(Qt.PointingHandCursor)
    if icon:
        t = theme.current()
        color = {"primary": t.on_accent, "danger": t.danger, "dangerFilled": "#ffffff"}.get(kind or "", t.text)
        widget.setIcon(theme.icon(icon, color, 18))
        widget.setIconSize(QSize(18, 18))
    return widget


def clear_layout(layout: Any) -> None:
    """Vacía un layout ocultando ya los widgets (deleteLater no actúa hasta volver al bucle de eventos)."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.hide()
            widget.setParent(None)
            widget.deleteLater()


def hline() -> QFrame:
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: {theme.current().border};")
    return line


class FlowLayout(QLayout):
    """Coloca los elementos en filas que se reparten según el ancho disponible."""

    def __init__(self, parent: QWidget | None = None, spacing: int = 18):
        super().__init__(parent)
        self._items: list[Any] = []
        self._spacing = spacing

    def addItem(self, item: Any) -> None:  # noqa: N802
        self._items.append(item)

    def addWidget(self, widget: QWidget) -> None:  # noqa: N802
        self.addChildWidget(widget)
        self.addItem(QWidgetItem(widget))

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> Any:  # noqa: N802
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int) -> Any:  # noqa: N802
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self) -> Qt.Orientations:  # noqa: N802
        return Qt.Orientations(0)

    def hasHeightForWidth(self) -> bool:  # noqa: N802
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        return self._layout(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect: QRect) -> None:  # noqa: N802
        super().setGeometry(rect)
        self._layout(rect, apply=True)

    def sizeHint(self) -> QSize:  # noqa: N802
        return self.minimumSize()

    def minimumSize(self) -> QSize:  # noqa: N802
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def _layout(self, rect: QRect, *, apply: bool) -> int:
        margins = self.contentsMargins()
        area = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        x, y, row_height = area.x(), area.y(), 0
        for item in self._items:
            hint = item.sizeHint()
            if x + hint.width() > area.right() + 1 and row_height:
                x, y, row_height = area.x(), y + row_height + self._spacing, 0
            if apply:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self._spacing
            row_height = max(row_height, hint.height())
        return y + row_height - rect.y() + margins.bottom()


class CredentialCard(QWidget):
    """Credencial como tarjeta (formato ID-1), con el color del emisor."""

    clicked = Signal()
    WIDTH = 300

    def __init__(self, record: dict[str, Any], width: int = WIDTH, interactive: bool = True):
        super().__init__()
        self.record = record
        self.setFixedSize(width, round(width / 1.586))
        self.interactive = interactive
        if interactive:
            self.setCursor(Qt.PointingHandCursor)
            self.setToolTip(tr("Show the credential's data"))
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(24)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 60))
        self.setGraphicsEffect(shadow)
        self._shadow = shadow

    def enterEvent(self, event: Any) -> None:  # noqa: N802
        if self.interactive:
            self._shadow.setBlurRadius(34)
            self._shadow.setOffset(0, 10)
        super().enterEvent(event)

    def leaveEvent(self, event: Any) -> None:  # noqa: N802
        self._shadow.setBlurRadius(24)
        self._shadow.setOffset(0, 6)
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event: Any) -> None:  # noqa: N802
        if self.interactive and event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        start, end, text = theme.card_colors(self.record)
        w, h = self.width(), self.height()
        scale = w / self.WIDTH
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, w, h), 16 * scale, 16 * scale)
        gradient = QLinearGradient(0, 0, w, h)
        gradient.setColorAt(0, start)
        gradient.setColorAt(1, end)
        painter.fillPath(path, gradient)

        # Motivo decorativo: arcos concéntricos en la esquina.
        painter.setClipPath(path)
        decoration = QColor(text)
        for index, radius in enumerate((0.55, 0.78, 1.0)):
            decoration.setAlpha(26 - index * 6)
            painter.setPen(QPen(decoration, 18 * scale))
            r = h * radius
            painter.drawEllipse(QRectF(w - r * 0.75, -r * 0.55, r * 1.4, r * 1.4))
        painter.setClipping(False)

        pad = 20 * scale
        muted = QColor(text)
        muted.setAlpha(200)
        font = QFont(self.font())
        font.setPixelSize(round(12 * scale))
        font.setWeight(QFont.DemiBold)
        font.setLetterSpacing(QFont.PercentageSpacing, 104)
        painter.setFont(font)
        painter.setPen(muted)
        issuer = credential_issuer_name(self.record).upper()
        painter.drawText(QRectF(pad, pad, w - 2 * pad - 30 * scale, 20 * scale), Qt.AlignLeft | Qt.AlignVCenter,
                         painter.fontMetrics().elidedText(issuer, Qt.ElideRight, int(w - 2 * pad - 30 * scale)))
        painter.drawPixmap(int(w - pad - 22 * scale), int(pad - 2 * scale),
                           theme.icon_pixmap("id-card", muted.name(), round(22 * scale), stroke=1.6))

        font.setPixelSize(round(19 * scale))
        font.setWeight(QFont.Bold)
        font.setLetterSpacing(QFont.PercentageSpacing, 100)
        painter.setFont(font)
        painter.setPen(text)
        name_rect = QRectF(pad, h * 0.38, w - 2 * pad, h * 0.32)
        painter.drawText(name_rect, Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap, credential_name(self.record))

        font.setPixelSize(round(13 * scale))
        font.setWeight(QFont.Medium)
        painter.setFont(font)
        painter.setPen(muted)
        holder = credential_holder(self.record)
        bottom = QRectF(pad, h - pad - 18 * scale, w - 2 * pad, 18 * scale)
        painter.drawText(bottom, Qt.AlignLeft | Qt.AlignVCenter,
                         painter.fontMetrics().elidedText(holder, Qt.ElideRight, int(w - 2 * pad - 80 * scale)))
        if is_expired(self.record):
            font.setPixelSize(round(11 * scale))
            font.setWeight(QFont.Bold)
            painter.setFont(font)
            tag = QRectF(w - pad - 70 * scale, h - pad - 20 * scale, 70 * scale, 20 * scale)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(0, 0, 0, 90))
            painter.drawRoundedRect(tag, 10 * scale, 10 * scale)
            painter.setPen(QColor("#ffffff"))
            painter.drawText(tag, Qt.AlignCenter, tr("EXPIRED"))
        painter.end()


class IconBubble(QWidget):
    """Icono dentro de un círculo de color suave (cabecera de paneles y filas)."""

    def __init__(self, icon: str, color: str, background: str, size: int = 48):
        super().__init__()
        self.setFixedSize(size, size)
        self._pixmap = theme.icon_pixmap(icon, color, round(size * 0.46))
        self._background = QColor(background)

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(self._background)
        painter.drawEllipse(self.rect())
        size = self._pixmap.deviceIndependentSize()
        painter.drawPixmap(int((self.width() - size.width()) / 2), int((self.height() - size.height()) / 2),
                           self._pixmap)
        painter.end()


class Spinner(QWidget):
    def __init__(self, size: int = 40):
        super().__init__()
        self.setFixedSize(size, size)
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    def _tick(self) -> None:
        self._angle = (self._angle + 6) % 360
        self.update()

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        t = theme.current()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width = max(3, self.width() // 10)
        rect = QRectF(width, width, self.width() - 2 * width, self.height() - 2 * width)
        painter.setPen(QPen(QColor(t.accent_soft), width))
        painter.drawEllipse(rect)
        pen = QPen(QColor(t.accent), width)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, -self._angle * 16, 100 * 16)
        painter.end()


def pill(text: str, color: str, background: str) -> QLabel:
    widget = label(text, "pill")
    widget.setStyleSheet(f"QLabel#pill {{ color: {color}; background: {background}; }}")
    widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    return widget


class Panel(QFrame):
    """Superficie con borde redondeado que agrupa filas."""

    def __init__(self, margins: tuple[int, int, int, int] = (20, 16, 20, 16)):
        super().__init__()
        self.setObjectName("panel")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(*margins)
        self.body.setSpacing(0)


def key_value_row(key: str, value: str, *, last: bool = False) -> QWidget:
    row = QWidget()
    layout = QVBoxLayout(row)
    layout.setContentsMargins(0, 10, 0, 10)
    layout.setSpacing(2)
    layout.addWidget(label(key, "rowLabel"))
    layout.addWidget(label(value, "rowValue", wrap=True, selectable=True))
    if not last:
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(row)
        outer.addWidget(hline())
        return container
    return row


class EmptyState(QWidget):
    """Ilustración de línea + título + texto, para listas vacías."""

    def __init__(self, icon: str, title: str, text: str, action: QPushButton | None = None):
        super().__init__()
        t = theme.current()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(10)
        art = _EmptyArt(icon)
        layout.addWidget(art, alignment=Qt.AlignCenter)
        layout.addSpacing(6)
        heading = label(title, "sectionTitle")
        heading.setAlignment(Qt.AlignCenter)
        heading.setStyleSheet("font-size: 18px;")
        layout.addWidget(heading)
        body = label(text, "pageSubtitle", wrap=True)
        body.setAlignment(Qt.AlignCenter)
        body.setMaximumWidth(420)
        body.setStyleSheet(f"color: {t.text_muted};")
        layout.addWidget(body, alignment=Qt.AlignCenter)
        if action:
            layout.addSpacing(8)
            layout.addWidget(action, alignment=Qt.AlignCenter)


class _EmptyArt(QWidget):
    """Dos tarjetas superpuestas en línea discontinua con un icono: dibujo propio."""

    def __init__(self, icon: str):
        super().__init__()
        self.setFixedSize(180, 120)
        self._icon = icon

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        t = theme.current()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        back = QRectF(46, 10, 120, 76)
        front = QRectF(14, 34, 120, 76)
        painter.setPen(QPen(QColor(t.border), 2, Qt.DashLine))
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(back, 12, 12)
        painter.setPen(QPen(QColor(t.accent), 2))
        painter.setBrush(QColor(t.surface))
        painter.drawRoundedRect(front, 12, 12)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(t.accent_soft))
        painter.drawRoundedRect(QRectF(28, 50, 34, 34), 8, 8)
        painter.drawRoundedRect(QRectF(72, 56, 46, 7), 3, 3)
        painter.drawRoundedRect(QRectF(72, 70, 32, 7), 3, 3)
        pixmap = theme.icon_pixmap(self._icon, t.accent, 20)
        painter.drawPixmap(35, 57, pixmap)
        painter.end()


class Toast(QLabel):
    """Aviso breve en la parte inferior de la ventana."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("toast")
        self.setTextFormat(Qt.PlainText)
        self.hide()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_message(self, text: str, ms: int = 2800) -> None:
        self.setText(text)
        self.adjustSize()
        parent = self.parentWidget()
        self.move((parent.width() - self.width()) // 2, parent.height() - self.height() - 28)
        self.raise_()
        self.show()
        self._timer.start(ms)


def fade_in(widget: QWidget, ms: int = 160) -> None:
    effect = QGraphicsOpacityEffect(widget)
    widget.setGraphicsEffect(effect)
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(ms)
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.OutCubic)
    animation.finished.connect(lambda: widget.setGraphicsEffect(None))
    animation.start()


def locale() -> QLocale:
    """Formato de fechas del idioma de la interfaz."""
    return QLocale(i18n.current())


def short_date(timestamp: float) -> str:
    return locale().toString(QDateTime.fromSecsSinceEpoch(int(timestamp)).date(), QLocale.ShortFormat)


def relative_time(timestamp: float) -> str:
    """'hoy, 14:32', 'ayer, 09:10' o '3 mar 2026' (en el idioma de la interfaz)."""
    moment = time.localtime(timestamp)
    today = time.localtime()
    days = (time.mktime(today[:3] + (0, 0, 0, 0, 0, -1)) - time.mktime(moment[:3] + (0, 0, 0, 0, 0, -1))) / 86400
    clock = time.strftime("%H:%M", moment)
    if round(days) == 0:
        return tr("today, {time}", time=clock)
    if round(days) == 1:
        return tr("yesterday, {time}", time=clock)
    return locale().toString(QDateTime.fromSecsSinceEpoch(int(timestamp)).date(), "d MMM yyyy")


def make_horizontal(*widgets: QWidget, spacing: int = 10, stretch_first: bool = False) -> QWidget:
    container = QWidget()
    layout = QHBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(spacing)
    for index, widget in enumerate(widgets):
        layout.addWidget(widget, 1 if stretch_first and index == 0 else 0)
    return container

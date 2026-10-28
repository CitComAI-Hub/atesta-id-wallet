"""
Genera los iconos de la aplicación a partir de packaging/app-icon.svg (con PySide6 y Pillow):
  atesta_id_wallet/gui/icons/app-icon.png   ventana, menú de Linux (install-handler) y .deb/AppImage
  packaging/atesta-id-wallet.ico            ejecutables e instalador de Windows
Uso:  python packaging/make_icons.py   (los resultados se guardan en git; repetir si cambia el SVG)
"""

import io
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image  # noqa: E402
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt  # noqa: E402
from PySide6.QtGui import QGuiApplication, QImage, QPainter  # noqa: E402
from PySide6.QtSvg import QSvgRenderer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "packaging" / "app-icon.svg"


def render(size: int) -> Image.Image:
    image = QImage(size, size, QImage.Format_ARGB32)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    QSvgRenderer(QByteArray(SOURCE.read_bytes())).render(painter, QRectF(0, 0, size, size))
    painter.end()
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return Image.open(io.BytesIO(bytes(buffer.data()))).convert("RGBA")


def main() -> int:
    QGuiApplication(sys.argv[:1])
    render(256).save(ROOT / "atesta_id_wallet" / "gui" / "icons" / "app-icon.png", optimize=True)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = {size: render(size) for size in sizes}  # cada tamaño renderizado, no reescalado
    frames[256].save(ROOT / "packaging" / "atesta-id-wallet.ico", sizes=[(s, s) for s in sizes],
                     append_images=[frames[s] for s in sizes[:-1]])
    return 0


if __name__ == "__main__":
    sys.exit(main())

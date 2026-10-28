# -*- mode: python -*-
# PyInstaller: una carpeta con dos ejecutables que comparten las bibliotecas:
#   atesta-id-wallet-gui   interfaz gráfica (sin consola en Windows)
#   atesta-id-wallet       terminal
# Uso (desde la raíz del repositorio):  pyinstaller --noconfirm packaging/atesta-id-wallet.spec
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(SPECPATH).parent
ICON = str(ROOT / "packaging" / "atesta-id-wallet.ico") if sys.platform == "win32" else None
DATAS = collect_data_files("atesta_id_wallet")  # catálogos de idiomas e iconos
# Partes de Qt que el wallet no usa (ahorran espacio; QtNetwork sí: ventana única).
EXCLUDES = ["tkinter", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtPdf", "PySide6.QtOpenGL",
            "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtDBus", "PySide6.QtConcurrent"]

gui = Analysis([str(ROOT / "packaging" / "launch_gui.py")], pathex=[str(ROOT)], datas=DATAS,
               hiddenimports=["PySide6.QtSvg"], excludes=EXCLUDES)
cli = Analysis([str(ROOT / "packaging" / "launch_cli.py")], pathex=[str(ROOT)], datas=DATAS,
               excludes=EXCLUDES + ["PySide6", "shiboken6"])

# El tema GTK de Qt arrastraría una copia de GTK 3 que puede no casar con la del sistema; Qt usa
# entonces su propio estilo (Fusion, el de la aplicación) y los diálogos del portal xdg-desktop-portal.
gui.binaries = [b for b in gui.binaries
                if not any(part in b[0] for part in ("libqgtk3", "libgtk-3", "libgdk-3"))]

gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="atesta-id-wallet-gui",
              console=False, icon=ICON, upx=False)
cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="atesta-id-wallet",
              console=True, icon=ICON, upx=False)

COLLECT(gui_exe, gui.binaries, gui.datas, cli_exe, cli.binaries, cli.datas,
        name="atesta-id-wallet", upx=False)

# -*- mode: python -*-
# PyInstaller: one folder with two executables that share the libraries:
#   atesta-id-wallet-gui   graphical interface (no console on Windows)
#   atesta-id-wallet       terminal
# Usage (from the repository root):  pyinstaller --noconfirm packaging/atesta-id-wallet.spec
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(SPECPATH).parent
ICON = str(ROOT / "packaging" / "atesta-id-wallet.ico") if sys.platform == "win32" else None
DATAS = collect_data_files("atesta_id_wallet")  # language catalogs and icons
# Qt parts the wallet does not use (saves space; QtNetwork is used: single window).
EXCLUDES = ["tkinter", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtPdf", "PySide6.QtOpenGL",
            "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtDBus", "PySide6.QtConcurrent"]

gui = Analysis([str(ROOT / "packaging" / "launch_gui.py")], pathex=[str(ROOT)], datas=DATAS,
               hiddenimports=["PySide6.QtSvg"], excludes=EXCLUDES)
cli = Analysis([str(ROOT / "packaging" / "launch_cli.py")], pathex=[str(ROOT)], datas=DATAS,
               excludes=EXCLUDES + ["PySide6", "shiboken6"])

# Qt's GTK theme would pull in a copy of GTK 3 that may not match the system one; Qt then uses
# its own style (Fusion, the one the app uses) and the xdg-desktop-portal dialogs.
gui.binaries = [b for b in gui.binaries
                if not any(part in b[0] for part in ("libqgtk3", "libgtk-3", "libgdk-3"))]

gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="atesta-id-wallet-gui",
              console=False, icon=ICON, upx=False)
cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="atesta-id-wallet",
              console=True, icon=ICON, upx=False)

COLLECT(gui_exe, gui.binaries, gui.datas, cli_exe, cli.binaries, cli.datas,
        name="atesta-id-wallet", upx=False)

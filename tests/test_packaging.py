"""Aplicación empaquetada y aviso de versiones nuevas (0.6).  Ejecutar:  python -m unittest discover -s tests"""

import io
import os
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_offline as base  # noqa: E402  (fija ATESTA_ID_WALLET_HOME y el idioma de las pruebas)

from atesta_id_wallet import cli, common, desktop, i18n, storage, updates  # noqa: E402


class FakeResponse:
    def __init__(self, status, data):
        self.status_code, self.data, self.text = status, data, str(data)

    def json(self):
        return self.data


def fake_github(test, status=200, **data):
    """requests.get de updates devuelve 'data' y anota las peticiones."""
    calls = []
    saved = updates.requests.get
    test.addCleanup(setattr, updates.requests, "get", saved)

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(status, data)

    updates.requests.get = get
    return calls


class UpdateTests(unittest.TestCase):
    def setUp(self):
        base.isolated_home(self)
        i18n.set_language("es")  # cli.main() switches to the system language
        self.addCleanup(i18n.set_language, "es")

    def test_parse_version(self):
        self.assertEqual(updates.parse_version("v0.10.2"), (0, 10, 2))
        self.assertGreater(updates.parse_version("0.10.0"), updates.parse_version("0.9.9"))
        self.assertEqual(updates.parse_version("nightly"), ())

    def test_newer_release(self):
        calls = fake_github(self, tag_name="v9.0.0", html_url=updates.RELEASES_PAGE + "/tag/v9.0.0")
        release = updates.newer_release("0.5.1")
        self.assertEqual(release, updates.Release("9.0.0", updates.RELEASES_PAGE + "/tag/v9.0.0"))
        self.assertEqual(calls[0][0], updates.LATEST_API)
        self.assertIsNone(updates.newer_release("9.0.0"))
        self.assertIsNone(updates.newer_release("10.0"))

    def test_only_the_project_releases_page_is_opened(self):
        fake_github(self, tag_name="v9.0.0", html_url="https://evil.example/tag/v9.0.0")
        self.assertEqual(updates.newer_release("0.5.1").url, updates.RELEASES_PAGE)

    def test_no_release_published(self):
        fake_github(self, status=404, message="Not Found")
        with self.assertRaisesRegex(common.WalletError, "ninguna versión publicada"):
            updates.newer_release()

    def test_automatic_check_is_off_by_default_and_daily(self):
        self.assertFalse(updates.automatic_check_due())
        updates.set_automatic_check(True)
        self.assertTrue(updates.automatic_check_due())
        updates.record_check(now=1000)
        self.assertFalse(updates.automatic_check_due(now=1000 + 3600))
        self.assertTrue(updates.automatic_check_due(now=1000 + updates.CHECK_INTERVAL))

    def test_cli_check(self):
        fake_github(self, tag_name="v9.0.0", html_url=updates.RELEASES_PAGE + "/tag/v9.0.0")
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["update", "--check"]), 0)
        self.assertIn("9.0.0", out.getvalue())
        self.assertIn(updates.RELEASES_PAGE + "/tag/v9.0.0", out.getvalue())

    def test_packaged_update_only_checks(self):
        """En un ejecutable empaquetado 'update' no intenta git pull ni install.sh."""
        fake_github(self, tag_name="v0.0.1", html_url=updates.RELEASES_PAGE + "/tag/v0.0.1")
        self.addCleanup(setattr, cli, "FROZEN", cli.FROZEN)
        cli.FROZEN = True
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["update"]), 0)
        self.assertIn(common.__version__, out.getvalue())


class RenameMigrationTests(unittest.TestCase):
    def setUp(self):
        self.home = base.isolated_home(self)
        saved = os.environ.pop("ATESTA_ID_WALLET_HOME")
        self.addCleanup(os.environ.__setitem__, "ATESTA_ID_WALLET_HOME", saved)
        self.addCleanup(setattr, storage, "previous_name_dir", storage.previous_name_dir)
        self.old = self.home / "oid4vc-wallet"
        storage.previous_name_dir = lambda: self.old
        storage.BASE_DIR = self.home / "atesta-id-wallet"

    def test_data_of_the_previous_name_is_moved(self):
        (self.old / "credentials").mkdir(parents=True)
        (self.old / "holder_key.pem").write_text("key")
        storage.migrate_legacy_data()
        self.assertEqual((storage.BASE_DIR / "holder_key.pem").read_text(), "key")
        self.assertTrue((storage.BASE_DIR / "credentials").is_dir())
        self.assertFalse(self.old.exists())

    def test_existing_data_is_never_replaced(self):
        self.old.mkdir()
        storage.BASE_DIR.mkdir()
        storage.migrate_legacy_data()
        self.assertTrue(self.old.exists())


class FrozenLauncherTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, desktop, "FROZEN", desktop.FROZEN)
        self.addCleanup(setattr, sys, "executable", sys.executable)
        self.appimage = os.environ.pop("APPIMAGE", None)
        self.addCleanup(lambda: self.appimage and os.environ.__setitem__("APPIMAGE", self.appimage))
        self.addCleanup(os.environ.pop, "APPIMAGE", None)
        desktop.FROZEN = True
        self.folder = base.isolated_home(self) / "bundle"
        self.folder.mkdir()
        suffix = ".exe" if sys.platform == "win32" else ""
        sys.executable = str(self.folder / f"atesta-id-wallet{suffix}")
        self.gui_exe = self.folder / f"atesta-id-wallet-gui{suffix}"

    def test_both_executables_live_together(self):
        self.assertEqual(desktop._launcher(), [sys.executable])
        self.assertEqual(desktop._launcher(gui=True), [str(self.gui_exe)])
        self.assertFalse(desktop.gui_available())
        self.gui_exe.write_text("")
        self.assertTrue(desktop.gui_available())

    def test_appimage_links_point_to_the_appimage(self):
        os.environ["APPIMAGE"] = "/home/u/Apps/Atesta_ID_Wallet.AppImage"
        self.assertEqual(desktop._launcher(gui=True), ["/home/u/Apps/Atesta_ID_Wallet.AppImage"])
        self.assertEqual(desktop._launcher(), ["/home/u/Apps/Atesta_ID_Wallet.AppImage", "cli"])


class LinuxHandlerTests(unittest.TestCase):
    def setUp(self):
        home = base.isolated_home(self)
        for name, value in (("DESKTOP_FILE", home / "applications" / "atesta-id-wallet.desktop"),
                            ("ICON_THEME_FILE", home / "icons" / "atesta-id-wallet.png"),
                            ("_launcher", lambda gui=False: ["/opt/atesta-id-wallet/atesta-id-wallet-gui"]),
                            ("gui_available", lambda: True)):
            self.addCleanup(setattr, desktop, name, getattr(desktop, name))
            setattr(desktop, name, value)
        self.addCleanup(setattr, desktop.subprocess, "run", desktop.subprocess.run)
        self.commands = []
        desktop.subprocess.run = lambda command, **kwargs: self.commands.append(command)
        self.addCleanup(setattr, sys, "platform", sys.platform)
        sys.platform = "linux"

    def test_install_uses_the_app_icon_and_uninstall_removes_it(self):
        with redirect_stdout(io.StringIO()):
            desktop.cmd_install_handler(None)
        entry = desktop.DESKTOP_FILE.read_text()
        self.assertIn("Exec=/opt/atesta-id-wallet/atesta-id-wallet-gui %u\n", entry)
        self.assertIn("Icon=atesta-id-wallet\n", entry)
        self.assertEqual(desktop.ICON_THEME_FILE.read_bytes(), desktop.APP_ICON.read_bytes())
        self.assertIn(["xdg-mime", "default", "atesta-id-wallet.desktop", "x-scheme-handler/openid4vp"], self.commands)
        with redirect_stdout(io.StringIO()):
            desktop.cmd_uninstall_handler(None)
        self.assertFalse(desktop.DESKTOP_FILE.exists())
        self.assertFalse(desktop.ICON_THEME_FILE.exists())


@unittest.skipIf(base.gui is None, "PySide6 no instalado")
class GuiPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = base.QApplication.instance() or base.QApplication([])

    def setUp(self):
        base.isolated_home(self)

    def test_smoke_test_passes_from_source(self):
        self.assertEqual(base.gui.smoke_test(), 0)

    def test_windows_pipe_name_is_random_and_stable(self):
        self.addCleanup(setattr, sys, "platform", sys.platform)
        sys.platform = "win32"
        name = base.gui._instance_name()
        self.assertRegex(name, r"^atesta-id-wallet-[0-9a-f]{32}$")
        self.assertEqual(base.gui._instance_name(), name)
        self.assertNotIn(os.environ.get("USERNAME", "user"), name)

    def test_found_version_is_offered_in_settings(self):
        from PySide6.QtWidgets import QLabel

        fake_github(self, tag_name="v9.0.0", html_url=updates.RELEASES_PAGE + "/tag/v9.0.0")
        window = base.gui.MainWindow()
        self.addCleanup(window.close)
        window._go("settings")
        window.check_for_updates(automatic=True)
        deadline = time.time() + 5
        while window.available_release is None and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.assertEqual(window.available_release.version, "9.0.0")
        texts = [w.text() for w in window.settings_page.findChildren(QLabel) if w.isVisibleTo(window)]
        self.assertIn("La versión 9.0.0 está disponible", texts)
        self.assertIn("update_checked_at", storage.load_settings())


if __name__ == "__main__":
    unittest.main()

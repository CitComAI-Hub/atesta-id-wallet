"""Packaged application and new-version notice (0.6).  Run:  python -m unittest discover -s tests"""

import io
import os
import sys
import time
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import helpers as base  # noqa: E402  (sets ATESTA_ID_WALLET_HOME and the test language)

from atesta_id_wallet import cli, common, desktop, i18n, storage, updates  # noqa: E402


class FakeResponse:
    def __init__(self, status, data, headers=None):
        self.status_code, self.data, self.text, self.headers = status, data, str(data), headers or {}

    def json(self):
        return self.data


def fake_github(test, status=200, **data):
    """updates' requests.get returns 'data' and records the requests."""
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

    def test_rate_limit_is_explained(self):
        saved = updates.requests.get
        self.addCleanup(setattr, updates.requests, "get", saved)
        updates.requests.get = lambda url, **kwargs: FakeResponse(403, {"message": "API rate limit exceeded"},
                                                                   {"X-RateLimit-Remaining": "0"})
        with self.assertRaisesRegex(common.WalletError, "limitando las peticiones"):
            updates.newer_release()

    def test_automatic_check_is_on_by_default_and_daily(self):
        self.assertTrue(updates.automatic_check_due())
        updates.set_automatic_check(False)
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
        """In a packaged executable 'update' does not try git pull or install.sh."""
        fake_github(self, tag_name="v0.0.1", html_url=updates.RELEASES_PAGE + "/tag/v0.0.1")
        self.addCleanup(setattr, cli, "FROZEN", cli.FROZEN)
        cli.FROZEN = True
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["update"]), 0)
        self.assertIn(common.__version__, out.getvalue())


class SelfUpdateTests(unittest.TestCase):
    """Automatic update: only files listed in a SHA256SUMS signed by the release key."""

    VERSION = "99.0.0"

    def setUp(self):
        import base64
        import hashlib

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.home = base.isolated_home(self)
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.addCleanup(setattr, updates, "UPDATE_PUBLIC_KEY", updates.UPDATE_PUBLIC_KEY)
        updates.UPDATE_PUBLIC_KEY = base64.b64encode(public).decode()
        self.addCleanup(setattr, updates.storage, "BASE_DIR", updates.storage.BASE_DIR)
        updates.storage.BASE_DIR = self.home
        self.files = {}
        self.payload = b"new AppImage " * 1000
        self.publish({updates.asset_name("appimage", self.VERSION): self.payload,
                      updates.asset_name("windows-installer", self.VERSION): b"setup.exe"})
        saved = updates.requests.get
        self.addCleanup(setattr, updates.requests, "get", saved)
        updates.requests.get = self.get
        self._hashlib, self._b64 = hashlib, base64

    def publish(self, files, sign=True):
        import base64
        import hashlib

        self.files = dict(files)
        sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items()).encode()
        self.files[updates.SUMS] = sums
        if sign:
            self.files[updates.SIGNATURE] = base64.b64encode(self.key.sign(sums))

    def get(self, url, **kwargs):
        name = url.rsplit("/", 1)[-1]
        data = self.files.get(name)
        response = FakeResponse(200 if data is not None else 404, data)
        response.iter_content = lambda size: [data[i:i + size] for i in range(0, len(data), size)]
        response.__enter__ = lambda: response
        response.__exit__ = lambda *exc: None
        return type("Ctx", (), {"__enter__": lambda s: response, "__exit__": lambda s, *e: None})()

    def release(self, version=VERSION):
        names = [updates.asset_name("appimage", version), updates.asset_name("windows-installer", version),
                 updates.SUMS, updates.SIGNATURE]
        return updates.Release(version, updates.RELEASES_PAGE,
                               tuple((n, f"{updates.DOWNLOAD_PREFIX}v{version}/{n}") for n in names))

    def appimage(self):
        current = self.home / "Atesta_ID_Wallet-0.1.0-x86_64.AppImage"
        current.write_bytes(b"old")
        os.chmod(current, 0o755)
        return current

    def test_appimage_is_replaced_in_place(self):
        current = self.appimage()
        with unittest.mock.patch.dict(os.environ, {"APPIMAGE": str(current)}):
            updates.download_update(self.release(), "appimage")
        self.assertEqual(current.read_bytes(), self.payload)
        if sys.platform != "win32":
            self.assertTrue(os.access(current, os.X_OK))
        self.assertEqual(list(current.parent.glob(".*.new")), [])
        self.assertFalse(updates.updates_dir().exists())

    def test_unsigned_or_foreign_signature_is_refused(self):
        current = self.appimage()
        self.publish({updates.asset_name("appimage", self.VERSION): b"evil"}, sign=False)
        self.files[updates.SIGNATURE] = b"bm90IGEgc2lnbmF0dXJl"
        with unittest.mock.patch.dict(os.environ, {"APPIMAGE": str(current)}):
            with self.assertRaisesRegex(common.WalletError, "firma"):
                updates.download_update(self.release(), "appimage")
        self.assertEqual(current.read_bytes(), b"old")

    def test_file_not_matching_the_signed_checksum_is_refused(self):
        current = self.appimage()
        self.files[updates.asset_name("appimage", self.VERSION)] = b"tampered"
        with unittest.mock.patch.dict(os.environ, {"APPIMAGE": str(current)}):
            with self.assertRaises(common.WalletError):
                updates.download_update(self.release(), "appimage")
        self.assertEqual(current.read_bytes(), b"old")
        self.assertEqual(list(updates.updates_dir().glob("*")), [])

    def test_signed_list_of_another_version_is_refused(self):
        """An old, validly signed SHA256SUMS replayed under a newer tag names other files."""
        self.publish({updates.asset_name("appimage", "0.0.1"): b"old release"})
        self.files[updates.asset_name("appimage", self.VERSION)] = b"old release"
        with self.assertRaises(common.WalletError):
            updates.download_update(self.release(), "appimage")

    def test_apt_workflow_checks_the_same_signature(self):
        """packaging/verify_release.py (apt.yml) accepts what the wallets accept, and nothing else."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "verify_release", Path(__file__).resolve().parent.parent / "packaging" / "verify_release.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        root = self.home / "root"
        (root / "atesta_id_wallet").mkdir(parents=True)
        (root / "atesta_id_wallet" / "updates.py").write_text(
            f'UPDATE_PUBLIC_KEY = "{updates.UPDATE_PUBLIC_KEY}"\n', encoding="utf-8")
        module.ROOT = root
        sums, sig = self.home / updates.SUMS, self.home / updates.SIGNATURE
        sums.write_bytes(self.files[updates.SUMS])
        sig.write_bytes(self.files[updates.SIGNATURE])
        with unittest.mock.patch.object(sys, "argv", ["verify_release.py", str(sums)]), \
                redirect_stdout(io.StringIO()), unittest.mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(module.main(), 0)
            sums.write_bytes(self.files[updates.SUMS] + b"0" * 64 + b"  evil.deb\n")  # a file added by hand
            self.assertEqual(module.main(), 1)
            sig.unlink()
            self.assertEqual(module.main(), 1)

    def test_older_version_and_other_hosts_are_refused(self):
        with self.assertRaises(common.WalletError):
            updates.download_update(self.release("0.0.1"), "appimage")
        evil = updates.Release(self.VERSION, updates.RELEASES_PAGE, ((updates.SUMS, "https://evil.example/S"),))
        with self.assertRaisesRegex(common.WalletError, "evil.example"):
            updates.download_update(evil, "appimage")
        with self.assertRaises(common.WalletError):
            updates.download_update(self.release(), "deb")

    def test_windows_installer_waits_until_restart(self):
        path = updates.download_update(self.release(), "windows-installer")
        pending = updates.pending_update()
        self.assertEqual((pending["version"], pending["path"]), (self.VERSION, path))
        path.write_bytes(b"changed afterwards")
        self.assertIsNone(updates.pending_update())
        self.assertFalse(updates.updates_dir().exists())

    def test_installer_is_started_once(self):
        updates.download_update(self.release(), "windows-installer")
        started = []
        self.addCleanup(setattr, updates, "install_kind", updates.install_kind)
        updates.install_kind = lambda: "windows-installer"
        with unittest.mock.patch.object(updates.subprocess, "Popen", lambda cmd, **kw: started.append(cmd)):
            self.assertTrue(updates.install_pending())
            self.assertFalse(updates.install_pending())
        self.assertEqual(started[0][1:], ["/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS",
                                          "/LAUNCH=1"])

    def test_release_assets_only_from_the_project(self):
        fake_github(self, tag_name="v9.0.0", html_url=updates.RELEASES_PAGE + "/tag/v9.0.0", assets=[
            {"name": "SHA256SUMS", "browser_download_url": updates.DOWNLOAD_PREFIX + "v9.0.0/SHA256SUMS"},
            {"name": "x.AppImage", "browser_download_url": "https://evil.example/x.AppImage"}])
        release = updates.latest_release()
        self.assertEqual([name for name, _ in release.assets], ["SHA256SUMS"])

    def test_install_kind(self):
        self.addCleanup(setattr, updates, "FROZEN", updates.FROZEN)
        updates.FROZEN = False
        self.assertEqual(updates.install_kind(), "source")
        self.assertFalse(updates.can_update_itself())
        if sys.platform.startswith("linux"):
            updates.FROZEN = True
            with unittest.mock.patch.dict(os.environ, {"APPIMAGE": "/tmp/x.AppImage"}):
                self.assertEqual(updates.install_kind(), "appimage")
            with unittest.mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("APPIMAGE", None)
                with unittest.mock.patch.object(sys, "executable", "/opt/atesta-id-wallet/atesta-id-wallet"):
                    self.assertEqual(updates.install_kind(), "deb")


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


@unittest.skipIf(base.gui is None, "PySide6 not installed")
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

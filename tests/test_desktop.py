"""Desktop integration: link routing, clipboard, QR codes, Windows link handler.

Run:  python -m unittest discover -s tests
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import FakeWinreg, qr_png  # noqa: E402  (first: sets the test environment)
from atesta_id_wallet import common, desktop  # noqa: E402


class RoutingTests(unittest.TestCase):
    def test_offer_and_request(self):
        self.assertEqual(desktop.route_input("openid-credential-offer://?credential_offer_uri=x")[0], "issue")
        self.assertEqual(desktop.route_input(" 'openid4vp://?request_uri=x' ")[0], "present")
        self.assertEqual(desktop.route_input("openid4vp%3A%2F%2F%3Frequest_uri%3Dx")[0], "present")

    def test_unknown(self):
        with self.assertRaises(common.WalletError):
            desktop.route_input("hola")

    def test_doubled_paste(self):
        raw = "openid4vp://?request_uri=https://a/1openid4vp://?request_uri=https://a/2"
        self.assertEqual(common._last_deep_link(raw, "openid4vp://"), "openid4vp://?request_uri=https://a/2")


class ClipboardTests(unittest.TestCase):
    def setUp(self):
        self._clipboard_bytes = desktop._clipboard_bytes

    def tearDown(self):
        desktop._clipboard_bytes = self._clipboard_bytes

    def check(self, data):
        desktop._clipboard_bytes = lambda: data
        return desktop.clipboard_link()

    def test_text_link(self):
        self.assertEqual(self.check(b"openid4vp://?request_uri=x\n"), "openid4vp://?request_uri=x")

    def test_other_text(self):
        self.assertIsNone(self.check(b"hola"))

    def test_binary_is_not_text(self):
        # Print Screen leaves a PNG in the clipboard: reading must not break.
        self.assertIsNone(self.check(b"\xff\xfe\x00 binario"))
        self.assertIsNone(self.check(b"\x89PNG\r\n\x1a\n sin QR"))


class QrTests(unittest.TestCase):
    def setUp(self):
        self._clipboard_bytes = desktop._clipboard_bytes
        self.addCleanup(setattr, desktop, "_clipboard_bytes", self._clipboard_bytes)
        self.dir = Path(tempfile.mkdtemp(prefix="atesta-qr-"))

    def test_screenshot_and_newest_in_folder(self):
        old, new = self.dir / "a.png", self.dir / "b.png"
        qr_png("openid4vp://?request_uri=https://v/old", old)
        qr_png("openid-credential-offer://?credential_offer_uri=https://i/new", new)
        os.utime(old, (1, 1))
        self.assertEqual(desktop.decode_qr_image(str(old)), "openid4vp://?request_uri=https://v/old")
        self.assertEqual(desktop.decode_qr_image(str(self.dir)),
                         "openid-credential-offer://?credential_offer_uri=https://i/new")
        self.assertEqual(desktop.route_input(str(new))[0], "issue")

    def test_image_without_qr(self):
        from PIL import Image

        Image.new("RGB", (100, 100), "white").save(self.dir / "blank.png")
        with self.assertRaisesRegex(common.WalletError, "ningún QR"):
            desktop.decode_qr_image(str(self.dir / "blank.png"))

    def test_clipboard_png_with_qr(self):
        desktop._clipboard_bytes = lambda: qr_png("openid4vp://?request_uri=https://v/1")
        self.assertEqual(desktop.clipboard_link(), "openid4vp://?request_uri=https://v/1")


class WindowsHandlerTests(unittest.TestCase):
    def setUp(self):
        self.reg = FakeWinreg()
        self.addCleanup(sys.modules.pop, "winreg", None)
        sys.modules["winreg"] = self.reg
        self.platform = sys.platform
        self.addCleanup(setattr, sys, "platform", self.platform)
        sys.platform = "win32"
        self._launcher = desktop._launcher
        self.addCleanup(setattr, desktop, "_launcher", self._launcher)
        desktop._launcher = lambda gui=False: [rf"C:\Program Files\Wallet\atesta-id-wallet{'-gui' if gui else ''}.exe"]
        self._gui_available = desktop.gui_available
        self.addCleanup(setattr, desktop, "gui_available", self._gui_available)
        desktop.gui_available = lambda: False

    def test_gui_handler_has_no_pause(self):
        desktop.gui_available = lambda: True
        desktop.cmd_install_handler(None)
        command = self.reg.keys[r"Software\Classes\openid4vp\shell\open\command"][""]
        self.assertEqual(command, r'"C:\Program Files\Wallet\atesta-id-wallet-gui.exe" "%1"')

    def test_install_and_uninstall(self):
        desktop.cmd_install_handler(None)
        key = self.reg.keys[r"Software\Classes\openid4vp"]
        self.assertEqual(key, {"": "URL:openid4vp", "URL Protocol": ""})
        command = self.reg.keys[r"Software\Classes\openid4vp\shell\open\command"][""]
        self.assertEqual(command, r'"C:\Program Files\Wallet\atesta-id-wallet.exe" --pause "%1"')
        self.assertIn(r"Software\Classes\openid-credential-offer", self.reg.keys)
        desktop.cmd_uninstall_handler(None)
        self.assertFalse(any("openid" in k for k in self.reg.keys))

    def test_links_registered(self):
        self.assertIs(desktop.links_registered(), False)
        desktop.cmd_install_handler(None)
        self.assertIs(desktop.links_registered(), True)
        self.assertEqual(desktop.links_owner(), "us")
        self.reg.keys[r"Software\Classes\openid4vp\shell\open\command"][""] = r'"C:\Lissi\lissi.exe" "%1"'
        self.assertEqual(desktop.links_owner(), "other")
        del self.reg.keys[r"Software\Classes\openid-credential-offer\shell\open\command"]
        self.assertIs(desktop.links_registered(), False)  # every scheme is needed
        self.assertEqual(desktop.links_owner(), "none")


class LinuxHandlerQueryTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, sys, "platform", sys.platform)
        sys.platform = "linux"
        self.addCleanup(setattr, desktop.subprocess, "run", desktop.subprocess.run)

    def answer(self, handlers):
        def run(cmd, **_):
            self.assertEqual(cmd[:3], ["xdg-mime", "query", "default"])
            return subprocess.CompletedProcess(cmd, 0, stdout=handlers.get(cmd[3], "") + "\n", stderr="")
        desktop.subprocess.run = run

    def test_any_application_counts(self):
        self.answer({"x-scheme-handler/openid4vp": "other-wallet.desktop",
                     "x-scheme-handler/openid-credential-offer": "atesta-id-wallet.desktop"})
        self.assertIs(desktop.links_registered(), True)
        self.assertEqual(desktop.links_owner(), "other")
        self.answer({f"x-scheme-handler/{s}": "atesta-id-wallet.desktop" for s in ("openid4vp", "openid-credential-offer")})
        self.assertEqual(desktop.links_owner(), "us")

    def test_missing_scheme(self):
        self.answer({"x-scheme-handler/openid4vp": "atesta-id-wallet.desktop"})
        self.assertIs(desktop.links_registered(), False)

    def test_unknown_without_xdg_mime_or_on_macos(self):
        def missing(cmd, **_):
            raise FileNotFoundError(cmd[0])
        desktop.subprocess.run = missing
        self.assertIsNone(desktop.links_registered())
        sys.platform = "darwin"
        self.assertIsNone(desktop.links_registered())


if __name__ == "__main__":
    unittest.main()

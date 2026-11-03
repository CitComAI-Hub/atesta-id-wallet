"""The GUI end to end.

Run:  python -m unittest discover -s tests
"""

import base64
import http.server
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (  # noqa: E402  (first: sets the test environment)
    FakeIssuer, FakeVerifier, QApplication, QGuiApplication, _wide_png, gui, isolated_home, make_cert,
    make_sd_jwt, png_bytes, qr_png, verifier_request,
)
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import i18n, storage  # noqa: E402


@unittest.skipIf(gui is None, "PySide6 not installed")
class GuiFlowTests(unittest.TestCase):
    """The GUI end to end: worker thread + panels (answered by the test)."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.verifier = http.server.HTTPServer(("127.0.0.1", 0), FakeVerifier)
        cls.issuer = http.server.HTTPServer(("127.0.0.1", 0), FakeIssuer)
        for server in (cls.verifier, cls.issuer):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        FakeIssuer.base = f"http://localhost:{cls.issuer.server_port}"
        FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def tearDownClass(cls):
        cls.verifier.shutdown()
        cls.issuer.shutdown()

    def setUp(self):
        isolated_home(self)
        FakeVerifier.received = []
        QGuiApplication.clipboard().clear()
        # Never look at the user's real screenshots.
        self.addCleanup(setattr, gui, "_screenshot_dirs", gui._screenshot_dirs)
        gui._screenshot_dirs = lambda: []
        self.window = gui.MainWindow()
        self.asked, self.consent = [], True
        self.window._ask_offer = lambda request: self.asked.append("offer") or request.answer(True)
        self.window._ask_text = lambda request: self.asked.append(request.args[0]) or request.answer("1234")
        self.window._ask_consent = lambda request: (self.asked.append(request.args[0].identity.trust)
                                                    or request.answer(self.consent))
        self.addCleanup(self.window.close)

    def wait(self):
        deadline = time.time() + 10
        while self.window.busy and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.app.processEvents()
        self.assertFalse(self.window.busy, "la tarea no terminó")

    def present_link(self):
        key = ec.generate_private_key(ec.SECP256R1())
        return verifier_request(f"http://localhost:{self.verifier.server_port}", key, make_cert(key, "localhost"))

    def test_issue_then_present(self):
        self.window.process(f"openid-credential-offer://?credential_offer_uri={FakeIssuer.base}/offer")
        self.wait()
        self.assertEqual(self.window.last_result, (True, "Credencial añadida"))
        self.assertEqual(len(self.window.records), 1)
        self.assertEqual(self.asked[0], "offer")
        self.assertTrue(any("tx_code" in str(q) for q in self.asked))
        self.window.process(self.present_link())
        self.wait()
        self.assertEqual(self.asked[-1], "new")
        self.assertEqual(len(FakeVerifier.received), 1)
        self.assertEqual(self.window.last_result, (True, "Datos compartidos"))
        self.assertEqual([e["type"] for e in storage.load_history()], ["presented", "issued"])

    def test_card_logo(self):
        from atesta_id_wallet.gui import widgets
        record = {"display": {"logo": base64.b64encode(png_bytes(64)).decode()}}
        pixmap = widgets.issuer_logo(record, 24)
        self.assertEqual((pixmap.width(), pixmap.height()), (24, 24))
        wide = {"display": {"logo": base64.b64encode(_wide_png()).decode()}}
        self.assertIsNone(widgets.issuer_logo(wide, 24))  # dimensions checked before decoding
        self.assertIsNone(widgets.issuer_logo({"display": {"logo": "not base64!"}}, 24))
        card = widgets.CredentialCard({**record, "issuer": "https://kc.example.org"})
        card.grab()  # paints with the logo

    def test_password_can_be_shown(self):
        from atesta_id_wallet.gui import widgets
        field = widgets.password_field()
        self.assertEqual(field.echoMode(), widgets.QLineEdit.Password)
        field.toggle_visibility.trigger()
        self.assertEqual(field.echoMode(), widgets.QLineEdit.Normal)
        field.toggle_visibility.trigger()
        self.assertEqual(field.echoMode(), widgets.QLineEdit.Password)

    def test_missing_credential_offers_known_issuer(self):
        storage.save_config({"issuers": {FakeIssuer.base: {}}})
        holder = storage.HolderKey.load_or_create()
        self.addCleanup(setattr, gui, "issue_from_issuer", gui.issue_from_issuer)
        requested = []
        gui.issue_from_issuer = lambda session, issuer, ids, options, prompter: requested.append((issuer, ids)) or []
        exc = gui.NoMatchingCredential("no match", ["Legal"])
        self.window._on_failed(exc, "")
        self.wait()
        sheet = self.window.overlay.sheet
        [ask] = [b for b in sheet.findChildren(gui.QPushButton) if b.text().startswith("Pedirla a")]
        ask.click()
        self.wait()
        self.assertEqual(requested, [(FakeIssuer.base, ["Legal"])])
        del holder

    def test_activity_by_contact(self):
        for event in ({"type": "issued", "party": "Ayuntamiento", "party_id": "https://i.example/r"},
                      {"type": "presented", "party": "Verificador", "party_id": "x509_san_dns:v.example"},
                      {"type": "declined", "party": "Verificador", "party_id": "x509_san_dns:v.example"}):
            storage.add_history(event)
        page = self.window.activity_page
        self.window._go("activity")
        page.show_contact("x509_san_dns:v.example")
        self.assertTrue(page.contact_bar.isVisibleTo(page))
        self.assertIn("compartido una vez · rechazado una vez", page.contact_summary.text())
        self.window._nav("activity")  # the sidebar shows everything again
        self.assertIsNone(page.contact)

    def test_bad_new_password_asks_again(self):
        chosen = []
        self.window._choose_password("Nueva", "Cuerpo", chosen.append)
        self.window.overlay.sheet.field.setText("123")
        self.window.overlay.sheet.field.returnPressed.emit()
        sheet = self.window.overlay.sheet
        self.assertEqual(type(sheet).__name__, "TextSheet")  # asked again, not closed
        self.assertIn("al menos", sheet.body.text())
        sheet.field.setText("correct horse")
        sheet.field.returnPressed.emit()
        self.window.overlay.sheet.field.setText("other horse")
        self.window.overlay.sheet.field.returnPressed.emit()
        self.assertIn("no coinciden", self.window.overlay.sheet.body.text())
        self.assertEqual(chosen, [])

    def test_backdrop_stays_between_panels(self):
        self.window.show()
        self.window._onboarding_step(0)
        self.app.processEvents()
        self.window.overlay.sheet.findChildren(gui.QPushButton)[-1].click()  # Next
        self.assertTrue(self.window.overlay.isVisible())
        self.app.processEvents()
        self.assertTrue(self.window.overlay.isVisible())
        self.window._close_sheet()
        self.app.processEvents()
        self.assertFalse(self.window.overlay.isVisible())

    def test_onboarding_only_once(self):
        self.window.maybe_onboard()
        self.assertEqual(type(self.window.overlay.sheet).__name__, "ConfirmSheet")
        self.window._close_sheet()
        self.window.maybe_onboard()
        self.assertIsNone(self.window.overlay.sheet)
        self.assertTrue(storage.load_settings()["onboarded"])

    def test_consent_declined_sends_nothing(self):
        holder = storage.HolderKey.load_or_create()
        storage.save_credential(make_sd_jwt(holder), fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
        self.consent = False
        self.window.process(self.present_link())
        self.wait()
        self.assertEqual(FakeVerifier.received, [])
        self.assertIsNone(self.window.last_result)  # cancelling is not an error
        self.assertIsNone(self.window.overlay.sheet)
        self.assertEqual(storage.load_history()[0]["type"], "declined")

    def test_missing_credential(self):
        self.window.process(self.present_link())
        self.wait()
        self.assertEqual(self.window.last_result, (False, "No tienes la credencial que se pide"))

    def test_language_switch_rebuilds_window(self):
        self.addCleanup(i18n.set_language, "es")
        self.window.set_language("da")
        self.assertEqual(self.window.nav_buttons["settings"].text().strip(), "Indstillinger")
        self.assertEqual(storage.load_settings()["language"], "da")
        self.window.set_language("en")
        self.assertEqual(self.window.nav_buttons["wallet"].text().strip(), "Wallet")
        self.assertEqual(self.window.wallet_page.scan_button.text(), "Scan QR")

    def test_theme_setting_is_persistent(self):
        self.addCleanup(setattr, gui.theme, "preference", "auto")
        forced = os.environ.pop("ATESTA_ID_WALLET_THEME", None)
        if forced is not None:
            self.addCleanup(os.environ.__setitem__, "ATESTA_ID_WALLET_THEME", forced)
        self.window.set_theme("dark")
        self.assertTrue(gui.theme.current().dark)
        self.assertEqual(storage.load_settings()["theme"], "dark")
        self.window.set_theme("light")
        self.assertFalse(gui.theme.current().dark)
        self.window.set_theme("nonsense")  # ignored
        self.assertEqual(storage.load_settings()["theme"], "light")
        gui.theme.preference = "auto"
        other = gui.MainWindow()  # a new window (next start) reads it back from settings.json
        self.addCleanup(other.close)
        self.assertEqual(gui.theme.preference, "light")

    def test_scan_reads_clipboard(self):
        seen = []
        self.window.process = seen.append
        QGuiApplication.clipboard().setText("openid4vp://?request_uri=https://v/1")
        self.window.scan()
        self.assertEqual(seen, ["openid4vp://?request_uri=https://v/1"])

    def test_scan_ignores_already_used_qr(self):
        """After a QR code (failed or not), Scan must not pick the same one from the clipboard again."""
        self.window.process("openid4vp://?request_uri=https://127.0.0.1:9/no-existe")
        self.wait()
        seen = []
        self.window.process = seen.append
        QGuiApplication.clipboard().setText("openid4vp://?request_uri=https://127.0.0.1:9/no-existe")
        self.window.scan()
        self.assertEqual(seen, [])
        self.assertEqual(type(self.window.overlay.sheet).__name__, "ScanSheet")
        QGuiApplication.clipboard().setText("openid4vp://?request_uri=https://v/otro")
        self.window._watch_tick()
        self.assertEqual(seen, ["openid4vp://?request_uri=https://v/otro"])

    def test_scan_waits_for_new_screenshot(self):
        shots = Path(tempfile.mkdtemp(prefix="atesta-shots-"))
        old = shots / "old.png"
        qr_png("openid4vp://?request_uri=https://v/old", old)
        os.utime(old, (time.time() - 3600, time.time() - 3600))  # older: must not be used
        gui._screenshot_dirs = lambda: [shots]
        seen = []
        self.window.process = seen.append
        self.window.scan()
        self.assertEqual(seen, [])
        self.assertEqual(type(self.window.overlay.sheet).__name__, "ScanSheet")
        self.window._watch_tick()
        self.assertEqual(seen, [])
        qr_png("openid4vp://?request_uri=https://v/new", shots / "new.png")
        self.window._watch_tick()
        self.assertEqual(seen, ["openid4vp://?request_uri=https://v/new"])


if __name__ == "__main__":
    unittest.main()

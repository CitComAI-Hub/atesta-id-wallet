"""Login in the browser with the wallet's own client (0.10).  Run:  python -m unittest discover -s tests"""

import http.server
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_offline as base  # noqa: E402  (sets ATESTA_ID_WALLET_HOME, the test keyring and the language)

import requests  # noqa: E402

from atesta_id_wallet import cli, common, storage, vci  # noqa: E402


class FakeAuthorize(http.server.BaseHTTPRequestHandler):
    """Authorization endpoint answering the probe as configured in 'answer'."""

    answer = (200, None)
    requests = []

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        FakeAuthorize.requests.append(parse_qs(urlsplit(self.path).query))
        status, location = FakeAuthorize.answer
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.end_headers()


class LoopbackTests(unittest.TestCase):
    def test_free_port_and_callback(self):
        loop = vci._Loopback(vci.LOOPBACK_REDIRECT)
        self.addCleanup(loop.close)
        port = urlsplit(loop.redirect_uri).port
        self.assertTrue(port)
        self.assertEqual(loop.redirect_uri, f"http://127.0.0.1:{port}/callback")

        def browser():
            requests.get(f"http://127.0.0.1:{port}/favicon.ico", timeout=5)  # ignored
            requests.get(f"http://127.0.0.1:{port}/callback?code=C&state=S", timeout=5)

        threading.Thread(target=browser, daemon=True).start()
        self.assertEqual(loop.wait(threading.Event(), timeout=10), f"http://127.0.0.1:{port}/callback?code=C&state=S")

    def test_fixed_port_kept(self):
        probe = vci._Loopback("http://localhost/cb")
        port = urlsplit(probe.redirect_uri).port
        probe.close()
        loop = vci._Loopback(f"http://localhost:{port}/cb")
        self.addCleanup(loop.close)
        self.assertEqual(loop.redirect_uri, f"http://localhost:{port}/cb")

    def test_cancel(self):
        loop = vci._Loopback(vci.LOOPBACK_REDIRECT)
        stop = threading.Event()
        threading.Timer(0.3, stop.set).start()
        started = time.time()
        with self.assertRaises(common.Cancelled):
            loop.wait(stop, timeout=30)
        self.assertLess(time.time() - started, 5)

    def test_timeout(self):
        loop = vci._Loopback(vci.LOOPBACK_REDIRECT)
        with self.assertRaisesRegex(common.WalletError, "redirección del navegador"):
            loop.wait(threading.Event(), timeout=1)


def id_token(claims):
    return "e30." + common.b64u(json.dumps(claims).encode()) + ".sig"


class AccountTests(unittest.TestCase):
    def test_user_and_email(self):
        token = {"id_token": id_token({"preferred_username": "alice", "email": "alice@example.org"})}
        self.assertEqual(vci.account_of(token), "alice (alice@example.org)")

    def test_same_name_once(self):
        self.assertEqual(vci.account_of({"id_token": id_token({"preferred_username": "a@x.org", "email": "A@x.org"})}),
                         "a@x.org")
        self.assertEqual(vci.account_of({"id_token": id_token({"email": "a@x.org"})}), "a@x.org")

    def test_nothing_usable(self):
        for token in ({}, {"id_token": 3}, {"id_token": "a.b"}, {"id_token": "a.!!.c"},
                      {"id_token": "e30." + common.b64u(b"[1]") + ".s"}, {"id_token": id_token({"sub": "1"})}):
            self.assertIsNone(vci.account_of(token), token)


class OpenBrowserTests(unittest.TestCase):
    def test_without_console(self):
        """Windowed builds have no stdout/stderr (no file descriptors 1 and 2): the browser still opens."""
        opened = []
        self.addCleanup(setattr, vci.webbrowser, "open", vci.webbrowser.open)
        self.addCleanup(setattr, vci.os, "dup", vci.os.dup)
        vci.webbrowser.open = opened.append

        def no_console(fd):
            raise OSError(9, "Bad file descriptor")

        vci.os.dup = no_console
        vci._open_browser_quietly("https://kc.example/auth")
        self.assertEqual(opened, ["https://kc.example/auth"])


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeAuthorize)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.meta = {"authorization_endpoint": f"http://127.0.0.1:{cls.server.server_port}/auth"}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def probe(self, status, location=None):
        FakeAuthorize.answer, FakeAuthorize.requests = (status, location), []
        return vci.wallet_client_available(requests.Session(), self.meta)

    def test_login_page_means_available(self):
        self.assertTrue(self.probe(200))
        sent = FakeAuthorize.requests[0]
        self.assertEqual(sent["client_id"], [vci.WALLET_CLIENT_ID])
        self.assertTrue(sent["redirect_uri"][0].startswith("http://127.0.0.1:"))
        self.assertNotIn("issuer_state", sent)

    def test_error_page_means_not_available(self):
        self.assertFalse(self.probe(400))

    def test_redirect_to_an_identity_provider_means_available(self):
        self.assertTrue(self.probe(302, "https://idp.example/login"))

    def test_error_sent_back_to_the_wallet_means_not_available(self):
        self.assertFalse(self.probe(302, "http://127.0.0.1:49152/callback?error=invalid_scope"))

    def test_unreachable_or_no_endpoint(self):
        self.assertFalse(vci.wallet_client_available(requests.Session(), {}))
        self.assertFalse(vci.wallet_client_available(
            requests.Session(), {"authorization_endpoint": "http://127.0.0.1:9/auth"}))


class ClientChoiceTests(unittest.TestCase):
    """Which client issue() signs in with, and that the own client never sends issuer_state."""

    def setUp(self):
        base.isolated_home(self)
        self.available, self.probed, self.flows = True, 0, []

        def probe(session, as_meta):
            self.probed += 1
            return self.available

        def flow(session, as_meta, *, client_id, redirect_uri, issuer_state, **kwargs):
            self.flows.append((client_id, redirect_uri, issuer_state))
            return {"access_token": "AT", "token_type": "Bearer"}, None

        for name, fake in (("wallet_client_available", probe), ("authorization_code_flow", flow),
                           ("request_credential", lambda *a, **k: [])):
            self.addCleanup(setattr, vci, name, getattr(vci, name))
            setattr(vci, name, fake)
        issuer = "https://kc.example/realms/p"
        self.issuer = issuer
        metadata = {
            "credential_issuer": issuer, "credential_endpoint": issuer + "/credential",
            "credential_configurations_supported": {"Legal": {"format": "dc+sd-jwt", "scope": "Legal"}},
            "issuer": issuer, "token_endpoint": issuer + "/token", "authorization_endpoint": issuer + "/auth",
        }
        self.addCleanup(setattr, vci, "_get_first_json", vci._get_first_json)
        vci._get_first_json = lambda session, urls: metadata

    def issue(self, issuer_state="ST", **options):
        offer = {"credential_issuer": self.issuer, "credential_configuration_ids": ["Legal"],
                 "grants": {"authorization_code": {"issuer_state": issuer_state}}}
        vci.issue(requests.Session(), json.dumps(offer), vci.IssueOptions(**options), base.ScriptedPrompter())
        return self.flows[-1]

    def test_own_client_when_available_without_issuer_state(self):
        self.assertEqual(self.issue(), (vci.WALLET_CLIENT_ID, vci.LOOPBACK_REDIRECT, None))
        remembered = storage.load_config()["issuers"][self.issuer]
        self.assertEqual(remembered["client_id"], vci.WALLET_CLIENT_ID)
        # Remembered: used again without asking the server.
        self.assertEqual(self.issue()[0], vci.WALLET_CLIENT_ID)
        self.assertEqual(self.probed, 1)

    def test_account_console_when_not_available(self):
        self.available = False
        self.assertEqual(self.issue(), ("account-console", self.issuer + "/account/oid4vci-callback", "ST"))
        # account-console was only the default: the server is asked again next time.
        self.available = True
        self.assertEqual(self.issue()[0], vci.WALLET_CLIENT_ID)
        self.assertEqual(self.probed, 2)

    def test_in_app_login(self):
        self.assertEqual(self.issue(in_app_login=True)[0], "account-console")
        self.assertEqual(self.probed, 0)
        self.issue()  # remembers the own client...
        self.assertEqual(self.issue(in_app_login=True)[0], "account-console")  # ...which the option overrides

    def test_client_chosen_by_the_user(self):
        self.assertEqual(self.issue(client_id="mine", redirect_uri="https://app.example/cb"),
                         ("mine", "https://app.example/cb", "ST"))
        self.assertEqual(self.issue()[0], "mine")  # remembered
        self.assertEqual(self.probed, 0)

    def test_cli_option(self):
        seen = []
        self.addCleanup(setattr, cli, "issue", cli.issue)
        cli.issue = lambda session, raw, options, ui: seen.append(options) or []
        cli._run(["issue", "--offer", "openid-credential-offer://?credential_offer=%7B%7D", "--in-app-login", "--yes"])
        self.assertTrue(seen[0].in_app_login)


@unittest.skipIf(base.gui is None, "PySide6 not installed")
class GuiBrowserWaitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = base.QApplication.instance() or base.QApplication([])

    def setUp(self):
        base.isolated_home(self)
        self.window = base.gui.MainWindow()
        self.addCleanup(self.window.close)
        self.opened = []
        self.addCleanup(setattr, base.gui.webbrowser, "open", base.gui.webbrowser.open)
        base.gui.webbrowser.open = self.opened.append

    def run_wait(self, wait):
        prompter = base.gui.GuiPrompter(self.window.bridge)
        self.window._run("Test", lambda: prompter.wait_for_browser("kc.example", "https://kc.example/auth?x", wait),
                         lambda result: setattr(self, "result", result))

    def pump(self, until, seconds=10):
        deadline = time.time() + seconds
        while not until() and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.app.processEvents()

    def test_panel_open_again_and_cancel(self):
        self.run_wait(lambda stop: stop.wait(10) and (_ for _ in ()).throw(common.Cancelled()))
        self.pump(lambda: type(self.window.overlay.sheet).__name__ == "BrowserSheet")
        sheet = self.window.overlay.sheet
        self.assertIn("kc.example", sheet.body.text())
        buttons = {b.text(): b for b in sheet.findChildren(base.gui.QPushButton)}
        self.assertEqual(self.opened, [])  # vci already opened it: the panel does not open a second tab
        buttons["¿No se ha abierto? Ábrelo otra vez"].click()
        self.assertEqual(self.opened, ["https://kc.example/auth?x"])
        buttons["Cancelar"].click()
        self.pump(lambda: not self.window.busy)
        self.assertFalse(self.window.busy)

    def test_issued_shows_the_account_and_can_be_undone(self):
        record = {"_path": "/x/c1.enc", "configuration_id": "Legal", "display": {"name": "Legal person"},
                  "issuer": "https://kc.example"}
        self.window.records = [record]
        self.window.reload = lambda: None
        deleted = []
        self.addCleanup(setattr, base.gui, "delete_credential", base.gui.delete_credential)
        base.gui.delete_credential = deleted.append
        self.addCleanup(setattr, base.gui, "CredentialCard", base.gui.CredentialCard)
        base.gui.CredentialCard = lambda *a, **k: None
        self.window._issued([vci.IssuedCredential("Legal", Path("/x/c1.enc"), {}, "alice (alice@example.org)")])
        sheet = self.window.overlay.sheet
        self.assertIn("alice (alice@example.org)", sheet.body.text())
        buttons = {b.text(): b for b in sheet.findChildren(base.gui.QPushButton)}
        buttons["¿No es tu cuenta? Elimínala"].click()
        confirm = self.window.overlay.sheet
        {b.text(): b for b in confirm.findChildren(base.gui.QPushButton)}["Eliminar"].click()
        self.assertEqual(deleted, [record])

    def test_issued_without_account(self):
        self.window.reload = lambda: None
        self.window._issued([vci.IssuedCredential("Legal", Path("/x/none.enc"), {})])
        buttons = [b.text() for b in self.window.overlay.sheet.findChildren(base.gui.QPushButton)]
        self.assertNotIn("¿No es tu cuenta? Elimínala", buttons)

    def test_back_to_progress_when_the_browser_returns(self):
        self.run_wait(lambda stop: "http://127.0.0.1:1/callback?code=C")
        self.pump(lambda: not self.window.busy)
        self.assertEqual(self.result, "http://127.0.0.1:1/callback?code=C")


if __name__ == "__main__":
    unittest.main()

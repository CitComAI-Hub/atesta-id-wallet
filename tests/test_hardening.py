"""Regressions from the security and robustness review (0.5.1).  Run:  python -m unittest discover -s tests"""

import io
import json
import os
import stat
import subprocess
import sys
import time
import unittest
from unittest import mock
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import helpers as base  # noqa: E402  (sets ATESTA_ID_WALLET_HOME and the test language)
import requests  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import cli, common, desktop, i18n, jose, sdjwt, storage, vci, vp  # noqa: E402


def disclosure(*items):
    encoded = common.b64u(json.dumps(list(items)).encode())
    return encoded, sdjwt._sd_digest(encoded)


def sd_jwt(payload, *disclosures):
    issuer = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
    return issuer.sign_jwt({"typ": "dc+sd-jwt"}, payload) + "~" + "".join(d[0] + "~" for d in disclosures)


class JoseTests(unittest.TestCase):
    def test_malformed_jws_is_invalid_not_a_crash(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        for token in ("", "a.b", "a.b.c.d", "!!.??.##", common.b64u(b"[]") + ".e30.AA"):
            self.assertFalse(jose._verify_jws(token, key), token)

    def test_es256_needs_a_p256_key(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        signer = ec.generate_private_key(ec.SECP384R1())
        signing_input = f"{common.b64u_json({'alg': 'ES256'})}.{common.b64u_json({'a': 1})}"
        r, s = decode_dss_signature(signer.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        token = f"{signing_input}.{common.b64u(r.to_bytes(48, 'big') + s.to_bytes(48, 'big'))}"
        self.assertFalse(jose._verify_jws(token, signer.public_key()))  # says ES256 but the key is P-384
        p256 = ec.generate_private_key(ec.SECP256R1())
        self.assertTrue(jose._verify_jws(storage.HolderKey(p256).sign_jwt({}, {"a": 1}), p256.public_key()))

    def test_jwt_decode_of_garbage_is_a_wallet_error(self):
        for token in ("x.y.z", common.b64u(b"[1]") + "." + common.b64u(b"{}") + ".s"):
            with self.assertRaises(common.WalletError):
                common.jwt_decode_unverified(token)

    def test_jwe_needs_an_ecdh_es_key(self):
        n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": common.b64u(n.x.to_bytes(32, "big")),
               "y": common.b64u(n.y.to_bytes(32, "big"))}
        for keys in ([dict(jwk, alg="ECDH-ES+A128KW")], [dict(jwk, crv="secp256k1")], [{"kty": "RSA"}]):
            with self.assertRaisesRegex(common.WalletError, "direct_post.jwt"):
                jose.encrypt_response_jwe({}, {"client_metadata": {"jwks": {"keys": keys}}}, apv=None)
        jose.encrypt_response_jwe({}, {"client_metadata": {"jwks": {"keys": [dict(jwk, alg="ECDH-ES")]}}}, apv=None)


class SdJwtSafetyTests(unittest.TestCase):
    def test_duplicate_disclosure_rejected(self):
        email = disclosure("s1", "email", "a@b")
        with self.assertRaisesRegex(common.WalletError, "dos veces"):
            sdjwt.parse_sd_jwt(sd_jwt({"_sd": [email[1]]}, email, email))
        with self.assertRaisesRegex(common.WalletError, "dos veces"):
            sdjwt.parse_sd_jwt(sd_jwt({"_sd": [email[1]], "nested": {"_sd": [email[1]]}}, email))

    def test_disclosure_cannot_replace_a_visible_claim(self):
        fake = disclosure("s1", "iss", "https://attacker.example")
        with self.assertRaisesRegex(common.WalletError, "iss"):
            sdjwt.parse_sd_jwt(sd_jwt({"iss": "https://issuer.example", "_sd": [fake[1]]}, fake))

    def test_reserved_names_and_bad_encoding_rejected(self):
        for bad in (disclosure("s1", "_sd", "x"), disclosure("s1", "...", "x"), ("bm90LWpzb24", "")):
            with self.assertRaises(common.WalletError):
                sdjwt.parse_sd_jwt(sd_jwt({"_sd": [bad[1]]}, bad))

    def test_consent_shows_visible_claims_without_digests(self):
        street = disclosure("s1", "street", "Calle Mayor 1")
        sd = sdjwt.parse_sd_jwt(sd_jwt({"address": {"country": "ES", "_sd": [street[1]]}}, street))
        shown = {path: value for path, value, _ in sdjwt.disclosed_claims(sd, [])}
        self.assertEqual(shown, {"address": {"country": "ES"}})


class DcqlSelectionTests(unittest.TestCase):
    def setUp(self):
        self.holder = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        sd = sdjwt.parse_sd_jwt(base.make_sd_jwt(self.holder))
        self.record = {"format": "dc+sd-jwt", "_sd": sd, "_path": "/x/c.json"}

    def disclosed(self, match):
        token = vp.build_sd_jwt_presentation(self.record["_sd"], self.holder, audience="a", nonce="n",
                                             requested_paths=match.paths)
        return sorted(json.loads(common.b64u_decode(p))[1] for p in token.split("~")[1:-1])

    def test_without_claims_nothing_selective_is_disclosed(self):
        """OpenID4VP 1.0 §6.4.1: without 'claims' the verifier asks for no selective data."""
        match = vp.match_dcql({"credentials": [{"id": "q", "format": "dc+sd-jwt"}]}, [self.record], False)[0]
        self.assertEqual(match.paths, [])
        self.assertEqual(self.disclosed(match), [])

    def test_claim_sets_first_satisfiable_option(self):
        dcql = {"credentials": [{"id": "q", "format": "dc+sd-jwt", "claims": [
            {"id": "phone", "path": ["phone"]}, {"id": "mail", "path": ["email"]}, {"id": "first", "path": ["firstName"]},
        ], "claim_sets": [["phone"], ["mail"], ["first", "mail"]]}]}
        match = vp.match_dcql(dcql, [self.record], False)[0]
        self.assertEqual(match.paths, [["email"]])
        self.assertEqual(self.disclosed(match), ["email"])
        dcql["credentials"][0]["claim_sets"] = [["phone"]]
        with self.assertRaises(vp.NoMatchingCredential):
            vp.match_dcql(dcql, [self.record], False)

    def test_query_without_ids_is_an_error(self):
        with self.assertRaisesRegex(common.WalletError, "DCQL"):
            vp.match_dcql({"credentials": [{"format": "dc+sd-jwt"}]}, [self.record], False)


class RedirectAfterPresentationTests(unittest.TestCase):
    """The verifier's redirect_uri is opened in the browser: web addresses only."""

    def setUp(self):
        base.isolated_home(self)

    def send(self, redirect_uri):
        class Response:
            status_code = 200
            text = "{}"

            def json(self):
                return {"redirect_uri": redirect_uri}

        class Session:
            def post(self, *args, **kwargs):
                return Response()

        identity = vp.VerifierIdentity("x509_san_dns:v.example", "x509_san_dns", "v.example", "v.example")
        prepared = vp.PreparedPresentation({}, identity, "https://v.example/r", "direct_post", "n", [])
        return vp.send_presentation(Session(), prepared, {})

    def test_only_web_addresses_are_returned(self):
        self.assertEqual(self.send("https://v.example/done?x=1"), "https://v.example/done?x=1")
        self.assertEqual(self.send("http://localhost:8080/done"), "http://localhost:8080/done")
        # The last one is not even a URL: dropped too, the presentation was accepted all the same.
        for bad in ("file:///etc/passwd", "javascript:alert(1)", "http://v.example/done", ["x"], "smb://h/s",
                    "https://v.e]xample/done"):
            self.assertIsNone(self.send(bad), bad)


class StorageRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.home = base.isolated_home(self)

    def test_write_private_is_atomic_and_private(self):
        target = self.home / "config.json"
        storage.write_private(target, "uno")
        storage.write_private(target, "dos")
        self.assertEqual(target.read_text(), "dos")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual([p.name for p in self.home.iterdir()], ["config.json"])  # no temporary files

    def test_failed_write_keeps_the_old_file(self):
        target = self.home / "config.json"
        storage.write_private(target, '{"verifiers": {"a": 1}}')

        with self.assertRaises(TypeError):
            storage.write_private(target, object())  # fails while writing
        self.assertEqual(json.loads(target.read_text()), {"verifiers": {"a": 1}})
        self.assertEqual([p.name for p in self.home.iterdir()], ["config.json"])

    def test_credentials_in_the_same_second_do_not_overwrite(self):
        paths = {storage.save_credential(f"c{i}", fmt="x", issuer="https://i", configuration_id="same")
                 for i in range(3)}
        self.assertEqual(len(paths), 3)
        self.assertEqual(sorted(r["credential"] for r in storage.load_credentials()), ["c0", "c1", "c2"])

    def test_every_profile_lives_in_profiles(self):
        storage.HolderKey.load_or_create()
        storage.create_profile("work")
        self.assertEqual(storage.KEY_FILE, self.home / "profiles" / "default" / "holder_key.enc")
        self.assertEqual(storage.list_profiles(), ["default", "work"])
        if os.name == "posix":
            for folder in (self.home, self.home / "profiles", self.home / "profiles" / "default"):
                self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700, folder)

    def test_add_ca_does_not_replace_another_ca_with_the_same_file_name(self):
        folder_a, folder_b = self.home / "a", self.home / "b"
        for folder in (folder_a, folder_b):
            folder.mkdir()
            key = ec.generate_private_key(ec.SECP256R1())
            cert = base.make_cert(key, f"ca-{folder.name}", ca=True)
            from cryptography.hazmat.primitives import serialization
            (folder / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        first = storage.add_trusted_ca(folder_a / "ca.pem")
        second = storage.add_trusted_ca(folder_b / "ca.pem")
        self.assertNotEqual(first, second)
        self.assertEqual(storage.add_trusted_ca(folder_a / "ca.pem"), first)  # the same one: not duplicated
        self.assertEqual(len(list(storage.TRUST_DIR.glob("*.pem.enc"))), 2)
        (self.home / "bad.pem").write_text("no")
        with self.assertRaises(common.WalletError):
            storage.add_trusted_ca(self.home / "bad.pem")


class IssuanceChecksTests(unittest.TestCase):
    def test_offer_uri_must_be_https(self):
        with self.assertRaisesRegex(common.WalletError, "https"):
            vci.resolve_offer(None, "openid-credential-offer://?credential_offer_uri=http://issuer.example/o")

    def test_bad_offer_json_is_explained(self):
        for raw in ("{nope", "openid-credential-offer://?credential_offer=%5B1%5D"):
            with self.assertRaises(common.WalletError):
                vci.resolve_offer(None, raw)
        with self.assertRaisesRegex(common.WalletError, "credential_issuer"):
            vci.issue(None, '{"credential_configuration_ids": ["x"]}', vci.IssueOptions(), base.ScriptedPrompter())

    def test_display_follows_the_interface_language(self):
        displays = [{"name": "Town hall", "locale": "en"}, {"name": "Rådhus", "locale": "da"},
                    {"name": "Ayuntamiento", "locale": "es-ES"}]
        self.assertEqual(vci.pick_display(displays)["name"], "Ayuntamiento")  # the tests run in Spanish
        self.assertEqual(vci.pick_display(displays, ("da",))["name"], "Rådhus")
        self.assertEqual(vci.pick_display(displays[1:2], ("fr",))["name"], "Rådhus")

    def callback(self, url, as_meta=None):
        """authorization_code_flow with the return URL pasted by hand (--browser-login)."""
        prompter = base.ScriptedPrompter(texts=[url])
        captured = {}
        original = vci.secrets.token_bytes
        self.addCleanup(setattr, vci.secrets, "token_bytes", original)
        vci.secrets.token_bytes = lambda n: b"\x01" * n  # predictable state to build the URL
        captured["state"] = common.b64u(b"\x01" * 16)
        return vci.authorization_code_flow(
            None, {"authorization_endpoint": "https://as.example/auth", "issuer": "https://as.example", **(as_meta or {})},
            client_id="c", redirect_uri="https://as.example/cb", scopes=[], issuer_state=None,
            authorization_details=None, open_browser=False, browser_login=True, username=None, ui=prompter,
        )

    def test_callback_without_state_or_code_or_from_other_issuer(self):
        state = common.b64u(b"\x01" * 16)
        with self.assertRaisesRegex(common.WalletError, "state"):
            self.callback("https://as.example/cb?code=C")
        with self.assertRaisesRegex(common.WalletError, "código"):
            self.callback(f"https://as.example/cb?state={state}")
        with self.assertRaisesRegex(common.WalletError, "evil.example"):
            self.callback(f"https://as.example/cb?state={state}&code=C&iss=https%3A%2F%2Fevil.example")

    def test_password_form_over_http_refused(self):
        class Response:
            is_redirect, status_code, headers = False, 200, {}
            url = "https://kc.example/auth"
            text = ('<form action="http://kc.example/login"><input name="username" value=""/>'
                    '<input name="password" type="password"/></form>')

        class Session:
            def get(self, *args, **kwargs):
                return Response()

        prompter = base.ScriptedPrompter()
        prompter.login = lambda *a, **k: self.fail("no debe pedir la contraseña")
        with self.assertRaisesRegex(common.WalletError, "https"):
            vci.headless_login(Session(), "https://kc.example/auth", "https://kc.example/cb", "joan", prompter)


class IssuerMetadataTests(unittest.TestCase):
    """The issuer and authorization server metadata must belong to whoever makes the offer."""

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading

        cls.server = http.server.HTTPServer(("127.0.0.1", 0), base.FakeIssuer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        base.FakeIssuer.base = f"http://localhost:{cls.server.server_port}"
        base.FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        base.isolated_home(self)
        original = base.FakeIssuer._json
        self.addCleanup(setattr, base.FakeIssuer, "_json", original)
        self.patch = {}

        def patched(handler, data, code=200):
            return original(handler, dict(data, **self.patch.get(handler.path, {})), code)

        base.FakeIssuer._json = patched

    def issue(self):
        offer = f"openid-credential-offer://?credential_offer_uri={base.FakeIssuer.base}/offer"
        return vci.issue(requests.Session(), offer, vci.IssueOptions(), base.ScriptedPrompter(texts=["1234"]))

    def test_issuer_metadata_of_another_issuer(self):
        self.patch["/.well-known/openid-credential-issuer"] = {"credential_issuer": "https://other.example"}
        with self.assertRaisesRegex(common.WalletError, "other.example"):
            self.issue()

    def test_authorization_server_metadata_of_another_server(self):
        self.patch["/.well-known/oauth-authorization-server"] = {"issuer": "https://other.example"}
        with self.assertRaisesRegex(common.WalletError, "other.example"):
            self.issue()

    def test_endpoint_without_https(self):
        self.patch["/.well-known/oauth-authorization-server"] = {"token_endpoint": "http://plain.example/token"}
        with self.assertRaisesRegex(common.WalletError, "https"):
            self.issue()
        self.assertEqual(storage.load_credentials(), [])


class CliErrorTests(unittest.TestCase):
    def test_unexpected_exception_is_reported_not_a_traceback(self):
        base.isolated_home(self)
        self.addCleanup(i18n.set_language, "es")  # main() picks the system language again
        original = cli.cmd_list
        self.addCleanup(setattr, cli, "cmd_list", original)

        def broken(_args):
            raise KeyError("credential_endpoint")

        cli.cmd_list = broken
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = cli.main(["list"])
        self.assertEqual(code, 1)
        self.assertIn("KeyError", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


class QrPreferenceTests(unittest.TestCase):
    def test_wallet_link_wins_over_a_web_link(self):
        codes = ["https://shop.example", "openid4vp://?request_uri=https://v/r"]
        self.assertEqual(desktop._wallet_qr(codes, "x"), "openid4vp://?request_uri=https://v/r")
        self.assertEqual(desktop._wallet_qr(["https://v/r"], "x"), "https://v/r")


@unittest.skipIf(base.gui is None, "PySide6 not installed")
class GuiSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        base.isolated_home(self)
        self.addCleanup(setattr, base.gui, "_screenshot_dirs", base.gui._screenshot_dirs)
        base.gui._screenshot_dirs = lambda: []

    def test_external_text_is_never_html(self):
        from PySide6.QtCore import Qt

        from atesta_id_wallet.gui import sheets, widgets

        self.assertEqual(widgets.label("<b>x</b>").textFormat(), Qt.PlainText)
        self.assertEqual(widgets.esc("<b>a & b</b>\nc"), "&lt;b&gt;a &amp; b&lt;/b&gt;<br>c")
        holder = storage.HolderKey.load_or_create()
        storage.save_credential(base.make_sd_jwt(holder), fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
        record = storage.load_credentials()[0]
        name = '<span style="color:green">✔ Banco</span>'
        identity = vp.VerifierIdentity(name, "", name, name, trust="unverified")
        prepared = vp.PreparedPresentation({}, identity, "https://v/r", "direct_post", "n",
                                           [vp.Match("q", record, [["email"]])])
        sheet = sheets.ConsentSheet(prepared, lambda ok: None)
        self.assertEqual(sheet.title.textFormat(), Qt.PlainText)
        self.assertIn(name, sheet.title.text())
        login = sheets.LoginSheet("<i>h</i>", "<i>u</i>", False, lambda v: None)
        self.assertNotIn("<i>", login.body.text())

    def test_profile_is_remembered(self):
        storage.create_profile("work")
        window = base.gui.MainWindow()
        self.addCleanup(window.close)
        window.switch_profile("work")
        self.assertEqual(base.gui._choose_startup_profile(None), "work")
        storage.remove_profile("work")
        self.assertEqual(base.gui._choose_startup_profile(None), "default")

    def test_switching_profile_during_a_flow_is_ignored(self):
        storage.create_profile("work")
        window = base.gui.MainWindow()
        self.addCleanup(window.close)
        window.busy = True
        window.profile_combo.setCurrentText("work")
        self.assertEqual(storage.PROFILE, "default")
        self.assertEqual(window.profile_combo.currentText(), "default")

    def test_second_instance_forwards_the_link(self):
        window = base.gui.MainWindow()
        self.addCleanup(window.close)
        received = []
        window.process = received.append
        name = f"atesta-id-wallet-test-{os.getpid()}-{time.time_ns()}"
        server = base.gui.listen_for_instances(window, name)
        self.addCleanup(server.close)
        self.assertFalse(base.gui.forward_to_running_instance("x", name + "-nobody"))
        # The second instance is another process, as in real use (in a thread of this process, the
        # sender's blocking wait would keep the window from running and answering).
        code = ("import sys; from PySide6.QtCore import QCoreApplication; app = QCoreApplication([]); "
                "from atesta_id_wallet.gui.app import forward_to_running_instance as f; "
                f"sys.exit(0 if f('openid4vp://?request_uri=https://v/r', {name!r}) else 3)")
        root = str(Path(__file__).resolve().parent.parent)
        env = {**os.environ, "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
        sender = subprocess.Popen([sys.executable, "-c", code], env=env)
        self.addCleanup(sender.kill)
        deadline = time.time() + 20
        while (not received or sender.poll() is None) and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        forwarded = [sender.poll() == 0]
        self.assertEqual(forwarded, [True])
        self.assertEqual(received, ["openid4vp://?request_uri=https://v/r"])


if __name__ == "__main__":
    unittest.main()


class ReviewNovember2026Tests(unittest.TestCase):
    """Security review of the DPoP / logos / retry branch (November 2026)."""

    def test_shared_hosting_is_not_named_after_the_platform(self):
        self.assertEqual(common.site_of("https://evil.github.io/realms/x"), "evil.github.io")
        self.assertEqual(common.site_of("https://kc.city.example.eu"), "example.eu")

    def test_local_http_only_when_allowed(self):
        saved = os.environ.pop("ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP", None)
        self.addCleanup(lambda: os.environ.__setitem__("ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP", saved) if saved else None)
        with self.assertRaises(common.WalletError):
            common.require_https("http://localhost:8080/offer", "credential_offer_uri")
        os.environ["ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP"] = "1"
        common.require_https("http://localhost:8080/offer", "credential_offer_uri")

    def test_logo_never_on_a_local_address_of_a_remote_issuer(self):
        calls = []

        class Session:
            def get(self, *args, **kwargs):
                calls.append(args)
                raise AssertionError("must not be fetched")

        for uri in ("https://127.0.0.1/logo.png", "https://192.168.1.10/l.png", "https://router.localhost/l.png",
                    "https://[::1]/l.png", "https://169.254.169.254/latest/meta-data"):
            self.assertEqual(vci.fetch_logo(Session(), uri, "https://kc.example.org/realms/x"), {}, uri)
        self.assertEqual(calls, [])

    def test_damaged_unlock_counter_does_not_block(self):
        base.isolated_home(self)
        storage.save_settings({"unlock_failures": {storage.PROFILE: {"count": "x", "until": "soon"}}})
        self.assertEqual((storage.unlock_wait(), storage.attempts_before_wait()), (0, storage.FREE_ATTEMPTS))
        storage.save_settings({"unlock_failures": ["nonsense"]})
        self.assertEqual(storage.unlock_wait(), 0)



class RedactionTests(unittest.TestCase):
    """Logs and technical details are pasted into support requests: no codes, tokens or credentials."""

    JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"

    def test_secrets_are_removed(self):
        cases = {
            "https://kc/auth?response_type=code&state=S1&issuer_state=IS1&code_challenge=CC":
                "https://kc/auth?response_type=code&state=<redacted>&issuer_state=<redacted>&code_challenge=CC",
            "http://127.0.0.1:5000/callback?session_state=SS&code=C1&iss=x":
                "http://127.0.0.1:5000/callback?session_state=<redacted>&code=<redacted>&iss=x",
            '{"pre-authorized_code": "P1", "tx_code": {"length": 4}}':
                '{"pre-authorized_code": "<redacted>", "tx_code": {"length": 4}}',
            "{'access_token': 'T1', 'token_type': 'DPoP'}": "{'access_token': '<redacted>', 'token_type': 'DPoP'}",
            '{"refresh_token": "R1': '{"refresh_token": "<redacted>"',  # cut short by a [:200]
            "Authorization: Bearer abcdefghijklmnopqrst": "Authorization: Bearer <redacted>",
            f"proof {self.JWT}": "proof <JWT <redacted>>",
            f"credential {self.JWT}~WyJzIiwiZW1haWwiLCJhQGIuYyJd~": "credential <JWT <redacted>>",
            "jwt eyJhbGciOiJFUzI1NiJ9.eyJzdW": "jwt <JWT <redacted>>",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(common.redact(text), expected)
                self.assertEqual(common.redact(expected), expected)

    def test_useful_details_are_kept(self):
        for text in ('{"error": "invalid_grant", "error_description": "Code not valid"}',
                     "response_uri: https://v.example/resp (direct_post) nonce=n1",
                     "grant-type:pre-authorized_code", "client_id=x509_san_dns:v.example&response_type=code"):
            with self.subTest(text=text):
                self.assertEqual(common.redact(text), text)

    def test_log_and_debug_are_redacted(self):
        seen = []
        old = (common.LOG_HANDLER, common.VERBOSE)
        common.LOG_HANDLER, common.VERBOSE = (lambda message, is_debug: seen.append(message)), True
        try:
            common.debug("GET https://i/cb?code=C2")
            common.log(f"token {self.JWT}")
        finally:
            common.LOG_HANDLER, common.VERBOSE = old
        self.assertEqual(seen, ["GET https://i/cb?code=<redacted>", "token <JWT <redacted>>"])

    def test_cli_error_is_redacted(self):
        err = io.StringIO()
        with mock.patch.object(cli, "_run", side_effect=common.WalletError("bad callback ?code=C3")), \
                redirect_stderr(err):
            try:
                self.assertEqual(cli.main([]), 1)
            finally:
                i18n.set_language("es")  # main() picks the language from the settings
        self.assertNotIn("C3", err.getvalue())


class SecondReviewTests(unittest.TestCase):
    """Security and robustness review after 0.12.0."""

    def setUp(self):
        base.isolated_home(self)

    @staticmethod
    def serve(test, handler):
        import http.server
        import threading

        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        test.addCleanup(server.server_close)
        test.addCleanup(server.shutdown)
        return f"http://localhost:{server.server_port}"

    def test_wildcard_path_also_selects_the_array_element(self):
        """DCQL ['roles', null, 'name']: the element's own disclosure goes with the claim inside it."""
        name = disclosure("s1", "name", "admin")
        element = disclosure("s2", {"_sd": [name[1]]})
        roles = disclosure("s3", "roles", [{"...": element[1]}])
        orphan = disclosure("s9", "secret", "x")
        sd = sdjwt.parse_sd_jwt(sd_jwt({"_sd": [roles[1]]}, name, element, roles, orphan))
        selected = {d.encoded for d in sdjwt.select_disclosures(sd, [["roles", None, "name"]])}
        self.assertEqual(selected, {name[0], element[0], roles[0]})
        # The index 0 is not the claim "0", and a wildcard only stands for array elements.
        self.assertEqual(sdjwt.select_disclosures(sd, [["roles", "0"]]), [d for d in sd.disclosures if d.name == "roles"])
        # Disclosing everything still leaves out what the credential does not refer to.
        self.assertNotIn(orphan[0], [d.encoded for d in sdjwt.select_disclosures(sd, None)])
        self.assertEqual(len(sdjwt.select_disclosures(sd, None)), 3)

    def test_malformed_x5c_is_a_wallet_error(self):
        from atesta_id_wallet import trust

        key = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        for x5c in (["not base64 !!"], [common.b64u(b"not a certificate")], "abc", [1], {"a": 1}):
            token = key.sign_jwt({"x5c": x5c}, {"client_id": "x509_san_dns:v.example"})
            with self.assertRaisesRegex(common.WalletError, "x5c", msg=x5c):
                trust.check_request_object(token, "x509_san_dns:v.example")
            with self.assertRaisesRegex(common.WalletError, "x5c", msg=x5c):
                vci.issuer_keys(None, {"x5c": x5c}, "https://issuer.example", "https://issuer.example", {})

    def test_short_rsa_keys_do_not_verify(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        for bits, valid in ((1024, False), (2048, True)):
            key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            signing_input = f"{common.b64u_json({'alg': 'RS256'})}.{common.b64u_json({'a': 1})}"
            signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
            self.assertEqual(jose._verify_jws(f"{signing_input}.{common.b64u(signature)}", key.public_key()), valid)

    def test_redirects_never_leave_https(self):
        import http.server

        class Redirecting(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "http://192.0.2.1/metadata" if self.path == "/out" else "/out")
                self.end_headers()

        url = self.serve(self, Redirecting)
        with self.assertRaisesRegex(common.WalletError, "https.*192.0.2.1"):
            common.new_session().get(f"{url}/start", timeout=5)

    def test_a_redirect_that_is_only_read_is_not_a_request(self):
        """The check for the wallet's own client reads a redirect to http://127.0.0.1 without following it."""
        saved = os.environ.pop("ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP", None)
        self.addCleanup(lambda: os.environ.__setitem__("ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP", saved) if saved else None)

        class Keycloak(requests.adapters.BaseAdapter):
            def send(self, request, **kwargs):
                response = requests.Response()
                response.status_code, response.url, response.request = 302, request.url, request
                response.headers["Location"] = "http://127.0.0.1:49152/callback?error=invalid_request"
                response.raw = io.BytesIO(b"")
                return response

            def close(self):
                pass

        def session(*_args, **_kwargs):
            http = common.new_session()
            http.mount("https://", Keycloak())
            return http

        response = session().get("https://kc.example/auth", allow_redirects=False, timeout=5)
        self.assertEqual(response.status_code, 302)
        with mock.patch.object(vci, "new_session", session):
            self.assertFalse(vci.wallet_client_available(session(), {"authorization_endpoint": "https://kc.example/auth"}))
        with self.assertRaisesRegex(common.WalletError, "https"):  # followed, it would be a request in clear text
            session().get("https://kc.example/auth", timeout=5)
        with self.assertRaisesRegex(common.WalletError, "https"):
            common.new_session().get("http://kc.example/metadata", timeout=5)

    def test_presentation_is_not_posted_again_after_a_redirect(self):
        import http.server

        posts = []

        class Verifier(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):  # noqa: N802
                posts.append(self.path)
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(307)
                self.send_header("Location", "/elsewhere")
                self.end_headers()

        url = self.serve(self, Verifier)
        identity = vp.VerifierIdentity("x509_san_dns:localhost", "x509_san_dns", "localhost", "localhost")
        prepared = vp.PreparedPresentation({}, identity, f"{url}/response", "direct_post", "n", [])
        with self.assertRaisesRegex(common.WalletError, "redirección"):
            vp.send_presentation(common.new_session(), prepared, {"vp_token": "secret"})
        self.assertEqual(posts, ["/response"])
        self.assertEqual(storage.load_history(), [])  # nothing was accepted

    def test_request_values_must_be_text(self):
        class Session:
            pass

        for change in ({"nonce": ["n"]}, {"nonce": 7}, {"response_uri": {"a": 1}}, {"state": ["s"]},
                       {"client_id": 5}):
            request = {"client_id": "redirect_uri:https://v.example/r", "response_mode": "direct_post",
                       "response_uri": "https://v.example/r", "nonce": "n", "dcql_query": {}, **change}
            with mock.patch.object(vp, "fetch_request", return_value=(
                    request, vp.VerifierIdentity("redirect_uri:https://v.example/r", "redirect_uri",
                                                 "https://v.example/r", "v.example"))):
                with self.assertRaises(common.WalletError, msg=change):
                    vp.prepare_presentation(Session(), "openid4vp://?x", [], allow_unverified=True)
        token = storage.HolderKey(ec.generate_private_key(ec.SECP256R1())).sign_jwt({}, {"client_id": 5})

        class Response:
            status_code, text = 200, token

        class Fetching:
            def get(self, *args, **kwargs):
                return Response()

        with self.assertRaisesRegex(common.WalletError, "client_id"):
            vp.fetch_request(Fetching(), "openid4vp://?request_uri=https://v.example/request")

    def test_presentation_definition_from_the_verifier_is_checked(self):
        holder = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        record = {"format": "dc+sd-jwt", "_sd": sdjwt.parse_sd_jwt(base.make_sd_jwt(holder)), "_path": "/x/c.json"}

        def definition(flt):
            return {"input_descriptors": [{"id": "d", "constraints": {"fields": [{"path": ["$.email"], "filter": flt}]}}]}

        self.assertEqual(len(vp.match_presentation_definition(definition({"pattern": "@example"}), [record], False)), 1)
        for bad in (definition({"pattern": "("}), definition({"pattern": "a" * 300}), definition({"pattern": 5}),
                    definition("x"), {"input_descriptors": "x"}, {"input_descriptors": [5]}, [],
                    {"input_descriptors": [{"id": "d", "constraints": {"fields": [{"path": [1]}]}}]}):
            with self.assertRaisesRegex(common.WalletError, "presentation_definition", msg=bad):
                vp.match_presentation_definition(bad, [record], False)

    def test_one_time_code_only_goes_to_the_authorization_server(self):
        for action, expected in (("https://evil.example/otp", "evil.example"), ("http://kc.example/otp", "https")):
            class Response:
                is_redirect, status_code, headers = False, 200, {}
                url = "https://kc.example/auth"
                text = f'<form action="{action}"><input name="otp" value=""/></form>'

            class Session:
                def get(self, *args, **kwargs):
                    return Response()

                def post(self, *args, **kwargs):
                    raise AssertionError("the code must not be sent")

            prompter = base.ScriptedPrompter()
            prompter.text = lambda *a, **k: self.fail("no debe pedir el código")
            with self.assertRaisesRegex(common.WalletError, expected):
                vci.headless_login(Session(), "https://kc.example/auth", "https://kc.example/cb", "joan", prompter)

    def test_login_does_not_follow_a_redirect_out_of_https(self):
        class Response:
            is_redirect, status_code, text = True, 302, ""
            headers = {"Location": "http://kc.example/login"}

        class Session:
            calls = 0

            def get(self, *args, **kwargs):
                Session.calls += 1
                return Response()

        with self.assertRaisesRegex(common.WalletError, "https"):
            vci.headless_login(Session(), "https://kc.example/auth", "https://kc.example/cb", "joan",
                               base.ScriptedPrompter())
        self.assertEqual(Session.calls, 1)

    def test_issuer_keys_are_never_fetched_in_clear_text(self):
        class Session:
            def get(self, url, **kwargs):
                raise AssertionError(f"must not be fetched: {url}")

        for uri in ("http://issuer.example/jwks", "ftp://issuer.example/jwks", None, 5):
            with self.assertRaises(common.WalletError, msg=uri):
                vci._fetch_jwks(Session(), uri)
        key = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "kid": "k1", "x": common.b64u(key.x.to_bytes(32, "big")),
               "y": common.b64u(key.y.to_bytes(32, "big"))}
        self.assertEqual(len(vci._jwks_keys({"keys": [jwk, "x", 5, {"kty": "oct"}]}, "k1")), 1)
        for jwks in (None, [], {"keys": "x"}, {"keys": {"a": 1}}, "x"):
            self.assertEqual(vci._jwks_keys(jwks, None), [], jwks)

    def test_names_from_outside_cannot_rewrite_the_screen(self):
        self.assertEqual(common.printable("ok\x1b[2J\x1b[1;1Hbank.example‮gro.live\x07\n"),
                         "ok�[2J�[1;1Hbank.example�gro.live�\n")
        self.assertEqual(common.clean_text("  Ayuntamiento\n\tde ‮València\x1b[0m  "), "Ayuntamiento de València [0m")
        self.assertEqual(len(common.clean_text("x" * 500)), 80)
        for value in (None, 5, ["a"], {"name": "x"}, "", " \n "):
            self.assertIsNone(common.clean_text(value), value)
        display = vci.credential_display({"display": [{"name": ["a list"], "description": 7,
                                                       "background_color": "#12107c\x1b[31m"}]}, "LegalPerson", "Issuer")
        self.assertEqual((display["name"], "description" in display), ("Legal Person", False))
        self.assertNotIn("\x1b", display["background_color"])

        holder = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        record = {"format": "dc+sd-jwt", "_sd": sdjwt.parse_sd_jwt(base.make_sd_jwt(holder)), "_path": "/x/c.json",
                  "display": {"name": "Card\x1b[1A\x1b[2K", "issuer_name": "Issuer"}}
        identity = vp.VerifierIdentity("x509_hash:abc", "x509_hash", "abc", "bank.example\x1b[2A\x1b[2K", trust="new")
        prepared = vp.PreparedPresentation({}, identity, "https://v.example/r", "direct_post", "n",
                                           [vp.Match("q", record, [["email"]])])
        out = io.StringIO()
        from contextlib import redirect_stdout

        with redirect_stdout(out), self.assertRaises(common.WalletError):  # no terminal: nothing is sent
            base.ui.TerminalPrompter().consent(prepared)
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("PRIMERA VEZ", out.getvalue())

    def test_damaged_settings_file_gives_the_defaults(self):
        for content in ("[1, 2]", '"text"', "null", "{broken"):
            storage.write_private(storage.settings_file(), content)
            self.assertEqual(storage.load_settings(), {}, content)
            self.assertEqual(storage.unlock_wait(), 0)

    def test_status_check_never_stops_a_presentation(self):
        from atesta_id_wallet import status

        record = {"_path": "/x/c.json", "display": {"name": "Card"}}
        failed = []
        with mock.patch.object(status, "due", return_value=True), \
                mock.patch.object(status, "check", side_effect=ValueError("bad list")):
            self.assertEqual(status.refresh(None, [record], failed=failed), [])
        self.assertEqual(failed, [record])


class AuditNovember2026Tests(unittest.TestCase):
    """Regressions from the security audit of November 2026 (0.13.0)."""

    def setUp(self):
        base.isolated_home(self)

    def test_every_spelling_of_a_local_address(self):
        for host in ("localhost.", "127.1", "2130706433", "0x7f000001", "100.64.0.1", "::ffff:127.0.0.1",
                     "224.0.0.1", "0.0.0.0", "fe80::1", "10.1.2.3", "[::1]"):
            self.assertTrue(common.is_local_host(host), host)
        for host in ("8.8.8.8", "example.org", "keycloak.pgtec-vrain-dataspace.eu", "2001:4860::1", "1e100.net"):
            self.assertFalse(common.is_local_host(host), host)

    def test_release_version_is_only_digits_and_dots(self):
        from atesta_id_wallet import updates

        def answer(tag):
            response = mock.Mock(status_code=200, headers={})
            response.json.return_value = {"tag_name": tag, "html_url": updates.RELEASES_PAGE, "assets": []}
            return response

        with mock.patch.object(updates.requests, "get", return_value=answer("v99.1.0")):
            self.assertEqual(updates.latest_release().version, "99.1.0")
        for tag in ("v99.0.0/../../x", "99.0.0-evil", "v99", "99.0.0 "):
            with mock.patch.object(updates.requests, "get", return_value=answer(tag)):
                with self.assertRaises(common.WalletError, msg=tag):
                    updates.latest_release()
        with self.assertRaises(common.WalletError):
            updates.download_update(updates.Release("99.0.0/../x", updates.RELEASES_PAGE), "appimage")

    def test_missing_credential_is_matched_without_contacting_the_issuers(self):
        meta = {"credential_configurations_supported": {"LegalPersonCredential": {"vct": "LegalPerson"}},
                "display": [{"name": "City"}]}
        storage.save_config({"issuers": {"https://i.example": {"catalog": vci._catalog(meta, "https://i.example")},
                                         "https://j.example": {}}})
        session = mock.Mock()
        session.get.side_effect = AssertionError("an issuer was contacted")
        self.assertEqual(vci.known_issuer_for(session, ["LegalPerson"]),
                         ("https://i.example", "LegalPersonCredential", "City"))
        # An issuer used before the catalog existed is asked once, and its answer kept.
        with mock.patch.object(vci, "_get_first_json", return_value=meta) as fetch:
            self.assertIsNone(vci.known_issuer_for(session, ["Other"]))
            self.assertIsNone(vci.known_issuer_for(session, ["Other"]))
        self.assertEqual(fetch.call_count, 1)
        self.assertIn("catalog", storage.load_config()["issuers"]["https://j.example"])

    def test_windows_clipboard_runs_powershell_by_full_path(self):
        with mock.patch.object(desktop.sys, "platform", "win32"), mock.patch.dict(os.environ, {"SystemRoot": r"C:\Win"}):
            program = desktop._clipboard_commands()[0][0]
        self.assertTrue(program.endswith("powershell.exe") and "Win" in program, program)

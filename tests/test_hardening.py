"""Regresiones de la revisión de seguridad y robustez (0.5.1).  Ejecutar:  python -m unittest discover -s tests"""

import io
import json
import os
import stat
import sys
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_offline as base  # noqa: E402  (fija ATESTA_ID_WALLET_HOME y el idioma de las pruebas)
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import cli, common, desktop, i18n, jose, sdjwt, storage, vci, vp  # noqa: E402


POSIX_ONLY = unittest.skipIf(os.name != "posix", "Windows: los datos los protege la ACL del perfil, no los bits de modo")


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
        self.assertFalse(jose._verify_jws(token, signer.public_key()))  # dice ES256 pero la clave es P-384
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
        """OpenID4VP 1.0 §6.4.1: sin 'claims' el verificador no pide datos selectivos."""
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
    """El redirect_uri del verificador se abre en el navegador: solo direcciones web."""

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
        for bad in ("file:///etc/passwd", "javascript:alert(1)", "http://v.example/done", ["x"], "smb://h/s"):
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
        self.assertEqual([p.name for p in self.home.iterdir()], ["config.json"])  # sin temporales

    def test_failed_write_keeps_the_old_file(self):
        target = self.home / "config.json"
        storage.write_private(target, '{"verifiers": {"a": 1}}')

        with self.assertRaises(TypeError):
            storage.write_private(target, object())  # falla al escribir
        self.assertEqual(json.loads(target.read_text()), {"verifiers": {"a": 1}})
        self.assertEqual([p.name for p in self.home.iterdir()], ["config.json"])

    def test_credentials_in_the_same_second_do_not_overwrite(self):
        paths = {storage.save_credential(f"c{i}", fmt="x", issuer="https://i", configuration_id="same")
                 for i in range(3)}
        self.assertEqual(len(paths), 3)
        self.assertEqual(sorted(r["credential"] for r in storage.load_credentials()), ["c0", "c1", "c2"])

    @POSIX_ONLY
    def test_harden_permissions_only_touches_wallet_files(self):
        other = self.home / "notes.txt"
        other.write_text("x")
        os.chmod(other, 0o644)
        storage.write_private(storage.CONFIG_FILE, "{}")
        os.chmod(storage.CONFIG_FILE, 0o644)
        storage.harden_permissions()
        self.assertEqual(stat.S_IMODE(other.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(storage.CONFIG_FILE.stat().st_mode), 0o600)

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
        self.assertEqual(storage.add_trusted_ca(folder_a / "ca.pem"), first)  # el mismo: no se duplica
        self.assertEqual(len(list(storage.TRUST_DIR.glob("*.pem"))), 2)
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
        self.assertEqual(vci.pick_display(displays)["name"], "Ayuntamiento")  # las pruebas van en español
        self.assertEqual(vci.pick_display(displays, ("da",))["name"], "Rådhus")
        self.assertEqual(vci.pick_display(displays[1:2], ("fr",))["name"], "Rådhus")

    def callback(self, url, as_meta=None):
        """authorization_code_flow con la URL de vuelta pegada a mano (--browser-login)."""
        prompter = base.ScriptedPrompter(texts=[url])
        captured = {}
        original = vci.secrets.token_bytes
        self.addCleanup(setattr, vci.secrets, "token_bytes", original)
        vci.secrets.token_bytes = lambda n: b"\x01" * n  # state predecible para construir la URL
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
    """La metadata del emisor y del servidor de autorización deben ser las de quien hace la oferta."""

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
        return vci.issue(base.requests.Session(), offer, vci.IssueOptions(), base.ScriptedPrompter(texts=["1234"]))

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
        self.addCleanup(i18n.set_language, "es")  # main() vuelve a elegir el idioma del sistema
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


@unittest.skipIf(base.gui is None, "PySide6 no instalado")
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
        self.assertTrue(base.gui.forward_to_running_instance("openid4vp://?request_uri=https://v/r", name))
        deadline = time.time() + 5
        while not received and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.assertEqual(received, ["openid4vp://?request_uri=https://v/r"])


if __name__ == "__main__":
    unittest.main()

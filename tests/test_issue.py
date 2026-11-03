"""Receiving credentials (OpenID4VCI): login, issuance, DPoP, logos, issuer names.

Run:  python -m unittest discover -s tests
"""

import base64
import getpass
import http.server
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (  # noqa: E402  (first: sets the test environment)
    FakeDPoPIssuer, FakeIssuer, FakeKeycloak, ScriptedPrompter, isolated_home, make_sd_jwt, png_bytes,
)
import requests  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import common, sdjwt, storage, vci  # noqa: E402


class HeadlessLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeKeycloak)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.redirect = "https://kc/realms/p/account/oid4vci-callback"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self._getpass = getpass.getpass

    def tearDown(self):
        getpass.getpass = self._getpass

    def test_login_with_consent(self):
        getpass.getpass = lambda prompt="": "good"
        url, username = vci.headless_login(requests.Session(), f"{self.base}/auth?state=ST1", self.redirect, "joan")
        self.assertEqual(username, "joan")
        self.assertIn("code=THECODE", url)
        self.assertIn("state=ST1", url)

    def test_password_never_sent_to_other_host(self):
        FakeKeycloak.state["phishing"] = True
        self.addCleanup(FakeKeycloak.state.pop, "phishing")
        getpass.getpass = lambda prompt="": self.fail("no debe pedir la contraseña")
        with self.assertRaisesRegex(common.WalletError, "evil.example"):
            vci.headless_login(requests.Session(), f"{self.base}/auth?state=ST3", self.redirect, "joan")

    def test_wrong_password(self):
        getpass.getpass = lambda prompt="": "bad"
        with self.assertRaisesRegex(common.WalletError, "Invalid username or password"):
            vci.headless_login(requests.Session(), f"{self.base}/auth?state=ST2", self.redirect, "joan")


class IssuedCredentialTests(unittest.TestCase):
    def setUp(self):
        self.holder = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        self._issuer_keys = vci._issuer_keys
        self.addCleanup(setattr, vci, "_issuer_keys", self._issuer_keys)

    def test_bad_signature_and_wrong_binding(self):
        vci._issuer_keys = lambda *a: ([ec.generate_private_key(ec.SECP256R1()).public_key()], True)
        with self.assertRaisesRegex(common.WalletError, "firma"):
            vci.verify_issued_credential(None, make_sd_jwt(self.holder), self.holder, "did:web:issuer.example", {})
        vci._issuer_keys = lambda *a: ([], False)
        stranger = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaisesRegex(common.WalletError, "otra clave"):
            vci.verify_issued_credential(None, make_sd_jwt(stranger), self.holder, "did:web:issuer.example", {})

    def test_did_web_issuer_offered_by_keycloak(self):
        """Keycloak offers the credential but iss is a did:web: it is verified with the DID document."""
        issuer_key = ec.generate_private_key(ec.SECP256R1())
        did = "did:web:issuer.example"
        n = issuer_key.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": common.b64u(n.x.to_bytes(32, "big")), "y": common.b64u(n.y.to_bytes(32, "big"))}
        document = {"id": did, "verificationMethod": [{"id": did, "type": "JsonWebKey2020", "publicKeyJwk": jwk}]}

        class Response:
            status_code, text = 200, ""

            def json(self):
                return document

        class Session:
            urls = []

            def get(self, url, **kwargs):
                self.urls.append(url)
                return Response()

        sd = sdjwt.parse_sd_jwt(make_sd_jwt(self.holder))
        payload = dict(sd.payload)
        raw = storage.HolderKey(issuer_key).sign_jwt({"typ": "dc+sd-jwt", "kid": did}, payload)
        raw += "~" + "".join(d.encoded + "~" for d in sd.disclosures)
        session = Session()
        vci.verify_issued_credential(session, raw, self.holder, "https://kc.example/realms/provider", {})
        self.assertEqual(session.urls, ["https://issuer.example/.well-known/did.json"])
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        document["verificationMethod"][0]["publicKeyJwk"] = dict(
            jwk, x=common.b64u(other.x.to_bytes(32, "big")), y=common.b64u(other.y.to_bytes(32, "big")))
        with self.assertRaisesRegex(common.WalletError, "firma"):
            vci.verify_issued_credential(Session(), raw, self.holder, "https://kc.example/realms/provider", {})

    def test_humanize(self):
        self.assertEqual(common.humanize("LegalPersonCredential"), "Legal Person Credential")
        self.assertEqual(common.humanize("first_name"), "First name")

    def test_did_web_url(self):
        self.assertEqual(vci.did_web_url("did:web:a.example"), "https://a.example/.well-known/did.json")
        self.assertEqual(vci.did_web_url("did:web:a.example%3A8443:u:alice"), "https://a.example:8443/u/alice/did.json")


class IssueFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeIssuer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        FakeIssuer.base = f"http://localhost:{cls.server.server_port}"
        FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        isolated_home(self)
        self.offer = f"openid-credential-offer://?credential_offer_uri={FakeIssuer.base}/offer"

    def test_pre_authorized_with_tx_code(self):
        prompter = ScriptedPrompter(texts=["1234"])
        issued = vci.issue(requests.Session(), self.offer, vci.IssueOptions(), prompter)
        self.assertEqual([(c.configuration_id, c.claims["email"]) for c in issued], [("Legal", "user@example.org")])
        self.assertTrue(any("primera vez" in q for q in prompter.asked))
        record = storage.load_credentials()[0]
        self.assertEqual(storage.credential_name(record), "Persona jurídica")
        self.assertEqual(storage.credential_issuer_name(record), "Ayuntamiento")
        self.assertEqual(record["display"]["background_color"], "#12355b")
        self.assertEqual(base64.b64decode(record["display"]["logo"]), png_bytes())  # stored, not fetched later
        self.assertEqual(record["display"]["logo_type"], "image/png")
        event = storage.load_history()[0]
        self.assertEqual((event["type"], event["party"], event["credentials"]),
                         ("issued", "Ayuntamiento", ["Persona jurídica"]))
        # Known issuer: it does not ask again.
        prompter = ScriptedPrompter(texts=["1234"], confirms=False)
        vci.issue(requests.Session(), self.offer, vci.IssueOptions(), prompter)
        self.assertFalse(any("primera vez" in q for q in prompter.asked))

    def test_new_issuer_declined(self):
        with self.assertRaisesRegex(common.WalletError, "Cancelado"):
            vci.issue(requests.Session(), self.offer, vci.IssueOptions(), ScriptedPrompter(confirms=False))
        self.assertEqual(storage.load_credentials(), [])

    def test_signature_from_other_key_rejected(self):
        real = FakeIssuer.key
        self.addCleanup(setattr, FakeIssuer, "key", real)
        original_do_get = FakeIssuer.do_GET
        impostor = ec.generate_private_key(ec.SECP256R1())

        def do_get(handler):
            if handler.path == "/jwks":  # publishes another key: the signature will not match
                FakeIssuer.key = impostor
                try:
                    return original_do_get(handler)
                finally:
                    FakeIssuer.key = real
            return original_do_get(handler)

        FakeIssuer.do_GET = do_get
        self.addCleanup(setattr, FakeIssuer, "do_GET", original_do_get)
        with self.assertRaisesRegex(common.WalletError, "firma"):
            vci.issue(requests.Session(), self.offer, vci.IssueOptions(), ScriptedPrompter(texts=["1234"]))
        self.assertEqual(storage.load_credentials(), [])


class DPoPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeDPoPIssuer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        FakeIssuer.base = FakeDPoPIssuer.base = f"http://localhost:{cls.server.server_port}"
        FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        isolated_home(self)
        FakeDPoPIssuer.seen = []
        self.offer = f"openid-credential-offer://?credential_offer_uri={FakeDPoPIssuer.base}/offer"

    def test_token_and_credential_bound_with_dpop(self):
        issued = vci.issue(requests.Session(), self.offer, vci.IssueOptions(), ScriptedPrompter(texts=["1234"]))
        self.assertEqual([c.configuration_id for c in issued], ["Legal"])
        # Token: without nonce, retried with the server's; credential: the nonce from the nonce endpoint.
        self.assertEqual(FakeDPoPIssuer.seen, [("/token", None), ("/token", "N1"), ("/credential", "N2")])

    def test_no_dpop_option(self):
        with self.assertRaisesRegex(common.WalletError, "DPoP proof is missing"):
            vci.issue(requests.Session(), self.offer, vci.IssueOptions(dpop=False), ScriptedPrompter(texts=["1234"]))


class LogoTests(unittest.TestCase):
    def data_uri(self, data, mime="image/png"):
        return f"data:{mime};base64," + base64.b64encode(data).decode()

    def test_raster_data_uri_accepted(self):
        logo = vci.fetch_logo(requests.Session(), self.data_uri(png_bytes()))
        self.assertEqual((base64.b64decode(logo["logo"]), logo["logo_type"]), (png_bytes(), "image/png"))

    def test_svg_and_unknown_rejected(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        self.assertEqual(vci.fetch_logo(requests.Session(), self.data_uri(svg, "image/svg+xml")), {})
        self.assertEqual(vci.fetch_logo(requests.Session(), self.data_uri(b"hello")), {})

    def test_too_big_rejected(self):
        big = png_bytes() + b"\0" * vci.LOGO_MAX_BYTES
        self.assertEqual(vci.fetch_logo(requests.Session(), self.data_uri(big)), {})

    def test_plain_http_rejected(self):
        self.assertEqual(vci.fetch_logo(requests.Session(), "http://example.org/logo.png"), {})

    def test_data_uri_not_stored_twice(self):
        stored = vci._stored_display({"name": "X", "logo_uri": "data:image/png;base64,AAAA"}, {"logo": "AAAA"})
        self.assertEqual(stored, {"name": "X", "logo": "AAAA"})


class IssuerNameTests(unittest.TestCase):
    def test_site_of(self):
        self.assertEqual(common.site_of("https://keycloak-ciudadania.pgtec-vrain-dataspace.eu/realms/p"),
                         "pgtec-vrain-dataspace.eu")
        self.assertEqual(common.site_of("https://kc.city.gov.uk/realms/p"), "city.gov.uk")
        self.assertEqual(common.site_of("https://example.org"), "example.org")
        self.assertEqual(common.site_of("http://localhost:8080/x"), "localhost")
        self.assertEqual(common.site_of("http://127.0.0.1:8080/x"), "127.0.0.1")

    def test_stored_host_shown_as_site(self):
        issuer = "https://keycloak-ciudadania.pgtec-vrain-dataspace.eu/realms/provider"
        old = {"issuer": issuer, "display": {"issuer_name": "keycloak-ciudadania.pgtec-vrain-dataspace.eu"}}
        self.assertEqual(storage.credential_issuer_name(old), "pgtec-vrain-dataspace.eu")
        named = {"issuer": issuer, "display": {"issuer_name": "Ayuntamiento"}}
        self.assertEqual(storage.credential_issuer_name(named), "Ayuntamiento")


class WalletInitiatedTests(unittest.TestCase):
    def setUp(self):
        isolated_home(self)

    def _capture(self, meta=None):
        calls = []
        original_issue, original_get = vci.issue, vci._get_first_json
        vci.issue = lambda session, raw, options, ui: calls.append(json.loads(raw)) or []
        vci._get_first_json = lambda session, urls: meta
        self.addCleanup(setattr, vci, "issue", original_issue)
        self.addCleanup(setattr, vci, "_get_first_json", original_get)
        return calls

    def test_builds_offer_without_issuer_state(self):
        calls = self._capture({"credential_configurations_supported": {"ServiceCredential": {}}})
        vci.issue_from_issuer(requests.Session(), "https://kc.example/realms/p/", [], vci.IssueOptions(),
                              ScriptedPrompter())
        self.assertEqual(calls, [{"credential_issuer": "https://kc.example/realms/p",
                                  "credential_configuration_ids": ["ServiceCredential"],
                                  "grants": {"authorization_code": {}}}])

    def test_several_credentials_need_a_choice(self):
        self._capture({"credential_configurations_supported": {"A": {}, "B": {}}})
        with self.assertRaisesRegex(common.WalletError, "--credential: A, B"):
            vci.issue_from_issuer(requests.Session(), "https://kc.example/realms/p", [], vci.IssueOptions(),
                                  ScriptedPrompter())

    def _bound_offer(self, direct):
        """FakeIssuer with an authorization_code offer that Keycloak ties to another wallet's client."""
        calls = []

        def flow(session, as_meta, *, issuer_state, ui, **kwargs):
            calls.append((issuer_state, session, ui.login("kc.example", None, ask_username=True)))
            if issuer_state:
                exc = common.WalletError(
                    "POST https://kc/token -> HTTP 400: {\"error\":\"invalid_authorization_details\","
                    "\"error_description\":\"Credential offer target client 'lissi' different "
                    "from login client 'account-console'\"}")
                exc.username = "joan"
                raise exc
            return direct()

        original = vci.authorization_code_flow
        vci.authorization_code_flow = flow
        self.addCleanup(setattr, vci, "authorization_code_flow", original)
        server = http.server.HTTPServer(("127.0.0.1", 0), FakeIssuer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        saved = FakeIssuer.base, FakeIssuer.key
        self.addCleanup(lambda: (setattr(FakeIssuer, "base", saved[0]), setattr(FakeIssuer, "key", saved[1])))
        FakeIssuer.base = f"http://localhost:{server.server_port}"
        FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())
        original_get = FakeIssuer.do_GET

        def do_get(handler):
            if handler.path == "/.well-known/oauth-authorization-server":
                return handler._json({"issuer": FakeIssuer.base, "token_endpoint": FakeIssuer.base + "/token",
                                      "authorization_endpoint": FakeIssuer.base + "/auth",
                                      "jwks_uri": FakeIssuer.base + "/jwks"})
            return original_get(handler)

        FakeIssuer.do_GET = do_get
        self.addCleanup(setattr, FakeIssuer, "do_GET", original_get)
        offer = json.dumps({"credential_issuer": FakeIssuer.base, "credential_configuration_ids": ["Legal"],
                            "grants": {"authorization_code": {"issuer_state": "x"}}})
        return offer, calls

    def test_offer_for_another_client_retried_without_offer(self):
        offer, calls = self._bound_offer(lambda: ({"access_token": "AT", "token_type": "Bearer"}, None))
        prompter = ScriptedPrompter(texts=["joan"])
        prompter.secret = lambda prompt: prompter.asked.append(prompt) or "pw"
        first = requests.Session()
        issued = vci.issue(first, offer, vci.IssueOptions(), prompter)
        # The same credential, asked for without issuer_state and without the SSO cookie of the first
        # login (Keycloak would reuse that client session and its issuer_state note).
        self.assertEqual([state for state, _, _ in calls], ["x", None])
        self.assertIs(calls[0][1], first)
        self.assertIsNot(calls[1][1], first)
        # One login for the user: the retry replays it (in memory, this issuance only).
        self.assertEqual([login for _, _, login in calls], [("joan", "pw"), ("joan", "pw")])
        self.assertEqual(sum("Contraseña" in str(q) for q in prompter.asked), 1)
        self.assertEqual([c.configuration_id for c in issued], ["Legal"])
        self.assertEqual(sum("offer" in str(q).lower() or "primera vez" in str(q) for q in prompter.asked), 1)
        self.assertEqual(storage.load_config()["issuers"][FakeIssuer.base]["username"], "joan")

    def test_login_replay_once_same_host(self):
        inner = ScriptedPrompter(texts=["ana", "ana"])
        inner.secret = lambda prompt: "pw"
        replay = vci._LoginReplay(inner)
        self.assertEqual(replay.login("kc", None, ask_username=True), ("ana", "pw"))
        replay.armed = True
        self.assertEqual(replay.login("other", None, ask_username=True), ("ana", "pw"))  # other host: asked
        self.assertEqual(len(inner.asked), 2)
        replay.armed = True
        self.assertEqual(replay.login("other", None, ask_username=True), ("ana", "pw"))  # replayed
        self.assertEqual(len(inner.asked), 2)
        self.assertFalse(replay.armed)
        replay.forget()
        self.assertIsNone(replay.saved)

    def test_offer_for_another_client_and_no_direct_issuance(self):
        def refused():
            raise common.WalletError("User 'joan' does not have verifiable credential 'Legal'.")

        offer, calls = self._bound_offer(refused)
        prompter = ScriptedPrompter(texts=["joan"])
        prompter.secret = lambda prompt: "pw"
        with self.assertRaisesRegex(common.WalletError, "'lissi'.*does not have verifiable credential"):
            vci.issue(requests.Session(), offer, vci.IssueOptions(), prompter)
        self.assertEqual([state for state, _, _ in calls], ["x", None])
        self.assertEqual(storage.load_credentials(), [])


if __name__ == "__main__":
    unittest.main()

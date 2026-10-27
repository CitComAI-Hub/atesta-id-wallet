"""Pruebas sin red de oid4vc_wallet.  Ejecutar:  python -m unittest discover -s tests"""

import base64
import datetime
import getpass
import http.server
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

os.environ["OID4VC_WALLET_HOME"] = tempfile.mkdtemp(prefix="oid4vc-wallet-test-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from oid4vc_wallet import cli, common, desktop, i18n, jose, sdjwt, storage, trust, ui, vci, vp  # noqa: E402

# Las aserciones sobre mensajes están en español: así se ejercita también su catálogo.
i18n.set_language("es")


def make_sd_jwt(holder: storage.HolderKey) -> str:
    issuer = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))

    def disclosure(*items):
        encoded = common.b64u(json.dumps(list(items)).encode())
        return encoded, sdjwt._sd_digest(encoded)

    email = disclosure("s1", "email", "user@example.org")
    first = disclosure("s2", "firstName", "Joan")
    role = disclosure("s3", "admin")
    roles = disclosure("s4", "roles", [{"...": role[1]}])
    payload = {
        "iss": "did:web:issuer.example", "vct": "LegalPersonCredential", "_sd_alg": "sha-256",
        "_sd": [email[1], first[1], roles[1]], "cnf": {"jwk": holder.public_jwk},
    }
    jwt = issuer.sign_jwt({"typ": "dc+sd-jwt"}, payload)
    return jwt + "~" + "~".join(d[0] for d in (email, first, role, roles)) + "~"


class SdJwtTests(unittest.TestCase):
    def setUp(self):
        self.holder = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        self.sd = sdjwt.parse_sd_jwt(make_sd_jwt(self.holder))
        self.record = {"format": "dc+sd-jwt", "_sd": self.sd, "_path": "/x/cred.json"}

    def test_claims_reconstructed(self):
        self.assertEqual(self.sd.claims["email"], "user@example.org")
        self.assertEqual(self.sd.claims["roles"], ["admin"])

    def test_selective_disclosure_and_kb_jwt(self):
        dcql = {"credentials": [{
            "id": "legal", "format": "dc+sd-jwt", "meta": {"vct_values": ["LegalPersonCredential"]},
            "claims": [{"path": ["email"]}, {"path": ["roles"]}],
        }]}
        match = vp.match_dcql(dcql, [self.record], False)[0]
        presentation = vp.build_sd_jwt_presentation(
            match.record["_sd"], self.holder, audience="x509_san_dns:v.example", nonce="n1",
            requested_paths=match.paths,
        )
        parts = presentation.split("~")
        names = {json.loads(common.b64u_decode(p))[1] if len(json.loads(common.b64u_decode(p))) == 3 else "elem"
                 for p in parts[1:-1]}
        self.assertEqual(names, {"email", "roles", "elem"})
        header, payload = common.jwt_decode_unverified(parts[-1])
        self.assertEqual(header["typ"], "kb+jwt")
        self.assertEqual(payload["sd_hash"], sdjwt._sd_digest(presentation[: presentation.rfind("~") + 1]))
        self.assertEqual(payload["nonce"], "n1")

    def test_credential_sets_pick_one_option(self):
        query = {"format": None, "claims": [{"path": ["firstName"]}],
                 "meta": {"vct_values": ["LegalPersonCredential"]}}
        dcql = {
            "credentials": [dict(query, id="dc", format="dc+sd-jwt"), dict(query, id="vc", format="vc+sd-jwt")],
            "credential_sets": [{"options": [["dc"], ["vc"]], "required": True}],
        }
        self.assertEqual([m.query_id for m in vp.match_dcql(dcql, [self.record], False)], ["dc"])
        dcql["credentials"] = dcql["credentials"][1:]
        dcql["credential_sets"] = [{"options": [["vc"]]}]
        self.assertEqual([m.query_id for m in vp.match_dcql(dcql, [self.record], False)], ["vc"])

    def test_presentation_exchange(self):
        pd = {"id": "pd", "input_descriptors": [{"id": "d1", "constraints": {"fields": [
            {"path": ["$.vct"], "filter": {"const": "LegalPersonCredential"}}, {"path": ["$.email"]}]}}]}
        self.assertEqual(vp.match_presentation_definition(pd, [self.record], False)[0].query_id, "d1")


class RequestObjectTests(unittest.TestCase):
    def setUp(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "v.example")])
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime.datetime(2025, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("v.example")]), False)
            .sign(key, hashes.SHA256())
        )
        x5c = [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]
        self.token = storage.HolderKey(key).sign_jwt({"x5c": x5c}, {"client_id": "x509_san_dns:v.example"})

    def test_valid(self):
        trust.check_request_object(self.token, "x509_san_dns:v.example")

    def test_san_mismatch(self):
        with self.assertRaises(common.WalletError):
            trust.check_request_object(self.token, "x509_san_dns:evil.example")

    def test_bad_signature(self):
        bad = self.token[:-4] + ("AAAA" if not self.token.endswith("AAAA") else "BBBB")
        with self.assertRaises(common.WalletError):
            trust.check_request_object(bad, "x509_san_dns:v.example")


class JweTests(unittest.TestCase):
    def test_roundtrip(self):
        key = ec.generate_private_key(ec.SECP256R1())
        n = key.public_key().public_numbers()
        request = {"client_metadata": {
            "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "use": "enc", "kid": "k1",
                               "x": common.b64u(n.x.to_bytes(32, "big")), "y": common.b64u(n.y.to_bytes(32, "big"))}]},
            "encrypted_response_enc_values_supported": ["A256GCM"],
        }}
        jwe = jose.encrypt_response_jwe({"vp_token": "abc"}, request, apv="n1")
        protected, _, iv, ciphertext, tag = jwe.split(".")
        epk = json.loads(common.b64u_decode(protected))["epk"]
        ephemeral = ec.EllipticCurvePublicNumbers(
            int.from_bytes(common.b64u_decode(epk["x"]), "big"), int.from_bytes(common.b64u_decode(epk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        cek = jose._concat_kdf(key.exchange(ec.ECDH(), ephemeral), "A256GCM", b"", b"n1", 256)
        plain = AESGCM(cek).decrypt(
            common.b64u_decode(iv), common.b64u_decode(ciphertext) + common.b64u_decode(tag), protected.encode()
        )
        self.assertEqual(json.loads(plain), {"vp_token": "abc"})


LOGIN_PAGE = """<html><form id="kc-form-login" action="/login-actions/authenticate?session_code=a&amp;execution=b"
method="post"><input id="username" name="username" value="" type="text"/>
<input id="password" name="password" type="password"/><input type="hidden" name="credentialId"/>
<input type="submit" name="login" value="Sign In"/></form>%s</html>"""
CONSENT_PAGE = """<form class="form-actions" id="kc-oauth" action="/login-actions/consent?x=1" method="POST">
<input type="hidden" name="code" value="cc"><input name="accept" id="kc-login" type="submit" value="Yes"/></form>"""


class FakeKeycloak(http.server.BaseHTTPRequestHandler):
    state = {}

    def log_message(self, *args):
        pass

    def _send(self, code, body="", location=None):
        self.send_response(code)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):  # noqa: N802
        FakeKeycloak.state["s"] = parse_qs(urlsplit(self.path).query)["state"][0]
        page = LOGIN_PAGE % ""
        if FakeKeycloak.state.get("phishing"):
            page = page.replace('action="/login-actions', 'action="https://evil.example/login-actions')
        self._send(200, page)

    def do_POST(self):  # noqa: N802
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        if self.path.startswith("/login-actions/authenticate"):
            if body.get("password") != ["good"]:
                return self._send(200, LOGIN_PAGE % '<span id="input-error">Invalid username or password.</span>')
            return self._send(200, CONSENT_PAGE)
        self._send(302, location="https://kc/realms/p/account/oid4vci-callback?state=%s&code=THECODE"
                   % FakeKeycloak.state["s"])


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
        # Impr Pant deja un PNG en el portapapeles: no debe romper la lectura.
        self.assertIsNone(self.check(b"\xff\xfe\x00 binario"))
        self.assertIsNone(self.check(b"\x89PNG\r\n\x1a\n sin QR"))


def isolated_home(test: unittest.TestCase) -> Path:
    """Directorio de datos propio para el test; restaura el perfil al terminar."""
    home = Path(tempfile.mkdtemp(prefix="oid4vc-wallet-test-"))
    saved = storage.BASE_DIR, storage.PROFILES_DIR
    storage.BASE_DIR, storage.PROFILES_DIR = home, home / "profiles"
    storage.set_profile("default")

    def restore():
        storage.BASE_DIR, storage.PROFILES_DIR = saved
        storage.set_profile("default")

    test.addCleanup(restore)
    return home


def make_cert(subject_key, dns, issuer_key=None, issuer_name=None, ca=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
    builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
        .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1)).not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
    return builder.sign(issuer_key or subject_key, hashes.SHA256())


def der_b64(cert):
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


class VerifierTrustTests(unittest.TestCase):
    def setUp(self):
        isolated_home(self)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = make_cert(self.ca_key, "Test CA", ca=True)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.leaf = make_cert(self.key, "v.example", self.ca_key, self.ca.subject)
        self.token = storage.HolderKey(self.key).sign_jwt(
            {"x5c": [der_b64(self.leaf), der_b64(self.ca)]}, {"client_id": "x509_san_dns:v.example"})

    def add_ca(self):
        storage.write_private(storage.TRUST_DIR / "ca.pem", self.ca.public_bytes(serialization.Encoding.PEM).decode())

    def test_new_then_pinned_then_changed(self):
        identity = trust.check_request_object(self.token, "x509_san_dns:v.example")
        self.assertEqual(identity.trust, "new")
        trust.remember_verifier(identity)
        self.assertEqual(trust.check_request_object(self.token, "x509_san_dns:v.example").trust, "pinned")
        other_key = ec.generate_private_key(ec.SECP256R1())
        other = storage.HolderKey(other_key).sign_jwt({"x5c": [der_b64(make_cert(other_key, "v.example"))]}, {})
        self.assertEqual(trust.check_request_object(other, "x509_san_dns:v.example").trust, "changed")

    def test_trusted_ca(self):
        self.add_ca()
        self.assertEqual(trust.check_request_object(self.token, "x509_san_dns:v.example").trust, "trusted")

    def test_response_uri_must_match_dns_unless_trusted(self):
        identity = trust.check_request_object(self.token, "x509_san_dns:v.example")
        trust.check_response_uri(identity, "https://v.example/response")
        with self.assertRaisesRegex(common.WalletError, "evil.example"):
            trust.check_response_uri(identity, "https://evil.example/response")
        with self.assertRaisesRegex(common.WalletError, "https"):
            trust.check_response_uri(identity, "http://v.example/response")
        self.add_ca()
        trusted = trust.check_request_object(self.token, "x509_san_dns:v.example")
        trust.check_response_uri(trusted, "https://other.example/response")

    def test_x509_hash(self):
        client_id = "x509_hash:" + jose.cert_fingerprint(self.leaf)
        identity = trust.check_request_object(self.token, client_id)
        self.assertEqual((identity.name, identity.trust), ("v.example", "new"))
        with self.assertRaises(common.WalletError):
            trust.check_request_object(self.token, "x509_hash:AAAA")

    def test_unsigned_and_expired(self):
        unsigned = common.b64u_json({"alg": "none"}) + "." + common.b64u_json({}) + ".sig"
        self.assertEqual(trust.check_request_object(unsigned, "x509_san_dns:v.example").trust, "unverified")
        expired = storage.HolderKey(self.key).sign_jwt({"x5c": [der_b64(self.leaf)]}, {"exp": 1})
        with self.assertRaisesRegex(common.WalletError, "caducado"):
            trust.check_request_object(expired, "x509_san_dns:v.example")


class DisclosureAndChoiceTests(unittest.TestCase):
    def setUp(self):
        self.holder = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        self.sd = sdjwt.parse_sd_jwt(make_sd_jwt(self.holder))

    def test_disclosed_claims_shows_only_requested(self):
        shown = {path: value for path, value, _ in sdjwt.disclosed_claims(self.sd, [["email"], ["roles"]])}
        self.assertEqual(shown, {"email": "user@example.org", "roles": ["admin"]})

    def test_orphan_disclosure_never_revealed(self):
        orphan = common.b64u(json.dumps(["s9", "secret", "x"]).encode())
        sd = sdjwt.parse_sd_jwt(make_sd_jwt(self.holder) + orphan + "~")
        self.assertNotIn(orphan, [d.encoded for d in sdjwt.select_disclosures(sd, [["email"]])])

    def test_chooser_and_expired(self):
        old = {"format": "dc+sd-jwt", "_sd": self.sd, "_path": "/x/old.json"}
        new = {"format": "dc+sd-jwt", "_sd": sdjwt.parse_sd_jwt(make_sd_jwt(self.holder)), "_path": "/x/new.json"}
        dcql = {"credentials": [{"id": "q", "format": "dc+sd-jwt", "claims": [{"path": ["email"]}]}]}
        seen = []

        def choose(qid, candidates):
            seen.append(len(candidates))
            return candidates[1]

        self.assertIs(vp.match_dcql(dcql, [new, old], False, choose)[0].record, old)
        self.assertEqual(seen, [2])
        new["_sd"].payload["exp"] = 1
        self.assertIs(vp.match_dcql(dcql, [new, old], False)[0].record, old)


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
        """Keycloak ofrece la credencial pero el iss es un did:web: se verifica con el documento DID."""
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


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home(self)
        self._getpass = getpass.getpass
        self.addCleanup(setattr, getpass, "getpass", self._getpass)

    @unittest.skipIf(os.name != "posix", "Windows: los datos los protege la ACL del perfil, no los bits de modo")
    def test_private_permissions(self):
        storage.HolderKey.load_or_create()
        path = storage.save_credential("x", fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(storage.DATA_DIR.stat().st_mode & 0o777, 0o700)
        self.assertEqual(storage.KEY_FILE.stat().st_mode & 0o777, 0o600)

    def test_profiles_are_separate(self):
        storage.HolderKey.load_or_create()
        default_key = storage.KEY_FILE.read_bytes()
        cli.cmd_profiles(type("A", (), {"action": "add", "name": "work"})())
        storage.set_profile("work")
        self.assertEqual(storage.DATA_DIR, self.home / "profiles" / "work")
        storage.HolderKey.load_or_create()
        self.assertNotEqual(storage.KEY_FILE.read_bytes(), default_key)
        self.assertEqual(storage.list_profiles(), ["default", "work"])
        with self.assertRaises(common.WalletError):
            storage.profile_dir("../escape")

    def test_reset_default_keeps_other_profiles(self):
        storage.HolderKey.load_or_create()
        storage.ensure_data_dir(storage.PROFILES_DIR / "work")
        cli.cmd_reset(type("A", (), {"yes": True})())
        self.assertFalse(storage.KEY_FILE.exists())
        self.assertTrue((storage.PROFILES_DIR / "work").is_dir())

    def test_backup_restore_roundtrip(self):
        holder = storage.HolderKey.load_or_create()
        storage.save_credential(make_sd_jwt(holder), fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
        getpass.getpass = lambda prompt="": "contraseña-larga"
        target = self.home / "copia.bak"
        cli.cmd_backup(type("A", (), {"file": str(target), "yes": True})())
        with self.assertRaisesRegex(common.WalletError, "ya tiene datos"):
            cli.cmd_restore(type("A", (), {"file": str(target)})())
        storage.ensure_data_dir(storage.PROFILES_DIR / "nuevo")
        storage.set_profile("nuevo")
        getpass.getpass = lambda prompt="": "mala"
        with self.assertRaisesRegex(common.WalletError, "incorrecta"):
            cli.cmd_restore(type("A", (), {"file": str(target)})())
        getpass.getpass = lambda prompt="": "contraseña-larga"
        cli.cmd_restore(type("A", (), {"file": str(target)})())
        self.assertEqual(storage.HolderKey.load_or_create().public_jwk, holder.public_jwk)
        self.assertEqual(len(storage.load_credentials()), 1)

    def test_pop_profile(self):
        argv = ["--verbose", "--profile", "work", "list"]
        self.assertEqual(cli._pop_profile(argv), "work")
        self.assertEqual(argv, ["--verbose", "list"])
        self.assertEqual(cli._pop_profile(["--profile=x"]), "x")


class FakeVerifier(http.server.BaseHTTPRequestHandler):
    token = ""
    received = []

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/oauth-authz-req+jwt")
        self.end_headers()
        self.wfile.write(FakeVerifier.token.encode())

    def do_POST(self):  # noqa: N802
        FakeVerifier.received.append(parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")


def verifier_request(base, key, cert, response_uri=None, signed=True):
    """Publica en FakeVerifier una petición DCQL (email) y devuelve el enlace openid4vp://."""
    payload = {
        "client_id": "x509_san_dns:localhost", "response_type": "vp_token", "response_mode": "direct_post",
        "response_uri": response_uri or f"{base}/response", "nonce": "n1",
        "dcql_query": {"credentials": [{"id": "q", "format": "dc+sd-jwt", "claims": [{"path": ["email"]}]}]},
    }
    FakeVerifier.token = (storage.HolderKey(key).sign_jwt({"x5c": [der_b64(cert)]}, payload) if signed
                          else json.dumps(payload))
    return f"openid4vp://?client_id=x509_san_dns:localhost&request_uri={base}/request"


class PresentFlowTests(unittest.TestCase):
    """present de principio a fin contra un verificador local (x509_san_dns:localhost)."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeVerifier)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://localhost:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        isolated_home(self)
        holder = storage.HolderKey.load_or_create()
        storage.save_credential(make_sd_jwt(holder), fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
        FakeVerifier.received = []
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = make_cert(self.key, "localhost")

    def request(self, response_uri=None, signed=True):
        return verifier_request(self.base, self.key, self.cert, response_uri, signed)

    def present(self, link, *extra):
        return cli._run(["present", "--request", link, "--no-browser", *extra])

    def test_yes_sends_only_requested_claim(self):
        self.assertEqual(self.present(self.request(), "--yes"), 0)
        token = json.loads(FakeVerifier.received[0]["vp_token"][0])["q"][0]
        names = [json.loads(common.b64u_decode(p))[1] for p in token.split("~")[1:-1]]
        self.assertEqual(names, ["email"])
        self.assertIn("x509_san_dns:localhost", storage.load_config()["verifiers"])
        event = storage.load_history()[0]
        self.assertEqual((event["type"], event["party"], event["claims"]), ("presented", "localhost", ["email"]))

    def test_missing_credential_is_explained(self):
        for path in storage.CRED_DIR.glob("*.json"):
            path.unlink()
        with self.assertRaisesRegex(vp.NoMatchingCredential, "localhost pide una credencial que no tienes"):
            self.present(self.request(), "--yes")

    def test_no_tty_without_yes_sends_nothing(self):
        with self.assertRaisesRegex(common.WalletError, "confirmación"):
            self.present(self.request())
        self.assertEqual(FakeVerifier.received, [])

    def test_declined_is_recorded(self):
        self.addCleanup(setattr, ui, "confirm", ui.confirm)
        ui.confirm = lambda *a, **k: False
        with self.assertRaisesRegex(common.WalletError, "Cancelado"):
            self.present(self.request())
        self.assertEqual(FakeVerifier.received, [])
        self.assertEqual(storage.load_history()[0]["type"], "declined")

    def test_unsigned_request_refused(self):
        with self.assertRaisesRegex(common.WalletError, "allow-unverified"):
            self.present(self.request(signed=False), "--yes")
        with self.assertRaisesRegex(common.WalletError, "no verificado"):
            self.present(self.request(signed=False), "--yes", "--allow-unverified")
        self.assertEqual(FakeVerifier.received, [])

    def test_response_uri_on_other_host_refused(self):
        with self.assertRaisesRegex(common.WalletError, "127.0.0.1"):
            self.present(self.request(f"http://127.0.0.1:{self.server.server_port}/r"), "--yes")
        self.assertEqual(FakeVerifier.received, [])


def qr_png(text: str, path: Path | None = None) -> bytes:
    """Captura simulada: QR en medio de una 'pantalla' blanca."""
    import io

    import zxingcpp
    from PIL import Image

    qr = Image.fromarray(zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode).to_image(scale=4))
    screen = Image.new("RGB", (1280, 800), "white")
    screen.paste(qr.convert("RGB"), (500, 250))
    buffer = io.BytesIO()
    screen.save(buffer, format="PNG")
    if path:
        path.write_bytes(buffer.getvalue())
    return buffer.getvalue()


class I18nTests(unittest.TestCase):
    PACKAGE = Path(__file__).resolve().parent.parent / "oid4vc_wallet"

    def tearDown(self):
        i18n.set_language("es")

    @classmethod
    def extract(cls):
        """Textos fuente de tr()/N_() y pares de tr_n() en todo el paquete."""
        import ast

        messages, plurals, dynamic = set(), set(), []
        for path in cls.PACKAGE.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.args):
                    continue
                first = node.args[0]
                if node.func.id in ("tr", "N_", "tr_n") and isinstance(first, ast.JoinedStr):
                    dynamic.append(f"{path.name}:{node.lineno}")
                elif node.func.id in ("tr", "N_") and isinstance(first, ast.Constant):
                    messages.add(first.value)
                elif node.func.id == "tr_n" and isinstance(first, ast.Constant):
                    plurals.add((first.value, node.args[1].value))
        return messages, plurals, dynamic

    @staticmethod
    def fields(text):
        import string

        return {name for _, name, _, _ in string.Formatter().parse(text) if name}

    def test_catalogs_complete_and_consistent(self):
        messages, plurals, dynamic = self.extract()
        self.assertEqual(dynamic, [], "tr() con f-string: nunca coincidiría con el catálogo")
        self.assertGreater(len(messages), 300)
        for code in ("es", "da"):
            catalog = i18n.load_catalog(code)
            with self.subTest(code=code):
                self.assertEqual(set(catalog["messages"]) - messages, set(), "entradas sobrantes")
                self.assertEqual(messages - set(catalog["messages"]), set(), "faltan traducciones")
                self.assertEqual(set(catalog["plurals"]), {s for s, _ in plurals})
                for source, translated in catalog["messages"].items():
                    self.assertTrue(translated, source)
                    self.assertEqual(self.fields(translated), self.fields(source), source)
                for singular, plural in plurals:
                    forms = catalog["plurals"][singular]
                    self.assertEqual(len(forms), 2, singular)
                    for form, source in zip(forms, (singular, plural)):
                        # {n} es opcional; el resto de marcadores, los mismos que en el original
                        self.assertEqual(self.fields(form) - {"n"}, self.fields(source) - {"n"}, singular)

    def test_fallback_plural_and_formatting(self):
        i18n.set_language("en")
        self.assertEqual(i18n.tr("Wallet"), "Wallet")
        self.assertEqual(i18n.tr("not in any catalog {x}", x=1), "not in any catalog 1")
        self.assertEqual(i18n.tr_n("{n} credential", "{n} credentials", 2), "2 credentials")
        i18n.set_language("da")
        self.assertEqual(i18n.tr("Wallet"), "Wallet")
        self.assertEqual(i18n.tr("Settings"), "Indstillinger")
        self.assertEqual(i18n.tr_n("{n} credential", "{n} credentials", 1), "1 legitimation")
        self.assertEqual(i18n.tr("not in any catalog"), "not in any catalog")  # fallback al inglés
        self.assertEqual(i18n.set_language("fr"), "en")

    def test_system_language(self):
        saved = {k: os.environ.pop(k, None) for k in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")}
        self.addCleanup(lambda: [os.environ.__setitem__(k, v) for k, v in saved.items() if v is not None])
        os.environ["LANG"] = "da_DK.UTF-8"
        self.assertEqual(i18n.system_language(), "da")
        os.environ["LANGUAGE"] = "fr:es"
        self.assertEqual(i18n.system_language(), "es")
        self.assertEqual(i18n.system_language("es_ES"), "es")
        self.assertEqual(i18n.resolve("auto", "en_GB"), "en")
        self.assertEqual(i18n.resolve("da", "es_ES"), "da")
        self.assertEqual(i18n.resolve(None, "pt_BR"), i18n.system_language())

    def test_cli_language_setting_is_persistent(self):
        isolated_home(self)
        self.assertEqual(cli.main(["language", "da"]), 0)
        self.assertEqual(storage.load_settings()["language"], "da")
        self.assertEqual(i18n.current(), "da")
        cli.main(["language", "auto"])
        self.assertEqual(storage.load_settings()["language"], "auto")


class QrTests(unittest.TestCase):
    def setUp(self):
        self._clipboard_bytes = desktop._clipboard_bytes
        self.addCleanup(setattr, desktop, "_clipboard_bytes", self._clipboard_bytes)
        self.dir = Path(tempfile.mkdtemp(prefix="oid4vc-qr-"))

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


class FakeWinreg:
    """winreg mínimo en memoria para probar el registro de enlaces en Windows."""
    HKEY_CURRENT_USER, REG_SZ = "HKCU", 1

    def __init__(self):
        self.keys = {}

    def CreateKey(self, parent, sub):  # noqa: N802
        path = sub if parent == self.HKEY_CURRENT_USER else f"{parent}\\{sub}"
        self.keys.setdefault(path, {})
        registry = self

        class Key(str):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def set(self, name, value):
                registry.keys[str(self)][name] = value

        return Key(path)

    def SetValueEx(self, key, name, _reserved, _type, value):  # noqa: N802
        key.set(name, value)

    def DeleteKey(self, _root, path):  # noqa: N802
        if path not in self.keys or any(k.startswith(path + "\\") for k in self.keys):
            raise FileNotFoundError(path)
        del self.keys[path]


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
        desktop._launcher = lambda gui=False: [rf"C:\Program Files\Wallet\oid4vc-wallet{'-gui' if gui else ''}.exe"]
        self._gui_available = desktop.gui_available
        self.addCleanup(setattr, desktop, "gui_available", self._gui_available)
        desktop.gui_available = lambda: False

    def test_gui_handler_has_no_pause(self):
        desktop.gui_available = lambda: True
        desktop.cmd_install_handler(None)
        command = self.reg.keys[r"Software\Classes\openid4vp\shell\open\command"][""]
        self.assertEqual(command, r'"C:\Program Files\Wallet\oid4vc-wallet-gui.exe" "%1"')

    def test_install_and_uninstall(self):
        desktop.cmd_install_handler(None)
        key = self.reg.keys[r"Software\Classes\openid4vp"]
        self.assertEqual(key, {"": "URL:openid4vp", "URL Protocol": ""})
        command = self.reg.keys[r"Software\Classes\openid4vp\shell\open\command"][""]
        self.assertEqual(command, r'"C:\Program Files\Wallet\oid4vc-wallet.exe" --pause "%1"')
        self.assertIn(r"Software\Classes\openid-credential-offer", self.reg.keys)
        desktop.cmd_uninstall_handler(None)
        self.assertFalse(any("openid" in k for k in self.reg.keys))


class ScriptedPrompter(ui.Prompter):
    """Respuestas fijas; registra lo que se preguntó."""

    def __init__(self, texts=(), confirms=True):
        self.texts, self.confirms, self.asked = list(texts), confirms, []

    def text(self, prompt, *, default=None):
        self.asked.append(prompt)
        return self.texts.pop(0)

    def confirm(self, question, *, default=False):
        self.asked.append(question)
        return self.confirms

    def notice(self, message):
        self.asked.append(message)


class FakeIssuer(http.server.BaseHTTPRequestHandler):
    """Emisor OpenID4VCI mínimo con pre-authorized_code + tx_code."""
    key = None
    base = ""

    def log_message(self, *args):
        pass

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        n = FakeIssuer.key.public_key().public_numbers()
        routes = {
            "/offer": {"credential_issuer": self.base, "credential_configuration_ids": ["Legal"],
                       "grants": {vci.PRE_AUTH_GRANT: {"pre-authorized_code": "PRE", "tx_code": {"length": 4}}}},
            "/.well-known/openid-credential-issuer": {
                "credential_issuer": self.base, "credential_endpoint": self.base + "/credential",
                "nonce_endpoint": self.base + "/nonce",
                "display": [{"name": "Ayuntamiento", "locale": "es"}, {"name": "Town hall", "locale": "en"}],
                "credential_configurations_supported": {"Legal": {"format": "dc+sd-jwt", "credential_metadata": {
                    "display": [{"name": "Persona jurídica", "locale": "es", "background_color": "#12355b"}]}}}},
            "/.well-known/oauth-authorization-server": {
                "issuer": self.base, "token_endpoint": self.base + "/token", "jwks_uri": self.base + "/jwks"},
            "/jwks": {"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1",
                                "x": common.b64u(n.x.to_bytes(32, "big")), "y": common.b64u(n.y.to_bytes(32, "big"))}]},
        }
        if self.path in routes:
            return self._json(routes[self.path])
        self._json({"error": "not_found"}, 404)

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.path == "/token":
            form = parse_qs(body)
            if form.get("tx_code") != ["1234"]:
                return self._json({"error": "invalid_grant"}, 400)
            return self._json({"access_token": "AT", "token_type": "Bearer"})
        if self.path == "/nonce":
            return self._json({"c_nonce": "CN"})
        if self.path == "/credential":
            proof = json.loads(body)["proofs"]["jwt"][0]
            header, claims = common.jwt_decode_unverified(proof)
            assert claims["nonce"] == "CN" and claims["aud"] == self.base
            email = common.b64u(json.dumps(["s1", "email", "user@example.org"]).encode())
            payload = {"iss": self.base, "vct": "Legal", "_sd_alg": "sha-256", "_sd": [sdjwt._sd_digest(email)],
                       "cnf": {"jwk": header["jwk"]}}
            jwt = storage.HolderKey(FakeIssuer.key).sign_jwt({"typ": "dc+sd-jwt", "kid": "k1"}, payload)
            return self._json({"credentials": [{"credential": f"{jwt}~{email}~"}]})
        self._json({"error": "not_found"}, 404)


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
        event = storage.load_history()[0]
        self.assertEqual((event["type"], event["party"], event["credentials"]),
                         ("issued", "Ayuntamiento", ["Persona jurídica"]))
        # Emisor ya conocido: no vuelve a preguntar.
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
            if handler.path == "/jwks":  # publica otra clave: la firma no casará
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


try:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    from oid4vc_wallet.gui import app as gui
except ImportError:  # la GUI es opcional
    gui = None


@unittest.skipIf(gui is None, "PySide6 no instalado")
class GuiFlowTests(unittest.TestCase):
    """La GUI de principio a fin: hilo de trabajo + paneles (respondidos por el test)."""

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
        # Nunca mirar las capturas reales del usuario.
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

    def test_consent_declined_sends_nothing(self):
        holder = storage.HolderKey.load_or_create()
        storage.save_credential(make_sd_jwt(holder), fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
        self.consent = False
        self.window.process(self.present_link())
        self.wait()
        self.assertEqual(FakeVerifier.received, [])
        self.assertIsNone(self.window.last_result)  # cancelar no es un error
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

    def test_scan_reads_clipboard(self):
        seen = []
        self.window.process = seen.append
        QGuiApplication.clipboard().setText("openid4vp://?request_uri=https://v/1")
        self.window.scan()
        self.assertEqual(seen, ["openid4vp://?request_uri=https://v/1"])

    def test_scan_ignores_already_used_qr(self):
        """Tras un QR (fallido o no), Escanear no debe volver a coger el mismo del portapapeles."""
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
        shots = Path(tempfile.mkdtemp(prefix="oid4vc-shots-"))
        old = shots / "old.png"
        qr_png("openid4vp://?request_uri=https://v/old", old)
        os.utime(old, (time.time() - 3600, time.time() - 3600))  # anterior: no debe usarse
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

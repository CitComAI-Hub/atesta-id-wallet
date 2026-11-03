"""
Shared by the offline tests: test environment (own data folder, in-memory keyring, Spanish),
fake servers (Keycloak, issuer, verifier) and helpers. Importing it first sets the environment.
"""

import base64
import datetime
import hashlib
import http.server
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

os.environ["ATESTA_ID_WALLET_HOME"] = tempfile.mkdtemp(prefix="atesta-id-wallet-test-")
os.environ["ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP"] = "1"  # the fake servers run on http://localhost
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import keyring  # noqa: E402
import keyring.backend  # noqa: E402
import keyring.errors  # noqa: E402
import urllib3.util.connection  # noqa: E402

# The fake servers listen on 127.0.0.1. On Windows "localhost" resolves to ::1 first, and every
# refused IPv6 connection costs about 2 seconds (enough to hit the GUI tests' timeouts).
urllib3.util.connection.HAS_IPV6 = False
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from atesta_id_wallet import common, i18n, jose, sdjwt, storage, ui, vci  # noqa: E402


class MemoryKeyring(keyring.backend.KeyringBackend):
    """Keyring in memory: the tests must never touch the user's real keyring."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.secrets = {}

    def get_password(self, service, username):
        return self.secrets.get((service, username))

    def set_password(self, service, username, password):
        self.secrets[(service, username)] = password

    def delete_password(self, service, username):
        if self.secrets.pop((service, username), None) is None:
            raise keyring.errors.PasswordDeleteError(username)


TEST_KEYRING = MemoryKeyring()
keyring.set_keyring(TEST_KEYRING)

# Assertions on messages are in Spanish: this exercises its catalog too.
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


def isolated_home(test: unittest.TestCase) -> Path:
    """Own data folder for the test; restores the profile at the end."""
    home = Path(tempfile.mkdtemp(prefix="atesta-id-wallet-test-"))
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
    """Publishes a DCQL request (email) on FakeVerifier and returns the openid4vp:// link."""
    payload = {
        "client_id": "x509_san_dns:localhost", "response_type": "vp_token", "response_mode": "direct_post",
        "response_uri": response_uri or f"{base}/response", "nonce": "n1",
        "dcql_query": {"credentials": [{"id": "q", "format": "dc+sd-jwt", "claims": [{"path": ["email"]}]}]},
    }
    FakeVerifier.token = (storage.HolderKey(key).sign_jwt({"x5c": [der_b64(cert)]}, payload) if signed
                          else json.dumps(payload))
    return f"openid4vp://?client_id=x509_san_dns:localhost&request_uri={base}/request"


def qr_png(text: str, path: Path | None = None) -> bytes:
    """Simulated screenshot: QR code in the middle of a white 'screen'."""
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


class FakeWinreg:
    """Minimal in-memory winreg to test the link registration on Windows."""
    HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, REG_SZ = "HKCU", "HKCR", 1

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

    def QueryValue(self, root, sub):  # noqa: N802
        """Default value of a key; HKEY_CLASSES_ROOT shows the user's Software\\Classes."""
        path = rf"Software\Classes\{sub}" if root == self.HKEY_CLASSES_ROOT else sub
        if path not in self.keys:
            raise FileNotFoundError(path)
        return self.keys[path].get("", "")

    def DeleteKey(self, _root, path):  # noqa: N802
        if path not in self.keys or any(k.startswith(path + "\\") for k in self.keys):
            raise FileNotFoundError(path)
        del self.keys[path]


class ScriptedPrompter(ui.Prompter):
    """Fixed answers; records what was asked."""

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


def png_bytes(size=8, color=(200, 30, 60)):
    import io
    from PIL import Image
    out = io.BytesIO()
    Image.new("RGB", (size, size), color).save(out, "PNG")
    return out.getvalue()


def _wide_png():
    import io
    from PIL import Image
    out = io.BytesIO()
    Image.new("1", (5000, 1)).save(out, "PNG")
    return out.getvalue()


class FakeIssuer(http.server.BaseHTTPRequestHandler):
    """Minimal OpenID4VCI issuer with pre-authorized_code + tx_code."""
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
                    "display": [{"name": "Persona jurídica", "locale": "es", "background_color": "#12355b",
                                 "logo": {"uri": self.base + "/logo.png"}}]}}}},
            "/.well-known/oauth-authorization-server": {
                "issuer": self.base, "token_endpoint": self.base + "/token", "jwks_uri": self.base + "/jwks"},
            "/jwks": {"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1",
                                "x": common.b64u(n.x.to_bytes(32, "big")), "y": common.b64u(n.y.to_bytes(32, "big"))}]},
        }
        if self.path in routes:
            return self._json(routes[self.path])
        if self.path == "/logo.png":
            body = png_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
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


class FakeDPoPIssuer(FakeIssuer):
    """Like FakeIssuer, but the token endpoint requires DPoP with a server nonce (RFC 9449)."""
    seen: list = []

    def _json(self, data, code=200, headers=None):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/.well-known/oauth-authorization-server":
            return self._json({"issuer": self.base, "token_endpoint": self.base + "/token",
                               "jwks_uri": self.base + "/jwks", "dpop_signing_alg_values_supported": ["ES256"]})
        return super().do_GET()

    def _dpop(self, method, path, access_token=None):
        proof = self.headers.get("DPoP")
        if not proof:
            return None
        header, claims = common.jwt_decode_unverified(proof)
        assert header["typ"] == "dpop+jwt" and jose._verify_jws(proof, jose.jwk_to_public_key(header["jwk"]))
        assert claims["htm"] == method and claims["htu"] == self.base + path and claims["jti"]
        if access_token:
            assert claims["ath"] == common.b64u(hashlib.sha256(access_token.encode()).digest())
        FakeDPoPIssuer.seen.append((path, claims.get("nonce")))
        return header["jwk"], claims

    def do_POST(self):  # noqa: N802
        if self.path == "/token":
            dpop = self._dpop("POST", "/token")
            if dpop is None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                return self._json({"error": "invalid_request", "error_description": "DPoP proof is missing"}, 400)
            if dpop[1].get("nonce") != "N1":
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                return self._json({"error": "use_dpop_nonce"}, 400, {"DPoP-Nonce": "N1"})
            FakeDPoPIssuer.bound = jose.jwk_to_public_key(dpop[0]).public_numbers()
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            return self._json({"access_token": "AT", "token_type": "DPoP"})
        if self.path == "/nonce":
            return self._json({"c_nonce": "CN"}, 200, {"DPoP-Nonce": "N2"})
        if self.path == "/credential":
            assert self.headers.get("Authorization") == "DPoP AT"
            jwk, _ = self._dpop("POST", "/credential", "AT")
            assert jose.jwk_to_public_key(jwk).public_numbers() == FakeDPoPIssuer.bound
        return super().do_POST()


try:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtGui import QGuiApplication  # noqa: F401  (for the GUI tests)
    from PySide6.QtWidgets import QApplication  # noqa: F401  (for the GUI tests)

    from atesta_id_wallet.gui import app as gui
except ImportError:  # the GUI is optional
    gui = None


if gui is not None:
    import atexit

    atexit.register(gui.release_widgets)

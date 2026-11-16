"""Wallet provider (provider/wallet_provider.py) and the wallet's use of it: wallet attestation as
client authentication, key attestation in the proofs.

Run:  python -m unittest discover -s tests
"""

import http.server
import io
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from wsgiref.simple_server import WSGIRequestHandler, make_server

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "provider"))

from helpers import FakeIssuer, ScriptedPrompter, isolated_home  # noqa: E402  (first: sets the test environment)
import requests  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import wallet_provider as wp  # noqa: E402
from atesta_id_wallet import attestation, common, jose, keys, storage, vci  # noqa: E402


class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def provider_config(folder, url):
    wp.init(Path(folder), "Test provider")
    return wp.Config.from_env({"WP_URL": url, "WP_KEY": f"{folder}/signer.key", "WP_CERTS": f"{folder}/signer.pem",
                               "WP_SECRET": "s3cret"})


def serve_provider(test):
    """A provider on http://localhost:PORT; returns (url, Provider, CA certificate)."""
    folder = tempfile.mkdtemp(prefix="atesta-provider-")
    server = make_server("127.0.0.1", 0, lambda env, start: app(env, start), handler_class=Quiet)
    url = f"http://localhost:{server.server_port}"
    app = wp.Provider(provider_config(folder, url))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test.addClassCleanup(server.shutdown)
    test.addClassCleanup(server.server_close)
    ca = x509.load_pem_x509_certificate(Path(folder, "ca.pem").read_bytes())
    return url, app, ca


def verified(token, ca, typ):
    """Claims of an attestation signed by the provider's certificate, which the CA issued."""
    header, claims = common.jwt_decode_unverified(token)
    assert header["typ"] == typ, header
    [leaf] = jose._x5c_chain(header)
    leaf.verify_directly_issued_by(ca)
    assert jose._verify_jws(token, leaf.public_key())
    return claims


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="atesta-provider-")
        self.now = 1_800_000_000
        self.app = wp.Provider(provider_config(self.folder, "https://wp.example"), clock=lambda: self.now)
        self.ca = x509.load_pem_x509_certificate(Path(self.folder, "ca.pem").read_bytes())

    def call(self, method, path, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        status = []
        out = self.app({"REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(raw)),
                        "wsgi.input": io.BytesIO(raw)}, lambda s, headers: status.append(s))
        return int(status[0].split()[0]), json.loads(b"".join(out))

    def request(self, key, typ, nonce=None, **claims):
        nonce = nonce or self.call("POST", "/nonce")[1]["nonce"]
        return key.sign_jwt({"typ": typ, "jwk": key.public_jwk},
                            {"aud": "https://wp.example", "nonce": nonce, "iat": self.now, **claims})

    def test_wallet_attestation(self):
        key = keys.HolderKey.generate()
        status, body = self.call("POST", "/wallet-attestation",
                                 {"request": self.request(key, "wallet-attestation-request+jwt")})
        self.assertEqual(status, 200, body)
        claims = verified(body["wallet_attestation"], self.ca, "oauth-client-attestation+jwt")
        self.assertEqual((claims["iss"], claims["sub"]), ("https://wp.example", "atesta-id-wallet"))
        self.assertEqual(claims["cnf"]["jwk"], key.public_jwk)
        self.assertEqual(claims["exp"] - claims["iat"], 3600)

    def test_key_attestation(self):
        batch = [keys.HolderKey.generate() for _ in range(3)]
        nonce = self.call("POST", "/nonce")[1]["nonce"]
        status, body = self.call("POST", "/key-attestation", {"keys": [
            self.request(k, "key-attestation-request+jwt", nonce, issuer_nonce="CN") for k in batch]})
        self.assertEqual(status, 200, body)
        claims = verified(body["key_attestation"], self.ca, "key-attestation+jwt")
        self.assertEqual(claims["attested_keys"], [k.public_jwk for k in batch])
        self.assertEqual(claims["nonce"], "CN")
        self.assertNotIn("key_storage", claims)  # nothing checked about the storage yet (step B2)

    def test_refused(self):
        key, other = keys.HolderKey.generate(), keys.HolderKey.generate()
        good = self.request(key, "wallet-attestation-request+jwt")
        head, body, _ = good.split(".")
        forged = other.sign_jwt({"typ": "wallet-attestation-request+jwt", "jwk": key.public_jwk},
                                common.jwt_decode_unverified(good)[1])
        cases = {
            "signed by another key": forged,
            "wrong type": self.request(key, "key-attestation-request+jwt"),
            "other audience": key.sign_jwt({"typ": "wallet-attestation-request+jwt", "jwk": key.public_jwk},
                                           {"aud": "https://evil.example", "nonce": "x", "iat": self.now}),
            "made-up nonce": self.request(key, "wallet-attestation-request+jwt", nonce=common.b64u(bytes(40))),
            "not a JWT": "abc",
            "bad signature": head + "." + body + ".sig",
        }
        for name, request in cases.items():
            with self.subTest(name):
                status, answer = self.call("POST", "/wallet-attestation", {"request": request})
                self.assertEqual(status, 400, answer)
        # An old nonce.
        request = self.request(key, "wallet-attestation-request+jwt")
        self.now += wp.NONCE_TTL + 1
        status, answer = self.call("POST", "/wallet-attestation", {"request": request})
        self.assertEqual((status, answer["error"]), (400, "invalid_nonce"))
        # Key attestation: the same key twice, too many keys, different issuer nonces.
        nonce = self.call("POST", "/nonce")[1]["nonce"]
        batch = [keys.HolderKey.generate() for _ in range(2)]
        for name, requests_ in {
            "twice": [self.request(key, "key-attestation-request+jwt", nonce)] * 2,
            "too many": [self.request(keys.HolderKey.generate(), "key-attestation-request+jwt", nonce)
                         for _ in range(wp.MAX_KEYS + 1)],
            "two nonces": [self.request(k, "key-attestation-request+jwt", nonce, issuer_nonce=n)
                           for k, n in zip(batch, ("a", "b"))],
        }.items():
            with self.subTest(name):
                self.assertEqual(self.call("POST", "/key-attestation", {"keys": requests_})[0], 400)
        self.assertEqual(self.call("GET", "/nonce")[0], 404)
        self.assertEqual(self.call("GET", "/health"), (200, {"status": "ok"}))

    def test_configuration_checks(self):
        env = {"WP_URL": "https://wp.example", "WP_KEY": f"{self.folder}/signer.key",
               "WP_CERTS": f"{self.folder}/ca.pem", "WP_SECRET": "x"}
        with self.assertRaisesRegex(SystemExit, "not that of WP_KEY"):
            wp.Config.from_env(env)
        with self.assertRaisesRegex(SystemExit, "WP_URL"):
            wp.Config.from_env({})


class FakeAttestingIssuer(FakeIssuer):
    """FakeIssuer whose authorization server requires a wallet attestation (with a challenge) and
    whose credential requires a key attestation, both from the CA in `ca`."""
    ca = None
    challenge = True
    seen: list = []

    def do_GET(self):  # noqa: N802
        if self.path == "/.well-known/oauth-authorization-server":
            return self._json({"issuer": self.base, "token_endpoint": self.base + "/token",
                               "jwks_uri": self.base + "/jwks",
                               "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"]})
        if self.path == "/.well-known/openid-credential-issuer":
            original = self.wfile
            self.wfile = io.BytesIO()
            super().do_GET()
            head, _, body = self.wfile.getvalue().partition(b"\r\n\r\n")
            self.wfile = original
            meta = json.loads(body)
            meta["credential_configurations_supported"]["Legal"]["proof_types_supported"] = {"jwt": {
                "proof_signing_alg_values_supported": ["ES256"], "key_attestations_required": {}}}
            return self._json(meta)
        return super().do_GET()

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.rfile = io.BytesIO(body)
        if self.path == "/token" and self.headers.get("OAuth-Client-Attestation"):  # else a public client
            attestation_jwt = self.headers.get("OAuth-Client-Attestation")
            pop = self.headers.get("OAuth-Client-Attestation-PoP")
            claims = verified(attestation_jwt, self.ca, "oauth-client-attestation+jwt")
            header, pop_claims = common.jwt_decode_unverified(pop)
            assert header["typ"] == "oauth-client-attestation-pop+jwt"
            assert jose._verify_jws(pop, jose.jwk_to_public_key(claims["cnf"]["jwk"]))
            assert pop_claims["aud"] == self.base and pop_claims["jti"]
            form = dict(p.split("=", 1) for p in body.decode().split("&"))
            assert form.get("client_id") == claims["sub"] == "atesta-id-wallet", form
            if FakeAttestingIssuer.challenge and pop_claims.get("challenge") != "CH1":
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("OAuth-Client-Attestation-Challenge", "CH1")
                self.end_headers()
                self.wfile.write(b'{"error": "use_attestation_challenge"}')
                return
            FakeAttestingIssuer.seen.append(("token", pop_claims.get("challenge"), claims["cnf"]["jwk"]["x"]))
        if self.path == "/credential":
            for proof in json.loads(body)["proofs"]["jwt"]:
                header, _ = common.jwt_decode_unverified(proof)
                claims = verified(header["key_attestation"], self.ca, "key-attestation+jwt")
                assert claims["nonce"] == "CN"
                assert header["jwk"] in claims["attested_keys"]
                FakeAttestingIssuer.seen.append(("proof", len(claims["attested_keys"])))
        return super().do_POST()


class AttestedIssuanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider_url, cls.provider, FakeAttestingIssuer.ca = serve_provider(cls)
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeAttestingIssuer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        FakeIssuer.base = f"http://localhost:{cls.server.server_port}"
        FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        isolated_home(self)
        self.offer = f"openid-credential-offer://?credential_offer_uri={FakeIssuer.base}/offer"
        FakeAttestingIssuer.seen, FakeAttestingIssuer.challenge = [], True
        FakeIssuer.batch_size = 3
        self.addCleanup(setattr, FakeIssuer, "batch_size", None)

    def issue(self):
        return vci.issue(requests.Session(), self.offer, vci.IssueOptions(), ScriptedPrompter(texts=["1234"]))

    def test_attested_issuance(self):
        attestation.set_provider_url(self.provider_url)
        self.assertEqual(attestation.provider_url(), self.provider_url)
        [issued] = self.issue()
        # The token request carried the attestation, after the challenge the server asked for.
        [token] = [s for s in FakeAttestingIssuer.seen if s[0] == "token"]
        self.assertEqual(token[1], "CH1")
        # One key attestation for the three keys of the batch, in each proof.
        self.assertEqual([s for s in FakeAttestingIssuer.seen if s[0] == "proof"], [("proof", 3)] * 3)
        self.assertEqual(len(storage.load_credentials()[0]["instances"]), 3)
        # The attestation key is not one of the holder keys (nothing links it to the credentials).
        holder_x = {keys.load(i["key"]).public_jwk["x"] for i in storage.load_credentials()[0]["instances"]}
        self.assertNotIn(token[2], holder_x)
        # A second issuance: another attestation key.
        FakeAttestingIssuer.challenge = False
        self.issue()
        tokens = [s for s in FakeAttestingIssuer.seen if s[0] == "token"]
        self.assertNotEqual(tokens[0][2], tokens[1][2])

    def test_without_provider(self):
        attestation.set_provider_url(None)
        with mock.patch.dict("os.environ", {attestation.ENV_PROVIDER: ""}):
            with self.assertRaisesRegex(common.WalletError, "proveedor"):
                self.issue()  # the key attestation cannot be had: said so, not a server error

    def test_provider_answers_for_another_key(self):
        attestation.set_provider_url(self.provider_url)
        real = self.provider.wallet_attestation

        def other_key(body):
            key = keys.HolderKey.generate()
            nonce = self.provider.nonce()
            return real({"request": key.sign_jwt({"typ": "wallet-attestation-request+jwt", "jwk": key.public_jwk},
                                                 {"aud": self.provider_url, "nonce": nonce,
                                                  "iat": int(__import__("time").time())})})
        with mock.patch.object(self.provider, "wallet_attestation", other_key):
            with self.assertRaisesRegex(common.WalletError, "otra clave"):
                self.issue()

    def test_needed(self):
        self.assertEqual(attestation.key_attestation_needed({}), (False, False))
        self.assertEqual(attestation.key_attestation_needed(
            {"proof_types_supported": {"jwt": {"key_attestations_required": {}}}}), (True, False))
        self.assertEqual(attestation.key_attestation_needed(
            {"proof_types_supported": {"attestation": {}}}), (True, True))
        self.assertFalse(attestation.required_by({"token_endpoint_auth_methods_supported": ["none"]}))
        with self.assertRaises(common.WalletError):
            attestation.set_provider_url("http://wp.example")  # https only


if __name__ == "__main__":
    unittest.main()

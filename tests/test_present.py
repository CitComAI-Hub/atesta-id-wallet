"""Presenting credentials (OpenID4VP): verifier trust, disclosure, the flow.

Run:  python -m unittest discover -s tests
"""

import http.server
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (  # noqa: E402  (first: sets the test environment)
    FakeVerifier, der_b64, isolated_home, make_cert, make_sd_jwt, verifier_request,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import cli, common, jose, sdjwt, storage, trust, ui, vp  # noqa: E402


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
        storage.write_secret(storage.TRUST_DIR / "ca.pem.enc", self.ca.public_bytes(serialization.Encoding.PEM))

    def test_new_then_pinned_then_changed(self):
        identity = trust.check_request_object(self.token, "x509_san_dns:v.example")
        self.assertEqual(identity.trust, "new")
        trust.remember_verifier(identity)
        self.assertEqual(trust.check_request_object(self.token, "x509_san_dns:v.example").trust, "pinned")
        other_key = ec.generate_private_key(ec.SECP256R1())
        other = storage.HolderKey(other_key).sign_jwt({"x5c": [der_b64(make_cert(other_key, "v.example"))]},
                                                      {"client_id": "x509_san_dns:v.example"})
        self.assertEqual(trust.check_request_object(other, "x509_san_dns:v.example").trust, "changed")

    def test_trusted_ca(self):
        self.add_ca()
        self.assertEqual(trust.check_request_object(self.token, "x509_san_dns:v.example").trust, "trusted")

    def test_response_uri_must_match_dns_even_if_trusted(self):
        identity = trust.check_request_object(self.token, "x509_san_dns:v.example")
        trust.check_response_uri(identity, "https://v.example/response")
        with self.assertRaisesRegex(common.WalletError, "evil.example"):
            trust.check_response_uri(identity, "https://evil.example/response")
        with self.assertRaisesRegex(common.WalletError, "https"):
            trust.check_response_uri(identity, "http://v.example/response")
        # A CA the user added vouches for who signs, not for wherever the request sends the data.
        self.add_ca()
        trusted = trust.check_request_object(self.token, "x509_san_dns:v.example")
        self.assertEqual(trusted.trust, "trusted")
        trust.check_response_uri(trusted, "https://v.example/response")
        with self.assertRaisesRegex(common.WalletError, "other.example"):
            trust.check_response_uri(trusted, "https://other.example/response")

    def test_x509_hash(self):
        client_id = "x509_hash:" + jose.cert_fingerprint(self.leaf)
        token = storage.HolderKey(self.key).sign_jwt({"x5c": [der_b64(self.leaf)]}, {"client_id": client_id})
        identity = trust.check_request_object(token, client_id)
        self.assertEqual(identity.trust, "new")
        trust.check_response_uri(identity, "https://v.example/response")
        self.assertEqual(identity.name, "v.example")
        bad = storage.HolderKey(self.key).sign_jwt({"x5c": [der_b64(self.leaf)]}, {"client_id": "x509_hash:AAAA"})
        with self.assertRaises(common.WalletError):
            trust.check_request_object(bad, "x509_hash:AAAA")

    def test_x509_hash_cannot_borrow_another_name(self):
        """A self-signed certificate that names a known site, with the data sent elsewhere (audit, Nov 2026)."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = make_cert(key, "marketplace.example")
        client_id = "x509_hash:" + jose.cert_fingerprint(cert)
        token = storage.HolderKey(key).sign_jwt({"x5c": [der_b64(cert)]}, {"client_id": client_id})
        identity = trust.check_request_object(token, client_id)
        self.assertNotEqual(identity.name, "marketplace.example")  # not named before the destination is known
        with self.assertRaisesRegex(common.WalletError, "attacker.example"):
            trust.check_response_uri(identity, "https://attacker.example/cb")
        # Without a DNS name in the certificate, the verifier is shown as where the data goes.
        bare = trust.VerifierIdentity(client_id, "x509_hash", client_id[10:], client_id[10:], trust="new")
        trust.check_response_uri(bare, "https://attacker.example/cb")
        self.assertEqual(bare.name, "attacker.example")

    def test_signed_client_id_required(self):
        """The client_id checked against the certificate must be inside the signature, not only in the QR code."""
        unsigned_id = storage.HolderKey(self.key).sign_jwt({"x5c": [der_b64(self.leaf)]}, {"nonce": "n"})
        with self.assertRaisesRegex(common.WalletError, "client_id"):
            trust.check_request_object(unsigned_id, "x509_san_dns:v.example")
        with self.assertRaisesRegex(common.WalletError, "client_id"):
            trust.check_request_object(self.token, "x509_hash:" + jose.cert_fingerprint(self.leaf))

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


class PresentFlowTests(unittest.TestCase):
    """present end to end against a local verifier (x509_san_dns:localhost)."""

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
        for path in storage.CRED_DIR.glob("*.enc"):
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


if __name__ == "__main__":
    unittest.main()

"""SD-JWT, request objects and JWE.

Run:  python -m unittest discover -s tests
"""

import base64
import datetime
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import make_sd_jwt  # noqa: E402  (first: sets the test environment)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from atesta_id_wallet import common, jose, sdjwt, storage, trust, vp  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()

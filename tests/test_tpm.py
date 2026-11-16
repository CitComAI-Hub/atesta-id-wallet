"""TPM evidence for key attestation (phase 3, step B2): the wallet provider's checks (provider/tpm2.py)
and the wallet's enrolment, with a TPM emulated here in Python (FakeTpm).

FakeTpm builds the TPM's own structures; tests/test_tpm_swtpm.py checks the provider against a
real TPM 2.0 implementation (swtpm), and docs/TESTING-WINDOWS.md §5c on Windows.

Run:  python -m unittest discover -s tests
"""

import datetime
import hashlib
import hmac
import http.server
import json
import struct
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "provider"))

from helpers import FakeIssuer, ScriptedPrompter, isolated_home  # noqa: E402  (first: sets the test environment)
import requests  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import tpm2  # noqa: E402
import wallet_provider as wp  # noqa: E402
from atesta_id_wallet import attestation, cng, common, storage, vci  # noqa: E402
from test_keys import FakeChip, with_chip  # noqa: E402
from test_provider import FakeAttestingIssuer, serve_provider  # noqa: E402

KEY_ATTRS = tpm2.NON_EXPORTABLE | tpm2.SIGN | 0x40  # userWithAuth
AIK_ATTRS = tpm2.NON_EXPORTABLE | tpm2.SIGN | tpm2.RESTRICTED | 0x40
MANUFACTURER = "id:41544553"  # "ATES"


def public_ecc(key, attributes=KEY_ATTRS):
    n = key.public_numbers()
    return (struct.pack(">HHI", tpm2.ALG_ECC, tpm2.ALG_SHA256, attributes) + tpm2.tpm2b(b"")
            + struct.pack(">H", tpm2.ALG_NULL) + struct.pack(">HH", tpm2.ALG_ECDSA, tpm2.ALG_SHA256)
            + struct.pack(">HH", tpm2.ECC_NIST_P256, tpm2.ALG_NULL)
            + tpm2.tpm2b(n.x.to_bytes(32, "big")) + tpm2.tpm2b(n.y.to_bytes(32, "big")))


def public_rsa(key, attributes=AIK_ATTRS):
    return (struct.pack(">HHI", tpm2.ALG_RSA, tpm2.ALG_SHA256, attributes) + tpm2.tpm2b(b"")
            + struct.pack(">H", tpm2.ALG_NULL) + struct.pack(">HH", tpm2.ALG_RSASSA, tpm2.ALG_SHA256)
            + struct.pack(">HI", 2048, 0) + tpm2.tpm2b(key.public_numbers().n.to_bytes(256, "big")))


def name_of(public):
    return struct.pack(">H", tpm2.ALG_SHA256) + hashlib.sha256(public).digest()


def certificate(subject, key, issuer=None, issuer_key=None, ca=False, san=None, days=365):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)] if subject else [])  # EK: often empty
    builder = (x509.CertificateBuilder().subject_name(name)
               .issuer_name(issuer.subject if issuer else name)
               .public_key(key.public_key() if hasattr(key, "public_key") else key)
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DirectoryName(x509.Name([
            x509.NameAttribute(x509.ObjectIdentifier(tpm2.OID_MANUFACTURER), san)]))]), critical=True)
    return builder.sign(issuer_key or key, hashes.SHA256())


def manufacturer():
    """A TPM manufacturer's root and intermediate CA: (root, intermediate, intermediate key)."""
    root_key, inter_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    root = certificate("Test TPM Root", root_key, ca=True)
    inter = certificate("Test TPM EK CA", inter_key, root, root_key, ca=True)
    return root, inter, inter_key


class FakeTpm(FakeChip):
    """FakeChip with an EK (and its certificate) and an AIK: enrolment and TPM2_Certify as a TPM does them."""
    name = "fake-tpm"
    label = "the fake TPM"

    def __init__(self, inter, inter_key):
        super().__init__()
        self.ek = rsa.generate_private_key(65537, 2048)
        self.ek_cert = certificate("", self.ek, inter, inter_key, san=MANUFACTURER)
        self.aik = None
        self.activations = 0

    def endorsement_certificate(self):
        from cryptography.hazmat.primitives import serialization

        return self.ek_cert.public_bytes(serialization.Encoding.DER)

    def attestation_key(self):
        self.aik = self.aik or rsa.generate_private_key(65537, 2048)
        return public_rsa(self.aik.public_key())

    def activate(self, credential_blob, encrypted_secret):
        """TPM2_ActivateCredential (TPM 2.0 Part 1 §24), with the EK and the AIK's name."""
        self.activations += 1
        seed = self.ek.decrypt(tpm2.Reader(encrypted_secret).tpm2b(), padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"IDENTITY\0"))
        reader = tpm2.Reader(tpm2.Reader(credential_blob).tpm2b())
        integrity = reader.tpm2b()
        enc_identity = reader.take(len(reader.data) - reader.at)
        aik_name = name_of(self.attestation_key())
        hmac_key = tpm2.kdfa("sha256", seed, b"INTEGRITY", b"", b"", 256)
        if not hmac.compare_digest(integrity, hmac.new(hmac_key, enc_identity + aik_name, "sha256").digest()):
            raise RuntimeError("TPM_RC_INTEGRITY")
        sym = tpm2.kdfa("sha256", seed, b"STORAGE", aik_name, b"", 128)
        decryptor = Cipher(algorithms.AES(sym), tpm2.CFB(b"\0" * 16)).decryptor()
        return tpm2.Reader(decryptor.update(enc_identity) + decryptor.finalize()).tpm2b()

    def certify(self, key_name, qualifying):
        public = public_ecc(self.keys[key_name].public_key())
        attest = (struct.pack(">IH", tpm2.TPM_GENERATED_VALUE, tpm2.TPM_ST_ATTEST_CERTIFY)
                  + tpm2.tpm2b(name_of(self.attestation_key())) + tpm2.tpm2b(qualifying)
                  + struct.pack(">QIIB", 1, 2, 3, 1) + struct.pack(">Q", 7)
                  + tpm2.tpm2b(name_of(public)) + tpm2.tpm2b(b"qualified"))
        signature = self.aik.sign(attest, padding.PKCS1v15(), hashes.SHA256())
        return attest, struct.pack(">HH", tpm2.ALG_RSASSA, tpm2.ALG_SHA256) + tpm2.tpm2b(signature), public


class ProviderTpmTests(unittest.TestCase):
    """The provider's checks, step by step."""

    def setUp(self):
        from test_provider import provider_config
        import tempfile

        self.now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        self.app = wp.Provider(provider_config(tempfile.mkdtemp(), "https://wp.example"), clock=lambda: self.now)
        self.root, inter, inter_key = manufacturer()
        self.app.config.tpm_roots = [self.root, inter]
        self.tpm = FakeTpm(inter, inter_key)
        self.ek = common.b64u(self.tpm.endorsement_certificate())
        self.aik = common.b64u(self.tpm.attestation_key())

    def refused(self, call, body, error):
        with self.assertRaises(wp.Refused) as caught:
            call(body)
        self.assertEqual(caught.exception.error, error, caught.exception.description)

    def enrol(self):
        challenge = self.app.tpm_enroll({"ek_certificate": self.ek, "aik_public": self.aik})
        secret = self.tpm.activate(common.b64u_decode(challenge["credential_blob"]),
                                   common.b64u_decode(challenge["encrypted_secret"]))
        return challenge, secret

    def test_enrolment(self):
        challenge, secret = self.enrol()
        body = {"ek_certificate": self.ek, "aik_public": self.aik, "issued_at": challenge["issued_at"],
                "secret": common.b64u(secret)}
        credential = self.app.tpm_activate(body)["aik_credential"]
        header, claims = common.jwt_decode_unverified(credential)
        self.assertEqual(header["typ"], "tpm-aik+jwt")
        self.assertEqual((claims["aik"], claims["tpm_manufacturer"]), (self.aik, MANUFACTURER))
        self.assertNotIn(self.ek, credential)  # nothing that identifies the TPM
        self.assertEqual(self.app._aik(credential).name, name_of(self.tpm.attestation_key()))
        # A secret that was not recovered, a late answer, another AIK.
        self.refused(self.app.tpm_activate, {**body, "secret": common.b64u(b"x" * 32)}, "invalid_tpm_evidence")
        other = FakeTpm(*manufacturer()[1:])
        self.refused(self.app.tpm_activate, {**body, "aik_public": common.b64u(other.attestation_key())},
                     "invalid_tpm_evidence")
        self.now += wp.NONCE_TTL + 1
        self.refused(self.app.tpm_activate, body, "invalid_request")

    def test_the_credential_only_reaches_the_tpm_with_that_ek(self):
        challenge, _ = self.enrol()
        other = FakeTpm(*manufacturer()[1:])
        other.aik = self.tpm.aik  # even with the same AIK, another TPM's EK cannot open it
        with self.assertRaises(ValueError):
            other.activate(common.b64u_decode(challenge["credential_blob"]),
                           common.b64u_decode(challenge["encrypted_secret"]))

    def test_endorsement_checks(self):
        stranger = FakeTpm(*manufacturer()[1:])  # a manufacturer this provider does not know
        self.refused(self.app.tpm_enroll, {"ek_certificate": common.b64u(stranger.endorsement_certificate()),
                                           "aik_public": self.aik}, "invalid_tpm_evidence")
        exportable = public_rsa(self.tpm.aik.public_key(), AIK_ATTRS & ~tpm2.FIXED_TPM)
        self.refused(self.app.tpm_enroll, {"ek_certificate": self.ek, "aik_public": common.b64u(exportable)},
                     "invalid_tpm_evidence")
        unrestricted = public_rsa(self.tpm.aik.public_key(), AIK_ATTRS & ~tpm2.RESTRICTED)
        self.refused(self.app.tpm_enroll, {"ek_certificate": self.ek, "aik_public": common.b64u(unrestricted)},
                     "invalid_tpm_evidence")
        self.refused(self.app.tpm_enroll, {"ek_certificate": 123, "aik_public": self.aik}, "invalid_request")
        self.refused(self.app.tpm_enroll, {"ek_certificate": "@@", "aik_public": self.aik}, "invalid_tpm_evidence")
        self.app.config.tpm_roots = []
        self.refused(self.app.tpm_enroll, {"ek_certificate": self.ek, "aik_public": self.aik}, "tpm_not_supported")

    def test_certified_key_checks(self):
        aik = tpm2.parse_public(self.tpm.attestation_key())
        key = ec.generate_private_key(ec.SECP256R1())
        self.tpm.keys["k"] = key
        q = hashlib.sha256(b"nonce").digest()
        attest, signature, public = self.tpm.certify("k", q)
        self.assertEqual(tpm2.certified_key(aik, attest, signature, public, q).public_numbers(),
                         key.public_key().public_numbers())
        raw = tpm2.Reader(signature[4:]).tpm2b()
        tpm2.certified_key(aik, attest, raw, public, q)  # CNG gives the bare signature
        cases = {
            "other nonce": (attest, signature, public, hashlib.sha256(b"other").digest()),
            "changed attestation": (attest[:-1] + b"X", signature, public, q),
            "other key's public": (attest, signature, public_ecc(ec.generate_private_key(ec.SECP256R1()).public_key()),
                                   q),
            "exportable key": (*self._certified(key, KEY_ATTRS & ~tpm2.FIXED_TPM, q), q),
            "restricted key": (*self._certified(key, KEY_ATTRS | tpm2.RESTRICTED, q), q),
        }
        for name, args in cases.items():
            with self.subTest(name), self.assertRaises(tpm2.TpmError):
                tpm2.certified_key(aik, *args)

    def _certified(self, key, attributes, q):
        public = public_ecc(key.public_key(), attributes)
        attest = (struct.pack(">IH", tpm2.TPM_GENERATED_VALUE, tpm2.TPM_ST_ATTEST_CERTIFY) + tpm2.tpm2b(b"")
                  + tpm2.tpm2b(q) + bytes(17) + bytes(8) + tpm2.tpm2b(name_of(public)) + tpm2.tpm2b(b""))
        return attest, self.tpm.aik.sign(attest, padding.PKCS1v15(), hashes.SHA256()), public

    def test_parsers_refuse_garbage(self):
        for data in (b"", b"\x00", b"\x00\x23" + bytes(10), public_ecc(ec.generate_private_key(ec.SECP256R1())
                                                                        .public_key()) + b"!"):
            with self.subTest(data=data[:8]), self.assertRaises(tpm2.TpmError):
                tpm2.parse_public(data)
        with self.assertRaises(tpm2.TpmError):
            tpm2.parse_certify(b"\x00" * 30)


class WalletTpmTests(unittest.TestCase):
    """The wallet enrols its TPM with the provider and attaches TPM2_Certify to each key."""

    @classmethod
    def setUpClass(cls):
        cls.provider_url, cls.provider, FakeAttestingIssuer.ca = serve_provider(cls)
        cls.root, cls.inter, cls.inter_key = manufacturer()
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
        self.provider.config.tpm_roots = [self.root, self.inter]
        self.tpm = with_chip(self, FakeTpm(self.inter, self.inter_key))
        attestation.set_provider_url(self.provider_url)
        self.offer = f"openid-credential-offer://?credential_offer_uri={FakeIssuer.base}/offer"
        FakeAttestingIssuer.seen, FakeAttestingIssuer.challenge = [], False
        FakeIssuer.batch_size = 2
        self.addCleanup(setattr, FakeIssuer, "batch_size", None)
        self.storages = []
        original = FakeAttestingIssuer.do_POST

        def spy(handler):
            if handler.path == "/credential":
                body = handler.rfile.read(int(handler.headers.get("Content-Length") or 0))
                handler.rfile = __import__("io").BytesIO(body)
                handler.headers.replace_header("Content-Length", str(len(body)))
                header, _ = common.jwt_decode_unverified(json.loads(body)["proofs"]["jwt"][0])
                self.storages.append(common.jwt_decode_unverified(header["key_attestation"])[1].get("key_storage"))
            return original(handler)
        patch = mock.patch.object(FakeAttestingIssuer, "do_POST", spy)
        patch.start()
        self.addCleanup(patch.stop)

    def issue(self):
        vci.issue(requests.Session(), self.offer, vci.IssueOptions(), ScriptedPrompter(texts=["1234"]))

    def test_key_storage_with_tpm_evidence(self):
        self.issue()
        self.assertEqual(self.storages, [["iso_18045_moderate"]])
        self.assertEqual(self.tpm.activations, 1)
        kept = storage.load_settings()["tpm_aik"][self.provider_url]
        # Kept: the provider's credential for the AIK, which carries nothing that identifies the TPM.
        _, claims = common.jwt_decode_unverified(kept["credential"])
        self.assertEqual(set(claims), {"iss", "iat", "exp", "aik", "tpm_manufacturer"})
        self.issue()  # the AIK credential is kept: no second enrolment
        self.assertEqual((self.storages[-1], self.tpm.activations), (["iso_18045_moderate"], 1))

    def test_expired_credential_enrols_again(self):
        self.issue()
        # A credential the provider no longer takes (expired there, or signed with an older key).
        settings = storage.load_settings()
        settings["tpm_aik"][self.provider_url]["credential"] = "e30.e30.AAAA"
        storage.save_settings(settings)
        self.issue()
        self.assertEqual((self.storages[-1], self.tpm.activations), (["iso_18045_moderate"], 2))

    def test_without_evidence_the_issuance_goes_on(self):
        for name, setup in {
            "provider without TPM roots": lambda: setattr(self.provider.config, "tpm_roots", []),
            "unknown manufacturer": lambda: setattr(self.provider.config, "tpm_roots", list(manufacturer()[:2])),
            "the chip fails": lambda: setattr(self.tpm, "certify", mock.Mock(side_effect=OSError("TPM busy"))),
        }.items():
            with self.subTest(name):
                self.provider.config.tpm_roots = [self.root, self.inter]
                storage.save_settings({**storage.load_settings(), "tpm_aik": {}})
                setup()
                self.storages.clear()
                self.issue()
                self.assertEqual(self.storages, [None])  # attested, but no key_storage stated
                self.tpm.__dict__.pop("certify", None)

    def test_software_keys_get_no_evidence(self):
        storage.set_hardware_keys(False)
        self.issue()
        self.assertEqual((self.storages, self.tpm.activations), ([None], 0))


class PcpBlobTests(unittest.TestCase):
    """CNG's key attestation blob (PCP_KEY_ATTESTATION_BLOB) unwrapped to the TPM's structures."""

    def test_unwrap(self):
        attest, signature, public = b"A" * 30, b"S" * 256, b"P" * 90
        key_blob = struct.pack("<5I", 0x5043504D, 60, 0, 0, len(public) + 2) + bytes(40) \
            + struct.pack(">H", len(public)) + public + b"private"
        header = struct.pack("<6I", cng.KEY_ATTESTATION_MAGIC, 2, 24, len(attest), len(signature), len(key_blob))
        self.assertEqual(cng.unwrap_key_attestation(header + attest + signature + key_blob),
                         (attest, signature, public))
        with self.assertRaises(cng.CngError):
            cng.unwrap_key_attestation(b"XXXX" + header[4:] + attest + signature + key_blob)
        with self.assertRaises(cng.CngError):
            cng.unwrap_key_attestation(header + attest)


if __name__ == "__main__":
    unittest.main()

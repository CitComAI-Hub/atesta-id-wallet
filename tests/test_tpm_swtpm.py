"""TPM evidence against a real TPM 2.0 implementation: swtpm (libtpms), driven with tpm2-pytss.

What tests/test_tpm.py emulates is done here by a TPM: ActivateCredential of the provider's
MakeCredential, TPM2_Certify of a holder key by an AIK, and the wallet's key attestation with keys
that live in the TPM. The EK certificate is issued by a test manufacturer (swtpm's own is not
needed). Skipped without swtpm and tpm2-pytss (CI: the hardware-keys job of checks.yml).

Run:  python -m unittest tests.test_tpm_swtpm
"""

import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "provider"))

from helpers import isolated_home  # noqa: E402  (first: sets the test environment)
import requests  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

import tpm2  # noqa: E402
import wallet_provider as wp  # noqa: E402
from atesta_id_wallet import attestation, common, keys  # noqa: E402
from test_tpm import certificate, manufacturer  # noqa: E402

try:
    import tpm2_pytss as pytss
    from tpm2_pytss.utils import NVReadEK, create_ek_template
except ImportError:  # optional: only this test needs it
    pytss = None

json_dumps = json.dumps
AVAILABLE = pytss is not None and shutil.which("swtpm") is not None


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class SwTpm:
    """keys.Backend and keys.TpmEvidence on swtpm: what cng.PlatformTpm does with Windows' TPM."""
    name = "swtpm"
    label = "swtpm"

    def __init__(self, esys, inter, inter_key):
        self.esys, self.handles = esys, {}
        _, self.ek_template = create_ek_template("EK-RSA2048", NVReadEK(esys))
        ek, ek_public = self._ek()
        esys.flush_context(ek)  # swtpm holds 3 objects: the EK is made again when needed (the same key)
        modulus = int.from_bytes(bytes(ek_public.publicArea.unique.rsa), "big")
        self.ek_cert = certificate("", rsa.RSAPublicNumbers(65537, modulus).public_key(), inter, inter_key,
                                   san="id:53575450")

    def _ek(self):
        ek, public, *_ = self.esys.create_primary(None, self.ek_template, pytss.ESYS_TR.ENDORSEMENT)
        return ek, public

    def _primary(self, alg, attributes, unique=None):
        public = pytss.TPM2B_PUBLIC.parse(alg, objectAttributes=attributes)
        if alg.startswith("ecc"):  # different keys from the same template: a unique field of its own
            public.publicArea.unique.ecc.x = unique or os.urandom(32)
        else:
            public.publicArea.unique.rsa = unique or os.urandom(256)
        return self.esys.create_primary(None, public, pytss.ESYS_TR.OWNER)

    def _aik(self):
        """The AIK, loaded while it is used (the same key every time, as a persisted one would be)."""
        a = pytss.TPMA_OBJECT
        handle, public, *_ = self._primary("rsa2048:rsassa-sha256:null", a.RESTRICTED | a.SIGN_ENCRYPT | a.FIXEDTPM
                                           | a.FIXEDPARENT | a.SENSITIVEDATAORIGIN | a.USERWITHAUTH, b"aik" * 80)
        return handle, public

    # keys.Backend
    def available(self):
        return True

    def create(self, key_name):
        a = pytss.TPMA_OBJECT
        handle, public, *_ = self._primary("ecc256:ecdsa-sha256:null", a.SIGN_ENCRYPT | a.FIXEDTPM | a.FIXEDPARENT
                                           | a.SENSITIVEDATAORIGIN | a.USERWITHAUTH)
        # Kept outside the TPM (swtpm holds 3 objects) and loaded while used, as a resource manager does.
        self.handles[key_name] = (self.esys.context_save(handle), public)
        self.esys.flush_context(handle)
        return self.public_key(key_name)

    def _loaded(self, key_name):
        return self.esys.context_load(self.handles[key_name][0])

    def public_key(self, key_name):
        if key_name not in self.handles:
            return None
        point = self.handles[key_name][1].publicArea.unique.ecc
        return ec.EllipticCurvePublicNumbers(int.from_bytes(bytes(point.x), "big"), int.from_bytes(bytes(point.y), "big"),
                                             ec.SECP256R1()).public_key()

    def sign(self, key_name, digest):
        scheme = pytss.TPMT_SIG_SCHEME(scheme=pytss.TPM2_ALG.ECDSA)
        scheme.details.any.hashAlg = pytss.TPM2_ALG.SHA256
        ticket = pytss.TPMT_TK_HASHCHECK(tag=pytss.TPM2_ST.HASHCHECK, hierarchy=pytss.TPM2_RH.NULL)
        handle = self._loaded(key_name)
        try:
            signature = self.esys.sign(handle, pytss.TPM2B_DIGEST(digest), scheme, ticket)
        finally:
            self.esys.flush_context(handle)
        ecdsa = signature.signature.ecdsa
        return bytes(ecdsa.signatureR).rjust(32, b"\0") + bytes(ecdsa.signatureS).rjust(32, b"\0")

    def delete(self, key_name):
        self.handles.pop(key_name, None)  # saved contexts only: nothing loaded to flush

    def names(self):
        return list(self.handles)

    # keys.TpmEvidence
    def endorsement_certificate(self):
        return self.ek_cert.public_bytes(serialization.Encoding.DER)

    def attestation_key(self):
        handle, public = self._aik()
        self.esys.flush_context(handle)
        return public.publicArea.marshal()

    def activate(self, credential_blob, encrypted_secret):
        aik, _ = self._aik()
        ek, _ = self._ek()
        session = self.esys.start_auth_session(pytss.ESYS_TR.NONE, pytss.ESYS_TR.NONE, pytss.TPM2_SE.POLICY,
                                               pytss.TPMT_SYM_DEF(algorithm=pytss.TPM2_ALG.NULL), pytss.TPM2_ALG.SHA256)
        try:
            self.esys.policy_secret(pytss.ESYS_TR.ENDORSEMENT, session, b"", b"", b"", 0)
            return bytes(self.esys.activate_credential(
                aik, ek, pytss.TPM2B_ID_OBJECT.unmarshal(credential_blob)[0],
                pytss.TPM2B_ENCRYPTED_SECRET.unmarshal(encrypted_secret)[0],
                session1=pytss.ESYS_TR.PASSWORD, session2=session))
        finally:
            for handle in (session, ek, aik):
                self.esys.flush_context(handle)

    def certify(self, key_name, qualifying):
        aik, _ = self._aik()
        key = self._loaded(key_name)
        try:
            info, signature = self.esys.certify(key, aik, pytss.TPM2B_DATA(qualifying),
                                                pytss.TPMT_SIG_SCHEME(scheme=pytss.TPM2_ALG.NULL))
        finally:
            self.esys.flush_context(aik)
            self.esys.flush_context(key)
        return bytes(info), signature.marshal(), self.handles[key_name][1].publicArea.marshal()


@unittest.skipUnless(AVAILABLE, "swtpm and tpm2-pytss are not installed")
class SwTpmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = tempfile.mkdtemp(prefix="atesta-swtpm-")
        port = free_port()
        cls.swtpm = subprocess.Popen(  # noqa: S603,S607
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={cls.state}", "--server", f"type=tcp,port={port}",
             "--ctrl", f"type=tcp,port={port + 1}", "--flags", "not-need-init,startup-clear"],  # TCTI: port + 1
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                cls.esys = pytss.ESAPI(f"swtpm:port={port}")
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("swtpm did not start")
        cls.root, inter, inter_key = manufacturer()
        cls.tpm = SwTpm(cls.esys, inter, inter_key)
        cls.roots = [cls.root, inter]

    @classmethod
    def tearDownClass(cls):
        cls.esys.close()
        cls.swtpm.terminate()
        cls.swtpm.wait(10)
        shutil.rmtree(cls.state, ignore_errors=True)

    def tearDown(self):
        for name in self.tpm.names():
            self.tpm.delete(name)

    def setUp(self):
        from test_provider import provider_config

        isolated_home(self)
        self.app = wp.Provider(provider_config(tempfile.mkdtemp(), "https://wp.example"))
        self.app.config.tpm_roots = self.roots

    def test_make_credential_activates_in_the_tpm(self):
        aik = tpm2.parse_public(self.tpm.attestation_key())
        handle, _ = self.tpm._aik()
        self.assertEqual(aik.name, bytes(self.esys.tr_get_name(handle)))  # the name the TPM computes
        self.esys.flush_context(handle)
        ek = common.b64u(self.tpm.endorsement_certificate())
        challenge = self.app.tpm_enroll({"ek_certificate": ek, "aik_public": common.b64u(aik.raw)})
        secret = self.tpm.activate(common.b64u_decode(challenge["credential_blob"]),
                                   common.b64u_decode(challenge["encrypted_secret"]))
        credential = self.app.tpm_activate({"ek_certificate": ek, "aik_public": common.b64u(aik.raw),
                                            "issued_at": challenge["issued_at"], "secret": common.b64u(secret)})
        self.assertEqual(self.app._aik(credential["aik_credential"]).name, aik.name)
        # For another key's name the TPM refuses (the secret is bound to the AIK).
        blob, encrypted = tpm2.make_credential(
            rsa.RSAPublicNumbers(65537, self.tpm.ek_cert.public_key().public_numbers().n).public_key(),
            b"\x00\x0b" + os.urandom(32), b"s" * 32)
        with self.assertRaises(pytss.TSS2_Exception):
            self.tpm.activate(blob, encrypted)

    def test_certify(self):
        self.tpm.create("k1")
        aik = tpm2.parse_public(self.tpm.attestation_key())
        q = hashlib.sha256(b"nonce").digest()
        attest, signature, public = self.tpm.certify("k1", q)
        key = tpm2.certified_key(aik, attest, signature, public, q)
        self.assertEqual(key.public_numbers(), self.tpm.public_key("k1").public_numbers())
        with self.assertRaises(tpm2.TpmError):
            tpm2.certified_key(aik, attest, signature, public, hashlib.sha256(b"other").digest())

    def test_wallet_key_attestation_with_keys_in_the_tpm(self):
        """The wallet's whole path, with keys made and used in the TPM (keys.HardwareKey on swtpm)."""
        class Session:  # the provider in this process, as requests would reach it
            def __init__(inner, app):
                inner.app = app

            def post(inner, url, json=None, timeout=None):  # noqa: A002  (requests' name)
                raw = json_dumps(json or {}).encode()
                status = []
                out = inner.app({"REQUEST_METHOD": "POST", "PATH_INFO": url.removeprefix("https://wp.example"),
                                 "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw)},
                                lambda s, headers: status.append(s))
                response = requests.Response()
                response.status_code, response._content = int(status[0].split()[0]), b"".join(out)
                response.headers["Content-Type"] = "application/json"
                return response

        batch = [keys.HardwareKey(self.tpm, f"w{n}", self.tpm.create(f"w{n}")) for n in range(2)]
        signature = batch[0].sign_raw(b"data")  # the TPM signs as the holder key
        batch[0].public_key.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                                        int.from_bytes(signature[32:], "big")),
                                   b"data", ec.ECDSA(hashes.SHA256()))
        provider = attestation.Provider(Session(self.app), "https://wp.example")
        token = provider.key_attestation(batch, "CN")
        _, claims = common.jwt_decode_unverified(token)
        self.assertEqual(claims["key_storage"], ["iso_18045_moderate"])
        self.assertEqual(claims["attested_keys"], [k.public_jwk for k in batch])


if __name__ == "__main__":
    unittest.main()

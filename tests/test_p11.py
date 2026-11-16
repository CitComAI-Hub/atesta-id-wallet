"""Keys on a PKCS#11 token (p11.py), against SoftHSM2: made on the token, signed with its PIN (asked for
once), found again, deleted, and a token that is not connected.

Skipped without SoftHSM2 (softhsm2-util and libsofthsm2.so; ATESTA_SOFTHSM2_MODULE and
ATESTA_SOFTHSM2_UTIL point at them elsewhere) or python-pkcs11. CI: the hardware-keys job of checks.yml.

Run:  python -m unittest discover -s tests
"""

import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import FakeIssuer, ScriptedPrompter, isolated_home  # noqa: E402  (first: sets the test environment)
import requests  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import common, jose, keys, p11, storage, vci  # noqa: E402
from test_keys import FakeChip, verifies, with_chip  # noqa: E402

MODULE = os.environ.get("ATESTA_SOFTHSM2_MODULE") or next(
    (m for m in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                 "/usr/lib64/pkcs11/libsofthsm2.so") if Path(m).is_file()), None)
UTIL = os.environ.get("ATESTA_SOFTHSM2_UTIL") or shutil.which("softhsm2-util")
PIN = "123456"
AVAILABLE = bool(MODULE and UTIL and p11.library_installed())


FOLDER = None


def setUpModule():  # noqa: N802
    """Two tokens, once: the module reads SOFTHSM2_CONF when it is first loaded, and stays loaded."""
    global FOLDER
    if not AVAILABLE:
        return
    FOLDER = tempfile.mkdtemp(prefix="atesta-softhsm-")
    (Path(FOLDER) / "tokens").mkdir()
    conf = Path(FOLDER) / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {FOLDER}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)
    for label in ("atesta-a", "atesta-b"):
        subprocess.run([UTIL, "--module", MODULE, "--init-token", "--free", "--label", label,  # noqa: S603
                        "--pin", PIN, "--so-pin", "87654321"], check=True, capture_output=True)


def tearDownModule():  # noqa: N802
    if FOLDER:
        shutil.rmtree(FOLDER, ignore_errors=True)


class TokenCase(unittest.TestCase):
    def setUp(self):
        isolated_home(self)
        p11.forget_pins()
        self.addCleanup(p11.forget_pins)
        self.asked = []
        patch = mock.patch.object(keys, "ask_pin", lambda prompt: self.asked.append(prompt) or PIN)
        patch.start()
        self.addCleanup(patch.stop)
        for patch in (mock.patch.object(keys, "BACKENDS", []), mock.patch.dict(keys._available, {}, clear=True),
                      mock.patch.object(keys, "_checked", set())):
            patch.start()
            self.addCleanup(patch.stop)
        storage.set_pkcs11(MODULE, "atesta-a")
        token = p11.Pkcs11Token(MODULE, "atesta-a", lambda prompt: PIN)
        self.addCleanup(lambda: [token.delete(n) for n in token.names()])  # each test starts with an empty token


@unittest.skipUnless(AVAILABLE, "SoftHSM2 or python-pkcs11 is not installed")
class TokenTests(TokenCase):
    def test_tokens(self):
        self.assertEqual(sorted(p11.tokens(MODULE)), ["atesta-a", "atesta-b"])

    def test_key_on_the_token(self):
        key = storage.new_holder_key()
        self.assertTrue(key.hardware)
        self.assertEqual(key.stored()["backend"], "pkcs11")
        self.assertEqual(len(self.asked), 1)  # the PIN, once: kept for the rest of the run
        self.assertIn("atesta-a", self.asked[0])
        again = keys.load(key.stored())
        self.assertEqual(again.public_jwk, key.public_jwk)
        self.assertTrue(verifies(key.public_key, b"data", again.sign_raw(b"data")))
        jwt = again.sign_jwt({"typ": "t"}, {"a": 1})
        self.assertTrue(jose._verify_jws(jwt, jose.jwk_to_public_key(key.public_jwk)))
        self.assertEqual(len(self.asked), 1)
        self.assertIn(key.stored()["name"], p11.Pkcs11Token(MODULE, "atesta-a", None).names())
        p11.forget_pins()  # the wallet locked
        again.sign_raw(b"data")
        self.assertEqual(len(self.asked), 2)

    def test_wrong_pin(self):
        answers = iter(["000000", PIN])
        with mock.patch.object(keys, "ask_pin", lambda prompt: next(answers)):
            key = storage.new_holder_key()  # asked again once after the wrong one
        self.assertTrue(key.hardware)
        p11.forget_pins()
        with mock.patch.object(keys, "ask_pin", lambda prompt: "000000"), \
                self.assertRaisesRegex(common.WalletError, "PIN"):
            keys.load(key.stored()).sign_raw(b"data")
        p11.forget_pins()
        with mock.patch.object(keys, "ask_pin", None), self.assertRaisesRegex(common.WalletError, "PIN"):
            keys.load(key.stored()).sign_raw(b"data")

    def test_token_not_connected(self):
        stored = storage.new_holder_key().stored()
        storage.set_pkcs11(MODULE, "atesta-b")  # another token chosen: the key is not there
        with self.assertRaisesRegex(common.WalletError, "no está conectado"):
            keys.load(stored)
        self.assertFalse(keys.is_here(stored))
        storage.set_pkcs11(MODULE, "atesta-gone")  # a token that is not plugged in: software keys
        self.assertIsNone(keys.hardware_backend())
        self.assertFalse(storage.new_holder_key().hardware)
        storage.set_pkcs11(MODULE, "atesta-a")
        self.assertTrue(keys.is_here(stored))

    def test_deleted_with_the_credential_and_the_profile(self):
        token = p11.Pkcs11Token(MODULE, "atesta-a", None)
        mine = storage.new_holder_key().stored()["name"]
        storage.create_profile("other")
        storage.set_profile("other")
        other = storage.new_holder_key().stored()["name"]
        storage.set_profile("default")
        keys.discard({"backend": "pkcs11", "name": mine})
        self.assertNotIn(mine, token.names())
        storage.remove_profile("other")
        self.assertNotIn(other, token.names())

    def test_token_before_the_chip(self):
        chip = with_chip(self, FakeChip())
        on_token = storage.new_holder_key()
        self.assertEqual(on_token.stored()["backend"], "pkcs11")
        storage.set_pkcs11(None)
        in_chip = storage.new_holder_key()
        self.assertEqual(in_chip.stored()["backend"], "fake-chip")
        storage.set_pkcs11(MODULE, "atesta-a")
        # Both kinds keep working: each key is looked up where it was made.
        self.assertTrue(keys.is_here(on_token.stored()) and keys.is_here(in_chip.stored()))
        self.assertEqual(len(chip.keys), 1)


@unittest.skipUnless(AVAILABLE, "SoftHSM2 or python-pkcs11 is not installed")
class IssuanceOnTokenTests(TokenCase):
    """A credential issued with its copies' keys on the token, and presented (signed) with them."""

    def test_issued_and_presented(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), FakeIssuer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        FakeIssuer.base, FakeIssuer.key, FakeIssuer.batch_size = (f"http://localhost:{server.server_port}",
                                                                  ec.generate_private_key(ec.SECP256R1()), 2)
        self.addCleanup(setattr, FakeIssuer, "batch_size", None)
        vci.issue(requests.Session(), f"openid-credential-offer://?credential_offer_uri={FakeIssuer.base}/offer",
                  vci.IssueOptions(), ScriptedPrompter(texts=["1234"]))
        [record] = storage.load_credentials()
        self.assertEqual({i["key"]["backend"] for i in record["instances"]}, {"pkcs11"})
        holder = storage.holder_key(record)
        cnf = record["_sd"].payload["cnf"]["jwk"]
        self.assertEqual((holder.public_jwk["x"], holder.public_jwk["y"]), (cnf["x"], cnf["y"]))
        self.assertEqual(len(self.asked), 1)  # one PIN for the whole issuance (two keys and the check)
        storage.delete_credential(record)
        self.assertEqual(p11.Pkcs11Token(MODULE, "atesta-a", None).names(), [])


if __name__ == "__main__":
    unittest.main()

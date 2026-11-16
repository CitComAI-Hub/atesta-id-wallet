"""Holder keys in a security chip: made there, found again, deleted with their credential or profile.

A fake chip stands in for the TPM (keys.Backend); the real one (Windows CNG) is tried in
test_windows_tpm, which only runs on a Windows with a TPM 2.0.

Run:  python -m unittest discover -s tests
"""

import http.server
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import FakeIssuer, ScriptedPrompter, gui, isolated_home  # noqa: E402  (first: sets the test environment)
import requests  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

from atesta_id_wallet import common, jose, keys, storage, vci  # noqa: E402


class FakeChip:
    """Keys that never leave the object, as in a TPM; `broken` makes every new key fail."""
    name = "fake-chip"
    label = "the fake chip"

    def __init__(self):
        self.keys = {}
        self.broken = False
        self.signed = 0

    def available(self):
        return True

    def create(self, key_name):
        if self.broken:
            raise OSError("chip busy")
        self.keys[key_name] = ec.generate_private_key(ec.SECP256R1())
        return self.keys[key_name].public_key()

    def public_key(self, key_name):
        key = self.keys.get(key_name)
        return key.public_key() if key else None

    def sign(self, key_name, digest):
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

        self.signed += 1
        r, s = decode_dss_signature(self.keys[key_name].sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def delete(self, key_name):
        self.keys.pop(key_name, None)

    def names(self):
        return list(self.keys)


def verifies(key, data, signature):
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return False
    return True


def with_chip(test, chip=None):
    chip = chip or FakeChip()
    patches = [mock.patch.object(keys, "BACKENDS", [chip]), mock.patch.dict(keys._available, {}, clear=True),
               mock.patch.object(keys, "_checked", set())]
    for patch in patches:
        patch.start()
        test.addCleanup(patch.stop)
    return chip


class KeyTests(unittest.TestCase):
    def setUp(self):
        isolated_home(self)
        self.chip = with_chip(self)

    def test_made_in_the_chip(self):
        key = storage.new_holder_key()
        self.assertTrue(key.hardware)
        stored = key.stored()
        self.assertEqual(stored["backend"], "fake-chip")
        self.assertTrue(stored["name"].startswith("atesta-id-wallet:default:"))
        self.assertNotIn("PRIVATE", str(stored))
        again = keys.load(stored)
        self.assertEqual(again.public_jwk, key.public_jwk)
        self.assertTrue(verifies(key.public_key, b"data", again.sign_raw(b"data")))
        self.assertEqual(self.chip.signed, 2)  # the first key of the run was checked once
        storage.new_holder_key()
        self.assertEqual(self.chip.signed, 2)
        jwt = again.sign_jwt({"typ": "t"}, {"a": 1})
        self.assertTrue(jose._verify_jws(jwt, jose.jwk_to_public_key(key.public_jwk)))

    def test_software_when_off_or_no_chip_or_failing(self):
        storage.set_hardware_keys(False)
        self.assertFalse(storage.new_holder_key().hardware)
        storage.set_hardware_keys(True)
        self.chip.broken = True
        with mock.patch.object(keys, "log") as log:
            self.assertFalse(storage.new_holder_key().hardware)  # the issuance goes on with a software key
        self.assertIn("fake chip", log.call_args[0][0])
        with mock.patch.object(keys, "BACKENDS", []):
            keys._available.clear()
            self.assertIsNone(keys.hardware_backend())
            self.assertFalse(storage.new_holder_key().hardware)

    def test_a_chip_whose_signatures_do_not_verify_is_not_used(self):
        self.chip.sign = lambda name, digest: bytes(64)
        with mock.patch.object(keys, "log"):
            self.assertFalse(storage.new_holder_key().hardware)
        self.assertEqual(self.chip.keys, {})  # the key made for the check is deleted
        self.assertIsNone(keys.hardware_backend())  # not tried again in this run
        self.assertFalse(storage.new_holder_key().hardware)

    def test_a_chip_that_fails_to_answer_is_no_chip(self):
        self.chip.available = mock.Mock(side_effect=OSError("no TPM"))
        keys._available.clear()
        self.assertIsNone(keys.hardware_backend())
        self.assertFalse(storage.new_holder_key().hardware)

    def test_key_on_another_computer(self):
        stored = storage.new_holder_key().stored()
        self.chip.keys.clear()
        with self.assertRaisesRegex(common.WalletError, "otro equipo"):
            keys.load(stored)
        self.assertFalse(keys.is_here(stored))
        self.assertTrue(keys.is_here(keys.HolderKey.generate().stored()))
        with mock.patch.object(keys, "BACKENDS", []):  # a computer without that kind of chip
            with self.assertRaisesRegex(common.WalletError, "otro equipo"):
                keys.load({"backend": "fake-chip", "name": "x"})
        with self.assertRaisesRegex(common.WalletError, "ligada"):
            keys.load(None)

    def test_profile_keys_deleted_with_the_profile(self):
        mine = storage.new_holder_key()
        storage.create_profile("work")
        storage.set_profile("work")
        other = storage.new_holder_key()
        storage.set_profile("default")
        storage.create_profile("work.2")  # a name that starts like "work": its keys are not touched
        storage.set_profile("work.2")
        similar = storage.new_holder_key()
        storage.set_profile("default")
        storage.remove_profile("work")
        self.assertEqual(set(self.chip.keys), {mine.stored()["name"], similar.stored()["name"]})
        self.assertFalse(keys.is_here(other.stored()))
        storage._wipe_profile(storage.DATA_DIR)
        self.assertEqual(set(self.chip.keys), {similar.stored()["name"]})


class IssuanceWithChipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeIssuer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        FakeIssuer.base = f"http://localhost:{cls.server.server_port}"
        FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        isolated_home(self)
        self.chip = with_chip(self)
        self.offer = f"openid-credential-offer://?credential_offer_uri={FakeIssuer.base}/offer"
        FakeIssuer.batch_size, FakeIssuer.proofs_seen = 3, []
        self.addCleanup(setattr, FakeIssuer, "batch_size", None)

    def issue(self):
        vci.issue(requests.Session(), self.offer, vci.IssueOptions(), ScriptedPrompter(texts=["1234"]))

    def test_each_copy_bound_to_a_key_in_the_chip(self):
        self.issue()
        record = storage.load_credentials()[0]
        self.assertTrue(storage.hardware_bound(record))
        names = {i["key"]["name"] for i in record["instances"]}
        self.assertEqual(names, set(self.chip.keys))
        for instance in record["instances"]:
            cnf = instance["_sd"].payload["cnf"]["jwk"]
            self.assertEqual(keys.load(instance["key"]).public_jwk, {"kty": "EC", "crv": "P-256",
                                                                      "x": cnf["x"], "y": cnf["y"]})
        holder = storage.holder_key(record)
        self.assertTrue(holder.hardware)
        storage.delete_credential(record)
        self.assertEqual(self.chip.keys, {})  # deleted with the credential

    def test_keys_of_a_failed_issuance_are_deleted(self):
        with mock.patch.object(vci, "verify_issued_credential", side_effect=common.WalletError("bad")):
            with self.assertRaises(common.WalletError):
                self.issue()
        self.assertEqual(self.chip.keys, {})
        # Fewer copies than keys: the keys left over are deleted.
        original = vci.request_credential

        def one_copy(*args, **kwargs):
            return original(*args, **kwargs)[:1]
        with mock.patch.object(vci, "request_credential", one_copy):
            self.issue()
        [record] = storage.load_credentials()
        self.assertEqual(set(self.chip.keys), {i["key"]["name"] for i in record["instances"]})
        self.assertEqual(len(self.chip.keys), 1)

    def test_backup_restored_on_another_computer(self):
        self.issue()
        backup = Path(storage.BASE_DIR) / "b.bak"
        storage.write_backup(backup, "a long password")
        # The same computer: the keys are still there.
        storage.create_profile("same")
        storage.set_profile("same")
        self.assertEqual(storage.restore_backup(backup, "a long password"), 1)
        self.assertEqual(storage.bound_elsewhere(storage.load_credentials()), [])
        # Another computer: no such keys in its chip.
        storage.set_profile("default")
        storage.create_profile("elsewhere")
        storage.set_profile("elsewhere")
        self.chip.keys.clear()
        storage.restore_backup(backup, "a long password")
        [lost] = storage.bound_elsewhere(storage.load_credentials())
        with self.assertRaisesRegex(common.WalletError, "otro equipo"):
            storage.holder_key(lost)


@unittest.skipIf(gui is None, "PySide6 not installed")
class SettingTests(unittest.TestCase):
    def setUp(self):
        from PySide6.QtWidgets import QApplication

        self.app = QApplication.instance() or QApplication([])
        isolated_home(self)

    def boxes(self, window):
        from PySide6.QtWidgets import QCheckBox

        window._go("settings")
        return [b for b in window.settings_page.findChildren(QCheckBox)
                if b.accessibleName() == "Claves en el chip de seguridad"]

    def test_shown_only_with_a_chip(self):
        with mock.patch.object(keys, "BACKENDS", []), mock.patch.dict(keys._available, {}, clear=True):
            self.assertEqual(self.boxes(gui.MainWindow()), [])
        with_chip(self)
        [box] = self.boxes(gui.MainWindow())
        self.assertTrue(box.isChecked())
        box.setChecked(False)
        self.assertFalse(storage.hardware_keys_enabled())
        self.assertFalse(storage.new_holder_key().hardware)
        box.setChecked(True)
        self.assertTrue(storage.new_holder_key().hardware)


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class WindowsTpmTests(unittest.TestCase):
    """The real TPM through CNG; skipped where there is none (most CI runners)."""

    def test_ncrypt_functions(self):
        """Every function is found in ncrypt.dll, on any Windows (a TPM is not needed for this)."""
        from atesta_id_wallet import cng

        ncrypt = cng._NCrypt()
        self.assertEqual(len(ncrypt._functions), 14)
        try:
            print("TPM 2.0:", cng.PlatformTpm().available())
        except cng.CngError as exc:
            print("TPM 2.0: none", exc)

    def test_windows_tpm(self):
        from atesta_id_wallet import cng

        chip = cng.PlatformTpm()
        try:
            chip.available()
        except cng.CngError as exc:
            self.skipTest(f"no TPM 2.0 here: {exc}")
        name = "atesta-id-wallet:test:" + common.b64u(__import__("os").urandom(6))
        public = chip.create(name)
        try:
            self.assertEqual(chip.public_key(name).public_numbers(), public.public_numbers())
            self.assertIn(name, chip.names())
            key = keys.HardwareKey(chip, name, public)
            self.assertTrue(verifies(public, b"data", key.sign_raw(b"data")))
        finally:
            chip.delete(name)
        self.assertIsNone(chip.public_key(name))
        self.assertNotIn(name, chip.names())


if __name__ == "__main__":
    unittest.main()

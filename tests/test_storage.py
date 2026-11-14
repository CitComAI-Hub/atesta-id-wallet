"""Profile storage.

Run:  python -m unittest discover -s tests
"""

import getpass
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import isolated_home, make_sd_jwt  # noqa: E402  (first: sets the test environment)
from atesta_id_wallet import cli, common, storage  # noqa: E402


class ValidityTests(unittest.TestCase):
    """The credential's state from its own dates (revocation is not checked yet)."""

    @staticmethod
    def record(**payload):
        class Sd:
            pass
        sd = Sd()
        sd.payload = payload
        return {"_sd": sd}

    def test_states(self):
        now = 1_800_000_000
        day = 86400
        self.assertEqual(storage.validity(self.record(), now), ("valid", None))
        self.assertEqual(storage.validity(self.record(exp=now + 90 * day), now), ("valid", now + 90 * day))
        self.assertEqual(storage.validity(self.record(exp=now + 12 * day), now), ("expiring", now + 12 * day))
        self.assertEqual(storage.validity(self.record(exp=now - 1), now), ("expired", now - 1))
        self.assertEqual(storage.validity(self.record(nbf=now + day, exp=now + 90 * day), now), ("not-yet", now + day))
        self.assertEqual(storage.validity({}, now), ("valid", None))


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home(self)
        self._getpass = getpass.getpass
        self.addCleanup(setattr, getpass, "getpass", self._getpass)

    def test_history_event_without_type(self):
        """'history' lists an event with no type instead of failing on it (found by mypy)."""
        storage.add_history({"party": "Ayuntamiento", "credentials": ["Persona jurídica"]})
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli._run(["history"]), 0)
        self.assertIn("Ayuntamiento: Persona jurídica", out.getvalue())

    @unittest.skipIf(os.name != "posix", "Windows: the data is protected by the profile ACL, not by mode bits")
    def test_private_permissions(self):
        path = storage.save_credential([("x", None)], fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(storage.DATA_DIR.stat().st_mode & 0o777, 0o700)

    def test_profiles_are_separate(self):
        storage.save_credential([("x", None)], fmt="x", issuer="https://i", configuration_id="c")
        cli.cmd_profiles(type("A", (), {"action": "add", "name": "work"})())
        storage.set_profile("work")
        self.assertEqual(storage.DATA_DIR, self.home / "profiles" / "work")
        self.assertFalse(storage.has_credentials())
        self.assertEqual(storage.list_profiles(), ["default", "work"])
        with self.assertRaises(common.WalletError):
            storage.profile_dir("../escape")

    def test_reset_default_keeps_other_profiles(self):
        storage.save_credential([("x", None)], fmt="x", issuer="https://i", configuration_id="c")
        storage.ensure_data_dir(storage.PROFILES_DIR / "work")
        cli.cmd_reset(type("A", (), {"yes": True})())
        self.assertFalse(storage.has_credentials())
        self.assertTrue((storage.PROFILES_DIR / "work").is_dir())

    def store_copies(self, n=3):
        keys = [storage.HolderKey.generate() for _ in range(n)]
        storage.save_credential([(make_sd_jwt(k), k) for k in keys], fmt="dc+sd-jwt", issuer="https://i",
                                configuration_id="c")
        return keys

    def test_copies_are_used_in_turn(self):
        keys = self.store_copies()
        record = storage.load_credentials()[0]
        used = []
        for _ in range(4):
            key = storage.holder_key(record)
            cnf = record["_sd"].payload["cnf"]["jwk"]
            self.assertEqual(cnf["x"], key.public_jwk["x"])  # the KB-JWT key is the one of the copy shown
            used.append(key.public_jwk["x"])
            storage.mark_used(record)
        self.assertEqual(used, [k.public_jwk["x"] for k in keys] + [keys[0].public_jwk["x"]])
        reloaded = storage.load_credentials()[0]  # the uses are stored
        self.assertEqual([i["uses"] for i in reloaded["instances"]], [2, 1, 1])
        self.assertEqual(reloaded["_instance"], 1)

    def test_a_revoked_copy_is_skipped(self):
        self.store_copies()
        record = storage.load_credentials()[0]
        revoked = {"state": "revoked", "checked_at": 1, "next_check": 0}
        record["instances"][0]["revocation"] = dict(revoked)
        storage.save_record(record)
        record = storage.load_credentials()[0]
        self.assertEqual(record["_instance"], 1)
        self.assertTrue(storage.is_usable(record))
        self.assertIsNone(storage.revocation_state(record))  # the other copies have not been checked yet
        for instance in record["instances"]:
            instance["revocation"] = dict(revoked)
        storage.save_record(record)
        record = storage.load_credentials()[0]
        self.assertEqual(storage.revocation_state(record), "revoked")
        self.assertFalse(storage.is_usable(record))

    def test_credentials_of_older_versions_are_ignored(self):
        storage.write_secret(storage.CRED_DIR / "20260101T000000_old.enc",
                             json.dumps({"format": "dc+sd-jwt", "issuer": "https://i", "credential": "x~"}).encode())
        self.assertEqual(storage.load_credentials(), [])

    def test_backup_of_an_older_version_is_refused(self):
        import tarfile

        plain = io.BytesIO()
        with tarfile.open(fileobj=plain, mode="w:gz") as tar:
            info = tarfile.TarInfo("holder_key.pem")
            info.size = 2
            tar.addfile(info, io.BytesIO(b"pk"))
        salt, nonce = b"s" * 16, b"n" * 12
        sealed = storage.AESGCM(storage._backup_key("contraseña-larga", salt)).encrypt(
            nonce, plain.getvalue(), storage.BACKUP_MAGIC)
        target = self.home / "antigua.bak"
        target.write_bytes(storage.BACKUP_MAGIC + salt + nonce + sealed)
        with self.assertRaisesRegex(common.WalletError, "anterior a la 0.14"):
            storage.restore_backup(target, "contraseña-larga")

    def test_backup_restore_roundtrip(self):
        holder = storage.HolderKey.generate()
        storage.save_credential([(make_sd_jwt(holder), holder)], fmt="dc+sd-jwt", issuer="https://i", configuration_id="c")
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
        records = storage.load_credentials()
        self.assertEqual(len(records), 1)
        self.assertEqual(storage.holder_key(records[0]).public_jwk, holder.public_jwk)

    def test_pop_profile(self):
        argv = ["--verbose", "--profile", "work", "list"]
        self.assertEqual(cli._pop_profile(argv), "work")
        self.assertEqual(argv, ["--verbose", "list"])
        self.assertEqual(cli._pop_profile(["--profile=x"]), "x")


if __name__ == "__main__":
    unittest.main()

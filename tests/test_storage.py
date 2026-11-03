"""Profile storage.

Run:  python -m unittest discover -s tests
"""

import getpass
import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import isolated_home, make_sd_jwt  # noqa: E402  (first: sets the test environment)
from atesta_id_wallet import cli, common, storage  # noqa: E402


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.home = isolated_home(self)
        self._getpass = getpass.getpass
        self.addCleanup(setattr, getpass, "getpass", self._getpass)

    def test_history_event_without_type(self):
        """'history' lists an event with no type instead of failing on it (found by mypy)."""
        storage.HolderKey.load_or_create()
        storage.add_history({"party": "Ayuntamiento", "credentials": ["Persona jurídica"]})
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli._run(["history"]), 0)
        self.assertIn("Ayuntamiento: Persona jurídica", out.getvalue())

    @unittest.skipIf(os.name != "posix", "Windows: the data is protected by the profile ACL, not by mode bits")
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


if __name__ == "__main__":
    unittest.main()

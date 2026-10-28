"""Profile encryption and wallet lock (0.8).  Run:  python -m unittest discover -s tests"""

import getpass
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_offline as base  # noqa: E402  (sets ATESTA_ID_WALLET_HOME, the test keyring and the language)

from atesta_id_wallet import cli, common, storage, vault  # noqa: E402

PASSWORD = "correct horse"


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self.home = base.isolated_home(self)
        self.addCleanup(vault.lock)
        vault.lock()
        base.TEST_KEYRING.secrets.clear()  # entries of earlier tests' profiles
        base.i18n.set_language("es")
        self.addCleanup(base.i18n.set_language, "es")

    def keyring_entries(self):
        return {user for service, user in base.TEST_KEYRING.secrets if service == vault.KEYRING_SERVICE}

    def without_keyring(self):
        self.addCleanup(setattr, vault, "keyring_available", vault.keyring_available)
        vault.keyring_available = lambda: False

    def store_something(self):
        storage.HolderKey.load_or_create()
        storage.save_credential("header.payload.signature~", fmt="x", issuer="https://issuer.example",
                                configuration_id="Secret")
        storage.save_config({"issuers": {"https://issuer.example": {"username": "alice"}}})
        storage.add_history({"type": "issued", "party": "Issuer"})


class EncryptionAtRestTests(VaultTestCase):
    def test_nothing_is_stored_in_clear_text(self):
        self.store_something()
        files = [p for p in storage.DATA_DIR.rglob("*") if p.is_file() and p.name != vault.VAULT_FILE]
        self.assertEqual(len(files), 4)
        for path in files:
            data = path.read_bytes()
            self.assertTrue(data.startswith(vault.FILE_MAGIC), path)
            for secret in (b"PRIVATE KEY", b"header.payload", b"alice", b"Issuer"):
                self.assertNotIn(secret, data, path)
        self.assertNotIn(b"key", (storage.DATA_DIR / vault.VAULT_FILE).read_bytes().lower().replace(b"keyring", b""))
        self.assertEqual(len(self.keyring_entries()), 1)

    def test_a_file_cannot_be_swapped_for_another(self):
        storage.save_credential("first~", fmt="x", issuer="https://i", configuration_id="a")
        second = storage.save_credential("second~", fmt="x", issuer="https://i", configuration_id="b")
        first = next(p for p in storage.CRED_DIR.glob("*.enc") if p != second)
        second.write_bytes(first.read_bytes())  # same key, different name: rejected
        self.assertEqual([r["credential"] for r in storage.load_credentials()], ["first~"])

    def test_folder_copied_without_its_keyring_entry(self):
        self.store_something()
        base.TEST_KEYRING.secrets.clear()
        vault.lock()
        self.assertEqual(storage.vault_state(), "locked")
        with self.assertRaisesRegex(common.WalletError, "no está en el llavero"):
            storage.unlock()


class PasswordTests(VaultTestCase):
    def test_password_locks_the_profile(self):
        self.store_something()
        vault.set_password(storage.DATA_DIR, PASSWORD)
        self.assertEqual(self.keyring_entries(), set())  # the key left the keyring
        vault.lock()
        self.assertEqual(storage.vault_state(), "locked")
        with self.assertRaises(vault.Locked):
            storage.load_credentials()
        with self.assertRaises(vault.WrongPassword):
            storage.unlock("wrong password")
        storage.unlock(PASSWORD)
        self.assertEqual(len(storage.load_credentials()), 1)
        self.assertEqual(storage.load_config()["issuers"]["https://issuer.example"]["username"], "alice")

    def test_removing_the_password_moves_the_key_back_to_the_keyring(self):
        self.store_something()
        vault.set_password(storage.DATA_DIR, PASSWORD)
        vault.set_password(storage.DATA_DIR, None)
        vault.lock()
        self.assertEqual(storage.vault_state(), "open")
        self.assertEqual(len(storage.load_credentials()), 1)

    def test_short_password_is_refused(self):
        with self.assertRaisesRegex(common.WalletError, "al menos 8"):
            vault.set_password(storage.DATA_DIR, "1234")

    def test_without_keyring_a_password_is_required(self):
        self.without_keyring()
        self.assertEqual(storage.vault_state(), "new")
        with self.assertRaises(vault.PasswordNeeded):
            storage.HolderKey.load_or_create()
        storage.unlock(PASSWORD)  # chooses it
        self.store_something()
        vault.lock()
        self.assertEqual(storage.vault_state(), "locked")
        storage.unlock(PASSWORD)
        with self.assertRaises(vault.PasswordNeeded):  # no keyring to move the key to
            vault.set_password(storage.DATA_DIR, None)

    def test_reset_forgets_the_key(self):
        self.store_something()
        storage._wipe_profile(storage.DATA_DIR)
        self.assertEqual(self.keyring_entries(), set())
        self.assertEqual(list(storage.DATA_DIR.iterdir()), [])
        self.assertEqual(storage.load_credentials(), [])


class BackupTests(VaultTestCase):
    def test_backup_restores_on_another_computer(self):
        self.store_something()
        vault.set_password(storage.DATA_DIR, PASSWORD)  # also with a wallet password
        out = self.home / "wallet.bak"
        storage.write_backup(out, "backup password")
        self.assertNotIn(b"PRIVATE KEY", out.read_bytes())

        # Another computer: another data folder and an empty keyring.
        other = base.isolated_home(self)
        base.TEST_KEYRING.secrets.clear()
        self.assertEqual(storage.restore_backup(out, "backup password"), 1)
        self.assertEqual(storage.load_history()[0]["party"], "Issuer")
        self.assertTrue(storage.KEY_FILE.read_bytes().startswith(vault.FILE_MAGIC))
        self.assertEqual(vault.mode(storage.DATA_DIR), "keyring")
        self.assertTrue(str(storage.DATA_DIR).startswith(str(other)))

    def test_unexpected_entries_are_refused(self):
        import tarfile

        self.store_something()
        out = self.home / "wallet.bak"
        storage.write_backup(out, "backup password")
        storage._wipe_profile(storage.DATA_DIR)
        plain = io.BytesIO()
        with tarfile.open(fileobj=plain, mode="w:gz") as tar:
            info = tarfile.TarInfo("../escape.json")
            info.size = 2
            tar.addfile(info, io.BytesIO(b"{}"))
        salt, nonce = b"s" * 16, b"n" * 12
        sealed = storage.AESGCM(storage._backup_key("backup password", salt)).encrypt(
            nonce, plain.getvalue(), storage.BACKUP_MAGIC)
        out.write_bytes(storage.BACKUP_MAGIC + salt + nonce + sealed)
        with self.assertRaisesRegex(common.WalletError, "escape"):
            storage.restore_backup(out, "backup password")


class CliTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, getpass, "getpass", getpass.getpass)
        self.addCleanup(setattr, cli.sys, "stdin", cli.sys.stdin)

    def test_locked_profile_without_terminal(self):
        self.store_something()
        vault.set_password(storage.DATA_DIR, PASSWORD)
        vault.lock()
        cli.sys.stdin = io.StringIO()
        with self.assertRaises(vault.Locked):
            cli.open_profile()

    def test_password_is_asked_in_a_terminal(self):
        self.store_something()
        vault.set_password(storage.DATA_DIR, PASSWORD)
        vault.lock()
        answers = ["wrong password", PASSWORD]
        getpass.getpass = lambda prompt="": answers.pop(0)

        class Tty(io.StringIO):
            def isatty(self):
                return True

        cli.sys.stdin = Tty()
        with redirect_stdout(io.StringIO()) as out:
            cli.open_profile()
        self.assertIn("incorrecta", out.getvalue())
        self.assertEqual(storage.vault_state(), "open")

    def test_password_command(self):
        answers = [PASSWORD, PASSWORD]
        getpass.getpass = lambda prompt="": answers.pop(0)
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["password", "set"]), 0)
            self.assertEqual(cli.main(["password"]), 0)  # already unlocked in this process
        self.assertEqual(vault.mode(storage.DATA_DIR), "password")
        self.assertEqual(out.getvalue().count("'default'"), 2)


@unittest.skipIf(base.gui is None, "PySide6 not installed")
class GuiLockTests(VaultTestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = base.QApplication.instance() or base.QApplication([])

    def setUp(self):
        super().setUp()
        self.store_something()
        vault.set_password(storage.DATA_DIR, PASSWORD)
        vault.lock()
        self.window = base.gui.MainWindow()
        self.addCleanup(self.window.close)
        self.asked = []
        self.window._ask_text_then = lambda title, body, action, **kwargs: self.asked.append((title, action))

    def test_locked_window_shows_nothing_until_unlocked(self):
        self.assertIs(self.window.stack.currentWidget(), self.window.lock_page)
        self.assertEqual(self.window.records, [])
        self.window.unlock()
        title, answer = self.asked.pop()
        answer("wrong password")
        self.assertEqual(self.asked[-1][0], "Contraseña del wallet")  # asked again
        self.asked.pop()[1](PASSWORD)
        self.assertEqual(len(self.window.records), 1)
        self.assertIs(self.window.stack.currentWidget(), self.window.wallet_page)
        self.assertTrue(self.window._idle_timer.isActive())

    def test_link_waits_for_the_password(self):
        handled = []
        self.window.process("openid4vp://?request_uri=https://v/r")
        self.window._run = lambda title, task, done: handled.append(title)
        self.asked.pop()[1](PASSWORD)
        self.assertEqual(handled, ["Leyendo la petición…"])

    def test_idle_timeout_locks(self):
        self.window.unlock()
        self.asked.pop()[1](PASSWORD)
        self.window._idle_timeout()
        self.assertEqual(storage.vault_state(), "locked")
        self.assertIs(self.window.stack.currentWidget(), self.window.lock_page)

    def test_keyring_profile_opens_without_asking(self):
        storage.unlock(PASSWORD)
        vault.set_password(storage.DATA_DIR, None)
        vault.lock()
        window = base.gui.MainWindow()
        self.addCleanup(window.close)
        self.assertEqual(len(window.records), 1)
        self.assertFalse(window._idle_timer.isActive())


if __name__ == "__main__":
    unittest.main()

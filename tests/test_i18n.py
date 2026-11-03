"""Translations and catalogs.

Run:  python -m unittest discover -s tests
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import isolated_home  # noqa: E402  (first: sets the test environment)
from atesta_id_wallet import cli, i18n, storage  # noqa: E402


class I18nTests(unittest.TestCase):
    PACKAGE = Path(__file__).resolve().parent.parent / "atesta_id_wallet"

    def tearDown(self):
        i18n.set_language("es")

    @classmethod
    def extract(cls):
        """Source texts of tr()/N_() and pairs of tr_n() in the whole package."""
        import ast

        messages, plurals, dynamic = set(), set(), []
        for path in cls.PACKAGE.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.args):
                    continue
                first = node.args[0]
                if node.func.id in ("tr", "N_", "tr_n") and isinstance(first, ast.JoinedStr):
                    dynamic.append(f"{path.name}:{node.lineno}")
                elif node.func.id in ("tr", "N_") and isinstance(first, ast.Constant):
                    messages.add(first.value)
                elif node.func.id == "tr_n" and isinstance(first, ast.Constant):
                    plurals.add((first.value, node.args[1].value))
        return messages, plurals, dynamic

    @staticmethod
    def fields(text):
        import string

        return {name for _, name, _, _ in string.Formatter().parse(text) if name}

    def test_catalogs_complete_and_consistent(self):
        messages, plurals, dynamic = self.extract()
        self.assertEqual(dynamic, [], "tr() with an f-string: it would never match the catalog")
        self.assertGreater(len(messages), 300)
        self.assertEqual(set(i18n.LANGUAGES), {"en", "es", "da", "de", "fr", "lb"})
        for code in sorted(set(i18n.LANGUAGES) - {i18n.DEFAULT}):
            catalog = i18n.load_catalog(code)
            with self.subTest(code=code):
                self.assertEqual(set(catalog["messages"]) - messages, set(), "unused entries")
                self.assertEqual(messages - set(catalog["messages"]), set(), "missing translations")
                self.assertEqual(set(catalog["plurals"]), {s for s, _ in plurals})
                for source, translated in catalog["messages"].items():
                    self.assertTrue(translated, source)
                    self.assertEqual(self.fields(translated), self.fields(source), source)
                for singular, plural in plurals:
                    forms = catalog["plurals"][singular]
                    self.assertEqual(len(forms), 2, singular)
                    for form, source in zip(forms, (singular, plural)):
                        # {n} is optional; the other placeholders must be the same as in the source
                        self.assertEqual(self.fields(form) - {"n"}, self.fields(source) - {"n"}, singular)

    def test_french_singular_for_zero(self):
        self.addCleanup(i18n.set_language, "es")
        i18n.set_language("fr")
        self.assertEqual(i18n.tr_n("{n} credential", "{n} credentials", 0), "0 attestation")
        self.assertEqual(i18n.tr_n("{n} credential", "{n} credentials", 2), "2 attestations")
        i18n.set_language("de")
        self.assertEqual(i18n.tr_n("{n} credential", "{n} credentials", 0), "0 Nachweise")
        self.assertEqual(i18n.system_language("lb_LU"), "lb")
        self.assertEqual(i18n.system_language("fr_FR"), "fr")

    def test_fallback_plural_and_formatting(self):
        i18n.set_language("en")
        self.assertEqual(i18n.tr("Wallet"), "Wallet")
        self.assertEqual(i18n.tr("not in any catalog {x}", x=1), "not in any catalog 1")
        self.assertEqual(i18n.tr_n("{n} credential", "{n} credentials", 2), "2 credentials")
        i18n.set_language("da")
        self.assertEqual(i18n.tr("Wallet"), "Wallet")
        self.assertEqual(i18n.tr("Settings"), "Indstillinger")
        self.assertEqual(i18n.tr_n("{n} credential", "{n} credentials", 1), "1 legitimation")
        self.assertEqual(i18n.tr("not in any catalog"), "not in any catalog")  # falls back to English
        self.assertEqual(i18n.set_language("pt"), "en")

    def test_system_language(self):
        saved = {k: os.environ.pop(k, None) for k in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")}
        self.addCleanup(lambda: [os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None)
                                 for k, v in saved.items()])
        os.environ["LANG"] = "da_DK.UTF-8"
        self.assertEqual(i18n.system_language(), "da")
        os.environ["LANGUAGE"] = "pt:es"
        self.assertEqual(i18n.system_language(), "es")
        self.assertEqual(i18n.system_language("es_ES"), "es")
        self.assertEqual(i18n.resolve("auto", "en_GB"), "en")
        self.assertEqual(i18n.resolve("da", "es_ES"), "da")
        self.assertEqual(i18n.resolve(None, "pt_BR"), i18n.system_language())

    def test_cli_language_setting_is_persistent(self):
        isolated_home(self)
        self.assertEqual(cli.main(["language", "da"]), 0)
        self.assertEqual(storage.load_settings()["language"], "da")
        self.assertEqual(i18n.current(), "da")
        cli.main(["language", "auto"])
        self.assertEqual(storage.load_settings()["language"], "auto")


if __name__ == "__main__":
    unittest.main()

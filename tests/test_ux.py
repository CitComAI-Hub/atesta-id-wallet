"""
UX/UI budgets: the audit of tests/ux_audit.py with limits that fail on a regression.

Every push renders the screens in English (light, with the keyboard checks) and German (dark: the
longest texts). ATESTA_UX_FULL=1 (nightly, .github/workflows/ux.yml) renders all six languages in
both themes.

Run:  python -m unittest tests.test_ux     ·   report with screenshots: python tests/ux_audit.py OUTDIR
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ux_audit  # noqa: E402  (first: sets the test environment)
from helpers import gui  # noqa: E402

from atesta_id_wallet import i18n  # noqa: E402

FULL = os.environ.get("ATESTA_UX_FULL") == "1"

# Plain language budgets per language. LIX: under 40 is "easy" (Björnsson); the Flesch-family scores:
# 60 or more is plain language for the general public (Flesch; Fernández-Huerta; Amstad; Kandel-Moles).
READABILITY = {"en": 60, "es": 70, "de": 55, "fr": 60}
MAX_LIX = 42
MAX_SENTENCE_WORDS = 25
# Interaction cost: decisions (clicks on panels) per task, including the Scan QR button.
MAX_DECISIONS = {"Receive a credential": 3, "Sign in to a service with it": 3}
# Response times in ms (Nielsen: 100 ms feels instant). Generous: CI machines are slow and shared.
MAX_MS = {"change page": 150, "open a panel": 150, "open a credential": 250, "open the window": 400}


def _findings(results, check):
    return [f"{lang}-{theme} · {f.screen} · {f.widget}: {f.detail}"
            for (lang, theme), audit in results.items() for f in audit.findings if f.check == check]


@unittest.skipIf(gui is None, "PySide6 not installed")
class ScreenAuditTests(unittest.TestCase):
    """Every screen and panel, measured (WCAG 2.2 AA where it can be measured)."""

    @classmethod
    def setUpClass(cls):
        saved = i18n.current()
        try:
            if FULL:
                cls.results = ux_audit.run(gui, list(i18n.LANGUAGES), ["light", "dark"])
            else:
                cls.results = ux_audit.run(gui, ["en"], ["light"])
                cls.results.update(ux_audit.run(gui, ["de"], ["dark"], keyboard=False))
            # the smallest window the wallet allows (920×640), with the longest texts
            small = ux_audit.run(gui, ["fr"], ["light"], keyboard=False, size=(920, 640))
            cls.results[("fr", "light-920x640")] = small[("fr", "light")]
        finally:
            i18n.set_language(saved)

    def assertNone(self, check, why):  # noqa: N802
        found = _findings(self.results, check)
        self.assertEqual(found, [], f"{why}:\n  " + "\n  ".join(found))

    def test_every_screen_rendered(self):
        for audit in self.results.values():
            self.assertGreaterEqual(audit.screens, 30)

    # On the Windows CI runners the offscreen platform measures text inconsistently (almost twice the
    # painted width, in different screens from one run to the next): Linux checks the layout on every
    # push and every night; the manual Windows test (docs/TESTING-WINDOWS.md) looks at it by eye.
    @unittest.skipIf(sys.platform == "win32", "text measurement of the offscreen platform unreliable on Windows")
    def test_no_text_cut_off(self):
        self.assertNone("text-clipped", "text that does not fit (often a long translation)")

    def test_controls_have_names(self):
        self.assertNone("name", "WCAG 4.1.2: screen readers need a name for every control")

    def test_targets_big_enough(self):
        self.assertNone("target-size", "WCAG 2.5.8: targets of at least 24x24 px or enough space around")

    def test_text_contrast_as_painted(self):
        self.assertNone("contrast", "WCAG 1.4.3: 4.5:1 for text (3:1 when large)")

    def test_no_tiny_text(self):
        self.assertNone("small-text", "text under 12 px")

    def test_focus_stays_in_panels(self):
        self.assertNone("focus-trap", "WCAG 2.4.3: Tab must not leave an open panel for the page behind it")

    def test_everything_reachable_with_the_keyboard(self):
        self.assertNone("keyboard", "WCAG 2.1.1: every control must be reachable with Tab")


@unittest.skipIf(gui is None, "PySide6 not installed")
class AuditSelfTests(unittest.TestCase):
    """The audit must see the problems it looks for: a panel built wrong on purpose."""

    def test_detects_planted_problems(self):
        from PySide6.QtWidgets import QApplication, QLineEdit, QPushButton

        from atesta_id_wallet.gui import sheets, widgets

        app = QApplication.instance() or QApplication([])
        widgets.ANIMATIONS = False
        ux_audit._fresh_home()
        window = gui.MainWindow()
        window.resize(1100, 740)
        window.show()
        self.addCleanup(window.close)
        sheet = sheets.Sheet(title="Planted problems")
        faint = widgets.label("This text is too faint to read")
        faint.setStyleSheet("color: #d0d0d0;")
        sheet.add(faint)
        sheet.add(QLineEdit())  # no name, no label
        faint_field = QLineEdit()
        faint_field.setAccessibleName("Faint")
        faint_field.setStyleSheet("QLineEdit { border: 1px solid #e8e9ee; }")  # its edge barely shows
        sheet.add(faint_field)
        from PySide6.QtWidgets import QHBoxLayout

        row = QHBoxLayout()
        row.setSpacing(2)  # two tiny targets side by side: no room for the spacing exception
        for text in ("x", "y"):
            tiny = QPushButton(text)
            tiny.setFixedSize(12, 12)
            row.addWidget(tiny)
        row.addStretch()
        sheet.layout_.addLayout(row)
        squeezed = QPushButton("A much longer label than the button")
        squeezed.setFixedWidth(60)
        sheet.add_buttons(squeezed)
        window._sheet(sheet)
        app.processEvents()
        audit = ux_audit.Audit()
        ux_audit.check_window(gui, window, "planted", audit, keyboard=False)
        found = audit.by_check()
        for check in ("contrast", "name", "target-size", "text-clipped"):
            self.assertIn(check, found, check)
        self.assertTrue(any(f.detail.startswith("field edge") for f in audit.findings), "faint field edge")
        window._close_sheet()


class TextTests(unittest.TestCase):
    """The texts the window shows: readable for the general public, without jargon."""

    def test_readability(self):
        for lang in i18n.LANGUAGES:
            m = ux_audit.text_metrics(lang)
            with self.subTest(lang=lang):
                self.assertLessEqual(m.lix, MAX_LIX, "LIX")
                if lang in READABILITY:
                    self.assertGreaterEqual(m.flesch, READABILITY[lang], m.flesch_name)

    def test_sentences_short(self):
        for lang in i18n.LANGUAGES:
            longest = ux_audit.text_metrics(lang).longest[0]
            with self.subTest(lang=lang):
                self.assertLessEqual(longest[0], MAX_SENTENCE_WORDS, longest[1])

    def test_no_jargon(self):
        for lang in i18n.LANGUAGES:
            jargon = ux_audit.text_metrics(lang).jargon
            with self.subTest(lang=lang):
                self.assertEqual(jargon, [], "technical words in the window (or add the text to TECHNICAL)")

    def test_every_window_text_is_measured(self):
        strings = ux_audit.ui_strings()
        self.assertGreater(len(strings), 200)
        self.assertIn("Welcome to Atesta ID Wallet", strings)
        self.assertIn("The username or password is not correct. Start again and check them.", strings)  # a hint


@unittest.skipIf(gui is None, "PySide6 not installed")
class TaskTests(unittest.TestCase):
    """The key tasks end to end in the real window, as a person would answer each panel."""

    @classmethod
    def setUpClass(cls):
        saved = i18n.current()
        i18n.set_language("en")
        try:
            cls.costs = {c.task: c for c in ux_audit.task_costs(gui)}
            cls.times = ux_audit.response_times(gui)
        finally:
            i18n.set_language(saved)

    def test_tasks_complete_with_few_decisions(self):
        for task, limit in MAX_DECISIONS.items():
            cost = self.costs[task]
            with self.subTest(task=task):
                self.assertTrue(cost.ok, cost.steps)
                self.assertLessEqual(cost.decisions, limit, " → ".join(cost.steps))

    def test_response_times(self):
        for action, limit in MAX_MS.items():
            with self.subTest(action=action):
                self.assertLess(self.times[action], limit)


if __name__ == "__main__":
    unittest.main()

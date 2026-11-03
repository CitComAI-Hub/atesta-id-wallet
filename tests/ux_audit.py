"""
UX/UI audit of the GUI: every screen and panel rendered with sample data and checked
(WCAG 2.2 AA where it can be measured), plus metrics of the interface texts.

Used by tests/test_ux.py (with budgets that fail on regressions) and as a report generator:

    python tests/ux_audit.py OUTDIR [--langs en,es,de] [--themes light,dark]

writes OUTDIR/<lang>-<theme>/<screen>.png and OUTDIR/report.md.

What is measured on each rendered screen:
- text-clipped      text that does not fit in its widget (also with long translations)
- name              interactive widgets without an accessible name (WCAG 4.1.2)
- target-size       targets under 24x24 px without enough space around (WCAG 2.5.8)
- contrast          contrast of the text as painted, against what is behind it (WCAG 1.4.3)
- small-text        text under 12 px (not a WCAG rule; legibility)
- focus-trap        Tab leaving an open panel for the page behind it (WCAG 2.4.3)
- keyboard          interactive widgets Tab never reaches (WCAG 2.1.1)
"""

from __future__ import annotations

import ast
import json
import re
import tempfile
import sys
import threading
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import helpers  # noqa: E402,F401  (first: own data folder, memory keyring)
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import common, i18n, sdjwt, storage, trust, ui, vp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "atesta_id_wallet"

# ---------------------------------------------------------------------------
# Interface texts and their metrics
# ---------------------------------------------------------------------------

# Strings for a technical audience: Settings → Trust and Advanced, the command line options of the
# GUI, file dialog filters. They are measured but exempt from the jargon rule.
TECHNICAL = {
    "Verifier authorities", "Verifiers with certificates from these CAs are shown as trusted. {authorities}",
    "Add CA…", "Remembered verifiers", "Forget all", "Advanced", "Protocol details",
    "Log the OpenID4VC requests and responses (for debugging).", "No technical activity in this session.",
    "Trust", "Trust this authority?", "Verifiers with certificates issued by:<br><b>{subjects}</b><br>will be "
    "shown as trusted.", "Authority added", "Invalid certificate", "CA certificate (PEM)",
    "Certificates (*.pem *.crt);;All files (*)", "Forget the verifiers?", "Verifiers forgotten",
    "Next time they will appear as new, and a change of certificate cannot be detected.",
    "{n} verifier whose certificate is remembered since its first use; you will be warned if it changes.",
    "{n} verifiers whose certificate is remembered since their first use; you will be warned if it changes.",
    "Atesta ID Wallet (graphical interface).", "openid4vp:// or openid-credential-offer:// link, or an image",
    "Profile to use", "Log the protocol details", "ERROR: {error}", "The profile '{name}' does not exist.",
    "Images (*.png *.jpg *.jpeg)", "Backups (*.bak);;All files (*)", "Data: {path}",
    "Paste the <b>openid4vp://</b> or <b>openid-credential-offer://</b> link the website gave you.",
    "Technical type", "Show technical details",
}

# Words that mean nothing to most people, per language (whole words, case-insensitive).
TECH_TERMS = ["token", "metadata", "endpoint", "jwt", "sd-jwt", "dcql", "oauth", "client_id", "nonce", "x5c",
              "pem", "payload", "openid", "openid4vp", "openid4vc", "oid4vc", "json", "http", "https", "url",
              "uri", "jwk", "jws", "jwe", "ca", "cas", "keycloak", "tx_code", "pre-authorized"]
JARGON = {
    "en": TECH_TERMS + ["issuer", "issuers", "verifier", "verifiers", "claim", "claims", "holder", "disclosure",
                        "relying party", "presentation", "protocol"],
    "es": TECH_TERMS + ["emisor", "emisores", "verificador", "verificadores", "wallet", "claim", "claims",
                        "presentación", "protocolo", "divulgación"],
    "da": TECH_TERMS + ["udstederen", "udstedere", "verifikator", "verifikatoren", "protokol"],
    "de": TECH_TERMS + ["aussteller", "verifizierer", "protokoll"],
    "fr": TECH_TERMS + ["émetteur", "vérificateur", "protocole"],
    "lb": TECH_TERMS + ["aussteller", "verifizéierer", "protokoll"],
}
# Not wrong, but worth counting: words that need some knowledge (reported, never a failure).
SOFT_TERMS = {
    "en": ["key", "keyring", "encrypted", "certificate", "profile", "domain"],
    "es": ["clave", "llavero", "cifrado", "cifrada", "cifradas", "certificado", "perfil", "dominio"],
}

VOWELS = {"en": "aeiouy", "es": "aeiouáéíóúü", "da": "aeiouyæøå", "de": "aeiouyäöü", "fr": "aeiouyéèêàâîôûùëïü",
          "lb": "aeiouyäéëöü"}


@lru_cache(maxsize=1)
def ui_strings() -> tuple[str, ...]:
    """English source of every text the window can show: the GUI and the 'hint' of the protocol errors."""
    found: dict[str, None] = {}
    for path in sorted((PACKAGE / "gui").glob("*.py")) + sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        gui = path.parent.name == "gui"
        hints = set()
        if not gui:  # only the plain words meant for the window
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "hint":
                    hints.update(id(n) for n in ast.walk(node.value))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and getattr(node.func, "id", None) in ("tr", "N_", "tr_n")
                    and (gui or id(node) in hints)):
                for arg in node.args[:2 if node.func.id == "tr_n" else 1]:  # type: ignore[attr-defined]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        found[arg.value] = None
    for name in common.CLAIM_NAMES.values():
        found[name] = None
    return tuple(found)


def translated(source: str, lang: str) -> str:
    if lang == "en":
        return source
    catalog = i18n.load_catalog(lang)
    if source in catalog["messages"]:
        return catalog["messages"][source]
    for singular, forms in catalog["plurals"].items():
        if source == singular:
            return forms[0]
    for singular, forms in catalog["plurals"].items():
        # the plural source of a pair is not a key: find it through the English pair in the code
        if len(forms) == 2 and source.replace("pieces", "piece") == singular:
            return forms[1]
    return source


def plain(text: str) -> str:
    """Without markup, placeholders and the shortcut/arrow decorations, for counting words."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\{[a-z_]+\}", "X", text)
    return re.sub(r"\s+", " ", text).strip()


def words(text: str) -> list[str]:
    return re.findall(r"[^\W\d_]+(?:['’-][^\W\d_]+)*", plain(text))


def sentences(text: str) -> list[str]:
    parts = [p for p in re.split(r"(?<=[.!?…])\s+|(?<=:)\s+(?=[A-ZÁÉÍÓÚÄÖÜ])", plain(text)) if words(p)]
    return parts or [text]


def syllables(word: str, lang: str) -> int:
    w = word.lower()
    if lang in ("en", "fr") and len(w) > 3 and w.endswith("e") and w[-2] not in VOWELS[lang]:
        w = w[:-1]  # silent final e
    return max(1, len(re.findall(f"[{VOWELS[lang]}]+", w)))


@dataclass
class TextMetrics:
    lang: str
    prose: int  # texts measured (6 words or more)
    words_per_sentence: float
    longest: list[tuple[int, str]]  # (words, sentence), longest first
    lix: float
    flesch: float | None  # the Flesch-family formula of the language, None without one
    flesch_name: str
    jargon: list[tuple[str, str]]  # (word, text)
    soft: dict[str, int]


@lru_cache(maxsize=None)
def text_metrics(lang: str) -> TextMetrics:
    texts = [translated(s, lang) for s in ui_strings()]
    prose = [t for t in texts if len(words(t)) >= 6]
    all_sentences = [s for t in prose for s in sentences(t)]
    all_words = [w for s in all_sentences for w in words(s)]
    n_s, n_w = max(1, len(all_sentences)), max(1, len(all_words))
    asl = n_w / n_s
    long_words = sum(len(w) > 6 for w in all_words)
    lix = asl + 100 * long_words / n_w
    asw = sum(syllables(w, lang) for w in all_words) / n_w
    formulas = {
        "en": ("Flesch Reading Ease", 206.835 - 1.015 * asl - 84.6 * asw),
        "es": ("Fernández-Huerta", 206.84 - 60 * asw - 1.02 * (100 / asl)),
        "de": ("Flesch-Amstad", 180 - asl - 58.5 * asw),
        "fr": ("Kandel-Moles", 207 - 1.015 * asl - 73.6 * asw),
    }
    name, score = formulas.get(lang, ("—", None))
    jargon = []
    for source, text in zip(ui_strings(), texts):
        if source in TECHNICAL:
            continue
        # the brand and the menu path the account page shows in English are names, not jargon
        low = plain(text).replace("Atesta ID Wallet", "").replace("Verifiable Credentials → Issue to wallet", "").lower()
        for term in JARGON.get(lang, []):
            if re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", low):
                jargon.append((term, text))
    soft = {t: sum(len(re.findall(rf"\b{t}\b", plain(x).lower())) for x in texts) for t in SOFT_TERMS.get(lang, [])}
    longest = sorted(((len(words(s)), s) for s in all_sentences), reverse=True)[:5]
    return TextMetrics(lang, len(prose), round(asl, 1), longest, round(lix, 1),
                       None if score is None else round(score, 1), name, jargon, {k: v for k, v in soft.items() if v})


# ---------------------------------------------------------------------------
# Sample data and the catalogue of screens
# ---------------------------------------------------------------------------


def _sd_jwt(holder: storage.HolderKey, claims: dict[str, Any], vct: str, exp: int | None = None) -> str:
    issuer = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
    disclosures, digests = [], []
    for index, (key, value) in enumerate(claims.items()):
        encoded = common.b64u(json.dumps([f"s{index}", key, value]).encode())
        disclosures.append(encoded)
        digests.append(sdjwt._sd_digest(encoded))
    payload: dict[str, Any] = {"iss": "https://x", "vct": vct, "_sd_alg": "sha-256", "_sd": digests,
                               "cnf": {"jwk": holder.public_jwk}, "iat": int(time.time()) - 86400 * 20}
    if exp:
        payload["exp"] = exp
    return issuer.sign_jwt({"typ": "dc+sd-jwt"}, payload) + "~" + "~".join(disclosures) + "~"


def fill_wallet() -> None:
    """Three credentials (one expired) and three events in the active profile."""
    holder = storage.HolderKey.load_or_create()
    now = int(time.time())
    storage.save_credential(_sd_jwt(holder, {"given_name": "Marta", "family_name": "Ribes Soler",
                                             "email": "marta.ribes@example.org", "organisation": "Ajuntament de València",
                                             "roles": ["data-provider", "member"]}, "MembershipCredential",
                                    exp=now + 86400 * 300),
                            fmt="dc+sd-jwt", issuer="https://keycloak.citcom.example/realms/citcom",
                            configuration_id="MembershipCredential",
                            display={"name": "CITCOM membership", "issuer_name": "CITCOM TEF"})
    storage.save_credential(_sd_jwt(holder, {"legalName": "PGTEC Consortium", "vatID": "ESB12345678",
                                             "email": "marta.ribes@example.org"}, "LegalPersonCredential"),
                            fmt="dc+sd-jwt", issuer="https://auth.pgtec-vrain-dataspace.eu/realms/pgtec",
                            configuration_id="LegalPersonCredential")
    storage.save_credential(_sd_jwt(holder, {"email": "marta@example.org", "username": "mribes"}, "UserCredential",
                                    exp=now - 86400),
                            fmt="dc+sd-jwt", issuer="https://id.example.com", configuration_id="UserCredential")
    for event in (
        {"type": "issued", "party": "CITCOM TEF", "party_id": "https://keycloak.citcom.example/realms/citcom",
         "credentials": ["CITCOM membership"]},
        {"type": "presented", "party": "marketplace.citcom.example",
         "party_id": "x509_san_dns:marketplace.citcom.example", "trust": "pinned",
         "credentials": ["CITCOM membership"], "claims": ["email", "roles"]},
        {"type": "declined", "party": "unknown-shop.example", "party_id": "x509_san_dns:unknown-shop.example",
         "trust": "new", "credentials": ["CITCOM membership"], "claims": ["email", "given_name", "family_name"]},
    ):
        storage.add_history(event)


def _prepared(level: str, records: list[dict[str, Any]], paths: list[Any]) -> vp.PreparedPresentation:
    identity = trust.VerifierIdentity("x509_san_dns:marketplace.citcom.example", "x509_san_dns",
                                      "marketplace.citcom.example", "marketplace.citcom.example", trust=level)
    return vp.PreparedPresentation({}, identity, "https://marketplace.citcom.example/wallet/response", "direct_post",
                                   "n", [vp.Match("q", r, p) for r, p in zip(records, paths)])


class _Ask:  # what a flow asks the window, answered by nobody
    def __init__(self, *args: Any):
        self.args = args

    def answer(self, *_: Any) -> None:
        pass

    def cancel(self) -> None:
        pass


class _Issued:
    def __init__(self, path: str, account: str | None):
        self.path, self.account = Path(path), account


def _citcom(w: Any) -> dict[str, Any]:
    return next(r for r in w.records if "CITCOM" in storage.credential_name(r))


def screens(gui: Any) -> list[tuple[str, Callable[[Any], None]]]:
    """(name, set up the window): pages first (empty wallet), then the filled wallet and every panel."""
    tr = i18n.tr

    def onboarding(index: int) -> Callable[[Any], None]:
        return lambda w: w._onboarding_step(index, ["welcome", "first-credential", "links", "protect"])

    def consent(level: str) -> Callable[[Any], None]:
        return lambda w: w._ask_consent(_Ask(_prepared(level, [_citcom(w)], [[["email"], ["roles"], ["given_name"],
                                                                               ["family_name"]]])))

    def progress(w: Any) -> None:
        w._progress_title = tr("Receiving the credential…")
        w._show_progress()

    def missing(w: Any) -> None:
        exc = vp.NoMatchingCredential.__new__(vp.NoMatchingCredential)
        exc.verifier, exc.wanted, exc.detail = "marketplace.citcom.example", ["LegalPersonCredential"], "DCQL …"
        w._missing_credential(exc, ("https://auth.pgtec", "LegalPersonCredential", "PGTEC"))

    def failed(exc: Exception, flow: str = "issue") -> Callable[[Any], None]:
        def run(w: Any) -> None:
            w._flow = flow
            w._on_failed(exc, "Traceback …")
        return run

    import requests

    return [
        ("wallet-empty", lambda w: w._go("wallet")),
        *[(f"guide-{i + 1}", onboarding(i)) for i in range(4)],
        ("_fill", lambda w: (fill_wallet(), w.reload())),
        ("wallet", lambda w: w._go("wallet")),
        ("credential", lambda w: w.open_credential(_citcom(w))),
        ("credential-expired", lambda w: w.open_credential(next(r for r in w.records if storage.is_expired(r)))),
        ("activity", lambda w: w._nav("activity")),
        ("activity-contact", lambda w: w.activity_page.show_contact("x509_san_dns:marketplace.citcom.example")),
        ("settings", lambda w: w._nav("settings")),
        ("scan", lambda w: (w._go("wallet"), w.scan())),
        ("offer", lambda w: w._ask_offer(_Ask(ui.OfferSummary("https://keycloak.citcom.example/realms/citcom",
                                                              "CITCOM TEF", ["CITCOM membership"], False)))),
        ("sign-in", lambda w: w._ask_login(_Ask("keycloak.citcom.example", None, True))),
        ("browser", lambda w: w._ask_browser(_Ask("keycloak.citcom.example", "https://x", threading.Event()))),
        ("collection-code", lambda w: w._ask_text(_Ask("tx_code", None))),
        ("progress", progress),
        ("consent-trusted", consent("trusted")),
        ("consent-new", consent("new")),
        ("consent-changed", consent("changed")),
        ("choose", lambda w: w._ask_choose(_Ask("q", w.records[:2]))),
        ("received", lambda w: w._issued([_Issued(_citcom(w)["_path"], "marta.ribes@example.org")])),
        ("shared", lambda w: w._presented((_prepared("pinned", [_citcom(w)], [[["email"], ["roles"]]]), None))),
        ("missing-credential", missing),
        ("error-connection", failed(requests.ConnectionError("HTTPSConnectionPool(host='x', port=443)"))),
        ("error-issue", failed(common.WalletError("credential_endpoint missing"))),
        ("error-present", failed(common.WalletError("x5c broken"), "present")),
        ("error-unexpected", failed(KeyError("credential_configurations_supported"))),
        ("delete", lambda w: w.confirm_delete(_citcom(w))),
        ("new-password", lambda w: w._choose_password(tr("New wallet password"), "…", lambda _: None)),
        ("new-profile", lambda w: w.new_profile()),
        ("licenses", lambda w: w.show_licenses()),
    ]


# ---------------------------------------------------------------------------
# Checks on a rendered window
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    screen: str
    check: str
    widget: str
    detail: str


@dataclass
class Audit:
    findings: list[Finding] = field(default_factory=list)
    screens: int = 0
    widgets: int = 0
    min_contrast: dict[str, float] = field(default_factory=dict)  # screen -> lowest text contrast

    def by_check(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.check] = counts.get(f.check, 0) + 1
        return counts


def _luminance(r: int, g: int, b: int) -> float:
    def channel(c: int) -> float:
        v = c / 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    high, low = sorted((_luminance(*a), _luminance(*b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def painted_contrast(image: Any, rect: Any, minimum: int = 20) -> float | None:
    """
    Contrast of the text painted in rect of image: the background is the most common colour, the text
    the pixel that differs most from it (anti-aliasing only lowers it, so this is the text's own colour).
    """
    from collections import Counter

    pixels = []
    for y in range(max(0, rect.top()), min(image.height(), rect.bottom() + 1)):
        for x in range(max(0, rect.left()), min(image.width(), rect.right() + 1)):
            c = image.pixel(x, y)
            pixels.append(((c >> 16) & 255, (c >> 8) & 255, c & 255))
    if len(pixels) < minimum:
        return None
    background = Counter(pixels).most_common(1)[0][0]
    return max(contrast(background, p) for p in set(pixels))


def _describe(widget: Any) -> str:
    text = ""
    for attr in ("text", "accessibleName", "placeholderText"):
        value = getattr(widget, attr, None)
        if callable(value) and value():
            text = re.sub(r"<[^>]+>", "", value())[:50]
            break
    return f"{type(widget).__name__}#{widget.objectName() or '-'} «{text}»"


def _visible_to(widget: Any, root: Any) -> bool:
    return widget.isVisibleTo(root) and widget.width() > 0 and widget.height() > 0


def _px(widget: Any) -> float:
    font = widget.font()
    return font.pixelSize() if font.pixelSize() > 0 else font.pointSizeF() * widget.logicalDpiY() / 72


def _interactive(gui: Any, root: Any) -> list[Any]:
    from PySide6.QtWidgets import QAbstractButton, QComboBox, QLineEdit

    found = []
    for w in root.findChildren(QWidgetType()):
        if not _visible_to(w, root) or not w.isEnabled():
            continue
        if isinstance(w, (QAbstractButton, QComboBox, QLineEdit)) or isinstance(w, gui.CredentialCard) and \
                w.interactive or w.objectName() == "activityRow":
            if type(w).__name__ == "QToolButton" and isinstance(w.parentWidget(), QLineEdit):
                found.append(w)  # the show/hide password button inside a field
            elif type(w).__name__ != "QToolButton" or w.isVisible():
                found.append(w)
    return found


def QWidgetType() -> Any:  # noqa: N802
    from PySide6.QtWidgets import QWidget
    return QWidget


def check_window(gui: Any, window: Any, screen: str, audit: Audit, *, keyboard: bool = True) -> None:
    from PySide6.QtCore import QPoint, QRect, Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QAbstractButton, QApplication, QCheckBox, QLabel, QLineEdit

    app = QApplication.instance()
    sheet = window.overlay.sheet
    root = window.centralWidget()
    image = window.grab().toImage()
    audit.screens += 1
    scope = sheet if sheet is not None else root

    def add(check: str, widget: Any, detail: str) -> None:
        audit.findings.append(Finding(screen, check, _describe(widget), detail))

    def window_rect(widget: Any) -> QRect:
        return QRect(widget.mapTo(window, QPoint(0, 0)), widget.size())

    # -- text: clipped, contrast, size ----------------------------------------
    lowest = 99.0
    for lab in scope.findChildren(QLabel):
        if not _visible_to(lab, window) or not lab.text() or lab.pixmap() and not lab.pixmap().isNull():
            continue
        audit.widgets += 1
        if lab.wordWrap():
            needed = lab.heightForWidth(lab.width())
            if needed > lab.height() + 2:
                add("text-clipped", lab, f"needs {needed} px of height, has {lab.height()}")
        elif lab.sizeHint().width() > lab.width() + 2:  # the hint includes the padding, like width()
            add("text-clipped", lab, f"needs {lab.sizeHint().width()} px of width, has {lab.width()}")
        if _px(lab) < 12:
            add("small-text", lab, f"{_px(lab):.0f} px")
        ratio = painted_contrast(image, window_rect(lab))
        if ratio is not None:
            large = _px(lab) >= 24 or (_px(lab) >= 18.66 and lab.font().bold())
            lowest = min(lowest, ratio)
            if ratio < (3 if large else 4.5) - 0.05:
                add("contrast", lab, f"{ratio:.2f}:1")
    interactive = _interactive(gui, scope)
    for w in interactive:
        audit.widgets += 1
        if isinstance(w, QAbstractButton) and w.text() and w.sizeHint().width() > w.width() + 2:
            add("text-clipped", w, f"needs {w.sizeHint().width()} px of width, has {w.width()}")
        if isinstance(w, QAbstractButton) and w.text() and not isinstance(w, QCheckBox) \
                and type(w).__name__ != "QToolButton":  # icon-only buttons: non-text contrast, 3:1
            ratio = painted_contrast(image, window_rect(w).adjusted(3, 3, -3, -3))
            if ratio is not None:
                lowest = min(lowest, ratio)
                if ratio < 4.45:
                    add("contrast", w, f"{ratio:.2f}:1")
    audit.min_contrast[screen] = round(lowest, 2)
    # the box of a checkbox or option is the control itself: 3:1 against what is behind (WCAG 1.4.11)
    from PySide6.QtWidgets import QComboBox, QRadioButton, QStyle, QStyleOptionButton

    for w in interactive:
        # The edge of a field, 3:1 unless something else says what it is: a drop-down's arrow, an icon
        # inside the field (the search field). Measured on its top edge, outside, border and inside.
        if isinstance(w, QComboBox) or not isinstance(w, QLineEdit) or w.hasFocus():
            continue
        if any(type(c).__name__ == "QToolButton" and c.isVisibleTo(w) and c.x() < w.width() // 3
               for c in w.children() if hasattr(c, "x")):
            continue  # a leading icon identifies it
        top = w.mapTo(window, QPoint(0, 0))
        edge = painted_contrast(image, QRect(top.x() + 14, top.y() - 2, w.width() - 28, 5), minimum=8)
        if edge is not None and edge < 2.95:
            add("contrast", w, f"field edge {edge:.2f}:1 (non-text, 3:1)")

    for w in interactive:
        if isinstance(w, (QCheckBox, QRadioButton)):
            option = QStyleOptionButton()
            w.initStyleOption(option)
            element = QStyle.SE_CheckBoxIndicator if isinstance(w, QCheckBox) else QStyle.SE_RadioButtonIndicator
            box = w.style().subElementRect(element, option, w)
            ratio = painted_contrast(image, QRect(w.mapTo(window, box.topLeft()), box.size()).adjusted(-2, -2, 2, 2))
            if ratio is not None and ratio < 3:
                add("contrast", w, f"box {ratio:.2f}:1 (non-text, 3:1)")

    # -- names and target size ----------------------------------------------
    rects = [window_rect(w) for w in interactive]
    for w, rect in zip(interactive, rects):
        name = w.accessibleName() or (w.text() if isinstance(w, QAbstractButton) else "")
        if isinstance(w, QLineEdit) and not name:
            add("name", w, "field without a name" + (" (only a placeholder)" if w.placeholderText() else ""))
        elif not name:
            add("name", w, "no accessible name")
        if min(w.width(), w.height()) < 24:
            # WCAG 2.5.8 spacing exception: a 24 px circle around it touches no other target
            centre = rect.center()
            circle = QRect(centre.x() - 12, centre.y() - 12, 24, 24)
            if any(circle.intersects(o) for o in rects if o != rect and not o.contains(rect)):
                add("target-size", w, f"{w.width()}x{w.height()} px")

    # -- keyboard -----------------------------------------------------------
    if not keyboard:
        return
    window.activateWindow()
    start = app.focusWidget() or (sheet if sheet is not None else window)
    reached = set()
    escaped = None
    current = start
    for _ in range(len(interactive) * 2 + 6):
        QTest.keyClick(current, Qt.Key_Tab)
        app.processEvents()
        current = app.focusWidget()
        if current is None:
            break
        reached.add(current)
        if sheet is not None and not sheet.isAncestorOf(current) and escaped is None:
            escaped = current
    if escaped is not None:
        add("focus-trap", escaped, "Tab leaves the open panel for the page behind it")
    groups_reached = set()
    for w in reached:
        group = getattr(w, "group", lambda: None)()
        if group is not None and group.exclusive():
            groups_reached.add(id(group))
    for w in interactive:
        if type(w).__name__ == "QToolButton":
            continue  # the actions inside a field (clear, show password): mouse helpers, checked by the name rule
        group = getattr(w, "group", lambda: None)()
        if group is not None and group.exclusive() and id(group) in groups_reached:
            continue  # a group of options is one Tab stop; the arrow keys move inside it
        if not (w.focusPolicy().value & Qt.TabFocus.value):
            add("keyboard", w, "cannot take the keyboard focus")
        elif w not in reached:
            add("keyboard", w, "Tab never reaches it")


def _fresh_home() -> None:
    """An empty data folder for each language and theme (the test helper's isolated_home, without a test)."""
    home = Path(tempfile.mkdtemp(prefix="atesta-id-wallet-ux-"))
    storage.BASE_DIR, storage.PROFILES_DIR = home, home / "profiles"
    storage.set_profile("default")


def run(gui: Any, langs: list[str], themes: list[str], outdir: Path | None = None,
        keyboard: bool = True) -> dict[tuple[str, str], Audit]:
    """Renders every screen in each language and theme; returns the audits (and saves the screenshots)."""
    from PySide6.QtWidgets import QApplication

    from atesta_id_wallet.gui import theme as theme_module
    from atesta_id_wallet.gui import widgets

    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    widgets.ANIMATIONS = False
    gui.links_registered = lambda: False
    gui._screenshot_dirs = lambda: []
    results = {}
    for lang in langs:
        for theme_name in themes:
            _fresh_home()
            i18n.set_language(lang)
            storage.save_settings({"theme": theme_name})  # the window reads it from the settings
            theme_module.preference = theme_name
            window = gui.MainWindow()
            window.resize(1100, 740)
            window.show()
            app.processEvents()
            audit = Audit()
            for name, setup in screens(gui):
                window._close_sheet()
                app.processEvents()
                setup(window)
                for _ in range(3):
                    app.processEvents()
                if name.startswith("_"):
                    continue
                if outdir is not None:
                    folder = outdir / f"{lang}-{theme_name}"
                    folder.mkdir(parents=True, exist_ok=True)
                    window.grab().save(str(folder / f"{name}.png"))
                check_window(gui, window, name, audit, keyboard=keyboard)
            window._close_sheet()
            window.close()
            window.deleteLater()
            app.processEvents()
            results[(lang, theme_name)] = audit
    return results


# ---------------------------------------------------------------------------
# Interaction cost of the key tasks (Keystroke-Level Model) and response times
# ---------------------------------------------------------------------------

# Card, Moran & Newell (1980), average non-secretary typist: Mental preparation, Pointing with the
# mouse, a mouse Button press + release, Homing between mouse and keyboard, a Keystroke.
KLM = {"M": 1.35, "P": 1.1, "BB": 0.2, "H": 0.4, "K": 0.28}


@dataclass
class TaskCost:
    task: str
    steps: list[str]  # what the person does, in order
    decisions: int  # panels where they have to choose (a click each)
    keystrokes: int
    seconds: float  # KLM estimate of the person's time (not the network's)
    ok: bool


def _click_cost() -> float:
    return KLM["M"] + KLM["P"] + KLM["BB"]


def drive_task(gui: Any, window: Any, task: str, start: Callable[[], None], timeout: float = 20) -> TaskCost:
    """Runs a flow in the real window answering each panel as a person would, and counts what they do."""
    from PySide6.QtWidgets import QApplication, QPushButton

    app = QApplication.instance()
    steps, decisions, keystrokes, seconds, ok = ["Scan QR"], 1, 0, _click_cost(), False
    start()
    deadline = time.time() + timeout
    answered = None
    while time.time() < deadline:
        app.processEvents()
        time.sleep(0.005)
        sheet = window.overlay.sheet
        if sheet is None or sheet is answered or isinstance(sheet, gui.ProgressSheet):
            if sheet is None and not window.busy and answered is not None:
                break
            continue
        answered = sheet
        buttons = [b for b in sheet.findChildren(QPushButton) if b.isVisibleTo(sheet)]
        kind = type(sheet).__name__
        if kind == "TextSheet":
            sheet.field.setText("1234")
            keystrokes += 5  # the code and Enter
            seconds += KLM["M"] + KLM["H"] + 5 * KLM["K"] + KLM["H"]
            steps.append("type the 4-digit code + Enter")
            sheet.field.returnPressed.emit()
            continue
        main = next((b for b in buttons if b.objectName() == "primary"), buttons[-1])
        steps.append(main.text())
        decisions += 1
        seconds += _click_cost()
        if kind == "ResultSheet":
            ok = sheet.title.text() in (i18n.tr("Credential added"), i18n.tr("Data shared"))
            main.click()
            break
        main.click()
    app.processEvents()
    return TaskCost(task, steps, decisions, keystrokes, round(seconds, 1), ok)


def task_costs(gui: Any) -> list[TaskCost]:
    """Receive a credential, then sign in with it, against the fake issuer and verifier of the tests."""
    import http.server

    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    from atesta_id_wallet.gui import widgets

    app = QApplication.instance() or QApplication([])
    widgets.ANIMATIONS = False
    gui._screenshot_dirs = lambda: []
    gui.links_registered = lambda: True
    issuer = http.server.HTTPServer(("127.0.0.1", 0), helpers.FakeIssuer)
    verifier = http.server.HTTPServer(("127.0.0.1", 0), helpers.FakeVerifier)
    for server in (issuer, verifier):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    helpers.FakeIssuer.base = f"http://localhost:{issuer.server_port}"
    helpers.FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())
    helpers.FakeVerifier.received = []
    _fresh_home()
    window = gui.MainWindow()
    window.show()
    try:
        offer = f"openid-credential-offer://?credential_offer_uri={helpers.FakeIssuer.base}/offer"
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(offer)
        costs = [drive_task(gui, window, "Receive a credential", window.scan)]
        key = ec.generate_private_key(ec.SECP256R1())
        clipboard.setText(helpers.verifier_request(f"http://localhost:{verifier.server_port}", key,
                                                   helpers.make_cert(key, "localhost")))
        costs.append(drive_task(gui, window, "Sign in to a service with it", window.scan))
        return costs
    finally:
        QGuiApplication.clipboard().clear()
        window.close()
        window.deleteLater()
        app.processEvents()
        for server in (issuer, verifier):
            server.shutdown()


def response_times(gui: Any, rounds: int = 5) -> dict[str, float]:
    """Median milliseconds of what must feel instant (Nielsen: 0.1 s): changing page, opening a panel."""
    import statistics as stats

    from PySide6.QtWidgets import QApplication

    from atesta_id_wallet.gui import widgets

    app = QApplication.instance() or QApplication([])
    widgets.ANIMATIONS = False
    _fresh_home()
    fill_wallet()
    window = gui.MainWindow()
    window.resize(1100, 740)
    window.show()
    app.processEvents()
    times: dict[str, list[float]] = {"open the window": [], "change page": [], "open a credential": [],
                                     "open a panel": []}

    def measure(name: str, action: Callable[[], None]) -> None:
        start = time.perf_counter()
        action()
        app.processEvents()
        times[name].append((time.perf_counter() - start) * 1000)

    try:
        for _ in range(rounds):
            measure("change page", lambda: window._nav("activity"))
            measure("change page", lambda: window._nav("settings"))
            measure("change page", lambda: window._nav("wallet"))
            measure("open a credential", lambda: window.open_credential(window.records[0]))
            measure("open a panel", lambda: window.confirm_delete(window.records[0]))
            window._close_sheet()
            app.processEvents()
            measure("open the window", window._build)
        return {k: round(stats.median(v), 1) for k, v in times.items()}
    finally:
        window.close()
        window.deleteLater()
        app.processEvents()


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def report(results: dict[tuple[str, str], Audit], langs: list[str], costs: list[TaskCost] | None = None,
           timings: dict[str, float] | None = None) -> str:
    lines = ["# UX audit (automatic)", "", f"Generated {time.strftime('%Y-%m-%d %H:%M')} by `tests/ux_audit.py`.", ""]
    if costs:
        lines += ["## Tasks (Keystroke-Level Model)", "",
                  "| Task | Decisions | Keystrokes | Estimated time | Steps | Completed |", "|---|---|---|---|---|---|"]
        lines += [f"| {c.task} | {c.decisions} | {c.keystrokes} | {c.seconds} s | {' → '.join(c.steps)} | "
                  f"{'yes' if c.ok else 'NO'} |" for c in costs]
        lines += ["", "Taking the screenshot of the QR code (outside the wallet) is not counted.", ""]
    if timings:
        lines += ["## Response times (median)", "", "| Action | ms |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in timings.items()]
        lines += ["", "Nielsen's limits: 100 ms feels instant, 1 s keeps the flow of thought.", ""]
    lines += ["## Screens", "", "| Language-theme | Screens | Widgets | " + " | ".join(CHECKS) + " | Lowest contrast |",
              "|---|---|---|" + "---|" * len(CHECKS) + "---|"]
    for (lang, theme_name), audit in results.items():
        counts = audit.by_check()
        lowest = min(audit.min_contrast.values()) if audit.min_contrast else 0
        lines.append(f"| {lang}-{theme_name} | {audit.screens} | {audit.widgets} | "
                     + " | ".join(str(counts.get(c, 0)) for c in CHECKS) + f" | {lowest:.2f}:1 |")
    lines += ["", "### Findings", ""]
    seen = set()
    for (lang, theme_name), audit in results.items():
        for f in audit.findings:
            key = (f.check, f.screen, f.widget, f.detail)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"- **{f.check}** · {lang}-{theme_name} · {f.screen} · {f.widget}: {f.detail}")
    if not seen:
        lines.append("None.")
    lines += ["", "## Texts", "", "| Language | Texts | Words/sentence | LIX | Formula | Score | Jargon |",
              "|---|---|---|---|---|---|---|"]
    metrics = [text_metrics(lang) for lang in langs]
    for m in metrics:
        lines.append(f"| {m.lang} | {m.prose} | {m.words_per_sentence} | {m.lix} | {m.flesch_name} | "
                     f"{'—' if m.flesch is None else m.flesch} | {len(m.jargon)} |")
    for m in metrics:
        lines += ["", f"### {m.lang}", "", "Longest sentences:", ""]
        lines += [f"- {n} words: {s}" for n, s in m.longest]
        if m.jargon:
            lines += ["", "Jargon:", ""] + [f"- *{t}*: {x}" for t, x in m.jargon]
        if m.soft:
            lines += ["", "Words that need some knowledge: " + ", ".join(f"{k} ×{v}" for k, v in m.soft.items())]
    return "\n".join(lines) + "\n"


CHECKS = ("text-clipped", "name", "target-size", "contrast", "small-text", "focus-trap", "keyboard")


def main(argv: list[str]) -> int:
    import argparse
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    parser = argparse.ArgumentParser(description="UX audit of the GUI")
    parser.add_argument("outdir", type=Path)
    parser.add_argument("--langs", default=",".join(i18n.LANGUAGES))
    parser.add_argument("--themes", default="light,dark")
    args = parser.parse_args(argv)
    from atesta_id_wallet.gui import app as gui

    langs = args.langs.split(",")
    i18n.set_language("en")
    costs = task_costs(gui)
    timings = response_times(gui)
    results = run(gui, langs, args.themes.split(","), args.outdir)
    (args.outdir / "report.md").write_text(report(results, langs, costs, timings), encoding="utf-8")
    total = sum(len(a.findings) for a in results.values())
    print(f"{sum(a.screens for a in results.values())} screens, {total} findings → {args.outdir / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""
Generates the README screenshots (docs/images/*.png) with made-up data, in a temporary profile and
with an in-memory keyring: it never touches the real wallet or keyring.
Usage:  python docs/make_screenshots.py   (run again when the interface changes)
"""

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
os.environ["ATESTA_ID_WALLET_HOME"] = tempfile.mkdtemp(prefix="atesta-screenshots-")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_SCALE_FACTOR", "2")  # sharp on high-density screens
sys.path.insert(0, str(ROOT))

import keyring  # noqa: E402
import keyring.backend  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402


class MemoryKeyring(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.secrets = {}

    def get_password(self, service, username):
        return self.secrets.get((service, username))

    def set_password(self, service, username, password):
        self.secrets[(service, username)] = password

    def delete_password(self, service, username):
        self.secrets.pop((service, username), None)


keyring.set_keyring(MemoryKeyring())

from atesta_id_wallet import common, i18n, storage  # noqa: E402

# (name, issuer name, issuer URL, colour or None, claims): all made up.
CREDENTIALS = [
    ("Data Space Membership", "Valencia Data Space", "https://dataspace.example", "#0f766e",
     {"given_name": "Alex", "family_name": "García", "membership": "Provider", "since": "2026-03-01"}),
    ("University Degree", "Example University", "https://university.example", "#8b1e3f",
     {"given_name": "Alex", "family_name": "García", "degree": "MSc Computer Science", "year": 2024}),
    ("Employee Badge", "Example Corp", "https://corp.example", "#1f4fd1",
     {"given_name": "Alex", "family_name": "García", "email": "alex.garcia@corp.example", "role": "Engineer"}),
    ("Legal Person Credential", "Marketplace Keycloak", "https://keycloak.example/realms/market", None,
     {"email": "alex.garcia@corp.example", "organization": "Example Corp"}),
]


def credential(issuer_key: storage.HolderKey, issuer: str, claims: dict) -> str:
    payload = {"iss": issuer, "iat": int(time.time()), **claims,
               "cnf": {"jwk": storage.HolderKey.load_or_create().public_jwk}}
    return issuer_key.sign_jwt({"typ": "dc+sd-jwt"}, payload) + "~"


def fill_profile() -> None:
    for index, (name, issuer_name, issuer, colour, claims) in enumerate(reversed(CREDENTIALS)):
        issuer_key = storage.HolderKey(ec.generate_private_key(ec.SECP256R1()))
        display = {"name": name, "issuer_name": issuer_name}
        if colour:
            display["background_color"] = colour
        claims = {"vct": f"{issuer}/{name.replace(' ', '')}", **claims}
        storage.save_credential(credential(issuer_key, issuer, claims), fmt="dc+sd-jwt", issuer=issuer,
                                configuration_id=name.replace(" ", ""), display=display)
        storage.add_history({"type": "issued", "party": issuer_name, "party_id": issuer, "credentials": [name]})
        time.sleep(1.01)  # distinct file names and dates
    storage.add_history({"type": "presented", "party": "marketplace.example", "party_id": "marketplace.example",
                         "credentials": ["Legal Person Credential"], "claims": ["email", "organization"]})


def shot(window, name: str) -> None:
    from PySide6.QtWidgets import QApplication

    for _ in range(3):
        QApplication.processEvents()
    OUT.mkdir(parents=True, exist_ok=True)
    window.grab().save(str(OUT / name), "PNG")
    print(f"✔ {OUT / name}")


def main() -> int:
    from PySide6.QtWidgets import QApplication

    common.LOG_HANDLER = lambda message, is_debug: None
    i18n.set_language("en")
    app = QApplication(sys.argv[:1])
    app.setStyle("Fusion")
    from atesta_id_wallet.gui import app as gui

    fill_profile()
    for theme_name in ("light", "dark"):
        os.environ["ATESTA_ID_WALLET_THEME"] = theme_name
        window = gui.MainWindow()
        window.resize(1180, 660)
        window.show()
        shot(window, f"wallet-{theme_name}.png")
        if theme_name == "light":
            window.open_credential(window.records[1])
            shot(window, "credential-light.png")
        window.close()
    gui.release_widgets()
    return 0


if __name__ == "__main__":
    sys.exit(main())

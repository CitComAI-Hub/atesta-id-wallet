"""
Integration tests against a real Keycloak with OID4VCI (realm in realm.json, next to this file).

They guard what the offline fakes cannot: Keycloak's real endpoints, its login pages and the error
text the wallet recognises (the fallback for offers bound to another client depends on it).

    tests/integration/run_keycloak.sh quay.io/keycloak/keycloak:26.7 /tmp/kc-certs
    ATESTA_KEYCLOAK_URL=https://localhost:8443 REQUESTS_CA_BUNDLE=/tmp/kc-certs/cert.pem \
        python -m unittest discover -s tests/integration -v

ATESTA_KEYCLOAK_BINDS_OFFERS=1 (or 0) also checks whether the server refuses offers made for another
client and the wallet has to fall back (SEAMWARE's 26.6.2, used by CitCom, and 26.7 do; 26.8 does not).
Skipped without ATESTA_KEYCLOAK_URL. Run nightly by .github/workflows/keycloak.yml.
"""

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

os.environ["ATESTA_ID_WALLET_HOME"] = tempfile.mkdtemp(prefix="atesta-id-wallet-it-")
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import keyring  # noqa: E402
import keyring.backend  # noqa: E402
import requests  # noqa: E402

from atesta_id_wallet import common, i18n, storage, ui, vci  # noqa: E402

KEYCLOAK = os.environ.get("ATESTA_KEYCLOAK_URL", "").rstrip("/")
ISSUER = f"{KEYCLOAK}/realms/atesta"
USER, PASSWORD, EMAIL = "alice", "alice-test-password", "alice@example.org"
CONFIG = "TestCredential"
# Never loaded: the headless login stops at the redirect (an http://localhost one would wait for a browser).
REDIRECT = "https://wallet.invalid/callback"


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
i18n.set_language("en")


class Browser:
    """The user's browser: keeps its cookies (Keycloak's SSO session) and signs in as alice."""

    def __init__(self):
        self.session = requests.Session()
        self.logins = 0  # login forms filled in
        self.visits = 0

    def visit(self, url):
        self.visits += 1
        browser = self

        class Typist(ui.Prompter):
            def login(self, host, username, *, ask_username):
                browser.logins += 1
                return USER, PASSWORD

        location, _ = vci.headless_login(self.session, url, "http://127.0.0.1:", None, Typist())
        self.session.get(location, timeout=20)  # back to the wallet's loopback server


class Answers(ui.Prompter):
    """Accepts every offer and signs in as alice; records the logins and the wallet's log."""

    def __init__(self):
        self.logins = 0  # passwords typed into the wallet
        self.browser = Browser()

    def wait_for_browser(self, host, url, wait):
        errors = []

        def run():
            try:
                self.browser.visit(url)
            except Exception as exc:  # shown by the test, not lost in the thread
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            return wait(threading.Event())
        finally:
            thread.join(20)
            if errors:
                raise errors[0]

    def login(self, host, username, *, ask_username):
        self.logins += 1
        return USER, PASSWORD

    def confirm(self, question, *, default=False):
        return True

    def notice(self, message):
        raise AssertionError(f"Unexpected instructions for the user: {message}")


def create_offer(client_id: str, *, pre_authorized: bool) -> str:
    """Credential offer URI made by Keycloak for alice, with a token of client_id (as a portal would)."""
    token = requests.post(f"{ISSUER}/protocol/openid-connect/token", timeout=20, data={
        "grant_type": "password", "client_id": client_id, "username": USER, "password": PASSWORD,
        # Not the credential scope: Keycloak 26.8 refuses tokens whose audience is the credential endpoint.
        "scope": "openid",
    })
    token.raise_for_status()
    response = requests.get(
        f"{ISSUER}/protocol/oid4vc/create-credential-offer", timeout=20,
        params={"credential_configuration_id": CONFIG, "pre_authorized": str(pre_authorized).lower()},
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    response.raise_for_status()
    offer = response.json()
    return f"{offer['issuer'].rstrip('/')}/{offer['nonce']}"


@unittest.skipUnless(KEYCLOAK, "ATESTA_KEYCLOAK_URL is not set")
class KeycloakIssuance(unittest.TestCase):
    def setUp(self):
        home = Path(tempfile.mkdtemp(prefix="atesta-id-wallet-it-"))
        saved = storage.BASE_DIR, storage.PROFILES_DIR
        storage.BASE_DIR, storage.PROFILES_DIR = home, home / "profiles"
        storage.set_profile("default")
        self.addCleanup(lambda: (setattr(storage, "BASE_DIR", saved[0]),
                                 setattr(storage, "PROFILES_DIR", saved[1]), storage.set_profile("default")))
        self.log = []
        saved_handler = common.LOG_HANDLER
        common.LOG_HANDLER = lambda message, is_debug: self.log.append(message)
        self.addCleanup(setattr, common, "LOG_HANDLER", saved_handler)
        self.answers = Answers()

    def assert_issued(self, issued):
        self.assertEqual([c.configuration_id for c in issued], [CONFIG])
        # Which account it was issued for: known after a login, not for pre-authorized offers.
        self.assertIn(issued[0].account, (f"{USER} ({EMAIL})", None))
        self.assertEqual(issued[0].claims.get("email"), EMAIL)
        self.assertEqual(issued[0].claims.get("vct"), CONFIG)
        self.assertEqual(len(storage.load_credentials()), 1)

    def test_pre_authorized_offer(self):
        offer = create_offer("atesta-test", pre_authorized=True)
        issued = vci.issue(requests.Session(), offer, vci.IssueOptions(), self.answers)
        self.assert_issued(issued)
        self.assertEqual(self.answers.logins, 0)

    def test_pre_authorized_offer_without_dpop(self):
        offer = create_offer("atesta-test", pre_authorized=True)
        self.assert_issued(vci.issue(requests.Session(), offer, vci.IssueOptions(dpop=False), self.answers))

    def test_authorization_code_offer(self):
        """issuer_state offer + headless login on Keycloak's real login page."""
        offer = create_offer("atesta-test", pre_authorized=False)
        issued = vci.issue(requests.Session(), offer, vci.IssueOptions(client_id="atesta-test", redirect_uri=REDIRECT), self.answers)
        self.assert_issued(issued)
        self.assertEqual(self.answers.logins, 1)
        remembered = storage.load_config()["issuers"][ISSUER]
        self.assertEqual((remembered["client_id"], remembered["username"]), ("atesta-test", USER))

    def test_wallet_initiated_with_dpop_client(self):
        """A client that requires DPoP-bound tokens: the credential request only works with the proof."""
        options = vci.IssueOptions(client_id="dpop-wallet", redirect_uri=REDIRECT)
        self.assert_issued(vci.issue_from_issuer(requests.Session(), ISSUER, [CONFIG], options, self.answers))

    def test_dpop_client_refuses_plain_bearer(self):
        options = vci.IssueOptions(client_id="dpop-wallet", redirect_uri=REDIRECT, dpop=False)
        with self.assertRaises(common.WalletError):
            vci.issue_from_issuer(requests.Session(), ISSUER, [CONFIG], options, self.answers)
        self.assertEqual(storage.load_credentials(), [])

    def test_browser_login_with_the_wallet_client(self):
        """The server knows atesta-id-wallet: the login happens in the browser, no password in the wallet."""
        options = vci.IssueOptions(open_browser=False)
        self.assert_issued(vci.issue_from_issuer(requests.Session(), ISSUER, [CONFIG], options, self.answers))
        self.assertEqual((self.answers.logins, self.answers.browser.logins), (0, 1))
        self.assertEqual(storage.load_history()[0].get("account"), f"{USER} ({EMAIL})")
        remembered = storage.load_config()["issuers"][ISSUER]
        self.assertEqual((remembered["client_id"], remembered["redirect_uri"]),
                         (vci.WALLET_CLIENT_ID, vci.LOOPBACK_REDIRECT))
        # Next time the browser's SSO session signs in without asking.
        self.assertEqual(len(vci.issue_from_issuer(requests.Session(), ISSUER, [CONFIG], options, self.answers)), 1)
        self.assertEqual((self.answers.browser.logins, self.answers.browser.visits), (1, 2))

    def test_browser_login_for_an_offer_made_by_another_client(self):
        """
        An issuer_state offer made by another client (atesta-test), as the account console makes them.
        With its own client the wallet does not send the issuer_state: servers that bind offers would
        refuse it and keep it in the browser's SSO session, breaking later logins too.
        """
        offer = create_offer("atesta-test", pre_authorized=False)
        issued = vci.issue(requests.Session(), offer, vci.IssueOptions(open_browser=False), self.answers)
        self.assert_issued(issued)
        self.assertEqual((self.answers.logins, self.answers.browser.logins), (0, 1))

    def test_offer_bound_to_another_client(self):
        """
        Offer made with another wallet's client (as the PGTEC onboarding does for Lissi). Keycloak 26.6.2
        (SEAMWARE) and 26.7 refuse it with 'offer target client ... different from login client' and the
        wallet asks again without the offer, replaying the login; 26.8 just accepts it.
        """
        offer = create_offer("other-wallet", pre_authorized=False)
        issued = vci.issue(requests.Session(), offer, vci.IssueOptions(client_id="atesta-test", redirect_uri=REDIRECT), self.answers)
        self.assert_issued(issued)
        self.assertEqual(self.answers.logins, 1)  # the user signs in once either way
        fell_back = any("made for another wallet (other-wallet)" in line for line in self.log)
        expected = os.environ.get("ATESTA_KEYCLOAK_BINDS_OFFERS")
        if expected is not None:
            self.assertEqual(fell_back, expected == "1", json.dumps(self.log, indent=1))


if __name__ == "__main__":
    unittest.main()

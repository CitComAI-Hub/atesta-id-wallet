"""
The OpenID Foundation conformance suite's OID4VP 1.0 Final/HAIP wallet plan, run against the wallet.

The suite plays the verifier (x509_hash, signed request by reference, direct_post.jwt, a DCQL query
for the test Keycloak's credential); the wallet gets one SD-JWT VC from Keycloak and answers every
module's request without asking. See run_suite.sh. Skipped without ATESTA_CONFORMANCE_URL.
Run nightly by .github/workflows/conformance.yml.
"""

import base64
import datetime
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ["ATESTA_ID_WALLET_HOME"] = tempfile.mkdtemp(prefix="atesta-id-wallet-conformance-")
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import keyring  # noqa: E402
import keyring.backend  # noqa: E402
import requests  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from atesta_id_wallet import common, i18n, storage, ui, vci, vp  # noqa: E402

SUITE = os.environ.get("ATESTA_CONFORMANCE_URL", "").rstrip("/")
KEYCLOAK = os.environ.get("ATESTA_KEYCLOAK_URL", "").rstrip("/")
PLAN = "oid4vp-1final-wallet-haip-test-plan"
PREFIX = "oid4vp-1final-wallet-"
# The wallet presents and the suite is satisfied.
PASS = {"happy-flow", "request-uri-method-post", "ignores-unusable-encryption-key", "fewer-claims-than-available",
        "optional-credential-set", "no-claims-in-dcql-query",
        # refused, with the error response the suite expects
        "negative-test-redirect-uri-with-direct-post", "negative-test-unknown-transaction-data-type"}
# The wallet must refuse; the suite then waits for a screenshot of the error (a manual step of
# certification), so it is enough that the wallet refused and the suite saw nothing wrong.
REFUSE = {"negative-test-invalid-request-object-signature", "negative-test-invalid-request-object-typ",
          "negative-test-missing-request-object-typ", "negative-test-mismatched-client-id",
          "negative-test-missing-nonce", "negative-test-invalid-client-id-prefix",
          "negative-test-required-non-matching-credential", "negative-test-claim-not-in-credential"}
# Needs a browser that runs the verifier's page after the redirect (the wallet hands it over).
SKIP = {"alternate-happy-flow"}


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


class Yes(ui.Prompter):
    def confirm(self, question, *, default=False):
        return True

    def notice(self, message):
        pass

    def text(self, prompt, *, default=None):
        raise AssertionError(f"asked: {prompt}")


def verifier_key() -> dict:
    """Request signing key with a certificate from a CA (HAIP: not self-signed, CA not in x5c)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "atesta conformance verifier CA")])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost.emobix.co.uk")]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost.emobix.co.uk")]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    numbers = key.private_numbers()

    def b64(value):
        return common.b64u(value.to_bytes(32, "big"))

    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "atesta-conformance",
            "x": b64(numbers.public_numbers.x), "y": b64(numbers.public_numbers.y), "d": b64(numbers.private_value),
            "x5c": [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()]}


def api(method, path, **kwargs):
    response = requests.request(method, f"{SUITE}/{path}", timeout=30, **kwargs)
    response.raise_for_status()
    return response.json() if response.content else None


def wait_status(test_id, statuses, timeout):
    end = time.time() + timeout
    info = api("GET", f"api/info/{test_id}")
    while info["status"] not in statuses and time.time() < end:
        time.sleep(0.5)
        info = api("GET", f"api/info/{test_id}")
    return info


@unittest.skipUnless(SUITE and KEYCLOAK, "ATESTA_CONFORMANCE_URL and ATESTA_KEYCLOAK_URL are not set")
class Oid4vpWalletPlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage.set_profile("default")
        realm = f"{KEYCLOAK}/realms/atesta"
        token = requests.post(f"{realm}/protocol/openid-connect/token", timeout=20, data={
            "grant_type": "password", "client_id": "atesta-test", "username": "alice",
            "password": "alice-test-password", "scope": "openid"})
        token.raise_for_status()
        offer = requests.get(f"{realm}/protocol/oid4vc/create-credential-offer", timeout=20,
                             params={"credential_configuration_id": "TestCredential", "pre_authorized": "true"},
                             headers={"Authorization": f"Bearer {token.json()['access_token']}"}).json()
        vci.issue(requests.Session(), f"{offer['issuer'].rstrip('/')}/{offer['nonce']}", vci.IssueOptions(), Yes())
        ca = Path(os.environ["ATESTA_KEYCLOAK_CA"]).read_text()
        config = {
            "alias": "atesta-id-wallet", "description": "Atesta ID Wallet (CI)",
            "server": {"authorization_endpoint": "openid4vp://"},
            "client": {"jwks": {"keys": [verifier_key()]}, "dcql": {"credentials": [{
                "id": "test", "format": "dc+sd-jwt", "meta": {"vct_values": ["TestCredential"]},
                "claims": [{"path": ["email"]}, {"path": ["firstName"]}]}]}},
            "credential": {"trust_anchor_pem": ca, "status_list_trust_anchor_pem": ca},
        }
        variant = {"credential_format": "sd_jwt_vc", "credential_type": "custom", "response_mode": "direct_post.jwt"}
        cls.plan = api("POST", "api/plan", params={"planName": PLAN, "variant": json.dumps(variant)}, json=config)
        print(f"\nPlan {cls.plan['id']}: {SUITE}/plan-detail.html?plan={cls.plan['id']}", file=sys.stderr)

    def run_module(self, module):
        """Runs one module; returns (the suite's result, the wallet's error or None)."""
        test_id = api("POST", "api/runner", params={"test": module, "plan": self.plan["id"]})["id"]
        wait_status(test_id, ("WAITING", "FINISHED", "INTERRUPTED"), 30)
        urls = api("GET", f"api/runner/browser/{test_id}").get("urls") or []
        self.assertTrue(urls, "the suite gave the wallet no request")
        error = None
        try:
            session = common.new_session()
            prepared = vp.prepare_presentation(session, urls[0], storage.load_credentials())
            redirect = vp.send_presentation(session, prepared, vp.build_response(prepared))
            if redirect:
                requests.get(redirect, timeout=20)  # what the browser would do
        except common.WalletError as exc:
            error = str(exc)
        info = wait_status(test_id, ("FINISHED", "INTERRUPTED"), 20)
        return info, error

    def test_modules(self):
        names = [m["testModule"] for m in self.plan["modules"]]
        for module in names:
            short = module.removeprefix(PREFIX)
            if short in SKIP:
                continue
            with self.subTest(module=short):
                if short not in PASS | REFUSE:
                    self.skipTest(f"{short}: no expectation yet")
                info, error = self.run_module(module)
                if short in PASS:
                    self.assertEqual(info.get("result"), "PASSED", f"{short}: {info.get('status')}, wallet: {error}")
                else:
                    self.assertIsNotNone(error, f"{short}: the wallet did not refuse")
                    self.assertNotEqual(info.get("result"), "FAILED", f"{short}: {error}")
        self.assertTrue(PASS | REFUSE <= {n.removeprefix(PREFIX) for n in names}, "modules missing from the plan")


if __name__ == "__main__":
    unittest.main()

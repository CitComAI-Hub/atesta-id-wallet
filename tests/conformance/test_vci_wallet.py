"""
The OpenID Foundation conformance suite's OID4VCI 1.0 Final/HAIP wallet plan, run against the wallet.

The suite plays the credential issuer and its authorization server (PAR, DPoP, wallet attestation
as client authentication, `iss` in the authorization response); the wallet asks for a credential
wallet-initiated, with a wallet provider (provider/wallet_provider.py) running in this process for
the wallet attestation and the key attestations. The suite never calls the provider: it trusts
the provider's CA (client_attestation.trust_anchor). The login is the suite's, with no user: the
"browser" here follows the authorization URL to the wallet's loopback address.

Two credential configurations of the suite: a JWT proof with a key attestation in its header,
and the `attestation` proof type. Modules for what the wallet does not do yet (deferred issuance,
encrypted credential requests) have no expectation. See run_suite.sh; skipped without
ATESTA_CONFORMANCE_URL. Run nightly by .github/workflows/conformance.yml.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

os.environ["ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP"] = "1"  # the wallet provider runs on http://localhost
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "provider"))

import test_vp_wallet as vp_plan  # noqa: E402  (first: sets the test environment)
import requests  # noqa: E402

import wallet_provider  # noqa: E402
from atesta_id_wallet import attestation, common, storage, vci  # noqa: E402

SUITE = vp_plan.SUITE
PLAN = "oid4vci-1_0-wallet-haip-test-plan"
ALIAS = "atesta-id-wallet-vci"
ISSUER = f"{SUITE}/test/a/{ALIAS}/"
# The wallet is issued the credential, or refuses what it must refuse, and the suite is satisfied.
PASS = {
    "oid4vci-1_0-wallet-test-credential-issuance", "oid4vci-1_0-wallet-test-client-attestation-challenge",
    "oid4vci-1_0-wallet-test-batch-credential-issuance",
    *(f"fapi2-security-profile-final-client-test-{name}" for name in (
        "happy-path", "discovery-issuer-mismatch", "invalid-authorization-response-iss",
        "remove-authorization-response-iss", "ensure-authorization-response-with-invalid-state-fails",
        "ensure-authorization-response-with-invalid-missing-state-fails",
        "token-endpoint-response-without-expires_in", "token-type-case-insensitivity",
        "rs-dpop-auth-scheme-case-insensitivity", "happy-path-no-dpop-nonce", "happy-path-no-mtls-endpoint-aliases")),
}
# The suite skips it: the wallet does not use the notification endpoint (it has nothing to notify).
SKIPPED = {"oid4vci-1_0-wallet-test-credential-issuance-notification"}


class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Browser(vp_plan.Yes):
    """Follows the authorization URL: the suite's server answers at once with a redirect to the wallet."""

    def wait_for_browser(self, host, url, wait):
        def go():
            response = requests.get(url, timeout=30, allow_redirects=False)
            location = response.headers.get("Location", "")
            if response.is_redirect and location.startswith("http://127.0.0.1"):
                requests.get(location, timeout=30)  # an error page instead means the test failed
        threading.Thread(target=go, daemon=True).start()
        stop = threading.Event()
        threading.Timer(20, stop.set).start()
        return wait(stop)


@unittest.skipUnless(SUITE, "ATESTA_CONFORMANCE_URL is not set")
class Oid4vciWalletPlan(unittest.TestCase):
    """Wallet-initiated issuance of an SD-JWT VC, with wallet attestation and key attestation."""

    @classmethod
    def setUpClass(cls):
        folder = tempfile.mkdtemp(prefix="atesta-provider-")
        server = make_server("127.0.0.1", 0, lambda env, start: cls.provider(env, start), handler_class=Quiet)
        cls.provider_url = f"http://localhost:{server.server_port}"
        wallet_provider.init(Path(folder), "Atesta conformance wallet provider")
        cls.provider = wallet_provider.Provider(wallet_provider.Config.from_env({
            "WP_URL": cls.provider_url, "WP_KEY": f"{folder}/signer.key", "WP_CERTS": f"{folder}/signer.pem",
            "WP_SECRET": os.urandom(16).hex()}))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.addClassCleanup(server.shutdown)
        cls.ca = Path(folder, "ca.pem").read_text()
        cls.redirect_uri = f"http://127.0.0.1:{free_port()}/callback"

    def setUp(self):
        storage.set_profile("vci")
        os.environ[attestation.ENV_PROVIDER] = self.provider_url
        self.addCleanup(os.environ.pop, attestation.ENV_PROVIDER, None)

    def make_plan(self, configuration_id):
        config = {
            "alias": ALIAS, "description": f"Atesta ID Wallet (CI, {configuration_id})",
            "client": {"client_id": "atesta-id-wallet", "redirect_uri": self.redirect_uri},
            "server": {"jwks": {"keys": [vp_plan.verifier_key()]}},
            "credential": {"signing_jwk": vp_plan.verifier_key()},
            "client_attestation": {"issuer": self.provider_url, "trust_anchor": self.ca,
                                   "key_attestation_trust_anchor_pem": self.ca},
            "vci": {"credential_configuration_id": configuration_id},
        }
        variant = {"credential_format": "sd_jwt_vc", "vci_authorization_code_flow_variant": "wallet_initiated"}
        plan = vp_plan.api("POST", "api/plan", params={"planName": PLAN, "variant": json.dumps(variant)}, json=config)
        print(f"\nPlan {plan['id']}: {SUITE}/plan-detail.html?plan={plan['id']}", file=sys.stderr)
        return plan

    def run_module(self, plan, module, configuration_id):
        test_id = vp_plan.api("POST", "api/runner", params={"test": module["testModule"], "plan": plan["id"],
                                                            "variant": json.dumps(module["variant"])})["id"]
        vp_plan.wait_status(test_id, ("WAITING", "FINISHED", "INTERRUPTED"), 30)
        error = None
        try:
            vci.issue_from_issuer(common.new_session(), ISSUER, [configuration_id],
                                  vci.IssueOptions(redirect_uri=self.redirect_uri, open_browser=False), Browser())
        except common.WalletError as exc:
            error = str(exc)
        info = vp_plan.wait_status(test_id, ("FINISHED", "INTERRUPTED"), 20)
        failures = [entry.get("msg") for entry in vp_plan.api("GET", f"api/log/{test_id}")
                    if entry.get("result") == "FAILURE"]
        return info, error, failures

    def run_plan(self, configuration_id, wanted=None):
        plan = self.make_plan(configuration_id)
        seen = set()
        for module in plan["modules"]:
            name, variant = module["testModule"], module["variant"]
            supported = (variant.get("vci_credential_issuance_mode") == "immediate"
                         and variant.get("vci_credential_encryption") == "plain")
            if not supported or name not in PASS | SKIPPED or (wanted and name not in wanted):
                continue  # deferred issuance and encrypted requests: not supported yet
            seen.add(name)
            with self.subTest(module=name, configuration=configuration_id):
                info, error, failures = self.run_module(plan, module, configuration_id)
                expected = "SKIPPED" if name in SKIPPED else "PASSED"
                self.assertEqual(info.get("result"), expected,
                                 f"{name}: {info.get('status')}, wallet: {error}, suite: {failures[:3]}")
        self.assertEqual(seen, wanted or PASS | SKIPPED, "modules missing from the plan")

    def test_jwt_proof_with_key_attestation(self):
        self.run_plan("eu.europa.ec.eudi.pid.1.jwt.keyattest")

    def test_attestation_proof_type(self):
        self.run_plan("eu.europa.ec.eudi.pid.1.attestation.keyattest",
                      {"oid4vci-1_0-wallet-test-credential-issuance",
                       "oid4vci-1_0-wallet-test-batch-credential-issuance"})


if __name__ == "__main__":
    unittest.main()

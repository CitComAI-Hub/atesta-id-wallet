"""
The OpenID Foundation conformance suite's OID4VP 1.0 Final/HAIP wallet plan, run against the wallet.

The suite plays the verifier (x509_hash, signed request by reference, direct_post.jwt) and the
wallet answers every module's request without asking, twice:
- sd_jwt_vc: a DCQL query for the test Keycloak's credential, one SD-JWT VC from Keycloak;
- iso_mdl: the suite's mDL query, an mDL issued here by a test IACA (its CRL served to the suite).
See run_suite.sh. Skipped without ATESTA_CONFORMANCE_URL (and ATESTA_KEYCLOAK_URL for sd_jwt_vc).
Run nightly by .github/workflows/conformance.yml.
"""

import base64
import datetime
import hashlib
import http.server
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

os.environ["ATESTA_ID_WALLET_HOME"] = tempfile.mkdtemp(prefix="atesta-id-wallet-conformance-")
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import cbor2  # noqa: E402
import keyring  # noqa: E402
import keyring.backend  # noqa: E402
import requests  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.x509.oid import NameOID, ObjectIdentifier  # noqa: E402

from atesta_id_wallet import common, i18n, mdoc, storage, ui, vci, vp  # noqa: E402

SUITE = os.environ.get("ATESTA_CONFORMANCE_URL", "").rstrip("/")
KEYCLOAK = os.environ.get("ATESTA_KEYCLOAK_URL", "").rstrip("/")
PLAN = "oid4vp-1final-wallet-haip-test-plan"
PREFIX = "oid4vp-1final-wallet-"
# The wallet presents and the suite is satisfied.
PASS = {"happy-flow", "alternate-happy-flow", "request-uri-method-post", "ignores-unusable-encryption-key",
        "fewer-claims-than-available", "optional-credential-set", "no-claims-in-dcql-query",
        # refused, with the error response the suite expects
        "negative-test-redirect-uri-with-direct-post", "negative-test-unknown-transaction-data-type"}
# Only in the mDL plan.
PASS_MDL = {"all-mandatory-claims", "age-over-18"}
# The wallet must refuse; the suite then waits for a screenshot of the error (a manual step of
# certification), so it is enough that the wallet refused and the suite saw nothing wrong.
REFUSE = {"negative-test-invalid-request-object-signature", "negative-test-invalid-request-object-typ",
          "negative-test-missing-request-object-typ", "negative-test-mismatched-client-id",
          "negative-test-missing-nonce", "negative-test-invalid-client-id-prefix",
          "negative-test-required-non-matching-credential", "negative-test-claim-not-in-credential"}


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


def follow_redirect(redirect):
    """What the browser does with the verifier's redirect_uri: its page posts the fragment back to the suite."""
    page = requests.get(redirect, timeout=20)
    target = re.search(r"xhr\.open\('POST', \"([^\"]+)\"", page.text)
    if target and "#" in redirect:
        requests.post(target.group(1).replace("\\/", "/"), data="#" + redirect.split("#", 1)[1],
                      headers={"Content-type": "text/plain"}, timeout=20)


class WalletPlan:
    """Runs every module of a plan made by setUpClass (cls.plan) and checks each one's outcome."""
    plan: dict
    passing: set = PASS

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
                follow_redirect(redirect)
        except common.WalletError as exc:
            error = str(exc)
        info = wait_status(test_id, ("FINISHED", "INTERRUPTED"), 20)
        return info, error

    def test_modules(self):
        names = [m["testModule"] for m in self.plan["modules"]]
        for module in names:
            short = module.removeprefix(PREFIX)
            with self.subTest(module=short):
                if short not in self.passing | REFUSE:
                    self.skipTest(f"{short}: no expectation yet")
                info, error = self.run_module(module)
                if short in self.passing:
                    self.assertEqual(info.get("result"), "PASSED", f"{short}: {info.get('status')}, wallet: {error}")
                else:
                    self.assertIsNotNone(error, f"{short}: the wallet did not refuse")
                    self.assertNotEqual(info.get("result"), "FAILED", f"{short}: {error}")
        self.assertTrue(self.passing | REFUSE <= {n.removeprefix(PREFIX) for n in names}, "modules missing from the plan")


@unittest.skipUnless(SUITE and KEYCLOAK, "ATESTA_CONFORMANCE_URL and ATESTA_KEYCLOAK_URL are not set")
class Oid4vpWalletPlan(WalletPlan, unittest.TestCase):
    """sd_jwt_vc: the test Keycloak's credential."""

    @classmethod
    def setUpClass(cls):
        storage.set_profile("sd-jwt")
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

    def setUp(self):
        storage.set_profile("sd-jwt")


MDL, MDL_NAMESPACE = "org.iso.18013.5.1.mDL", "org.iso.18013.5.1"


def suite_host_address():
    """Where the suite's containers reach this computer (the gateway of their network)."""
    if os.environ.get("ATESTA_CONFORMANCE_HOST"):
        return os.environ["ATESTA_CONFORMANCE_HOST"]
    out = subprocess.run(["docker", "network", "inspect", "atesta-conformance_default", "--format",  # noqa: S603,S607
                          "{{range .IPAM.Config}}{{.Gateway}}{{end}}"], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def serve(body, content_type):
    """Serves one document to the suite (on every interface: it comes from a container); returns its URL."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(body())
    server = http.server.HTTPServer(("0.0.0.0", 0), Handler)  # noqa: S104
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://{suite_host_address()}:{server.server_port}/"


def issue_mdl(holder):
    """
    An mDL from a test IACA, with the certificate profile of ISO 18013-5 Annex B (the suite checks it,
    and fetches the CRL the document signer certificate names). Returns (IssuerSigned, IACA).
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    iaca_key, ds_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    iaca_name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                           x509.NameAttribute(NameOID.COMMON_NAME, "Atesta conformance IACA")])
    crl = {}
    crl_url = serve(lambda: crl["der"], "application/pkix-crl")
    common_extensions = [
        (x509.IssuerAlternativeName([x509.UniformResourceIdentifier("https://atesta.example/contact")]), False),
        (x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None,
                                                            None)]), False),
    ]

    def certificate(subject, key, *extensions):
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(iaca_name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=30)))
        for extension, critical in [*extensions, *common_extensions]:
            builder = builder.add_extension(extension, critical=critical)
        return builder.sign(iaca_key, hashes.SHA256())

    iaca = certificate(iaca_name, iaca_key, (x509.BasicConstraints(ca=True, path_length=0), True),
                       (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),
                       (x509.SubjectKeyIdentifier.from_public_key(iaca_key.public_key()), False))
    ds = certificate(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                                x509.NameAttribute(NameOID.COMMON_NAME, "Atesta conformance DS")]), ds_key,
                     (x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
                     (x509.ExtendedKeyUsage([ObjectIdentifier("1.0.18013.5.1.2")]), True),
                     (x509.AuthorityKeyIdentifier.from_issuer_public_key(iaca_key.public_key()), False),
                     (x509.SubjectKeyIdentifier.from_public_key(ds_key.public_key()), False))
    crl["der"] = (x509.CertificateRevocationListBuilder().issuer_name(iaca_name)
                  .last_update(now - datetime.timedelta(hours=1)).next_update(now + datetime.timedelta(days=7))
                  .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(iaca_key.public_key()), False)
                  .add_extension(x509.CRLNumber(1), False)
                  .sign(iaca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def date(text):
        return cbor2.CBORTag(1004, text)
    elements = {
        "family_name": "Ribes Soler", "given_name": "Marta", "birth_date": date("1990-04-02"),
        "issue_date": date("2024-01-10"), "expiry_date": date("2034-01-10"), "issuing_country": "ES",
        "issuing_authority": "DGT", "document_number": "X1234567", "un_distinguishing_sign": "E",
        "portrait": b"\xff\xd8\xff\xe0" + secrets.token_bytes(64),
        "driving_privileges": [{"vehicle_category_code": "B", "issue_date": date("2010-05-01")}],
        "age_over_18": True, "age_over_21": True, "nationality": "ES", "resident_address": "Cami de Vera",
    }
    items, digests = [], {}
    for digest_id, (name, value) in enumerate(elements.items()):
        item = cbor2.CBORTag(24, cbor2.dumps({"digestID": digest_id, "random": secrets.token_bytes(16),
                                              "elementIdentifier": name, "elementValue": value}))
        items.append(item)
        digests[digest_id] = hashlib.sha256(cbor2.dumps(item)).digest()
    n = holder.private_key.public_key().public_numbers()
    mso = {"version": "1.0", "digestAlgorithm": "SHA-256", "valueDigests": {MDL_NAMESPACE: digests},
           "deviceKeyInfo": {"deviceKey": {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}},
           "docType": MDL, "validityInfo": {"signed": now, "validFrom": now,
                                            "validUntil": now + datetime.timedelta(days=30)}}
    payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso, datetime_as_timestamp=False)))
    protected = cbor2.dumps({1: -7})
    r, s = decode_dss_signature(ds_key.sign(cbor2.dumps(["Signature1", protected, b"", payload]),
                                            ec.ECDSA(hashes.SHA256())))
    issuer_auth = [protected, {33: ds.public_bytes(serialization.Encoding.DER)}, payload,
                   r.to_bytes(32, "big") + s.to_bytes(32, "big")]
    return common.b64u(cbor2.dumps({"nameSpaces": {MDL_NAMESPACE: items}, "issuerAuth": issuer_auth})), iaca


@unittest.skipUnless(SUITE, "ATESTA_CONFORMANCE_URL is not set")
class Oid4vpWalletPlanMdl(WalletPlan, unittest.TestCase):
    """iso_mdl: the suite's mDL query, answered with an mDL issued here."""
    passing = PASS | PASS_MDL

    @classmethod
    def setUpClass(cls):
        storage.set_profile("mdl")
        holder = storage.HolderKey.generate()
        raw, iaca = issue_mdl(holder)
        storage.save_credential([(raw, holder)], fmt=mdoc.FORMAT, issuer="https://atesta.example",
                                configuration_id="mDL")
        anchor = iaca.public_bytes(serialization.Encoding.PEM).decode()
        config = {
            "alias": "atesta-id-wallet-mdl", "description": "Atesta ID Wallet (CI, mDL)",
            "server": {"authorization_endpoint": "openid4vp://"},
            "client": {"jwks": {"keys": [verifier_key()]}},
            "credential": {"trust_anchor_pem": anchor, "status_list_trust_anchor_pem": anchor},
        }
        variant = {"credential_format": "iso_mdl", "credential_type": "mdl", "response_mode": "direct_post.jwt"}
        cls.plan = api("POST", "api/plan", params={"planName": PLAN, "variant": json.dumps(variant)}, json=config)
        print(f"\nPlan {cls.plan['id']}: {SUITE}/plan-detail.html?plan={cls.plan['id']}", file=sys.stderr)

    def setUp(self):
        storage.set_profile("mdl")


if __name__ == "__main__":
    unittest.main()

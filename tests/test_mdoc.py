"""ISO mdoc (mso_mdoc): reading an IssuerSigned, checking it at issuance, presenting it over OpenID4VP.

Run:  python -m unittest discover -s tests
"""

import datetime
import hashlib
import json
import secrets
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import FakeIssuer, ScriptedPrompter, isolated_home, make_cert  # noqa: E402  (first: test environment)
import http.server  # noqa: E402
import threading  # noqa: E402

import requests  # noqa: E402
import cbor2  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from atesta_id_wallet import common, cose, jose, mdoc, storage, ui, vci, vp  # noqa: E402

DOCTYPE = "eu.europa.ec.eudi.pid.1"
NS = "eu.europa.ec.eudi.pid.1"


def cose_key(public_key):
    n = public_key.public_numbers()
    return {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def make_mdoc(holder, issuer_key, cert, elements=None, *, valid_days=365, tamper=None, status=None):
    """An IssuerSigned as an issuer would send it (base64url), and its items."""
    elements = elements or {"given_name": "Marta", "family_name": "Ribes Soler",
                            "birth_date": cbor2.CBORTag(1004, "1990-04-02"), "age_over_18": True}
    items, digests = [], {}
    for digest_id, (name, value) in enumerate(elements.items()):
        item = cbor2.CBORTag(24, cbor2.dumps({"digestID": digest_id, "random": secrets.token_bytes(16),
                                              "elementIdentifier": name, "elementValue": value}))
        items.append(item)
        digests[digest_id] = hashlib.sha256(cbor2.dumps(item)).digest()
    if tamper:  # the item changes after the issuer signed its digest
        items[0] = cbor2.CBORTag(24, cbor2.dumps({"digestID": 0, "random": b"0" * 16,
                                                  "elementIdentifier": "given_name", "elementValue": tamper}))
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    mso = {"version": "1.0", "digestAlgorithm": "SHA-256", "valueDigests": {NS: digests},
           "deviceKeyInfo": {"deviceKey": cose_key(holder.private_key.public_key())}, "docType": DOCTYPE,
           "validityInfo": {"signed": now, "validFrom": now,
                            "validUntil": now + datetime.timedelta(days=valid_days)}}
    if status:
        mso["status"] = status
    payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso, datetime_as_timestamp=False)))
    protected = cbor2.dumps({1: -7})
    der = issuer_key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    issuer_auth = [protected, {33: cert.public_bytes(serialization.Encoding.DER)}, payload,
                   r.to_bytes(32, "big") + s.to_bytes(32, "big")]
    return common.b64u(cbor2.dumps({"nameSpaces": {NS: items}, "issuerAuth": issuer_auth}))


class MdocTests(unittest.TestCase):
    def setUp(self):
        isolated_home(self)
        self.holder = storage.HolderKey.generate()
        self.issuer_key = ec.generate_private_key(ec.SECP256R1())
        self.cert = make_cert(self.issuer_key, "issuer.example")

    def test_parse(self):
        document = mdoc.parse_mdoc(make_mdoc(self.holder, self.issuer_key, self.cert))
        self.assertEqual(document.doctype, DOCTYPE)
        self.assertEqual(document.claims[NS]["given_name"], "Marta")
        self.assertEqual(document.claims[NS]["birth_date"], "1990-04-02")  # full-date as JSON text
        self.assertEqual(document.display_claims["family_name"], "Ribes Soler")
        with_portrait = mdoc.parse_mdoc(make_mdoc(self.holder, self.issuer_key, self.cert,
                                                  {"given_name": "Marta", "portrait": b"\xff\xd8" * 500}))
        self.assertEqual(with_portrait.display_claims["portrait"], "(1000 bytes)")
        self.assertEqual(with_portrait.claims[NS]["portrait"], common.b64u(b"\xff\xd8" * 500))  # JSON for DCQL
        self.assertGreater(document.payload["exp"], document.payload["nbf"])
        self.assertEqual(document.payload["cnf"]["jwk"]["x"], self.holder.public_jwk["x"])
        self.assertEqual(len(document.header["x5c"]), 1)
        self.assertTrue(cose.verify_sign1(document.issuer_auth, self.issuer_key.public_key()))

    def test_digest_must_match(self):
        with self.assertRaisesRegex(mdoc.MdocError, "digest"):
            mdoc.parse_mdoc(make_mdoc(self.holder, self.issuer_key, self.cert, tamper="Mallory"))

    def test_malformed(self):
        for raw in ("", "not base64!", common.b64u(b"\xff"), common.b64u(cbor2.dumps({"nameSpaces": {}})),
                    common.b64u(cbor2.dumps({"issuerAuth": [b"", {}, b"\x01", b""]}))):
            with self.assertRaises(common.WalletError, msg=raw):
                mdoc.parse_mdoc(raw)

    def test_verified_at_issuance(self):
        raw = make_mdoc(self.holder, self.issuer_key, self.cert)
        other = storage.HolderKey.generate()
        self.assertIs(vci.verify_issued_mdoc(None, raw, [other, self.holder], "https://issuer.example", {}),
                      self.holder)
        with self.assertRaisesRegex(common.WalletError, "otra clave"):
            vci.verify_issued_mdoc(None, raw, [other], "https://issuer.example", {})
        forged = make_mdoc(self.holder, ec.generate_private_key(ec.SECP256R1()), self.cert)
        with self.assertRaisesRegex(common.WalletError, "firma"):
            vci.verify_issued_mdoc(None, forged, [self.holder], "https://issuer.example", {})

    def store(self, **kwargs):
        raw = make_mdoc(self.holder, self.issuer_key, self.cert, **kwargs)
        storage.save_credential([(raw, self.holder)], fmt=mdoc.FORMAT, issuer="https://issuer.example",
                                configuration_id="eu.europa.ec.eudi.pid_mdoc")
        return storage.load_credentials()[0]

    def test_stored_and_shown(self):
        record = self.store()
        self.assertIsInstance(record["_sd"], mdoc.Mdoc)
        self.assertEqual(storage.credential_holder(record), "Marta Ribes Soler")
        self.assertTrue(storage.is_usable(record))
        self.assertFalse(storage.is_usable(self.store(valid_days=-1)))  # expired
        mdocs = [r for r in storage.load_credentials() if r["format"] == mdoc.FORMAT]
        self.assertEqual(len(mdocs), 2)

    def query(self, *elements, doctype=DOCTYPE):
        return {"credentials": [{"id": "pid", "format": "mso_mdoc", "meta": {"doctype_value": doctype},
                                 "claims": [{"path": [NS, e]} for e in elements]}]}

    def test_dcql(self):
        record = self.store()
        [match] = vp.match_dcql(self.query("given_name", "age_over_18"), [record], False)
        self.assertEqual(match.paths, [[NS, "given_name"], [NS, "age_over_18"]])
        items = ui.consent_items([match])[0].claims
        self.assertEqual([path for path, _ in items], ["given_name", "age_over_18"])
        for query in (self.query("given_name", doctype="org.iso.18013.5.1.mDL"), self.query("nationality")):
            with self.assertRaises(vp.NoMatchingCredential):
                vp.match_dcql(query, [record], False)
        sd_query = {"credentials": [{"id": "q", "format": "dc+sd-jwt", "claims": [{"path": [NS, "given_name"]}]}]}
        with self.assertRaises(vp.NoMatchingCredential):  # the format must be the mdoc's
            vp.match_dcql(sd_query, [record], False)

    def prepared(self, record, query, mode="direct_post", request=None):
        identity = vp.VerifierIdentity("x509_san_dns:verifier.example", "x509_san_dns", "verifier.example",
                                       "verifier.example")
        matches = vp.match_dcql(query, [record], False)
        return vp.PreparedPresentation(request or {}, identity, "https://verifier.example/response", mode,
                                       "nonce-123", matches)

    def test_device_response(self):
        """What a verifier checks: issuer signature, digests of what came, device signature over the transcript."""
        record = self.store()
        prepared = self.prepared(record, self.query("given_name"))
        body = vp.build_response(prepared)
        token = json.loads(body["vp_token"])["pid"][0]
        response = cbor2.loads(common.b64u_decode(token))
        self.assertEqual((response["version"], response["status"]), ("1.0", 0))
        [document] = response["documents"]
        self.assertEqual(document["docType"], DOCTYPE)
        [item] = document["issuerSigned"]["nameSpaces"][NS]  # only what was asked for
        element = cbor2.loads(item.value)
        self.assertEqual((element["elementIdentifier"], element["elementValue"]), ("given_name", "Marta"))
        issuer_auth = cose.decode_sign1(document["issuerSigned"]["issuerAuth"])
        self.assertTrue(cose.verify_sign1(issuer_auth, self.issuer_key.public_key()))
        mso = cbor2.loads(cbor2.loads(issuer_auth.payload).value)
        self.assertEqual(mso["valueDigests"][NS][element["digestID"]], hashlib.sha256(cbor2.dumps(item)).digest())

        transcript = mdoc.session_transcript("x509_san_dns:verifier.example", "nonce-123", None,
                                             "https://verifier.example/response")
        device_auth = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(
            ["DeviceAuthentication", transcript, DOCTYPE, document["deviceSigned"]["nameSpaces"]])))
        signature = cose.decode_sign1(list(document["deviceSigned"]["deviceAuth"]["deviceSignature"]))
        self.assertIsNone(signature.payload)  # detached
        self.assertTrue(cose.verify_sign1(signature, self.holder.private_key.public_key(), payload=device_auth))
        other = mdoc.session_transcript("x509_san_dns:verifier.example", "another nonce", None,
                                        "https://verifier.example/response")
        replayed = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(
            ["DeviceAuthentication", other, DOCTYPE, document["deviceSigned"]["nameSpaces"]])))
        self.assertFalse(cose.verify_sign1(signature, self.holder.private_key.public_key(), payload=replayed))
        self.assertEqual(len(signature.signature), 64)  # raw r || s, as COSE wants it (not DER)

    def test_encrypted_response_binds_the_key(self):
        """direct_post.jwt: the transcript carries the thumbprint of the key the answer is encrypted to."""
        record = self.store()
        verifier_key = ec.generate_private_key(ec.SECP256R1())
        jwk = {"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "e",
               "x": common.b64u(verifier_key.public_key().public_numbers().x.to_bytes(32, "big")),
               "y": common.b64u(verifier_key.public_key().public_numbers().y.to_bytes(32, "big"))}
        request = {"client_metadata": {"jwks": {"keys": [jwk]}}}
        prepared = self.prepared(record, self.query("given_name"), "direct_post.jwt", request)
        with mock.patch.object(mdoc, "session_transcript", wraps=mdoc.session_transcript) as transcript:
            body = vp.build_response(prepared)
        self.assertEqual(transcript.call_args.args[2], jose.jwk_thumbprint(jwk))
        self.assertEqual(list(body), ["response"])

    def test_specification_vectors(self):
        """OpenID4VP 1.0 Appendix B.2.6.1: JWK thumbprint, OpenID4VPHandoverInfo and SessionTranscript."""
        jwk = {"kty": "EC", "crv": "P-256", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
               "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc", "alg": "ECDH-ES", "kid": "1"}
        thumbprint = jose.jwk_thumbprint(jwk)
        self.assertEqual(thumbprint.hex(), "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
        transcript = mdoc.session_transcript("x509_san_dns:example.com", "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                                             thumbprint, "https://example.com/response")
        self.assertEqual(cbor2.dumps(transcript).hex(),
                         "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b"
                         "046b11b68013722aad38ac")



class MdocIssuer(FakeIssuer):
    """FakeIssuer that offers a PID in mso_mdoc, signed with a certificate for its host (localhost)."""
    cert = None

    def do_GET(self):  # noqa: N802
        if self.path == "/offer":
            return self._json({"credential_issuer": self.base, "credential_configuration_ids": ["pid_mdoc"],
                               "grants": {vci.PRE_AUTH_GRANT: {"pre-authorized_code": "PRE",
                                                               "tx_code": {"length": 4}}}})
        if self.path == "/.well-known/openid-credential-issuer":
            return self._json({
                "credential_issuer": self.base, "credential_endpoint": self.base + "/credential",
                "nonce_endpoint": self.base + "/nonce",
                "credential_configurations_supported": {"pid_mdoc": {
                    "format": "mso_mdoc", "doctype": DOCTYPE,
                    "credential_metadata": {"display": [{"name": "PID (mdoc)", "locale": "en"}]}}}})
        return super().do_GET()

    def do_POST(self):  # noqa: N802
        if self.path != "/credential":
            return super().do_POST()
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        [proof] = body["proofs"]["jwt"]
        header, _ = common.jwt_decode_unverified(proof)
        holder_public = jose.jwk_to_public_key(header["jwk"])

        class Holder:  # make_mdoc only needs the public key
            private_key = type("K", (), {"public_key": staticmethod(lambda: holder_public)})
        raw = make_mdoc(Holder, MdocIssuer.key, MdocIssuer.cert)
        return self._json({"credentials": [{"credential": raw}]})


class MdocIssuanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MdocIssuer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        isolated_home(self)
        self.addCleanup(setattr, FakeIssuer, "base", FakeIssuer.base)
        self.addCleanup(setattr, FakeIssuer, "key", FakeIssuer.key)
        FakeIssuer.base = MdocIssuer.base = f"http://localhost:{self.server.server_port}"
        FakeIssuer.key = MdocIssuer.key = ec.generate_private_key(ec.SECP256R1())
        MdocIssuer.cert = make_cert(MdocIssuer.key, "localhost")

    def test_issued_verified_and_stored(self):
        offer = f"openid-credential-offer://?credential_offer_uri={MdocIssuer.base}/offer"
        [issued] = vci.issue(requests.Session(), offer, vci.IssueOptions(copies=1), ScriptedPrompter(texts=["1234"]))
        self.assertEqual(issued.claims[NS]["given_name"], "Marta")
        [record] = storage.load_credentials()
        self.assertEqual(record["format"], "mso_mdoc")
        self.assertEqual(storage.credential_name(record), "PID (mdoc)")
        # The stored copy's key is the mdoc's device key.
        key = storage.holder_key(record).private_key.public_key().public_numbers()
        self.assertEqual(record["_sd"].device_key.public_numbers(), key)

if __name__ == "__main__":
    unittest.main()

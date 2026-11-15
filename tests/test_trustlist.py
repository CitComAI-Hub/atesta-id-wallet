"""Trusted lists (ETSI TS 119 612): signature by the pinned certificate, services in force, issuers they certify.

Run:  python -m unittest discover -s tests
"""

import datetime
import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import der_b64, isolated_home, make_cert  # noqa: E402  (first: sets the test environment)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from lxml import etree  # noqa: E402
from signxml import XMLSigner  # noqa: E402

from atesta_id_wallet import common, sdjwt, storage, trustlist, vp  # noqa: E402

T = trustlist.TSL_NS
GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
URL = "https://tl.example/tl.xml"


def ca(name, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    return make_cert(key, name, ca=True), key


def leaf(name, ca_cert, ca_key, days=365):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=days))
            .sign(ca_key, hashes.SHA256()))
    return cert, key


def make_list(signer_cert, signer_key, services, *, next_update_days=30, tamper=None):
    """A trusted list signed (enveloped) by signer_key; services: [(provider, certificate, status)]."""
    root = etree.Element(f"{{{T}}}TrustServiceStatusList", nsmap={None: T}, TSLTag="http://uri.etsi.org/19612/TSLTag")
    info = etree.SubElement(root, f"{{{T}}}SchemeInformation")
    etree.SubElement(info, f"{{{T}}}TSLVersionIdentifier").text = "6"
    operator = etree.SubElement(etree.SubElement(info, f"{{{T}}}SchemeOperatorName"), f"{{{T}}}Name")
    operator.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
    operator.text = "Data space trust operator"
    etree.SubElement(info, f"{{{T}}}SchemeTerritory").text = "EU"
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=next_update_days)
    etree.SubElement(etree.SubElement(info, f"{{{T}}}NextUpdate"), f"{{{T}}}dateTime").text = \
        when.strftime("%Y-%m-%dT%H:%M:%SZ")
    providers = etree.SubElement(root, f"{{{T}}}TrustServiceProviderList")
    for provider, cert, status in services:
        tsp = etree.SubElement(providers, f"{{{T}}}TrustServiceProvider")
        name = etree.SubElement(etree.SubElement(etree.SubElement(tsp, f"{{{T}}}TSPInformation"),
                                                 f"{{{T}}}TSPName"), f"{{{T}}}Name")
        name.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
        name.text = provider
        service = etree.SubElement(etree.SubElement(etree.SubElement(tsp, f"{{{T}}}TSPServices"), f"{{{T}}}TSPService"),
                                   f"{{{T}}}ServiceInformation")
        etree.SubElement(service, f"{{{T}}}ServiceTypeIdentifier").text = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
        sname = etree.SubElement(etree.SubElement(service, f"{{{T}}}ServiceName"), f"{{{T}}}Name")
        sname.text = f"{provider} CA"
        digital = etree.SubElement(etree.SubElement(service, f"{{{T}}}ServiceDigitalIdentity"), f"{{{T}}}DigitalId")
        etree.SubElement(digital, f"{{{T}}}X509Certificate").text = der_b64(cert)
        etree.SubElement(service, f"{{{T}}}ServiceStatus").text = status
    signed = XMLSigner(signature_algorithm="ecdsa-sha256", digest_algorithm="sha256").sign(
        root, key=signer_key, cert=[signer_cert.public_bytes(serialization.Encoding.PEM).decode()])
    data = etree.tostring(signed)
    return tamper(data) if tamper else data


class TrustListTests(unittest.TestCase):
    def setUp(self):
        isolated_home(self)
        self.signer, self.signer_key = ca("operator.example")
        self.issuer_ca, self.issuer_ca_key = ca("Issuer CA")
        self.other_ca, _ = ca("Withdrawn CA")
        self.data = make_list(self.signer, self.signer_key, [("Good TSP", self.issuer_ca, GRANTED),
                                                             ("Old TSP", self.other_ca, WITHDRAWN)])

    def test_parse(self):
        self.assertEqual(trustlist.signer_certificate(self.data).subject, self.signer.subject)
        trusted = trustlist.parse(self.data, URL, self.signer)
        self.assertEqual((trusted.operator, trusted.territory), ("Data space trust operator", "EU"))
        self.assertEqual([s.provider for s in trusted.services], ["Good TSP"])  # the withdrawn one is left out
        self.assertGreater(trusted.next_update, time.time())
        self.assertEqual(len(trustlist.fingerprint(self.signer).split(":")), 32)

    def test_only_the_pinned_signer(self):
        impostor, impostor_key = ca("operator.example")  # same name, another key
        forged = make_list(impostor, impostor_key, [("Evil TSP", self.other_ca, GRANTED)])
        with self.assertRaisesRegex(trustlist.TrustListError, "fijado"):
            trustlist.parse(forged, URL, self.signer)

    def test_changed_after_signing(self):
        tampered = self.data.replace(b"Good TSP", b"Evil TSP")
        with self.assertRaises(trustlist.TrustListError):
            trustlist.parse(tampered, URL, self.signer)
        # A provider added outside what was signed is not read either.
        added = self.data.replace(b"</TrustServiceProviderList>", b"<TrustServiceProvider/></TrustServiceProviderList>")
        with self.assertRaises(trustlist.TrustListError):
            trustlist.parse(added, URL, self.signer)

    def test_outdated(self):
        old = make_list(self.signer, self.signer_key, [("Good TSP", self.issuer_ca, GRANTED)], next_update_days=-1)
        with self.assertRaisesRegex(trustlist.TrustListError, "expired on"):
            trustlist.parse(old, URL, self.signer)
        with self.assertRaisesRegex(trustlist.TrustListError, "signing certificate is not valid"):
            trustlist.parse(self.data, URL, self.signer, now=time.time() + 10 * 365 * 86400)

    def test_no_entities(self):
        xxe = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               b'<TrustServiceStatusList xmlns="' + T.encode() + b'">&x;</TrustServiceStatusList>')
        with self.assertRaises(trustlist.TrustListError):
            trustlist.signer_certificate(xxe)
        with self.assertRaises(trustlist.TrustListError):
            trustlist.parse(xxe, URL, self.signer)

    def test_certified_by(self):
        trusted = trustlist.parse(self.data, URL, self.signer)
        issued, _ = leaf("issuer.example", self.issuer_ca, self.issuer_ca_key)
        found = trustlist.certified_by([issued], [trusted])
        self.assertEqual(found[1].provider, "Good TSP")
        self.assertIsNotNone(trustlist.certified_by([issued, self.issuer_ca], [trusted]))  # CA in the chain
        self.assertIsNotNone(trustlist.certified_by([self.issuer_ca], [trusted]))  # the service's own certificate
        stranger, _ = leaf("issuer.example", *ca("Unknown CA"))
        self.assertIsNone(trustlist.certified_by([stranger], [trusted]))
        expired, _ = leaf("issuer.example", self.issuer_ca, self.issuer_ca_key, days=-1)
        self.assertIsNone(trustlist.certified_by([expired], [trusted]))
        # A chain whose links do not sign each other stops at the break.
        self.assertIsNone(trustlist.certified_by([stranger, self.issuer_ca], [trusted]))

    def session_serving(self, *bodies):
        session = mock.Mock()
        responses = []
        for body in bodies:
            response = mock.MagicMock()
            response.status_code = 200
            response.raw.read.return_value = body
            response.__enter__.return_value = response
            responses.append(response)
        session.get.side_effect = responses
        return session

    def test_configured_lists(self):
        trusted = trustlist.preview(self.session_serving(self.data), URL)
        trustlist.add(trusted)
        self.assertEqual([e["url"] for e in trustlist.configured()], [URL])
        self.assertEqual(trustlist.current(None)[0].services[0].provider, "Good TSP")
        # Past its NextUpdate: downloaded again, and only accepted from the pinned signer.
        later = time.time() + 40 * 86400
        impostor, impostor_key = ca("operator.example")
        forged = make_list(impostor, impostor_key, [("Evil TSP", self.other_ca, GRANTED)], next_update_days=60)
        self.assertEqual(trustlist.current(self.session_serving(forged), now=later), [])
        renewed = make_list(self.signer, self.signer_key, [("New TSP", self.issuer_ca, GRANTED)], next_update_days=60)
        [fresh] = trustlist.current(self.session_serving(renewed), now=later)
        self.assertEqual(fresh.services[0].provider, "New TSP")
        self.assertTrue(trustlist.remove(URL))
        self.assertEqual(trustlist.configured(), [])

    def test_dcql_etsi_tl(self):
        trustlist.add(trustlist.parse(self.data, URL, self.signer))
        issued, issuer_key = leaf("issuer.example", self.issuer_ca, self.issuer_ca_key)
        stranger, stranger_key = leaf("issuer.example", *ca("Unknown CA"))
        holder = storage.HolderKey.generate()
        email = common.b64u(json.dumps(["s1", "email", "a@example.org"]).encode())
        for name, cert, key in (("Certified", issued, issuer_key), ("Other", stranger, stranger_key)):
            payload = {"iss": "https://issuer.example", "vct": "Legal", "_sd_alg": "sha-256",
                       "_sd": [sdjwt._sd_digest(email)], "cnf": {"jwk": holder.public_jwk}}
            jwt = storage.HolderKey(key).sign_jwt({"typ": "dc+sd-jwt", "x5c": [der_b64(cert)]}, payload)
            storage.save_credential([(f"{jwt}~{email}~", holder)], fmt="dc+sd-jwt", issuer="https://issuer.example",
                                    configuration_id=name)
        records = storage.load_credentials()

        def offered(values):
            dcql = {"credentials": [{"id": "q", "format": "dc+sd-jwt",
                                     "trusted_authorities": [{"type": "etsi_tl", "values": values}]}]}
            found = []
            vp.match_dcql(dcql, records, False, choose=lambda _q, candidates: found.extend(candidates) or candidates[0])
            return sorted(r["credential_configuration_id"] for r in found)

        self.assertEqual(offered([URL]), ["Certified"])
        # A list the user did not add cannot be told: nothing is left out (and nothing is downloaded).
        self.assertEqual(offered(["https://elsewhere.example/tl.xml"]), ["Certified", "Other"])
        record = next(r for r in records if r["credential_configuration_id"] == "Certified")
        found = trustlist.certification(record["_sd"], trustlist.current(None))
        self.assertEqual(found[1].provider, "Good TSP")
        self.assertIsNone(trustlist.certification(
            next(r for r in records if r["credential_configuration_id"] == "Other")["_sd"], trustlist.current(None)))



if __name__ == "__main__":
    unittest.main()

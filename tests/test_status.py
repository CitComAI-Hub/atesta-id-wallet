"""Revocation: Token Status List (decoding, the signed list, the stored state, presenting).

Run:  python -m unittest discover -s tests
"""

import http.server
import json
import sys
import threading
import time
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import FakeIssuer, isolated_home  # noqa: E402  (first: sets the test environment)
import requests  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atesta_id_wallet import common, sdjwt, status, storage, vp  # noqa: E402


def pack(values, bits):
    """Status values -> bytes, least significant bits first (as the specification draws them)."""
    data = bytearray((len(values) * bits + 7) // 8)
    for index, value in enumerate(values):
        data[index * bits // 8] |= value << (index * bits % 8)
    return bytes(data)


def lst(values, bits):
    return common.b64u(zlib.compress(pack(values, bits)))


class StatusIssuer(FakeIssuer):
    """FakeIssuer that also serves status list tokens: lists[path] = body (or (code, headers))."""
    lists: dict = {}
    seen: list = []

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/status/"):
            StatusIssuer.seen.append((self.path, self.headers.get("Accept")))
            answer = StatusIssuer.lists.get(self.path)
            if isinstance(answer, tuple):
                code, headers = answer
                self.send_response(code)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                return
            if answer is None:
                return self._json({"error": "not_found"}, 404)
            body = answer.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/statuslist+jwt")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()


class DecodingTests(unittest.TestCase):
    def test_examples_of_the_specification(self):
        # draft-ietf-oauth-status-list: 1 bit per entry, then 2 bits.
        bits, data = status.decode_list({"bits": 1, "lst": "eNrbuRgAAhcBXQ"})
        self.assertEqual((bits, data), (1, bytes([0xB9, 0xA3])))
        self.assertEqual([status.status_at(1, data, i) for i in range(16)],
                         [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1])
        bits, data = status.decode_list({"bits": 2, "lst": "eNo76fITAAPfAgc"})
        self.assertEqual([status.status_at(2, data, i) for i in range(12)], [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3])

    def test_round_trip_for_every_width(self):
        for bits in (1, 2, 4, 8):
            values = [(i * 7) % (1 << bits) for i in range(50)]
            _, data = status.decode_list({"bits": bits, "lst": lst(values, bits)})
            self.assertEqual([status.status_at(bits, data, i) for i in range(50)], values)

    def test_malformed_lists(self):
        for bad in (None, {"bits": 3, "lst": lst([0], 1)}, {"bits": True, "lst": lst([0], 1)},
                    {"bits": 1, "lst": 5}, {"bits": 1, "lst": "not zlib"}):
            with self.subTest(bad=bad), self.assertRaises(status.StatusError):
                status.decode_list(bad)
        _, data = status.decode_list({"bits": 1, "lst": lst([0] * 8, 1)})
        with self.assertRaisesRegex(status.StatusError, "outside"):
            status.status_at(1, data, 8)

    def test_zlib_bomb_stops(self):
        bomb = common.b64u(zlib.compress(bytes(status.LIST_MAX_BYTES + 1), 9))
        with self.assertRaisesRegex(status.StatusError, "too large"):
            status.decode_list({"bits": 1, "lst": bomb})

    def test_reference(self):
        def sd(claims):
            return type("Sd", (), {"payload": claims})()

        self.assertIsNone(status.status_reference(sd({})))
        self.assertIsNone(status.status_reference(sd({"status": {"other_mechanism": {}}})))
        self.assertEqual(status.status_reference(sd({"status": {"status_list": {"idx": 3, "uri": "https://i/s"}}})),
                         ("https://i/s", 3))
        for ref in ({"idx": -1, "uri": "https://i/s"}, {"idx": "3", "uri": "https://i/s"}, {"idx": 1}, "x"):
            with self.subTest(ref=ref), self.assertRaises(status.StatusError):
                status.status_reference(sd({"status": {"status_list": ref}}))


class StatusListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), StatusIssuer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://localhost:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        isolated_home(self)
        StatusIssuer.base = self.base
        self.addCleanup(setattr, FakeIssuer, "key", FakeIssuer.key)
        self.addCleanup(setattr, FakeIssuer, "base", FakeIssuer.base)
        FakeIssuer.base = self.base
        StatusIssuer.key = FakeIssuer.key = ec.generate_private_key(ec.SECP256R1())  # FakeIssuer's /jwks
        StatusIssuer.lists, StatusIssuer.seen = {}, []
        self.holder = storage.HolderKey.load_or_create()
        self.uri = self.base + "/status/1"

    def publish(self, values, bits=1, *, path="/status/1", key=None, **claims):
        payload = {"sub": self.base + path, "iat": int(time.time()),
                   "status_list": {"bits": bits, "lst": lst(values, bits)}, **claims}
        header = {"typ": claims.pop("typ", None) or "statuslist+jwt", "kid": "k1"}
        payload.pop("typ", None)
        StatusIssuer.lists[path] = storage.HolderKey(key or StatusIssuer.key).sign_jwt(header, payload)

    def store(self, index, uri=None, name="Legal"):
        email = common.b64u(json.dumps(["s1", "email", "user@example.org"]).encode())
        payload = {"iss": self.base, "vct": name, "_sd_alg": "sha-256", "_sd": [sdjwt._sd_digest(email)],
                   "cnf": {"jwk": self.holder.public_jwk},
                   "status": {"status_list": {"idx": index, "uri": uri or self.uri}}}
        jwt = storage.HolderKey(StatusIssuer.key).sign_jwt({"typ": "dc+sd-jwt", "kid": "k1"}, payload)
        storage.save_credential(f"{jwt}~{email}~", fmt="dc+sd-jwt", issuer=self.base, configuration_id=name)
        return next(r for r in storage.load_credentials() if r["credential_configuration_id"] == name)

    def test_valid_revoked_suspended(self):
        self.publish([0, 1, 2], bits=2)
        session = requests.Session()
        valid, revoked, suspended = self.store(0, name="A"), self.store(1, name="B"), self.store(2, name="C")
        self.assertEqual(status.check(session, valid), "valid")
        self.assertEqual(status.check(session, revoked), "revoked")
        self.assertEqual(status.check(session, suspended), "suspended")
        self.assertEqual(StatusIssuer.seen[0], ("/status/1", "application/statuslist+jwt"))
        # Stored with the credential: known without asking again, and after a restart.
        by_name = {r["credential_configuration_id"]: r for r in storage.load_credentials()}
        self.assertTrue(storage.is_usable(by_name["A"]))
        self.assertEqual(storage.validity(by_name["B"])[0], "revoked")
        self.assertEqual(storage.validity(by_name["C"])[0], "suspended")
        self.assertFalse(storage.is_usable(by_name["B"]) or storage.is_usable(by_name["C"]))
        self.assertIn("[REVOCADA]", storage.credential_label(by_name["B"]))
        self.assertIn("[SUSPENDIDA]", storage.credential_label(by_name["C"]))

    def test_one_download_for_credentials_that_share_a_list(self):
        self.publish([0, 0, 1])
        records = [self.store(0, name="A"), self.store(2, name="B")]
        changed = status.refresh(requests.Session(), records)
        self.assertEqual(len(StatusIssuer.seen), 1)
        self.assertEqual([r["credential_configuration_id"] for r in changed], ["B"])

    def test_when_to_check_again(self):
        self.publish([0], ttl=600)
        record = self.store(0)
        self.assertTrue(status.due(record))
        status.check(requests.Session(), record)
        self.assertFalse(status.due(record))
        self.assertTrue(status.due(record, now=time.time() + 601))
        self.assertEqual(status.refresh(requests.Session(), [record]), [])
        self.assertEqual(len(StatusIssuer.seen), 1)  # not due: not asked again
        status.refresh(requests.Session(), [record], force=True)
        self.assertEqual(len(StatusIssuer.seen), 2)
        # A revocation is final: never asked again.
        self.publish([1])
        status.refresh(requests.Session(), [record], force=True)
        self.assertEqual(storage.revocation_state(record), "revoked")
        self.assertFalse(status.due(record, now=time.time() + 10 ** 6))
        # A short ttl is not obeyed to the second, nor a long one beyond a week.
        self.assertEqual(status._recheck_after({"ttl": 1}, 0), status.MIN_RECHECK)
        self.assertEqual(status._recheck_after({"ttl": 10 ** 9}, 0), status.MAX_RECHECK)
        self.assertEqual(status._recheck_after({}, 0), status.DEFAULT_RECHECK)
        self.assertEqual(status._recheck_after({"exp": 100}, 0), 100)

    def test_suspension_can_be_lifted(self):
        self.publish([2], bits=2)
        record = self.store(0)
        self.assertEqual(status.check(requests.Session(), record), "suspended")
        self.publish([0], bits=2)
        changed = status.refresh(requests.Session(), [record], force=True)
        self.assertEqual(changed, [record])
        self.assertTrue(storage.is_usable(storage.load_credentials()[0]))

    def test_tokens_that_are_not_accepted(self):
        record = self.store(0)
        cases = {
            "typ": lambda: self.publish([1], typ="JWT"),
            "sub": lambda: self.publish([1], sub=self.base + "/status/other"),
            "expired": lambda: self.publish([1], exp=int(time.time()) - 10),
            "iat": lambda: self.publish([1], iat="yesterday"),
            "signed by another key": lambda: self.publish([1], key=ec.generate_private_key(ec.SECP256R1())),
            "value 3": lambda: self.publish([3], bits=2),
            "not found": lambda: StatusIssuer.lists.pop("/status/1", None),
        }
        for name, prepare in cases.items():
            with self.subTest(name):
                prepare()
                with self.assertRaises(status.StatusError):
                    status.check(requests.Session(), record)
                self.assertNotIn("revocation", storage.load_credentials()[0])  # nothing concluded

    def test_failure_is_logged_and_changes_nothing(self):
        self.publish([0])
        record = self.store(0)
        status.check(requests.Session(), record)
        before = dict(record["revocation"])
        StatusIssuer.lists.clear()
        logged = []
        self.addCleanup(setattr, common, "LOG_HANDLER", common.LOG_HANDLER)
        common.LOG_HANDLER = lambda message, _debug: logged.append(message)
        self.assertEqual(status.refresh(requests.Session(), [record], force=True), [])
        self.assertEqual(record["revocation"], before)
        self.assertTrue(any("revocado" in m for m in logged), logged)

    def test_redirects_are_followed_and_checked(self):
        self.publish([1])
        StatusIssuer.lists["/status/moved"] = (302, {"Location": "/status/1"})
        record = self.store(0, uri=self.base + "/status/moved")
        # The list says it is for /status/1, not for the address in the credential.
        with self.assertRaisesRegex(status.StatusError, "sub"):
            status.check(requests.Session(), record)
        self.publish([1], path="/status/1", sub=self.base + "/status/moved")
        self.assertEqual(status.check(requests.Session(), record), "revoked")
        StatusIssuer.lists["/status/moved"] = (302, {"Location": "http://example.org/status"})
        with self.assertRaisesRegex(common.WalletError, "https"):
            status.check(requests.Session(), self.store(0, uri=self.base + "/status/moved", name="B"))

    def test_no_local_address_for_a_remote_issuer(self):
        record = {"issuer": "https://issuer.example", "_sd": None}
        with self.assertRaisesRegex(status.StatusError, "local"):
            status.fetch_token(requests.Session(), self.uri, record["issuer"])

    def test_profile_switch_does_not_write_into_another_profile(self):
        self.publish([1])
        record = self.store(0)
        storage.create_profile("other")
        storage.set_profile("other")
        self.addCleanup(storage.set_profile, "default")
        status.check(requests.Session(), record)  # the answer is not stored: wrong profile
        storage.set_profile("default")
        self.assertNotIn("revocation", storage.load_credentials()[0])

    def test_presenting_leaves_out_revoked_candidates(self):
        self.publish([1, 0])
        revoked, valid = self.store(0, name="A"), self.store(1, name="B")
        choose = vp._checking_status(requests.Session(), lambda _q, candidates: candidates[0])
        chosen = choose("q", [revoked, valid])
        self.assertEqual(chosen["credential_configuration_id"], "B")
        # Already known as revoked: it is not even a candidate.
        dcql = {"credentials": [{"id": "q", "format": "dc+sd-jwt", "meta": {"vct_values": ["A", "B"]}}]}
        matches = vp.match_dcql(dcql, storage.load_credentials(), False)
        self.assertEqual([m.record["credential_configuration_id"] for m in matches], ["B"])

    def test_presenting_when_every_candidate_is_revoked(self):
        self.publish([1])
        choose = vp._checking_status(requests.Session(), lambda _q, candidates: candidates[0])
        with self.assertRaises(common.WalletError) as caught:
            choose("q", [self.store(0)])
        self.assertIn("No se ha enviado nada", caught.exception.hint)

    def test_presenting_when_the_status_cannot_be_checked(self):
        record = self.store(0)  # nothing published: the verifier will check it
        choose = vp._checking_status(requests.Session(), lambda _q, candidates: candidates[0])
        self.assertIs(choose("q", [record]), record)

    def test_automatic_check_can_be_turned_off(self):
        self.assertTrue(status.automatic_enabled())  # on by default
        status.set_automatic(False)
        self.publish([1])
        record = self.store(0)
        choose = vp._checking_status(requests.Session(), lambda _q, candidates: candidates[0])
        self.assertIs(choose("q", [record]), record)
        self.assertEqual(StatusIssuer.seen, [])  # nobody was asked
        # What an earlier check found still counts.
        record["revocation"] = {"state": "revoked", "checked_at": 1, "next_check": 0}
        with self.assertRaises(common.WalletError):
            choose("q", [record])
        status.set_automatic(True)
        self.assertTrue(status.automatic_enabled())

    def test_failures_are_reported(self):
        record = self.store(0)  # nothing published
        failed = []
        self.assertEqual(status.refresh(requests.Session(), [record], force=True, failed=failed), [])
        self.assertEqual(failed, [record])

    def test_credential_without_status(self):
        email = common.b64u(json.dumps(["s1", "email", "user@example.org"]).encode())
        payload = {"iss": self.base, "vct": "Legal", "_sd": [sdjwt._sd_digest(email)]}
        jwt = storage.HolderKey(StatusIssuer.key).sign_jwt({"typ": "dc+sd-jwt"}, payload)
        storage.save_credential(f"{jwt}~{email}~", fmt="dc+sd-jwt", issuer=self.base, configuration_id="Legal")
        record = storage.load_credentials()[0]
        self.assertFalse(status.due(record))
        self.assertIsNone(status.check(requests.Session(), record))
        self.assertEqual(StatusIssuer.seen, [])


if __name__ == "__main__":
    unittest.main()

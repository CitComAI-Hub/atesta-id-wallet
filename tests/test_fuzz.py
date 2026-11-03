"""Fuzzing of what comes from outside (SD-JWT, offers, DCQL queries, JWTs).

Mutated and random inputs, with a fixed seed so that a failure can be reproduced: whatever comes
in, the parsers either work or raise WalletError (the GUI and the CLI show it), never another
exception. ATESTA_FUZZ_ROUNDS raises the number of rounds (default 400 per test) and
ATESTA_FUZZ_SEED changes the inputs (the nightly run uses a new one each time; .github/workflows/fuzz.yml).

Run:  python -m unittest discover -s tests
"""

import json
import os
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import isolated_home, make_sd_jwt  # noqa: E402  (first: sets the test environment)

from atesta_id_wallet import common, sdjwt, storage, vci, vp  # noqa: E402

ROUNDS = int(os.environ.get("ATESTA_FUZZ_ROUNDS", "400"))
SEED = int(os.environ.get("ATESTA_FUZZ_SEED", "20261103"))
ALPHABET = "~.=-_{}[]\":,/?&%+ \n\x00aZ09é"


def mutate(rng: random.Random, text: str) -> str:
    """A few random edits: flip, delete, insert, duplicate or cut a piece."""
    for _ in range(rng.randint(1, 4)):
        if not text:
            text = rng.choice(ALPHABET)
            continue
        i = rng.randrange(len(text))
        kind = rng.randrange(5)
        if kind == 0:
            text = text[:i] + rng.choice(ALPHABET) + text[i + 1:]
        elif kind == 1:
            text = text[:i] + text[i + rng.randint(1, 8):]
        elif kind == 2:
            text = text[:i] + "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 6))) + text[i:]
        elif kind == 3:
            j = rng.randrange(i, len(text))
            text = text[:j] + text[i:j] + text[j:]
        else:
            text = text[:i] if rng.random() < 0.5 else text[i:]
    return text


def random_json(rng: random.Random, depth: int = 0):
    """Random JSON value, biased towards the names the parsers look for."""
    names = ["credentials", "claims", "path", "values", "id", "format", "meta", "vct_values", "claim_sets",
             "credential_sets", "options", "required", "intent_to_retain", "x", ""]
    kind = rng.randrange(8 if depth < 4 else 5)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False, 0, -1, 2**70, 1.5])
    if kind == 2:
        return rng.choice(["", "email", "dc+sd-jwt", "LegalPersonCredential", "*", "a.b", "$.email"])
    if kind == 3:
        return rng.randint(-3, 5)
    if kind == 4:
        return rng.choice(names)
    if kind in (5, 6):
        return {rng.choice(names): random_json(rng, depth + 1) for _ in range(rng.randint(0, 4))}
    return [random_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]


class FuzzTests(unittest.TestCase):
    def setUp(self):
        isolated_home(self)
        self.rng = random.Random(SEED)
        saved = common.LOG_HANDLER
        common.LOG_HANDLER = lambda message, is_debug: None  # thousands of lines otherwise
        self.addCleanup(setattr, common, "LOG_HANDLER", saved)

    def only_wallet_errors(self, function, value):
        try:
            function(value)
        except common.WalletError:
            pass
        except Exception as exc:  # the input is in the message, to reproduce it
            self.fail(f"{type(exc).__name__}: {exc}\ninput: {value!r}\nseed: ATESTA_FUZZ_SEED={SEED}")

    def test_sd_jwt(self):
        valid = make_sd_jwt(storage.HolderKey.load_or_create())
        sdjwt.parse_sd_jwt(valid)  # the starting point is valid
        for _ in range(ROUNDS):
            self.only_wallet_errors(sdjwt.parse_sd_jwt, mutate(self.rng, valid))

    def test_sd_jwt_random_disclosures(self):
        valid = make_sd_jwt(storage.HolderKey.load_or_create())
        issuer_jwt = valid.split("~")[0]
        for _ in range(ROUNDS):
            disclosure = common.b64u(json.dumps(random_json(self.rng)).encode())
            self.only_wallet_errors(sdjwt.parse_sd_jwt, f"{issuer_jwt}~{disclosure}~")

    def test_jwt_decode(self):
        valid = make_sd_jwt(storage.HolderKey.load_or_create()).split("~")[0]
        for _ in range(ROUNDS):
            self.only_wallet_errors(common.jwt_decode_unverified, mutate(self.rng, valid))
            payload = common.b64u(json.dumps(random_json(self.rng)).encode())
            self.only_wallet_errors(common.jwt_decode_unverified, f"e30.{payload}.sig")

    def test_offers(self):
        class NoNetwork:
            def get(self, *args, **kwargs):
                raise common.WalletError("no network in this test")

        offer = json.dumps({"credential_issuer": "https://kc.example/realms/p",
                            "credential_configuration_ids": ["Legal"],
                            "grants": {"authorization_code": {"issuer_state": "x"}}})
        starts = [offer, "openid-credential-offer://?credential_offer=" + vci.quote(offer),
                  "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fkc.example%2Fo%2F1"]
        for _ in range(ROUNDS):
            raw = mutate(self.rng, self.rng.choice(starts))
            self.only_wallet_errors(lambda r: vci.resolve_offer(NoNetwork(), r), raw)
            raw = "openid-credential-offer://?credential_offer=" + vci.quote(json.dumps(random_json(self.rng)))
            self.only_wallet_errors(lambda r: vci.resolve_offer(NoNetwork(), r), raw)

    def test_presentation_requests(self):
        class NoNetwork:
            headers: dict = {}

            def get(self, *args, **kwargs):
                raise common.WalletError("no network in this test")

            post = get

        starts = ["openid4vp://?client_id=x509_san_dns:v.example&request_uri=https%3A%2F%2Fv.example%2Fr%2F1",
                  "openid4vp://authorize?client_id=redirect_uri:https://v.example/cb&response_type=vp_token"
                  "&response_mode=direct_post&nonce=n&dcql_query=%7B%7D", "https://v.example/r/1"]
        for _ in range(ROUNDS):
            self.only_wallet_errors(lambda r: vp.fetch_request(NoNetwork(), r),
                                    mutate(self.rng, self.rng.choice(starts)))

    def test_dcql_queries(self):
        key = storage.HolderKey.load_or_create()
        storage.save_credential(make_sd_jwt(key), fmt="dc+sd-jwt", issuer="https://kc.example",
                                configuration_id="Legal", display={"name": "Legal"})
        records = storage.load_credentials()
        for _ in range(ROUNDS):
            query = random_json(self.rng)
            if self.rng.random() < 0.7:  # mostly the right shape, with random insides
                extra = random_json(self.rng)
                query = {"credentials": [{"id": "q", "format": "dc+sd-jwt", **(extra if isinstance(extra, dict) else {}),
                                          "claims": random_json(self.rng)}],
                         **({"credential_sets": random_json(self.rng)} if self.rng.random() < 0.3 else {})}
            self.only_wallet_errors(
                lambda q: vp.match_dcql(q, records, False, vp._first), query)


if __name__ == "__main__":
    unittest.main()

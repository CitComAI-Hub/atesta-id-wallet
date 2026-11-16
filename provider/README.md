# Atesta wallet provider

A minimal, stateless service that vouches for Atesta ID Wallet to issuers that ask for it
(HAIP 1.0 §4.4.1 and §4.5.1):

- **Wallet attestation** (OpenID4VCI 1.0 Appendix E, OAuth 2.0 Attestation-Based Client
  Authentication): a Client Attestation JWT (`oauth-client-attestation+jwt`) for a key the wallet
  makes for one issuance. Its `sub` is the wallet's `client_id`, the same for every installation
  (`atesta-id-wallet` by default), so issuers cannot tell installations apart by it.
- **Key attestation** (OpenID4VCI 1.0 Appendix D, `key-attestation+jwt`): one JWT covering every
  key of a batch, with the issuer's `c_nonce`. The wallet only asks for it when the issuer
  requires one (`key_attestations_required`, or only the `attestation` proof type).

Both are signed with a certificate in `x5c` that is not self-signed; issuers trust the CA that
issued it (`ca.pem`), which is not sent.

## What it proves, and what not yet

Step B1 (this version): the request comes from a program that holds the keys and answered a
fresh nonce of this provider. Atesta ID Wallet is open source, so anyone can run a program that
does that: today an attestation tells an issuer *which wallet* asks and lets it use the
HAIP flows, not that the keys are protected. No `key_storage` or `user_authentication` is
stated. Step B2 adds evidence from the TPM (EK certificate, AIK activation, `TPM2_Certify` of
each key through CNG on Windows); only keys with that evidence will get `key_storage`.

## Privacy

The service keeps nothing (no database, no log of keys) and receives only public keys and
signatures over its nonces: nothing about the user, the issuer or the credentials, except the
issuer's `c_nonce`, which it copies into the key attestation. Each issuance uses a new
attestation key, so two issuances cannot be linked by the attestation.

## Protocol

| Request | Body | Answer |
|---|---|---|
| `POST /nonce` | `{}` | `{"nonce": N}` (valid for 5 minutes) |
| `POST /wallet-attestation` | `{"request": JWT}` | `{"wallet_attestation": JWT}` |
| `POST /key-attestation` | `{"keys": [JWT, …]}` (1 to 10) | `{"key_attestation": JWT}` |
| `GET /health` | | `{"status": "ok"}` |

Each request JWT is ES256, of type `wallet-attestation-request+jwt` or
`key-attestation-request+jwt`, signed by the key it asks about, with that key in its `jwk` header,
and carries `{"aud": WP_URL, "nonce": N, "iat": …}`; key attestation requests may add
`"issuer_nonce"`, the same in all of them. Errors are `{"error", "error_description"}` with
HTTP 400 (`invalid_request`, `invalid_nonce`).

## Running it

```bash
python provider/wallet_provider.py init /srv/wp            # test CA + signing key and certificate
export WP_URL=https://wp.example.org WP_KEY=/srv/wp/signer.key WP_CERTS=/srv/wp/signer.pem
export WP_SECRET=$(openssl rand -hex 32)                   # required: the same in every worker and instance
python provider/wallet_provider.py serve --port 8080       # behind a TLS reverse proxy
```

Or with Docker (`provider/Dockerfile`, gunicorn):

```bash
docker build -t atesta-wallet-provider provider
docker run -p 8080:8080 -v /srv/wp:/keys:ro -e WP_URL=https://wp.example.org \
  -e WP_KEY=/keys/signer.key -e WP_CERTS=/keys/signer.pem -e WP_SECRET=… atesta-wallet-provider
```

`init` makes a CA only for tests and throws its key away. A real deployment keeps its CA key
offline, issues the signing certificate from it (P-256, `digitalSignature`, not a CA) and gives
the CA certificate to the issuers. Other settings: `WP_WALLET_ID`, `WP_WALLET_NAME`,
`WP_WALLET_LINK`, `WP_WALLET_TTL` (3600 s) and `WP_KEY_TTL` (600 s).

In the wallet: `atesta-id-wallet provider https://wp.example.org` (or
`ATESTA_ID_WALLET_PROVIDER`). Without a provider the wallet works as before, as a public client,
and only fails where an issuer requires a key attestation.

Tests: `python -m unittest tests.test_provider` (provider alone, and issuance against an issuer
that requires both attestations).

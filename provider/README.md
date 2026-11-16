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

## What it proves

Without TPM evidence: the request comes from a program that holds the keys and answered a fresh
nonce of this provider. Atesta ID Wallet is open source, so anyone can run a program that does
that: such an attestation tells an issuer *which wallet* asks and lets it use the HAIP flows, not
that the keys are protected, and it states no `key_storage`.

With TPM evidence (`tpm2.py`, keys in the TPM through CNG on Windows), the provider also checks
where the keys are, and only then states `key_storage` (`WP_TPM_KEY_STORAGE`, by default
`iso_18045_moderate`):

1. **Enrolment, once per computer** (`/tpm/enroll`, `/tpm/activate`). The wallet sends the TPM's
   endorsement key (EK) certificate and the public area of an attestation key (AIK) it made in
   the TPM. The provider chains the EK certificate to a TPM manufacturer's root
   (`WP_TPM_ROOTS`), checks that the AIK is a restricted signing key fixed to the TPM, and
   answers with a `MakeCredential` for that EK and that AIK's name. Only that TPM's
   `ActivateCredential`, on that AIK, recovers the secret; when the wallet sends it back, the
   provider gives it an AIK credential (`tpm-aik+jwt`, 30 days). The secret is derived from
   `WP_SECRET`, so nothing is kept between the two calls.
2. **Each key attestation**: every key comes with a `TPM2_Certify` by the AIK, with
   SHA-256 of the provider's nonce as qualifying data. The provider checks the signature, the
   nonce, that the certified name is that of the key's public area, that the key is a P-256
   signing key made in the TPM that cannot leave it (`fixedTPM`, `fixedParent`,
   `sensitiveDataOrigin`), and that it is the key in the request.

If any of this fails, the wallet asks again without evidence: the issuance goes on, with no
`key_storage`. The checks are tested against a real TPM 2.0 implementation (swtpm,
`tests/test_tpm_swtpm.py`, the `hardware-keys` job in CI); the Windows side (CNG's PCP blobs) needs the
manual check in `docs/TESTING-WINDOWS.md` §5c.

**Which `key_storage`**: a TPM 2.0 with an EK certificate from its manufacturer, keys made in it
and not exportable. `iso_18045_moderate` (AVA_VAN.4) is what discrete TPMs certified under the
TCG PC Client protection profile claim; firmware TPMs (Intel PTT, AMD fTPM) are usually not
certified at that level. Set `WP_TPM_KEY_STORAGE` to what your ecosystem accepts, or empty to
state nothing. No `user_authentication` is stated (no Windows Hello per use yet).

**Roots**: Microsoft publishes the TPM manufacturers' roots and intermediates it trusts
(`TrustedTpm.cab`, https://go.microsoft.com/fwlink/?linkid=2097925); unpack it into the
`WP_TPM_ROOTS` folder. Only RSA 2048 EKs of the default templates are supported for now.

## Privacy

The service keeps nothing (no database, no log of keys) and receives only public keys and
signatures over its nonces: nothing about the user, the issuer or the credentials, except the
issuer's `c_nonce`, which it copies into the key attestation. At enrolment it sees the EK
certificate, which identifies the TPM; it does not keep it, and the AIK credential it gives
back names only the AIK and the TPM's manufacturer. Issuers never see either. Each issuance uses a new
attestation key, so two issuances cannot be linked by the attestation.

## Protocol

| Request | Body | Answer |
|---|---|---|
| `POST /nonce` | `{}` | `{"nonce": N}` (valid for 5 minutes) |
| `POST /wallet-attestation` | `{"request": JWT}` | `{"wallet_attestation": JWT}` |
| `POST /key-attestation` | `{"keys": [JWT, …]}` (1 to 10) | `{"key_attestation": JWT}` |
| `POST /tpm/enroll` | `{"ek_certificate", "aik_public"}` (base64url DER, `TPMT_PUBLIC`) | `{"credential_blob", "encrypted_secret", "issued_at"}` |
| `POST /tpm/activate` | `{"ek_certificate", "aik_public", "issued_at", "secret"}` | `{"aik_credential": JWT}` |
| `GET /health` | | `{"status": "ok"}` |

Each request JWT is ES256, of type `wallet-attestation-request+jwt` or
`key-attestation-request+jwt`, signed by the key it asks about, with that key in its `jwk` header,
and carries `{"aud": WP_URL, "nonce": N, "iat": …}`; key attestation requests may add
`"issuer_nonce"`, the same in all of them, and `"tpm": {"attest", "signature", "public"}`
(base64url `TPMS_ATTEST`, AIK signature, the key's `TPMT_PUBLIC`), with `"aik_credential"` in the
body. Errors are `{"error", "error_description"}` with HTTP 400 (`invalid_request`,
`invalid_nonce`, `tpm_not_supported`, `invalid_tpm_evidence`, `invalid_aik_credential`).

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

Add `-e WP_TPM_ROOTS=/roots -v /srv/tpm-roots:/roots:ro` for TPM evidence.

`init` makes a CA only for tests and throws its key away. A real deployment keeps its CA key
offline, issues the signing certificate from it (P-256, `digitalSignature`, not a CA) and gives
the CA certificate to the issuers. Other settings: `WP_WALLET_ID`, `WP_WALLET_NAME`,
`WP_WALLET_LINK`, `WP_WALLET_TTL` (3600 s) and `WP_KEY_TTL` (600 s).

In the wallet: `atesta-id-wallet provider https://wp.example.org` (or
`ATESTA_ID_WALLET_PROVIDER`). Without a provider the wallet works as before, as a public client,
and only fails where an issuer requires a key attestation.

Tests: `python -m unittest tests.test_provider` (provider alone, and issuance against an issuer
that requires both attestations).

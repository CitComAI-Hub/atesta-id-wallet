# Security model

This page explains what the wallet protects against, what it trusts and what it does not.
It describes version 0.5.1.

## Assets

| Asset | Where | Protection |
|---|---|---|
| Holder private key | `holder_key.pem` | File permissions `0600`. **Not encrypted.** Anyone who can read your files as your user can use your credentials. |
| Credentials (personal data) | `credentials/*.json` | File permissions `0600`. |
| Settings, pinned verifier certificates | `config.json` | `0600`, written atomically (a crash cannot leave it empty and silently drop the pins). |
| Activity history | `history.jsonl` | `0600`. Records who received what; it is personal data too. |
| Keycloak password | Never stored | Typed into the window or the terminal, sent only over HTTPS to the authorization server's host. |
| Backups | File chosen by the user | AES-256-GCM, key derived from a password with scrypt (N=2¹⁵, r=8, p=1). Restore rejects archive entries outside the profile (no path traversal, no links). |

## Presentation (OpenID4VP)

The main risk is a website or QR code that tricks the wallet into sending your data to the
wrong party. Clicking an `openid4vp://` link opens the wallet, so any website can start a request.

**1. User consent, always.** Before sending, the wallet shows the verifier, its trust level, the
destination host and every claim that will be disclosed. Nothing is sent until the user
presses **Share** in the window (where **Decline** has the focus) or answers `y` in the
terminal. For risky verifiers (`changed`, `unverified`) the window also requires ticking
*I understand the risk*. Without a terminal, nothing is sent unless `--yes` is given, and `--yes`
is refused for risky verifiers. Shared and declined requests are recorded in the activity history.

**2. Verifier authentication.** The wallet accepts these client_id schemes:

| client_id | Check |
|---|---|
| `x509_san_dns:<host>` | The request object must be signed with the key of the `x5c` leaf certificate, and `<host>` must be a DNS SAN of that certificate. |
| `x509_hash:<hash>` | Same signature check, plus `<hash>` must be the SHA-256 of the leaf certificate. |
| `redirect_uri:<uri>` and unsigned requests | Identity cannot be verified. Refused unless `--allow-unverified` is given, and then always asks. |
| Anything else (DID, attestation, federation) | Treated as unverified. |

Signatures are checked strictly: the algorithm must match the key type and curve (`ES256` only with
P-256, and so on), and `none` or HMAC algorithms are never accepted. The client_id in the QR code
must equal the one in the signed request, and an expired request (`exp`) is rejected.

A signature only proves possession of a key. Anyone can create a self-signed certificate for any
domain, so the wallet also decides how far it can **trust** that certificate:

| Trust level | Meaning | Shown as |
|---|---|---|
| `trusted` | The chain validates up to a CA in `trusted_cas/` (*Settings → Trust* or `oid4vc-wallet trust add-ca`). | green |
| `pinned` | Not CA-backed, but it is the same certificate as last time (trust on first use, like SSH). | green |
| `new` | Signed and consistent, but never seen before. | amber |
| `changed` | A different certificate for a client_id seen before. Possible impersonation. | red + risk checkbox |
| `unverified` | No usable signature. | red + risk checkbox |

**3. Response destination.** For `x509_san_dns` verifiers that are not `trusted`, the host of
`response_uri` must equal the certificate's DNS name (OpenID4VP 1.0 §5.9.3). This stops an
attacker from relaying a legitimate verifier's request and having your data posted elsewhere.
`redirect_uri` verifiers must use their client_id as `response_uri`. HTTPS is required for every
URL the wallet fetches or posts to, except `localhost` (tests).

**4. Replay protection and minimal disclosure.** Every presentation carries a Key-Binding JWT
with the verifier's `nonce`, `aud = client_id` and the `sd_hash` of what is sent. Only the
requested claims are disclosed, following OpenID4VP 1.0 §6.4.1:

- a DCQL query without `claims` gets **no** selectively disclosable claim, only the mandatory parts;
- with `claim_sets`, the wallet uses the first option it can satisfy, not the union of all claims;
- with Presentation Exchange, only the fields of an input descriptor with
  `limit_disclosure: required` are selected; otherwise the whole credential is disclosed, as that
  specification intends, and the consent screen shows it.

A disclosure that the credential does not reference is never sent. Expired credentials are not
offered.

**5. After the presentation.** The verifier may answer with a `redirect_uri` that the wallet opens
in the browser. Only `https://` addresses (or `http://localhost`) are opened, never `file:`,
`javascript:` or other local schemes.

**6. Untrusted text in the window.** Names, claim values and error messages come from issuers
and verifiers. The window shows them as plain text, never as HTML, so a verifier cannot style its
name to look like a trusted one or inject links.

## Issuance (OpenID4VCI)

- The first time an offer comes from an issuer, the wallet shows who is offering what and asks
  for confirmation. This matters because a malicious offer link could point to a fake "Keycloak"
  that collects your password.
- The offer must come over HTTPS (`credential_offer_uri`), and the metadata must belong to the
  issuer named in the offer: `credential_issuer` in the issuer metadata (OpenID4VCI 1.0) and
  `issuer` in the authorization server metadata (RFC 8414) must match. Every endpoint must be HTTPS.
- In the wallet's own login, the password is only submitted, over HTTPS, to a form on the same
  host as the `authorization_endpoint`. External IdPs need `--browser-login`.
- The authorization code flow uses PKCE (S256) and a `state` that must come back unchanged. If
  the response names its issuer (`iss`, RFC 9207), it must be the expected one.
- Before storing a credential, the wallet:
  - parses the SD-JWT strictly: duplicate disclosures, a disclosure that would overwrite a
    visible claim and the reserved names `_sd` / `...` are rejected;
  - verifies the issuer's signature with keys that belong to the credential's `iss`. It
    tries, in order: the `x5c` header, the `did:web` document of `iss`,
    `/.well-known/jwt-vc-issuer` of `iss`, and finally the `jwks_uri` of the authorization
    server that made the offer. Keycloak, for example, may issue credentials whose `iss` is a
    `did:web` and sign them with the DID's key. The wallet rejects the credential if the
    signature is invalid. It only warns if no key is found, or if the keys came from the
    offering server and cannot be tied to `iss`;
  - checks that `cnf.jwk` is this wallet's key.

## Desktop integration

- Only one window runs at a time. A link opened while the wallet is running is handed to that
  window through a local socket in the user's private runtime directory (`$XDG_RUNTIME_DIR`, or the
  data folder), so other users of the computer cannot receive it. On Windows named pipes are
  global, so the pipe name carries a random suffix stored in the user's data folder: another user
  cannot guess it and create the pipe first.
- Temporary files of the window (themed icons) go to a private, per-process temporary directory.
- `harden_permissions()` only touches the wallet's own files, even if `$OID4VC_WALLET_HOME` points
  to a folder that contains other things.

## Releases and updates

- Releases are built by GitHub Actions from a tag (`.github/workflows/release.yml`), not on a
  developer's machine. Each release has a `SHA256SUMS` file and, on a public repository, a signed
  build provenance attestation (`gh attestation verify FILE --repo CitComAI-Hub/oid4vc-wallet`).
  Windows builds are not Authenticode-signed yet.
- The wallet never downloads or installs anything by itself. *Settings → About → New versions*
  (off by default) or `oid4vc-wallet update` asks the GitHub API for the latest release. The
  request carries no wallet data: GitHub sees the IP address and the version in the User-Agent.
  The download page that is opened must be under the project's releases page.

## Known gaps

| Gap | Impact | Planned mitigation |
|---|---|---|
| Holder key not encrypted at rest, no app lock | Local malware, another person at the unlocked computer, or a stolen unencrypted disk can use the credentials. | OS keyring or passphrase-protected key, plus an app lock. |
| File permissions are POSIX-only | On Windows, `0600`/`0700` have no effect. The data relies on `%APPDATA%` being private to the user (the default ACL). | Encrypted holder key (see above). |
| No default trust list | Most verifiers start as `new`. Users must judge the domain shown. | Ship the project's verifier CA or trust list. |
| Issuer trust is not anchored | Any HTTPS issuer the user accepts can issue credentials. An `x5c` issuer certificate is not validated against a CA, only used to check the signature. | Issuer allow-list or trust list. |
| A credential is stored with a warning if no issuer key is found | The wallet may hold a credential whose signature it could not check. The verifier will check it anyway. | Make it an error once the pilot issuers are known. |
| One key per profile | Verifiers can link presentations from the same profile. | One key per credential (batch issuance). |
| No revocation / status list check | A revoked credential may still be offered. The verifier is expected to check status. | Token Status List support. |
| Clipboard and recent screenshots are read automatically by *Scan QR* | A QR the user did not intend could be picked. | Mitigated by the offer review and consent screens, which show what was picked and who asks. |
| Windows builds not code-signed; builds not reproducible | SmartScreen warns, and users rely on the checksums and the CI attestation to know what they installed. | Authenticode certificate for the Windows builds. |
| No external security review | Bugs like the ones fixed in 0.5.1 may remain. | Review before handing the wallet to end users. |

## Reporting

Please report vulnerabilities privately to the maintainers instead of opening a public issue.

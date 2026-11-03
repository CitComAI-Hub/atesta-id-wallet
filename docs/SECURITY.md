# Security model

This page explains what the wallet protects against, what it trusts and what it does not.
It describes version 0.8.0.

## Assets

| Asset | Where | Protection |
|---|---|---|
| Holder private key | `holder_key.enc` | Encrypted with the profile data key (see below), file `0600`. |
| Credentials (personal data) | `credentials/*.enc` | Encrypted with the profile data key, `0600`. |
| Settings, pinned verifier certificates | `config.enc` | Encrypted, `0600`, written atomically (a crash cannot leave it empty and silently drop the pins). |
| Activity history | `history.enc` | Encrypted, `0600`. Records who received what; it is personal data too. |
| Profile data key | System keyring, or `vault.json` wrapped with the wallet password | See *Encryption at rest*. |
| Trusted CA certificates | `trusted_cas/*.pem` | Public certificates: not encrypted, `0600`. |
| Keycloak password | Never stored | Typed into the window or the terminal, sent only over HTTPS to the authorization server's host. Kept in memory until that login ends; if the offer is tied to another wallet, it is sent once more to the same host for the retry without the offer (see *Issuance*). |
| Backups | File chosen by the user | AES-256-GCM, key derived from a password with scrypt (N=2¹⁵, r=8, p=1). Restore rejects archive entries outside the profile (no path traversal, no links). |

## Encryption at rest

Every profile has a random 256-bit data key. Its files are encrypted with AES-256-GCM under that
key, with the file's name inside the profile as associated data, so one file cannot be swapped for
another. The data key is kept in one of two ways:

- **System keyring** (default): Secret Service (GNOME Keyring, KWallet) on Linux, Credential
  Manager (DPAPI) on Windows. It opens with the user's session without questions. This protects
  against a copied data folder or backup of the disk, another user of the computer, and a stolen
  disk; not against programs running as the user, which can ask the keyring too.
- **Wallet password** (*Settings → Security*, `atesta-id-wallet password set`): the data key is
  wrapped with a key derived from the password with scrypt (N=2¹⁵, r=8, p=1) and removed from the
  keyring. Nothing can be read until the password is typed: this is the app lock. The window locks
  again after 5 minutes without use or with *Lock*. The password cannot be recovered; `reset`
  empties the profile and starts again.
  After 3 wrong passwords each new one doubles a wait (15 s, 30 s, ... up to 15 minutes), kept in
  `settings.json` so that restarting does not reset it; a right password clears it. This only slows
  down guessing through the wallet: whoever copies the files attacks scrypt offline, so a long
  password is what matters. Wallet and backup passwords need at least 12 characters.

Without a usable keyring (headless systems, some minimal desktops) a wallet password is required:
the data is never stored in clear text. Unlocked keys live in the process memory until it locks
or exits; Python cannot reliably wipe them. Backups contain the decrypted profile under their own
password, so they can be restored on another computer (whose keyring does not have the key).

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
| `trusted` | The chain validates up to a CA in `trusted_cas/` (*Settings → Trust* or `atesta-id-wallet trust add-ca`). | green |
| `pinned` | Not CA-backed, but it is the same certificate as last time (trust on first use, like SSH). | green |
| `new` | Signed and consistent, but never seen before. | amber |
| `changed` | A different certificate for a client_id seen before. Possible impersonation. | red + risk checkbox |
| `unverified` | No usable signature. | red + risk checkbox |

**3. Response destination.** For `x509_san_dns` verifiers that are not `trusted`, the host of
`response_uri` must equal the certificate's DNS name (OpenID4VP 1.0 §5.9.3). This stops an
attacker from relaying a legitimate verifier's request and having your data posted elsewhere.
`redirect_uri` verifiers must use their client_id as `response_uri`. HTTPS is required for every
URL the wallet fetches or posts to. `http://localhost` is only accepted with
`ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP=1` (development and tests): otherwise a QR code could make the wallet
call services on this computer.

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
in the browser. Only `https://` addresses (`http://localhost` only in development, see above) are
opened, never `file:`,
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
- **Login in the browser** (RFC 8252) when the issuer has the wallet's client `atesta-id-wallet`
  (public, PKCE, redirect `http://127.0.0.1/callback`). The wallet checks for it with an
  authorization request without cookies or credentials (Keycloak answers an unknown client or
  redirect URI with an error page), then opens the browser and waits on 127.0.0.1, on a free port,
  for the redirect; only that path is accepted, and `state` and PKCE apply as usual. The password,
  OTP, WebAuthn or external IdP stay in the browser. With this client the offer's `issuer_state`
  is not sent: offers are made for other clients, and Keycloak would both refuse it and keep it
  in the browser's SSO session for this client, so later logins would fail too (`prompt=login`
  does not clear it). The credentials are asked for by scope, which Keycloak grants only to an
  account entitled to them, as it does for the offer. `--in-app-login` turns this off.
  The browser may reuse a session that was already open, perhaps someone else's on a shared
  computer: after issuance the wallet says which account it was issued for (`preferred_username`
  and `email` of the `id_token` from the token endpoint; display only) and offers to delete it.
- In the wallet's own login, the password is only submitted, over HTTPS, to a form on the same
  host as the `authorization_endpoint`. External IdPs need `--browser-login`.
- The authorization code flow uses PKCE (S256) and a `state` that must come back unchanged. If
  the response names its issuer (`iss`, RFC 9207), it must be the expected one.
- **DPoP** (RFC 9449): when the authorization server advertises ES256 in
  `dpop_signing_alg_values_supported`, the access token is bound to a key made for that issuance
  only (not the holder key, so the issuer cannot link it to the credentials). Every request
  carries a fresh proof (`jti`, `htm`, `htu` without query, `iat`; `ath` at the credential
  endpoint), and server nonces are kept per endpoint. A stolen access token is useless without
  that key. `--no-dpop` turns it off.
- **Issuers without a published name** are shown by their domain on the cards, but by their full
  host in the offer review, where trust is decided; on shared hosting (`*.github.io`, `*.pages.dev`,
  ...) the full host everywhere, so a site there is not named after the platform.
- **Offers tied to another wallet.** Keycloak 26.6 and 26.7 bind every offer made through
  `create-credential-offer` to the OAuth client that created it, and refuses it at the token
  endpoint when another client signed in (`Credential offer target client ... different from
  login client`). Only on that exact error, the wallet asks the same issuer for the same
  credential configurations the user accepted, without `issuer_state` (wallet-initiated), so the
  server authorizes by scope and only issues what the account is entitled to. Nothing new is
  accepted on the user's behalf: the issuer, the credentials and the consent are those of the
  offer.
  - The retry uses a new HTTP session: Keycloak reuses the client session of an SSO login and
    keeps its `issuer_state` note, so the same cookies would hit the same offer.
  - The username and password typed for the first attempt are replayed once, only to the same
    host, for that retry. They stay in memory until the login ends and are never written
    anywhere. One-time codes (OTP) are asked again. With `--browser-login` the browser keeps its
    own session and the retry fails the same way.
  - The detection depends on Keycloak's error text: if it changes, the wallet shows the error
    instead of retrying.
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
- **Logos** published by the issuer (credential `display.logo`, else the issuer's) are fetched
  once, after the user accepted the offer, and stored encrypted with the credential: showing the
  wallet never contacts anyone, and declining an offer reveals nothing to a third-party logo host.
  Only HTTPS or `data:` URIs, never this computer or the local network (loopback, private and
  link-local addresses), no redirects, at most 256 KiB, and only PNG, JPEG, GIF or WebP
  recognised by their first bytes (no SVG: scripts and external references). The window reads the
  image dimensions from the header and refuses images larger than 2048 px before decoding. A logo
  that fails any check is left out; the credential is stored anyway.

## Desktop integration

- Only one window runs at a time. A link opened while the wallet is running is handed to that
  window through a local socket in the user's private runtime directory (`$XDG_RUNTIME_DIR`, or the
  data folder), so other users of the computer cannot receive it. On Windows named pipes are
  global, so the pipe name carries a random suffix stored in the user's data folder: another user
  cannot guess it and create the pipe first.
- Temporary files of the window (themed icons) go to a private, per-process temporary directory.

## Releases and updates

- Releases are built by GitHub Actions from a tag (`.github/workflows/release.yml`), not on a
  developer's machine. Each release has a `SHA256SUMS` file and, on a public repository, a signed
  build provenance attestation (`gh attestation verify FILE --repo CitComAI-Hub/atesta-id-wallet`).
  Windows builds are not Authenticode-signed yet.
- The wallet never downloads or installs anything by itself. *Settings → About → New versions*
  (off by default) or `atesta-id-wallet update` asks the GitHub API for the latest release. The
  request carries no wallet data: GitHub sees the IP address and the version in the User-Agent.
  The download page that is opened must be under the project's releases page.

## Known gaps

| Gap | Impact | Planned mitigation |
|---|---|---|
| Keys are software keys | Without a wallet password, malware running as the user can ask the keyring for the data key. With one, it can still read the key from memory while the wallet is unlocked. There is no hardware-backed key (TPM, secure element). | Hardware-backed holder keys if the pilot needs them. |
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

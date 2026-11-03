# TODO

## Decisions

- **Goal**: technical pilot (TRL 6) before distribution to end users.
- **Security first**: nothing is sent without explicit consent; see `docs/SECURITY.md`.
- **Platforms**: Linux (any distro) + Windows; macOS later (needs a signed .app bundle).
- **UI**: PySide6 (Qt) on top of the protocol code; the CLI stays for debugging and automation.
- **Language**: code, comments and documentation in English; the app in English (source and
  fallback), Spanish, Danish, German, French and Luxembourgish, chosen automatically from the system or by hand (Settings /
  `atesta-id-wallet language`).

## Status (0.10.0, November 2026)

**TRL 5**: the wallet works end to end against the real Keycloak and the CITCOM marketplace on
Linux, and receives credentials from the PGTEC onboarding portal (offers made for Lissi), with a
GUI, a CLI, six languages, an offline test suite (179 tests, GUI included) and nightly tests
against real Keycloak 26.6, 26.7 and latest. Release 0.10.0 is public on GitHub (Windows installer and zip, .deb, AppImage), built and
smoke-tested by CI (including a silent install/uninstall on Windows), but nobody outside the team
has used it and nobody has tested it by hand on real Windows or macOS.

**TRL 6 target**: a pilot with real users in the CITCOM environment. Blocking for that, in order:
the manual Windows test, the CITCOM verifier trust list, and a decision on the second login.

## Done

- 0.2: consent screen, verifier trust (CAs, TOFU pinning, `x509_hash`), `response_uri` bound to the
  verifier's DNS, unsigned requests refused, issuer signature and `cnf` checked before storing,
  password only sent to the authorization server, 0700/0600 permissions, profiles,
  `remove`/`reset`/`backup`/`restore`, `update`, English README + `docs/SECURITY.md`.
- Package split by responsibility; `Prompter` interface so CLI and GUI run the same flows.
- Portability: QR with zxing-cpp + Pillow, clipboard and screenshots per OS, data folders per OS,
  Windows link handler (HKCU). Untested on real Windows and macOS.
- 0.3–0.4: PySide6 GUI, redesigned with ideas from Lissi: issuer-coloured cards, sidebar, in-window
  flow panels, offer review, one-step login, activity history, light/dark theme, automatic QR wait.
- 0.5: English, Spanish and Danish, with catalogs checked by a test.
- **0.5.1: full review** (security and robustness; regression tests in `tests/test_hardening.py`):
  - [x] DCQL: a query without `claims` disclosed **every** claim; now only the mandatory parts
        (OpenID4VP 1.0 §6.4.1). `claim_sets` was ignored; now the first satisfiable option is used.
  - [x] GUI: names, claim values and server errors were rendered as HTML (a verifier could fake
        the green "trusted" look or inject links); all labels are plain text now.
  - [x] The verifier's `redirect_uri` was opened in the browser without checks (`file:`,
        `javascript:`...); only web addresses are opened now.
  - [x] Issuance: issuer and authorization server metadata must belong to the offering issuer
        (OpenID4VCI 1.0, RFC 8414); every endpoint and `credential_offer_uri` must be HTTPS; the
        password is never posted over plain HTTP; OAuth callback requires `state`, checks `iss`
        (RFC 9207) and reports a missing `code` instead of crashing.
  - [x] SD-JWT parsed strictly: duplicate disclosures, disclosures overwriting visible claims and
        reserved names are rejected. JWS: algorithm must match the key curve; malformed tokens no
        longer crash. JWE: only ECDH-ES keys of supported curves are used.
  - [x] Storage: `config.json` and other files written atomically (a crash could empty it and
        drop the verifier pins); two credentials received in the same second no longer overwrite
        each other; `harden_permissions` no longer chmods every file under `$ATESTA_ID_WALLET_HOME`;
        adding a CA with an existing file name no longer replaces the other CA.
  - [x] GUI: single window (links go to the running window through a private local socket);
        remembers the last profile; profile switch is ignored during a flow; temporary icon files
        in a private directory instead of a predictable name in the shared `/tmp`.
  - [x] CLI: unexpected errors print one line instead of a traceback (traceback with `--verbose`).
  - [x] Issuer display names follow the interface language (they were hard-coded to Spanish).
  - [x] Installer messages and package metadata in English; docs updated.
- **0.6.0: packaging** (`packaging/`, `.github/workflows/release.yml`, `docs/RELEASING.md`):
  - [x] PyInstaller folder with two executables (GUI and CLI); Windows installer (Inno Setup, per
        user, links in HKCU), portable zip, `.deb` and AppImage; `SHA256SUMS` and build provenance.
  - [x] CI on a `v*` tag: tests on Linux and Windows, `--smoke-test` of every build, silent
        install/uninstall on Windows checking the link handler; then the GitHub release.
  - [x] App aware of being packaged: link handler points to the executable or the AppImage,
        `update` only checks; *Settings → General → Wallet links → Register*.
  - [x] New-version notice: *Settings → About* (automatic daily check, off by default) and
        `atesta-id-wallet update [--check]`; the app never downloads anything by itself.
  - [x] Provisional app icon (`packaging/app-icon.svg`), also used by `install-handler`.
  - [x] Windows fixes found on review: random single-instance pipe name (other users could
        take a guessable one), CLI output that does not crash on non-UTF-8 consoles.

- **0.6.1**: the .deb only depends on libc6 and libegl1 (the X11 libraries are bundled; `dpkg -i`
  failed without libxcb-cursor0); readable message when GitHub's rate limit is hit.

- **0.7.0: no compatibility with earlier versions** (prototype, no users to keep): no data
  migration from `oid4vc-wallet` or `./wallet_data`, no permission repair of 0.1 data, every
  profile in `profiles/NAME` (also `default`), new backup format (`ATESTAB1`; older backups
  cannot be restored).

- **0.8.0: encryption at rest and app lock** (`vault`): every profile file encrypted with
  AES-256-GCM under a per-profile key, kept in the system keyring or wrapped with a wallet
  password (scrypt); window lock after 5 minutes without use; `atesta-id-wallet password`.

- **0.9.0: DPoP, offers made for other wallets, UX from Lissi, six languages**: DPoP-bound tokens (RFC 9449) on the token and
  credential endpoints when the server advertises them, with server nonces (`--no-dpop` to turn it
  off); `issue --issuer URL [--credential ID]` without an offer; an offer tied to another wallet's
  OAuth client (Keycloak 26.7 `target client ... different from login client`, e.g. the PGTEC
  onboarding portal, made for Lissi) is retried without the offer in a new HTTP session (Keycloak keeps the
  issuer_state note in the SSO client session), replaying the login of the first attempt
  from memory: the user signs in once.
  Theme setting (automatic, light, dark) in *Settings → General*.
  Issuers with no published name are shown by their domain (`pgtec-vrain-dataspace.eu`, not the
  Keycloak host); dates as `3 Nov 2026`; empty-wallet text no longer CITCOM-only.
  Issuer logos on the cards (downloaded once at issuance, stored with the credential).
  From a look at Lissi's screens: show/hide button in password fields; wait after 3 wrong wallet
  passwords (doubling, up to 15 min); issued / valid-from dates; "request it from <known issuer>"
  when a verifier asks for a credential you lack; Activity per contact; three-step first start;
  Settings → About → Licenses.
- **0.10.0: login in the browser, hardening**: when the issuer has the client `atesta-id-wallet`
  (public, PKCE, redirect `http://127.0.0.1/callback`), the wallet signs in through the browser and
  waits on a free loopback port: the password never reaches the wallet (`--in-app-login` to turn it
  off; without the client nothing changes). After issuance it says which account the credential was
  issued for, with "Not your account? Delete it". Wallet and backup passwords: at least 12
  characters. Found by mypy and fuzzing, now clear errors: links with a bad host, a broken verifier
  `redirect_uri` after an accepted presentation, malformed DCQL queries, `history` with an event
  without a type. Opening the browser no longer fails in the windowed builds. Releases carry a
  CycloneDX SBOM per build. Tests split by area; Keycloak integration tests and fuzzing every night.
  German, French and Luxembourgish (machine-made: German and French need a quick review by a native
  speaker, Luxembourgish a careful one). Smoother panel changes (the backdrop stays); a too short or
  mismatched new password asks again instead of ending the flow; notices centred on the page.
  Security review (November 2026): shared-hosting issuer names, no logos from local addresses,
  http://localhost only with ATESTA_ID_WALLET_ALLOW_LOCAL_HTTP=1. CI on every branch and pull request
  with ruff, bandit and pip-audit; Dependabot.

## Next: roadmap to the pilot (TRL 6)

1. [ ] **Windows code signing** (Authenticode certificate) to avoid the SmartScreen warning.
       Done: public repository, release 0.6.0 published by CI, new-version check working.
2. [ ] **Test on real Windows** by hand with [docs/TESTING-WINDOWS.md](docs/TESTING-WINDOWS.md)
       (browser links, clipboard, screenshots, `%APPDATA%` permissions, update/uninstall) and
       decide on macOS for the pilot.
3. [x] **CI**: tests on Linux and Windows for every push and pull request, `ruff` (bug-class rules),
       `bandit`, `pip-audit`, `mypy` (protocol code; the GUI still excluded: move it to Qt's scoped
       enums, e.g. `Qt.AlignmentFlag.AlignCenter`, then drop the override), Dependabot (`checks.yml`).
4. [x] **Holder key protection** (0.8.0): encrypted profile, key in the OS keyring or behind a
       wallet password with app lock. Still to check by hand on Windows (Credential Manager).
5. [ ] **Trust list**: ship the CITCOM verifier CA (or trust list) with the app, so pilot verifiers
       show as trusted instead of "first time".
6. [ ] **Second login when receiving a credential**: option B is in the wallet (0.10, below); the
       issuers still have to register the `atesta-id-wallet` client (CITCOM realm, PGTEC).
7. [ ] **Pilot plan**: who (number of users, roles), scenarios (receive, sign in, backup/restore,
       second device), what is measured (success rate, time, support requests), feedback form.
8. [x] **First-run guide** in the GUI: what the wallet is, how to get a credential, why a password and
       a backup matter.
       - [x] Offer the wallet links in the guide where nothing registered them (Windows .zip, AppImage,
             from source): an extra step, "Open wallet links with this application", with *Register* /
             *Not now* (= Settings → General → Register). Only when no application opens them (another
             wallet's choice is respected); not on macOS (no .app) nor without `xdg-mime`.
9. [ ] Final app icon for *Atesta ID Wallet* (replace `packaging/app-icon.svg`, run `make_icons.py`).
       Done: issuer logo (`display.logo`) on the cards.
10. [ ] Danish, German and French reviewed by native speakers; Luxembourgish carefully.
11. [ ] **UX**: expert review done ([docs/UX-REVIEW.md](docs/UX-REVIEW.md): 19 problems fixed, texts in plain
       words, keyboard and contrast to WCAG AA). Done since: plain words for the roles. Pending there:
       scanning by screenshot, text size, a screen reader test, technical sections of Settings. Then a
       usability test with 5–8 people of the pilot profile (part of item 7).

## Later (after the pilot)

- [ ] **Hardware-backed holder keys** (WSCD-like), together with one key per credential and
      batch issuance (less correlation between verifiers):
      - Windows: TPM 2.0 through CNG (*Microsoft Platform Crypto Provider*), optional Windows
        Hello. Guaranteed on Windows 11, so the first target.
      - Linux: TPM 2.0 through `tpm2-pkcs11` as an option (often needs the `tss` group and extra
        packages: support cost with pilot users). macOS: Secure Enclave, if macOS is supported.
      - Smart cards / USB tokens (PKCS#11) as an alternative.
      - Key attestation from the TPM: the first real step towards wallet attestation.
      - Decide first: a hardware key cannot be exported, so backups cannot restore credentials
        on another computer; a new or broken laptop means asking the issuers again.
- [ ] Token Status List (revocation)
- [ ] Make "issuer key not found" an error once the pilot issuers are known
- [ ] Issuer trust list / allow-list; validate issuer `x5c` chains
- [ ] Deferred issuance; `jwt_vc_json` and mso_mdoc if a verifier needs them
- [ ] DCQL `trusted_authorities`; verifier attestations / OpenID Federation client_ids
- [ ] Digital Credentials API (browser-mediated presentation), when browsers support it on desktop
- [ ] Redact secrets (codes, tokens) from the verbose log shown in *Settings → Advanced*
- [ ] External security review before end-user distribution
- [x] Split `tests/test_offline.py` (1000+ lines) by module: `tests/helpers.py` + one module per area
- [x] Fuzzing of SD-JWT, JWT, offer, presentation request and DCQL parsing (`tests/test_fuzz.py`;
      nightly with a new seed, `fuzz.yml`). Found: links with a bad host ('[') and malformed DCQL
      queries raised ValueError/AttributeError instead of a clear error.
- [x] SBOM (CycloneDX) of each build in the releases
- [ ] mypy on the GUI (scoped Qt enums); branch protection on `main` (GitHub settings, needs an admin)

## Pending decision: avoid the second login when receiving a credential

Keycloak generates *authorization_code* offers: the wallet has its own session and must log in
even if the browser already has one. Options (decide with whoever administers Keycloak):

- [ ] **A. Pre-authorized offers** (recommended): the page that generates the QR issues a
      `pre-authorized_code`. Keycloak already advertises it in `grant_types_supported`; the wallet
      supports it.
- [x] **B. Browser login** (0.10): when the issuer has the client `atesta-id-wallet` (public, PKCE,
      redirect `http://127.0.0.1/callback`, any port), the wallet finds it by itself and signs in
      through the browser, reusing its session; the password never reaches the wallet. GUI panel
      "Continue in your browser"; `--in-app-login` turns it off. Covered by the Keycloak tests.
- [ ] **C. Remember the wallet session** (no server changes): keep the SSO cookie in the profile.
      Only avoids later logins; the cookie gives access to the account while it is valid.
- [ ] **GUI for wallet-initiated issuance** ("Request a credential" from a known issuer); today only
      `issue --issuer` in the CLI.
- [ ] **Register `atesta-id-wallet`** in each issuer realm (public, standard flow only, PKCE S256,
      redirect `http://127.0.0.1/callback`, `oid4vci.enabled`, `profile` and `email` as default scopes
      so the wallet can say which account signed in, the credential scopes as optional scopes): CITCOM connectors (dataspace-on-upv), PGTEC (ask its admin). No wallet change needed.

## Open questions

- Hardware-backed keys: is it acceptable that credentials do not survive a change of computer
  (re-issuance instead of restore)? Decides whether and when to use the TPM.
- Becoming an official EUDI Wallet (provider, notifying Member State, certification budget) is a
  project decision, not a development task; today the wallet only uses the EUDI protocols.
- Is there a CA or trust list for the CITCOM verifiers that we can ship by default?
- Is macOS needed for the pilot?
- Who buys and keeps the Windows code-signing certificate?
- Who administers the CITCOM Keycloak (for options A/B of the second login)?
- App icon for the name *Atesta ID Wallet* (the current one is a placeholder).

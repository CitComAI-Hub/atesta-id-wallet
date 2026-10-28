# TODO

## Decisions

- **Goal**: technical pilot (TRL 6) before distribution to end users.
- **Security first**: nothing is sent without explicit consent; see `docs/SECURITY.md`.
- **Platforms**: Linux (any distro) + Windows; macOS later (needs a signed .app bundle).
- **UI**: PySide6 (Qt) on top of the protocol code; the CLI stays for debugging and automation.
- **Language**: code, comments and documentation in English; the app in English (source and
  fallback), Spanish and Danish, chosen automatically from the system or by hand (Settings /
  `atesta-id-wallet language`).

## Status (0.6.0, October 2026)

**TRL 5**: the wallet works end to end against the real Keycloak and the CITCOM marketplace on
Linux, with a GUI, a CLI, three languages and an offline test suite (100+ tests, GUI included).
Release 0.6.0 is public on GitHub (Windows installer and zip, .deb, AppImage), built and
smoke-tested by CI (including a silent install/uninstall on Windows), but nobody outside the team
has used it and nobody has tested it by hand on real Windows or macOS.

**TRL 6 target**: a pilot with real users in the CITCOM environment. Blocking for that, in order:
the manual Windows test, an encrypted holder key with an
app lock, the CITCOM verifier trust list, and a decision on the second login.

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

## Next: roadmap to the pilot (TRL 6)

1. [ ] **Windows code signing** (Authenticode certificate) to avoid the SmartScreen warning.
       Done: public repository, release 0.6.0 published by CI, new-version check working.
2. [ ] **Test on real Windows** by hand with [docs/TESTING-WINDOWS.md](docs/TESTING-WINDOWS.md)
       (browser links, clipboard, screenshots, `%APPDATA%` permissions, update/uninstall) and
       decide on macOS for the pilot.
3. [ ] **CI**: tests on Linux and Windows for every push (today only on release tags); add
       `ruff` and a type checker.
4. [ ] **Holder key protection**: OS keyring (Secret Service / DPAPI / Keychain) or passphrase,
       together with an app lock (PIN/password) in the GUI.
5. [ ] **Trust list**: ship the CITCOM verifier CA (or trust list) with the app, so pilot verifiers
       show as trusted instead of "first time".
6. [ ] **Second login when receiving a credential**: decide option A/B/C (below).
7. [ ] **Pilot plan**: who (number of users, roles), scenarios (receive, sign in, backup/restore,
       second device), what is measured (success rate, time, support requests), feedback form.
8. [ ] **First-run guide** in the GUI: what the wallet is, why a backup matters, where the data lives.
9. [ ] Final app icon for *Atesta ID Wallet* (replace `packaging/app-icon.svg`, run `make_icons.py`) and
       issuer logo (`display.logo`) on the cards; see open questions.
10. [ ] Danish reviewed by a native speaker.

## Later (after the pilot)

- [ ] One key per credential, batch issuance (less correlation between verifiers)
- [ ] Token Status List (revocation)
- [ ] Make "issuer key not found" an error once the pilot issuers are known
- [ ] Issuer trust list / allow-list; validate issuer `x5c` chains
- [ ] Deferred issuance; `jwt_vc_json` and mso_mdoc if a verifier needs them
- [ ] DCQL `trusted_authorities`; verifier attestations / OpenID Federation client_ids
- [ ] Digital Credentials API (browser-mediated presentation), when browsers support it on desktop
- [ ] Redact secrets (codes, tokens) from the verbose log shown in *Settings → Advanced*
- [ ] External security review before end-user distribution
- [ ] Split `tests/test_offline.py` (1000+ lines) by module

## Pending decision: avoid the second login when receiving a credential

Keycloak generates *authorization_code* offers: the wallet has its own session and must log in
even if the browser already has one. Options (decide with whoever administers Keycloak):

- [ ] **A. Pre-authorized offers** (recommended): the page that generates the QR issues a
      `pre-authorized_code`. Keycloak already advertises it in `grant_types_supported`; the wallet
      supports it.
- [ ] **B. Browser login**: a wallet client in Keycloak with a loopback redirect
      (`http://127.0.0.1:PORT/callback`); reuses the browser session. The GUI option is missing.
- [ ] **C. Remember the wallet session** (no server changes): keep the SSO cookie in the profile.
      Only avoids later logins; the cookie gives access to the account while it is valid.

## Open questions

- Is there a CA or trust list for the CITCOM verifiers that we can ship by default?
- Is macOS needed for the pilot?
- Who buys and keeps the Windows code-signing certificate?
- Who administers the CITCOM Keycloak (for options A/B of the second login)?
- App icon for the name *Atesta ID Wallet* (the current one is a placeholder).

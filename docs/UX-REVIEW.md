# UX/UI review (November 2026, version 0.10.0)

Expert review before the pilot: no users were observed yet (that is the usability test with 5–8
people of the pilot profile, see `todo.md`). It finds the obvious problems so that the user tests
are not spent on them.

## Method

- **Every screen and panel rendered with sample data** (32 screens: wallet, credential, activity,
  settings, lock, first-run guide, scan, offer, sign-in, browser, transaction code, progress,
  consent at each trust level, choose, results and errors), in English and Spanish, light and dark,
  plus German (the longest texts) to find text that does not fit.
- **Nielsen's heuristics** and a cognitive walkthrough of the key tasks (receive a credential,
  sign in with it, protect the wallet) as someone who has never used a wallet.
- **Text review** of the ~450 messages the window can show (the GUI and the errors of the protocol
  code), in English and Spanish, looking for technical words and unclear actions.
- **Accessibility (WCAG 2.2 AA)**: colour contrast computed for every pair of the theme; keyboard
  use; names for screen readers.
- **Lissi**, as a reference for plain wording (see below).

Severity: 4 = blocks a task or misleads on security · 3 = serious · 2 = minor · 1 = cosmetic.

## Fixed in this review

| # | Sev. | Problem | Fix |
|---|---|---|---|
| 1 | 3 | The progress panel cut its title ("Receiving the credential…" in two clipped lines) | Layout fixed |
| 2 | 3 | Protocol steps shown to the user while working ("Requesting MembershipCredential (dc+sd-jwt)…", "Access token received", "Pre-authorized code flow") | Only in the technical log (Settings → Advanced) |
| 3 | 3 | Errors showed raw technical text (`HTTPSConnectionPool(host=…) Max retries…`, `KeyError: 'credential_configurations_supported'`, `x5c`, `DCQL`, `metadata`…) | Plain explanation and what to do; the technical text behind "Show technical details". Errors where the user can act (expired request, wrong password, timeout, password sent to another site, data sent to another site, deferred issuance, credential that cannot be checked) have their own text (`WalletError(hint=…)`) |
| 4 | 3 | Claim names always in English and as identifiers ("Given name", "Family name", "Roles" in a Spanish window) | Common claims translated (`common.claim_label`): Nombre, Apellidos, Correo electrónico… |
| 5 | 3 | No visible keyboard focus anywhere (`outline: none`, no `:focus` style) — WCAG 2.4.7 | Focus ring on buttons, lists, cards and activity rows, only when the focus came from the keyboard (Qt has no `:focus-visible`: `widgets.keyboard_focus_ring` looks at the focus reason). A click, or a panel giving the focus to its default button, shows no ring |
| 6 | 3 | Credential cards and activity rows could only be used with the mouse; cards were invisible to screen readers | Reachable with Tab, opened with Enter/Space, with an accessible name (name, issuer, holder, expired) |
| 7 | 3 | Consent notices in jargon ("Its certificate is issued by an authority you trust", "verifier") | In plain words, "service" instead of "verifier" (as Lissi does): "An authority your wallet trusts confirms who this service is"; "Nobody has confirmed who this service is. Share only if you recognise the address below…" |
| 8 | 2 | Contrast below 4.5:1: green and red notice text (light), white on the red button (dark, 2.4:1); field edges almost invisible (1.3:1, WCAG 1.4.11 asks 3:1) | Colours adjusted; a test checks every pair |
| 9 | 2 | German "ABGELAUFEN" did not fit in the expired tag of the card | Tag sized to its text |
| 10 | 2 | Expired credentials looked like valid ones, first in the list and preselected when choosing | Faded, last in the list; when choosing, a valid one is preselected and expired ones say so |
| 11 | 2 | Credential details in jargon: "Bound to this wallet's key", "Selective disclosure", "Type MembershipCredential" | "Protection against copies: Only this wallet can use it", "Shared only with your approval: 4 pieces of data", "Technical type" last |
| 12 | 2 | "Profile default" in the header and a profile selector in the sidebar for people with a single profile | Only shown with more than one profile (always in Settings → Profile) |
| 13 | 2 | The password rule (12 characters) only appeared after a mistake | Stated from the start |
| 14 | 2 | Settings → Wallet links explained with `openid4vp://` and `openid-credential-offer://` | "Let buttons and links on web pages open this application, instead of scanning their QR code" |
| 15 | 2 | Missing credential named by its type identifier ("LegalPersonCredential") | Readable name ("Legal Person Credential") |
| 16 | 2 | Spanish mixed "cartera" (menu, empty wallet) with "el wallet" (everything else) | "cartera" everywhere, the EU's own word (*Cartera Europea de Identidad Digital*); also "Confianza" on the Trust button → "Confiar", "Poner contraseña" → "Crear una contraseña", "Hecho" → "Listo" |
| 17 | 1 | The scan panel spoke as "we" ("We will detect it"); everything else says "the wallet" | One voice |
| 18 | 1 | Empty wallet text mentioned "your Keycloak account" | "your account page" |
| 19 | 1 | Settings checkboxes (protocol details, new versions) had no name for screen readers | Each control is named after its setting |

The new texts are machine-made in Danish, German, French and Luxembourgish, like the rest of those
catalogs (native review still pending, `todo.md` item 10).

## Pending: decisions and larger changes

1. **Words for the roles** (sev. 3). Besides "verifier" (now "service" in the consent), the window
   still says *issuer*/*emisor* and *credential*/*credencial*. Lissi avoids the role names
   altogether ("digital services", "organisations") and calls credentials by what they are
   ("certificates, member cards, employee passes, licences"). Proposal: keep "credential" (the
   pilot users get it with that name) but explain it once with examples in the first-run guide,
   and replace "issuer" with "the organisation that gave it to you" where it is not a label. Needs a
   decision before the catalogs are touched again.
2. **Screenshot to scan** (sev. 3, to confirm in the user test). Taking a screenshot of a QR code
   on the same computer is not obvious for someone who is not technical, and Print Screen behaves
   differently on each desktop. Ideas: a short animation the first time; "Paste link" as visible as
   "Scan QR"; registering the links (now offered in the guide) so that the button on the page works.
3. **Text size** (sev. 2, WCAG 1.4.4). Font sizes are fixed pixels: the window ignores the system's
   text size setting. Move the style sheet to sizes relative to the system font.
4. **Screen readers** (sev. 2). Names and keyboard are in place, but nobody has tried the window with
   Orca (Linux) or NVDA (Windows). To do before the pilot if a participant needs one.
5. **Technical sections of Settings** (sev. 2). *Trust* (CAs, remembered verifiers) and *Advanced*
   (protocol log) are shown to everybody next to language and backup. Move them under a collapsed
   "Advanced" area.
6. **Credential names from the issuers** (sev. 2). "Legal Person Credential" and "User Credential"
   are built from the technical type because the issuer publishes no display name. Ask CITCOM and
   PGTEC to publish `display.name` (and colours, logo) in their metadata.
7. **Service names in the consent** (sev. 2). Verifiers are shown by their domain
   (`marketplace.citcom.example`). The CITCOM trust list (`todo.md` item 5) would let the wallet show
   the organisation's name and the green "trusted" notice.
8. **Lock screen** (sev. 1). "Unlock…" opens a second panel; the password field could be on the
   page itself.
9. **Credential page** (sev. 1). The name appears twice (card and title).

## Lissi as a reference

Lissi's public material for end users is thin (most of the site is for organisations), so this is
based on its app store description and its user FAQ, not a full walk through the app:

- No role names: no "issuer", "verifier" or "relying party"; the other side is a *digital service*
  or an *organisation*, and Lissi speaks of *Nachweise* (proofs) more than of credentials. → applied
  to the consent (item 7 above); proposed for the rest (pending 1).
- Credentials explained by examples: "certificates, member cards, employee passes, or licences". →
  proposed for the first-run guide.
- Organisations as *contacts* with a history of what was shared. → already in the wallet since 0.9
  (Activity per contact).
- Backup explained by its purpose: "if you switch devices, … backup and restore so you can recover
  your credentials". → the first-run guide and Settings already say it that way.

Sources: [Lissi for users (FAQ)](https://www.lissi.id/for-users),
[Lissi ID-Wallet on the App Store](https://apps.apple.com/de/app/lissi-id-wallet/id6475958390).

## How to repeat it

The screens were rendered offscreen with sample data (credentials, history, every panel). The
script is not in the repository yet; adding it under `tests/` (or `packaging/`) would let every
release produce the screenshots for the documentation and for a quick visual check.

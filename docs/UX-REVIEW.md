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

1. ~~**Words for the roles**~~ (sev. 3) — **done**: "credential" is kept (it is the word the pilot
   users see in Keycloak and in the issuers' emails) and explained once, with examples, in the first
   step of the guide ("like a digital card that says something about you: a membership card, an
   employee pass, a certificate"). "Issuer" no longer appears in sentences: the organisation's name
   where the wallet knows it ("First credential from CITCOM TEF", "ask CITCOM TEF for it again"),
   otherwise "the organisation that gives you the credential"; as a label, "Issued by". The other
   side is always "the service" in the window. Settings → Trust and the command line keep "issuer"
   and "verifier" (technical audience; see 5).
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
  to the consent (item 7 above) and to the rest of the window (pending 1, done).
- Credentials explained by examples: "certificates, member cards, employee passes, or licences". →
  done: the first step of the guide.
- Organisations as *contacts* with a history of what was shared. → already in the wallet since 0.9
  (Activity per contact).
- Backup explained by its purpose: "if you switch devices, … backup and restore so you can recover
  your credentials". → the first-run guide and Settings already say it that way.

Sources: [Lissi for users (FAQ)](https://www.lissi.id/for-users),
[Lissi ID-Wallet on the App Store](https://apps.apple.com/de/app/lissi-id-wallet/id6475958390).

## Second round: measured, and automated (November 2026)

The first round was an expert review of screenshots. The second one measures, with professional
metrics, and turns each measure into a test with a budget, so that a regression fails in CI.

### What is measured, and how

| Area | Metric | Standard | How |
|---|---|---|---|
| Accessibility | Text contrast **as painted** (pixels, not theme values) | WCAG 2.2 1.4.3 (4.5:1, 3:1 large) | Every label and button of every screen; background = most common colour, text = the pixel that differs most |
| | Contrast of the edges of fields, checkboxes and options | WCAG 1.4.11 (3:1) | The painted top edge of each field; the indicator rect from the Qt style |
| | Accessible name of every control | WCAG 4.1.2 | Name, text, or label of the field |
| | Target size | WCAG 2.5.8 (24×24 px, or spacing) | Every interactive widget, with the spacing exception |
| | Focus kept inside open panels | WCAG 2.4.3 | Real Tab key presses (QTest) |
| | Every control reachable with Tab | WCAG 2.1.1 | Same; a group of options counts as one stop (arrow keys inside) |
| | Visible keyboard focus | WCAG 2.4.7 | Test: ring with Tab, not with a click or a panel opening |
| Layout | Text cut off | — (i18n) | Size hint against the widget's size, in the 6 languages |
| | Text under 12 px | legibility | Font size of every label |
| Texts | Readability per language | Flesch Reading Ease (en), Fernández-Huerta (es), Flesch-Amstad (de), Kandel-Moles (fr), LIX (all) | The ~110 texts of 6 words or more the window can show, errors included |
| | Sentence length | plain language: ≤ 25 words | Longest sentence per language |
| | Jargon | per-language word list | Every window text, except a list for Settings → Trust/Advanced |
| Tasks | Decisions, keystrokes, estimated time | Keystroke-Level Model (Card, Moran & Newell) | The real flows against the fake issuer and verifier, answering each panel as a person would |
| Speed | Median response time | Nielsen: 0.1 s feels instant | Page change, opening a credential, a panel, rebuilding the window |

### Results (after the fixes)

384 screens rendered (32 screens × 6 languages × light and dark), 352 widgets per screen checked:
**0 findings**. Lowest text contrast 4.56:1 (light) and 4.82:1 (dark), the selected item of the sidebar.

| Language | LIX | Readability | Words per sentence | Longest sentence | Jargon |
|---|---|---|---|---|---|
| English | 29.4 (very easy) | Flesch 71.4 (fairly easy; plain English ≥ 60) | 10.0 | 22 | 0 |
| Spanish | 35.8 (easy) | Fernández-Huerta 80.1 (fairly easy) | 9.9 | 22 | 0 |
| Danish | 33.5 (easy) | — | 9.4 | 22 | 0 |
| German | 35.6 (easy) | Flesch-Amstad 68.2 (medium-easy) | 9.1 | 23 | 0 |
| French | 39.4 (easy) | Kandel-Moles 71.7 (fairly easy) | 10.1 | 22 | 0 |
| Luxembourgish | 34.8 (easy) | — | 9.3 | 23 | 0 |

| Task | Decisions | Keystrokes | Estimated time (KLM) |
|---|---|---|---|
| Receive a credential (with a collection code) | 3 | 5 | 11.5 s |
| Sign in to a service with it | 3 | 0 | 8.0 s |

Taking the screenshot of the QR code is outside the wallet and not counted.

Response times: change page 16 ms, open a panel 16 ms, open a credential 39 ms, rebuild the window
45 ms (all under 0.1 s).

### Found and fixed in this round

| # | Sev. | Problem | Fix |
|---|---|---|---|
| 20 | 4 | **Tab left every open panel** for the page behind it (25 of 32 screens): with the keyboard or a screen reader the panels were not modal | Tab and Shift+Tab go round the panel's own controls; panels without a default button (scan, progress) also take the focus |
| 21 | 3 | Fields without an accessible name: every password panel, the collection code, the sign-in fields (they had a visible label, not associated) | Named after the panel's title or their label |
| 22 | 3 | Checkboxes and options almost invisible in dark mode (dark box on dark panel, under 3:1), e.g. "I understand the risk…" | Drawn boxes with a 3:1 edge on every background, accent fill when checked |
| 23 | 2 | Panel buttons did not fit in French, German, Spanish and Luxembourgish (scan panel, "Did it not open?") | A row of buttons that does not fit is stacked, the main action on top |
| 24 | 2 | 11 px text (section captions of Settings, the "Expired" tag) | 12 px |
| 25 | 2 | Two sentences of 27–32 words (empty wallet, "Protect your wallet") | Split |
| 26 | 1 | The search field and its icon had no name | "Search credentials" |
| 27 | 1 | The 3:1 field edge of round 1 made the search field and the drop-downs look heavy | They are recognised by their icon and arrow (WCAG 1.4.11 asks 3:1 of what *identifies* a control), so they keep the subtle edge at rest and the accent on hover and focus. Text fields in panels and checkboxes keep 3:1, and the audit measures every field's painted edge: the subtle one is only allowed with a leading icon or an arrow |
| 28 | 1 | The icon of a button almost touched its text (Qt's fixed 4 px), unlike the sidebar and the search field | About 10 px on every button with an icon (`theme.BUTTON_ICON_GAP`) |

The audit found two problems of its own while being built, both fixed: the dark theme was never
applied (every "dark" result was the light theme), and padded labels were measured against their
inner width. A self-test now plants faint text, an unnamed field, tiny targets and a squeezed button
in a panel, and fails if the audit misses any of them.

### Heuristic evaluation (Nielsen) and cognitive walkthrough

What remains, by heuristic (severity 0–4; the measured items above are not repeated):

| Heuristic | Finding | Sev. |
|---|---|---|
| 1 Visibility of system status | Good: progress, waiting for a QR code, results with what happened. After sharing, the browser comes back by itself, but the "Data shared" panel still waits for *Done* | 1 |
| 2 Match with the real world | "Profile" appears 30 times, "key" 9, "certificate" 7 (mostly Settings). Profiles are an advanced idea: consider hiding them until a second one is created | 2 |
| 4 Consistency | Every task ends with *Done*. For "Sign in" it could close by itself (decisions 3 → 2, ~2.7 s less) | 1 |
| 6 Recognition rather than recall | The screenshot shortcut is shown in the panel (good); whether people manage it is for the user test | 3 (pending 2) |
| 8 Minimalist design | Settings has 7 sections; Trust and Advanced are for technicians (pending 5) | 2 |
| 10 Help and documentation | **There is no help in the app**: no link to a guide or to support from Settings or from the error panels | 2 |

Cognitive walkthrough ("will the person know what to do, and understand what happened?"):

- *Receive a credential*: the guide and the empty wallet say where to start; the offer names the
  organisation and warns on the first time; the collection code says where it comes from; the
  result shows the card and the account. Weak point: the screenshot step (pending 2).
- *Sign in to a service*: the person is on a website, not in the wallet: they must open the wallet
  and press *Scan QR* — or, with the links registered (offered in the guide), press the page's
  button. The consent shows who, what and where, with a safe default (*Decline* has the focus).
  Weak point: the wallet must be open, or the links registered.

### Automation

- `tests/ux_audit.py`: renders every screen and panel with sample data and measures it; also a report
  generator: `python tests/ux_audit.py OUTDIR [--langs …] [--themes …]` writes the screenshots of
  each language and theme and `report.md` with every table above.
- `tests/test_ux.py`: the budgets (0 findings; LIX ≤ 42; readability ≥ 60 en/fr, ≥ 70 es, ≥ 55 de;
  sentences ≤ 25 words; no jargon; ≤ 3 decisions per task; response times) — in every push, for
  English (light, with the keyboard checks) and German (dark).
- `.github/workflows/ux.yml`: every night, the six languages in both themes, and the report with
  the screenshots as an artifact (also when a budget fails).

What it cannot measure: whether people understand the screens and finish the tasks without help.
That is still the usability test with 5–8 people of the pilot profile (with SUS at the end).

## An outside opinion (three screenshots)

A review by another AI assistant of three screenshots (wallet, settings, credential detail, taken
from real CITCOM-VRAIN credentials), checked point by point against the measurements and the code:

| Point | Verdict | What was done |
|---|---|---|
| Validity must be obvious ("are they valid, and until when?") | **Right** | The validity under the card, coloured: "Valid until…", "Expires in 12 days (…)", "Expired on…", "Not valid until…"; an EXPIRES SOON tag on the card 30 days before |
| "Revoked" as a state | **Right, and a real gap** | The wallet does not check revocation (no Token Status List): "Valid" means "not expired". In `todo.md` (item 12) |
| Technical data shown like the rest (`Jti`, `Roles 1 › Target`) | **Right** (our sample data had none of it) | Identifiers (`jti`, `sub`, a role's `target`…) under "Show technical details"; one-item lists without an index; FIWARE roles as "Roles: a, b". The audit now uses a credential like the real ones |
| The name repeated under the card | Right | Replaced by the validity |
| Wallet links: no status | Right | "Registered", "Another application opens them now", "Not registered yet" (`desktop.links_owner`), and "Register again" |
| Buttons of different widths in Settings | Partly | The actions of Settings line up in one column (same minimum width) |
| Secondary text small and with low contrast | Half: the contrast is 5.8:1 (AA asks 4.5), the size was 12 px | Captions 13 px; the audit checks the layout still fits in six languages |
| Check smaller windows | Right | The audit also runs the smallest window (920×640) in French |
| Confirmation before removing a profile | Already there | Danger panel with what is lost; *Cancel* has the focus |
| Keyboard, screen readers, hover/focus/disabled states, success and error notices | Already there (round 2) | — |
| Labels "Issuer:", "Type:", "Holder:" on every card | **Not adopted** | A card is read like a physical one; the labels would clutter it. The detail page and the screen reader name say what each line is |
| Scores (8/10…), more space use, reference images | Not actionable | — |

Its closing questions are a good test of the wallet page and the credential page: *which
credentials do I have, who issued them, are they valid and until when, what can I do with them*.

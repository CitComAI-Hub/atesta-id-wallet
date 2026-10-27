# Manual test on real Windows

CI installs, starts and uninstalls the Windows build on every release
(see [RELEASING.md](RELEASING.md)), but it has no user session, browser, clipboard or screenshots.
This checklist covers what only a person on a real machine can check. Run it on Windows 11 and,
if the pilot needs it, Windows 10, with a normal (non-admin) account.

Note the Windows version, the build tested (file name and SHA-256) and, for each failure, what
you did, what you expected and what happened (with *Settings → Advanced → Protocol details*
enabled and the log copied).

## 1. Install

- [ ] Download the setup from the release; the SHA-256 (`Get-FileHash FILE`) matches `SHA256SUMS`.
- [ ] SmartScreen warns (unsigned build): *More info → Run anyway* works. Note the exact wording
      for the pilot instructions.
- [ ] The installer does not ask for administrator rights; its language follows Windows
      (English, Spanish or Danish).
- [ ] Installed in `%LOCALAPPDATA%\Programs\OID4VC Wallet`; Start menu entry *OID4VC Wallet* with the icon.
- [ ] The window opens from the Start menu, with the app icon in the taskbar and in Alt+Tab.
- [ ] The interface language follows Windows; changing it in *Settings → General* works.

## 2. Links from the browser

Use the CITCOM marketplace login and a Keycloak credential offer, in Edge **and** Chrome (and
Firefox if pilot users have it).

- [ ] Clicking an `openid-credential-offer://` link asks the browser for permission and opens the wallet.
- [ ] Clicking an `openid4vp://` link opens the wallet with the consent screen.
- [ ] With the wallet already open, a second link goes to the same window (no second window).
- [ ] After the presentation, the browser continues the login (redirect).

## 3. QR codes

- [ ] *Scan QR* + Win+Shift+S over the QR on the screen: the wallet picks it from the clipboard.
- [ ] *Scan QR* + Print Screen (or Win+PrtScn, saved to `Pictures\Screenshots`): picked up.
- [ ] Same with OneDrive folder backup turned on (`OneDrive\Pictures\Screenshots`).
- [ ] *Open image…* with a saved PNG/JPG of the QR.
- [ ] *Paste link* with the link copied as text.

## 4. Full flows

- [ ] Receive a credential (Keycloak login inside the wallet); it shows in *Wallet* with the issuer colours.
- [ ] Sign in to the marketplace with it; the consent screen shows the verifier and the data.
- [ ] *Activity* shows both events.
- [ ] Backup to a USB stick or another folder; *Restore* it into a new, empty profile.
- [ ] Profiles: create, switch, remove.

## 5. Data and permissions

- [ ] Data is in `%APPDATA%\oid4vc-wallet` (`holder_key.pem`, `credentials\`, `config.json`, `settings.json`).
- [ ] Another (non-admin) Windows user on the same PC cannot open that folder
      (*Properties → Security* only lists the user, SYSTEM and Administrators).
- [ ] Antivirus (Defender) does not quarantine or block the executables; note any warning.

## 6. Command line

From PowerShell, in the install folder (`cd "$env:LOCALAPPDATA\Programs\OID4VC Wallet"`):

- [ ] `.\oid4vc-wallet.exe --version`, `.\oid4vc-wallet.exe list` and `.\oid4vc-wallet.exe history`
      print correctly, including `✔` and accented characters.
- [ ] `.\oid4vc-wallet.exe update` reports the latest version (or that none is published).

## 7. Update and uninstall

- [ ] Install a newer build over the old one with the wallet closed: credentials and settings are kept.
- [ ] Same with the wallet open: the installer asks to close it.
- [ ] *Settings → About → New versions → Check now* reports the right result.
- [ ] Uninstall from *Settings → Apps*: the program, Start menu entry and links are gone
      (a link click no longer opens the wallet), and `%APPDATA%\oid4vc-wallet` is still there.

## 8. Portable zip

- [ ] Unzip, run `oid4vc-wallet-gui.exe`, *Settings → General → Wallet links → Register*:
      links open this copy.

## Decision: macOS

Record here whether the pilot needs macOS. If it does, it needs a `.app` bundle built on macOS,
an Apple Developer ID for signing and notarisation, and a link handler in `Info.plist`.

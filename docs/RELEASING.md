# Building and releasing

Releases are built by GitHub Actions (`.github/workflows/release.yml`), never on a developer's
machine, so every published file comes from a known commit.

## What a release contains

| File | Built with | Notes |
|---|---|---|
| `Atesta_ID_Wallet-X.Y.Z-windows-x64-setup.exe` | PyInstaller + Inno Setup (`packaging/atesta-id-wallet.iss`) | Per-user install in `%LOCALAPPDATA%\Programs\Atesta ID Wallet`, Start menu entry, link handler in HKCU; removed again by the uninstaller. No admin rights. |
| `Atesta_ID_Wallet-X.Y.Z-windows-x64.zip` | PyInstaller | Portable folder, for testing without installing. |
| `atesta-id-wallet_X.Y.Z_amd64.deb` | PyInstaller + `dpkg-deb` (`packaging/build_linux.sh`) | `/opt/atesta-id-wallet`, commands in `/usr/bin`, menu entry and link handler for every user. |
| `Atesta_ID_Wallet-X.Y.Z-x86_64.AppImage` | PyInstaller + appimagetool 13 (`packaging/build_linux.sh`) | `AppRun` opens the GUI; `… .AppImage cli ARGS` runs the command line. |
| `SHA256SUMS` | `sha256sum` | Checksums of all the files above. |

All of them hold the same PyInstaller folder (`packaging/atesta-id-wallet.spec`): two executables,
`atesta-id-wallet-gui` (no console on Windows) and `atesta-id-wallet`, sharing one copy of Python, Qt
and the other libraries. Linux builds run on Ubuntu 22.04, so they need glibc 2.35 or newer.

## Steps

1. Update the version in `pyproject.toml` **and** `atesta_id_wallet/common.py` (`__version__`);
   the workflow fails if they differ from each other or from the tag.
2. Update `todo.md` and the README status line; commit and push to `main`.
3. Every push to `main` already builds and tests everything without publishing (the files are
   kept as workflow artifacts); check that the last run on `main` is green. Test failures show
   up as annotations on the run page, readable without signing in (the logs are not).
4. Tag and push:

   ```bash
   git tag v0.6.0 && git push origin v0.6.0
   ```

5. The workflow then:
   - runs the tests on Linux and Windows;
   - builds the Linux and Windows files and runs `atesta-id-wallet-gui --smoke-test` on the bundle, the
     AppImage, the installed `.deb` and the installed Windows program (checks that Qt, the SVG
     icons, the translations, zxing-cpp, Pillow and cryptography are all inside);
   - installs and uninstalls the Windows setup silently and checks the link handler registry keys;
   - publishes the GitHub release with the files, `SHA256SUMS`, generated release notes and (on a
     public repository) a build provenance attestation.
6. Edit the release notes if needed. Apps with *New versions* enabled will show the new version
   within a day.

## Building locally

For trying the packaging, not for releases:

```bash
python3 -m venv /tmp/build-venv && /tmp/build-venv/bin/pip install ".[gui]" pyinstaller==6.22.3
/tmp/build-venv/bin/pyinstaller --noconfirm packaging/atesta-id-wallet.spec      # -> dist/atesta-id-wallet/
QT_QPA_PLATFORM=offscreen dist/atesta-id-wallet/atesta-id-wallet-gui --smoke-test && echo OK
FORMATS=deb packaging/build_linux.sh                                          # -> dist/*.deb
packaging/build_linux.sh                                                      # also the AppImage (downloads appimagetool)
```

On Windows, after PyInstaller: `iscc /DAppVersion=0.6.0 packaging\atesta-id-wallet.iss` (Inno Setup 6).

The app icon is generated from `packaging/app-icon.svg` with `python packaging/make_icons.py`
(writes `atesta_id_wallet/gui/icons/app-icon.png` and `packaging/atesta-id-wallet.ico`, both kept in git).
It is a placeholder until the product has a name.

## Pending

- **Windows code signing.** Without an Authenticode certificate, SmartScreen warns on the
  installer. Once there is one, add a signing step to the `windows` job before the upload
  (`signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 …` on both `.exe`
  files of the bundle and on the setup), with the certificate in a repository secret.
- **Public downloads.** Pilot users can only download releases (and the app can only check for
  new versions) if the repository is public; with a private repository GitHub answers 404.
- macOS (`.app` bundle, notarisation) is not built.

# Building and releasing

Releases are built by GitHub Actions (`.github/workflows/release.yml`), never on a developer's
machine, so every published file comes from a known commit.

Every push to any branch and every pull request run `.github/workflows/checks.yml`: the tests on
Linux and Windows, `ruff` (bug-class rules only, `[tool.ruff]` in `pyproject.toml`), `bandit`
(medium and high) and `pip-audit` (known vulnerabilities in the dependencies). `release.yml` calls
the same workflow first, so nothing is built or published if a check fails. Dependabot proposes
dependency and action updates every week (`.github/dependabot.yml`).

What goes into a release is pinned, because the result is signed for the automatic updates:

- **Python packages**: the builds install `packaging/requirements-release.txt` (the wallet's
  dependencies with the GUI, and PyInstaller) with `pip install --require-hashes`, and the jobs that
  sign or check signatures install `packaging/requirements-sign.txt` (only `cryptography`) the same
  way. A new upload to PyPI never reaches a release by itself. `checks.yml` runs `pip-audit` on both
  files. To update them (after changing `pyproject.toml`, or when `pip-audit` reports a
  vulnerability), with [uv](https://docs.astral.sh/uv/):

  ```bash
  uv pip compile pyproject.toml --extra gui packaging/requirements-release.in --universal \
    --python-version 3.12 --generate-hashes -o packaging/requirements-release.txt
  uv pip compile packaging/requirements-sign.in --universal --python-version 3.12 --generate-hashes \
    -o packaging/requirements-sign.txt
  ```

  The tests in `checks.yml` still install the newest versions allowed by `pyproject.toml`, so a
  breaking upstream change shows up there before the release files are updated.
- **GitHub actions**: by commit SHA, with the tag in a comment (`@<sha>  # v7`). A tag can be moved
  by whoever controls the action's repository; a commit cannot. Dependabot updates both.

## What a release contains

| File | Built with | Notes |
|---|---|---|
| `Atesta_ID_Wallet-X.Y.Z-windows-x64-setup.exe` | PyInstaller + Inno Setup (`packaging/atesta-id-wallet.iss`) | Per-user install in `%LOCALAPPDATA%\Programs\Atesta ID Wallet`, Start menu entry, link handler in HKCU; removed again by the uninstaller. No admin rights. |
| `Atesta_ID_Wallet-X.Y.Z-windows-x64.zip` | PyInstaller | Portable folder, for testing without installing. |
| `atesta-id-wallet_X.Y.Z_amd64.deb` | PyInstaller + `dpkg-deb` (`packaging/build_linux.sh`) | `/opt/atesta-id-wallet`, commands in `/usr/bin`, menu entry and link handler for every user. |
| `Atesta_ID_Wallet-X.Y.Z-x86_64.AppImage` | PyInstaller + appimagetool 1.9.1 (`packaging/build_linux.sh`, checksum pinned) | `AppRun` opens the GUI; `… .AppImage cli ARGS` runs the command line. |
| `Atesta_ID_Wallet-X.Y.Z-linux.cdx.json`, `…-windows-x64.cdx.json` | cyclonedx-bom (pinned in `release.yml`) | SBOM (CycloneDX JSON): the Python packages, with versions, of the environment each build was made from. |
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
   - installs the Windows setup silently, checks the link handler registry keys, runs an automatic
     update the way the wallet does it (installer waiting in `updates\`, the wallet starts it and
     exits, the installer reopens it) and uninstalls;
   - publishes a GitHub **pre-release** with the files, `SHA256SUMS`, `SHA256SUMS.sig` (see below),
     generated release notes and (on a public repository) a build provenance attestation.
6. **Test the pre-release.** Nobody gets it yet: installed wallets only look at the latest
   release, which leaves pre-releases out, and APT is not updated. Install it by hand (Windows,
   AppImage, `.deb`) and edit the release notes if needed.
7. **Deliver it**: edit the release on GitHub, untick *Set as a pre-release* and tick *Set as the
   latest release*. That starts `.github/workflows/apt.yml` (APT repository on GitHub Pages,
   `https://citcomai-hub.github.io/atesta-id-wallet/apt/`). Within a day, AppImage and Windows
   installations download it by themselves (installed when the wallet restarts), `.deb`
   installations get it with the system updates, and the rest show a notice.

If a delivered version turns out broken, there is no way back for installations that already
updated: release a fixed version as soon as possible. Until then, marking the previous release as
the latest again stops the remaining installations from taking the broken one.

## Automatic updates: keys and one-time setup

Two keys, both kept outside git (the maintainer's copy is in `~/.config/atesta-id-wallet-release/`;
keep a backup somewhere safe and offline):

| Secret (Settings → Secrets and variables → Actions) | What | Public part, in git |
|---|---|---|
| `UPDATE_SIGNING_KEY` | Ed25519 seed, base64 (`update-signing.key`). `packaging/sign_release.py` signs `SHA256SUMS` with it. | `UPDATE_PUBLIC_KEY` in `atesta_id_wallet/updates.py` |
| `APT_SIGNING_KEY` | Armored secret OpenPGP key (`apt-signing-key.asc`). `packaging/build_apt_repo.sh` signs the APT repository with it. | `packaging/apt-archive-keyring.gpg`, shipped in the `.deb` |

The installed applications only install a file listed in a `SHA256SUMS` signed by
`UPDATE_SIGNING_KEY`, and APT only accepts the repository signed by `APT_SIGNING_KEY`: files uploaded to a
release by hand or changed after the build are never installed. `apt.yml` checks `SHA256SUMS.sig`
(`packaging/verify_release.py`) before it signs the `.deb` into the APT repository, so the same
holds for `.deb` installations. The `publish` and `apt` jobs fail if a secret is missing or does
not match the public key in git.

**Required reviewer (once).** The `publish` job runs in the environment `release`. Without
protection, anyone who can push a `v*` tag gets a build signed. In *Settings → Environments*:

1. Create `release` (the first tagged run creates it, unprotected, if it does not exist), tick
   **Required reviewers** and add the maintainers; under *Deployment branches and tags* allow only
   tags `v*`.
2. Move `UPDATE_SIGNING_KEY` from the repository secrets to the secrets of `release`.
3. In `github-pages` (used by `apt.yml`), add `APT_SIGNING_KEY` as an environment secret, tick
   **Required reviewers** too, and delete both secrets from the repository secrets.

From then on a tag builds and tests everything, and waits on the run page for a reviewer to approve
the signing and the publication.

Also once: *Settings → Pages → Source: GitHub Actions*, and in *Settings → Environments →
github-pages*, add a rule of type **Tag** `v*` to the allowed deployment branches and tags (by
default only `main` may deploy; keep it too).

The APT repository is built by `.github/workflows/apt.yml` from the `.deb` of the release that has
just become the latest one. If that fails, fix it and use *Actions → APT repository → Run
workflow* (empty tag: the latest release).

**Changing a key** (lost or leaked): the installed applications keep trusting the old public key,
so they stop updating by themselves. Put the new public key in git and release; users of that
release onwards follow the new key, the others have to download it by hand once. For APT, users
re-install the new `.deb` by hand. If a key leaks, change it at once and say so in the release notes.

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

The app icon is generated from `atesta_id_wallet/gui/icons/app-icon.svg` with `python packaging/make_icons.py`
(writes `atesta_id_wallet/gui/icons/app-icon.png` and `packaging/atesta-id-wallet.ico`, both kept in git).
It follows the [GNOME app icon guidelines](https://developer.gnome.org/hig/guidelines/app-icons.html)
(the 128 px template, 2 px grid, flat colours, 4 px front profile) with Atesta's indigo instead of the GNOME
palette; preview it with [App Icon Preview](https://flathub.org/apps/org.gnome.design.AppIconPreview).
The symbolic version is `packaging/app-icon-symbolic.svg`.

## Pending

- **Windows code signing.** Without an Authenticode certificate, SmartScreen warns on the
  installer. Once there is one, add a signing step to the `windows` job before the upload
  (`signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 …` on both `.exe`
  files of the bundle and on the setup), with the certificate in a repository secret.
- **Public downloads.** Pilot users can only download releases (and the app can only check for
  new versions) if the repository is public; with a private repository GitHub answers 404.
- macOS (`.app` bundle, notarisation) is not built.

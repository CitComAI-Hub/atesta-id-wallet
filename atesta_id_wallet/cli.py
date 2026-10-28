# -*- coding: utf-8 -*-
"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import time
import traceback
import webbrowser
from pathlib import Path
from typing import Any

import requests

from . import common, i18n, storage, updates
from .common import Cancelled, WalletError, __version__, confirm, log
from .desktop import (
    FROZEN,
    cmd_install_handler,
    cmd_uninstall_handler,
    decode_qr_image,
    detect_input,
    gui_available,
    route_input,
)
from .i18n import N_, tr, tr_n
from .storage import (
    DEFAULT_PROFILE,
    HolderKey,
    _wipe_profile,
    add_trusted_ca,
    create_profile,
    credential_label,
    delete_credential,
    harden_permissions,
    list_profiles,
    load_config,
    load_credentials,
    load_history,
    load_settings,
    migrate_legacy_data,
    profile_dir,
    profile_is_empty,
    read_ca_file,
    remove_profile,
    restore_backup,
    save_config,
    save_settings,
    set_profile,
    write_backup,
)
from .trust import load_trust_anchors
from .ui import TerminalPrompter
from .vci import IssueOptions, issue
from .vp import build_response, prepare_presentation, record_declined, send_presentation


SUBCOMMANDS = ("issue", "present", "list", "history", "remove", "reset", "backup", "restore", "profiles",
               "trust", "update", "language", "install-handler", "uninstall-handler")


def cmd_issue(args: argparse.Namespace) -> int:
    raw = args.offer or input(tr("Paste the OpenID4VCI offer (openid-credential-offer://...): "))
    options = IssueOptions(
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        client_id_pre=args.client_id_pre,
        tx_code=args.tx_code,
        username=args.username,
        authorization_details=args.authorization_details,
        force_auth_code=args.force_auth_code,
        browser_login=args.browser_login,
        open_browser=not args.no_browser,
    )
    for credential in issue(requests.Session(), raw, options, TerminalPrompter(args.yes)):
        if credential.claims is not None:
            print(json.dumps(credential.claims, indent=2, ensure_ascii=False))
        print("\n" + tr("✔ {credential} added to the wallet.", credential=credential.configuration_id))
    return 0


def cmd_present(args: argparse.Namespace) -> int:
    session = requests.Session()
    records = load_credentials()

    if args.qr_image:
        raw = decode_qr_image(args.qr_image)
    else:
        raw = args.request or input(tr("Paste the OpenID4VP request (openid4vp://...) or the path of a QR screenshot: "))
        candidate = raw.strip().strip("'\"")
        if candidate and not candidate.startswith(("openid4vp", "http")) and Path(candidate).expanduser().exists():
            raw = decode_qr_image(candidate)
    ui = TerminalPrompter(args.yes)
    prepared = prepare_presentation(
        session, raw, records, disclose_all=args.disclose_all, allow_unverified=args.allow_unverified,
        choose=ui.choose_credential,
    )
    if not args.dry_run and not ui.consent(prepared):
        record_declined(prepared)
        raise Cancelled(tr("Cancelled by the user: nothing was sent."))
    body = build_response(prepared, HolderKey.load_or_create(), vp_token_style=args.vp_token_style)
    if args.dry_run:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0

    redirect_uri = send_presentation(session, prepared, body)
    print("\n" + tr("✔ Presentation accepted by {verifier}. Go back to the browser: the login should complete "
                    "by itself.", verifier=prepared.identity.name))
    if redirect_uri:
        log(tr("The verifier indicates redirect_uri: {uri}", uri=redirect_uri))
        if not args.no_browser:
            webbrowser.open(redirect_uri)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    records = load_credentials()
    print(tr("Profile: {profile}  ({path})", profile=storage.PROFILE, path=storage.DATA_DIR))
    if not records:
        print(tr("No credentials stored."))
    for index, record in enumerate(records, 1):
        print(f"\n{index}. {credential_label(record)}")
        print(f"   id: {Path(record['_path']).stem}  [{record.get('format')}]  {record.get('issuer')}")
        if record.get("_sd") and args.details:
            print(json.dumps(record["_sd"].claims, indent=4, ensure_ascii=False))
    return 0


HISTORY_TEXT = {"issued": N_("Received"), "presented": N_("Shared"), "declined": N_("Declined")}


def cmd_history(_: argparse.Namespace) -> int:
    events = load_history()
    if not events:
        print(tr("There is no activity in this profile yet."))
    for event in events:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(event.get("time", 0)))
        kind = tr(HISTORY_TEXT.get(event.get("type"), event.get("type")))
        print(f"{when}  {kind:11} {event.get('party')}: {', '.join(event.get('credentials') or [])}")
        if event.get("claims"):
            print(f"{'':29}" + tr("data: {claims}", claims=", ".join(event["claims"])))
    return 0


def _resolve_credentials(selectors: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Número de 'list' o id (nombre del fichero, admite prefijo único)."""
    out = []
    for selector in selectors:
        if selector.isdigit() and 1 <= int(selector) <= len(records):
            out.append(records[int(selector) - 1])
            continue
        hits = [r for r in records if Path(r["_path"]).stem.startswith(selector)]
        if len(hits) != 1:
            raise WalletError(tr("'{selector}' does not identify a single credential (see 'atesta-id-wallet list').",
                                 selector=selector))
        out.append(hits[0])
    return out


def cmd_remove(args: argparse.Namespace) -> int:
    targets = _resolve_credentials(args.credentials, load_credentials())
    for record in targets:
        print(f"  - {credential_label(record)}")
    if not confirm(tr_n("Delete {n} credential?", "Delete {n} credentials?", len(targets)), assume_yes=args.yes):
        raise Cancelled()
    for record in targets:
        delete_credential(record)
    print(tr_n("✔ {n} credential deleted.", "✔ {n} credentials deleted.", len(targets)))
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    count = len(load_credentials())
    print(tr_n("The wallet key, {n} credential and the settings of the profile '{profile}' ({path}) will be "
               "deleted.", "The wallet key, {n} credentials and the settings of the profile '{profile}' ({path}) "
               "will be deleted.", count, profile=storage.PROFILE, path=storage.DATA_DIR))
    print(tr("Deleted credentials cannot be recovered without a backup ('atesta-id-wallet backup')."))
    if not args.yes:
        if not sys.stdin.isatty():
            raise WalletError(tr("reset needs interactive confirmation (or --yes)."))
        if input(tr("Type the profile name ({profile}) to confirm: ", profile=storage.PROFILE)).strip() != storage.PROFILE:
            raise Cancelled(tr("Cancelled: nothing was deleted."))
    _wipe_profile(storage.DATA_DIR)
    print(tr("✔ Profile '{profile}' emptied.", profile=storage.PROFILE))
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    if not storage.KEY_FILE.exists():
        raise WalletError(tr("The profile '{profile}' is empty; there is nothing to back up.", profile=storage.PROFILE))
    out = Path(args.file).expanduser()
    if out.exists() and not confirm(tr("{file} already exists. Overwrite?", file=out), assume_yes=args.yes):
        raise Cancelled()
    password = getpass.getpass(tr("Password to encrypt the backup: "))
    if getpass.getpass(tr("Repeat it: ")) != password:
        raise WalletError(tr("The passwords do not match."))
    write_backup(out, password)
    print(tr("✔ Encrypted backup of the profile '{profile}' in {file}. Keep it outside this computer.",
             profile=storage.PROFILE, file=out))
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    if not profile_is_empty():
        raise WalletError(tr(
            "The profile '{profile}' already has data. Restore into a new profile (atesta-id-wallet profiles add NAME; "
            "atesta-id-wallet --profile NAME restore ...) or empty it with reset.", profile=storage.PROFILE
        ))
    count = restore_backup(Path(args.file).expanduser(), getpass.getpass(tr("Backup password: ")))
    print(tr_n("✔ Restored into the profile '{profile}': {n} credential.",
               "✔ Restored into the profile '{profile}': {n} credentials.", count, profile=storage.PROFILE))
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    if args.action == "add":
        create_profile(args.name)
        print(tr("✔ Profile '{name}' created. Use it with: atesta-id-wallet --profile {name} ...", name=args.name))
        return 0
    if args.action == "remove":
        profile_dir(args.name)  # valida el nombre antes de preguntar
        if args.name != DEFAULT_PROFILE and not confirm(
            tr("Remove the profile '{name}' with its key and credentials?", name=args.name), assume_yes=args.yes
        ):
            raise Cancelled()
        remove_profile(args.name)
        print(tr("✔ Profile '{name}' removed.", name=args.name))
        return 0
    for name in list_profiles():
        creds = profile_dir(name) / "credentials"
        count = len(list(creds.glob("*.json"))) if creds.is_dir() else 0
        marker = "*" if name == storage.PROFILE else " "
        print(f"{marker} {name:20} " + tr_n("{n} credential", "{n} credentials", count))
    return 0


def cmd_trust(args: argparse.Namespace) -> int:
    if args.action == "add-ca":
        source = Path(args.target).expanduser()
        for cert in read_ca_file(source):
            print(f"  {cert.subject.rfc4514_string()}  " + tr("(expires {date})",
                                                              date=f"{cert.not_valid_after_utc:%Y-%m-%d}"))
        if not confirm(tr("Trust the verifiers signed by this CA?"), assume_yes=args.yes):
            raise Cancelled()
        print(tr("✔ CA added to {path}", path=add_trusted_ca(source)))
        return 0
    if args.action == "remove-ca":
        target = storage.TRUST_DIR / f"{Path(args.target).stem}.pem"
        if not target.exists():
            raise WalletError(tr("{file} does not exist in {path}.", file=target.name, path=storage.TRUST_DIR))
        target.unlink()
        print(tr("✔ {file} removed.", file=target.name))
        return 0
    if args.action == "forget":
        config = load_config()
        verifiers = config.get("verifiers", {})
        if args.target == "all":
            verifiers.clear()
        elif verifiers.pop(args.target, None) is None:
            raise WalletError(tr("No remembered verifier has the client_id '{client_id}'.", client_id=args.target))
        config["verifiers"] = verifiers
        save_config(config)
        print(tr("✔ Done."))
        return 0

    print(tr("Trusted CAs ({path}):", path=storage.TRUST_DIR))
    for cert in load_trust_anchors():
        print(f"  {cert.subject.rfc4514_string()}  " + tr("(expires {date})",
                                                          date=f"{cert.not_valid_after_utc:%Y-%m-%d}"))
    print("\n" + tr("Remembered verifiers (certificate pinned after the first use):"))
    for client_id, info in load_config().get("verifiers", {}).items():
        used = time.strftime("%Y-%m-%d", time.localtime(info.get("last_used", 0)))
        print(f"  {client_id}  " + tr("(last used {date})", date=used))
    return 0


def cmd_check_update() -> int:
    log(tr("Asking GitHub for the latest version…"))
    release = updates.newer_release()
    if release is None:
        print(tr("✔ This is the latest version ({version}).", version=__version__))
    else:
        print(tr("Version {version} is available (this is {current}). Download it from:\n  {url}",
                 version=release.version, current=__version__, url=release.url))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    if args.check or FROZEN:  # los paquetes (AppImage, .deb, instalador) se actualizan descargando el nuevo
        return cmd_check_update()
    marker = Path(sys.prefix) / "atesta-id-wallet-source"
    if not marker.exists():
        raise WalletError(tr("This installation was not made with install.sh. Update with 'git pull' and "
                             "'./install.sh', or with 'pipx upgrade atesta-id-wallet'."))
    source = Path(marker.read_text(encoding="utf-8").strip())
    if not (source / ".git").exists():
        raise WalletError(tr("{path} is not a git repository; it cannot be updated.", path=source))
    log(tr("Updating from {path}…", path=source))
    subprocess.run(["git", "-C", str(source), "pull", "--ff-only"], check=True)
    subprocess.run([str(source / "install.sh")] + ([] if gui_available() else ["--no-gui"]), check=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atesta-id-wallet",
        description=tr("Desktop OpenID4VCI/OpenID4VP wallet."),
        epilog=tr("Without a subcommand, 'atesta-id-wallet [LINK|IMAGE]' detects whether it is an offer or a login "
                  "request. Without arguments it uses the clipboard or the latest screenshot with a QR code."),
    )
    parser.add_argument("--verbose", action="store_true", help=tr("Show protocol details."))
    parser.add_argument("--profile", metavar=tr("NAME"),
                        help=tr("Profile (identity) to use; also $ATESTA_ID_WALLET_PROFILE. Default: default."))
    parser.add_argument("--pause", action="store_true",
                        help=tr("Wait for Enter at the end (when launched from the desktop)."))
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    issue = sub.add_parser("issue", help=tr("Accept an openid-credential-offer:// offer"))
    issue.add_argument("--offer", help=tr("Offer (URI or JSON). If missing, it is asked for."))
    issue.add_argument("--offer-file", help=tr("File with the offer."))
    issue.add_argument("--client-id",
                       help=tr("OAuth client_id for authorization_code (default: the last one that worked with "
                               "that issuer, or account-console)."))
    issue.add_argument("--redirect-uri",
                       help=tr("Registered redirect_uri (default: <realm>/account/oid4vci-callback)."))
    issue.add_argument("--client-id-pre", help=tr("Optional client_id for pre-authorized_code."))
    issue.add_argument("--tx-code", help=tr("tx_code/PIN for pre-authorized_code."))
    issue.add_argument("--authorization-details", action="store_true",
                       help=tr("Send authorization_details in addition to the scope."))
    issue.add_argument("--force-auth-code", action="store_true",
                       help=tr("Use authorization_code even if there is a pre-authorized_code."))
    issue.add_argument("--username", help=tr("Keycloak username (asked for if missing)."))
    issue.add_argument("--browser-login", action="store_true",
                       help=tr("Log in in the browser and paste the redirect URL by hand."))
    issue.add_argument("--no-browser", action="store_true", help=tr("Do not open the browser."))
    issue.add_argument("--yes", "-y", action="store_true", help=tr("Do not ask for confirmation."))
    issue.set_defaults(func=cmd_issue)

    present = sub.add_parser("present", help=tr("Answer an openid4vp:// request"))
    present.add_argument("--request", help=tr("OpenID4VP request. If missing, it is asked for."))
    present.add_argument("--request-file", help=tr("File with the request."))
    present.add_argument("--qr-image",
                         help=tr("Screenshot with the QR code (or a folder: the newest image is used)."))
    present.add_argument("--disclose-all", action="store_true",
                         help=tr("Disclose all disclosures, not only the requested ones."))
    present.add_argument("--vp-token-style", choices=("array", "string"), default="array",
                         help=tr("DCQL: vp_token {id: [vp]} (OpenID4VP 1.0) or {id: vp} (drafts)."))
    present.add_argument("--dry-run", action="store_true", help=tr("Show the response without sending it."))
    present.add_argument("--no-browser", action="store_true")
    present.add_argument("--yes", "-y", action="store_true",
                         help=tr("Send without asking for confirmation (only to verified verifiers)."))
    present.add_argument("--allow-unverified", action="store_true",
                         help=tr("Allow verifiers whose identity cannot be checked (unsigned requests)."))
    present.set_defaults(func=cmd_present)

    lst = sub.add_parser("list", help=tr("List stored credentials"))
    lst.add_argument("--details", "-d", action="store_true", help=tr("Show all the data of each credential."))
    lst.set_defaults(func=cmd_list)

    history = sub.add_parser("history", help=tr("What was received, shared or declined, and with whom"))
    history.set_defaults(func=cmd_history)

    remove = sub.add_parser("remove", help=tr("Delete credentials (number or id from 'list')"))
    remove.add_argument("credentials", nargs="+", metavar=tr("CREDENTIAL"))
    remove.add_argument("--yes", "-y", action="store_true")
    remove.set_defaults(func=cmd_remove)

    reset = sub.add_parser("reset", help=tr("Delete the key, credentials and settings of the profile"))
    reset.add_argument("--yes", "-y", action="store_true")
    reset.set_defaults(func=cmd_reset)

    backup = sub.add_parser("backup", help=tr("Encrypted backup of the profile (key included)"))
    backup.add_argument("file", metavar=tr("FILE"))
    backup.add_argument("--yes", "-y", action="store_true", help=tr("Overwrite without asking."))
    backup.set_defaults(func=cmd_backup)

    restore = sub.add_parser("restore", help=tr("Restore a backup into the profile (it must be empty)"))
    restore.add_argument("file", metavar=tr("FILE"))
    restore.set_defaults(func=cmd_restore)

    profiles = sub.add_parser("profiles", help=tr("List, create or remove profiles"))
    profiles.add_argument("action", nargs="?", choices=("list", "add", "remove"), default="list")
    profiles.add_argument("name", nargs="?", metavar=tr("NAME"))
    profiles.add_argument("--yes", "-y", action="store_true")
    profiles.set_defaults(func=cmd_profiles)

    trust = sub.add_parser("trust", help=tr("Trusted CAs and remembered verifiers"))
    trust.add_argument("action", nargs="?", choices=("list", "add-ca", "remove-ca", "forget"), default="list")
    trust.add_argument("target", nargs="?", metavar=tr("FILE|NAME|CLIENT_ID"))
    trust.add_argument("--yes", "-y", action="store_true")
    trust.set_defaults(func=cmd_trust)

    update = sub.add_parser("update", help=tr("Update from the git repository (installation with install.sh), or "
                                              "check for a new version (packaged application)"))
    update.add_argument("--check", action="store_true",
                        help=tr("Only check whether a newer version has been published (asks GitHub)."))
    update.set_defaults(func=cmd_update)

    language = sub.add_parser("language", help=tr("Show or change the language (auto, en, es, da)"))
    language.add_argument("code", nargs="?", choices=(i18n.AUTO, *i18n.LANGUAGES))
    language.set_defaults(func=cmd_language)

    handler = sub.add_parser("install-handler",
                             help=tr("Register the wallet for openid4vp:// and openid-credential-offer:// links"))
    handler.add_argument("--terminal", action="store_true",
                         help=tr("Open the links in the terminal even if the graphical interface is installed."))
    handler.set_defaults(func=cmd_install_handler)
    unhandler = sub.add_parser("uninstall-handler", help=tr("Remove the link registration"))
    unhandler.set_defaults(func=cmd_uninstall_handler)
    return parser


def _pop_profile(argv: list[str]) -> str | None:
    """Extrae --profile X / --profile=X de cualquier posición."""
    for index, arg in enumerate(argv):
        if arg == "--profile":
            if index + 1 >= len(argv):
                raise WalletError(tr("--profile needs a name."))
            value = argv[index + 1]
            del argv[index:index + 2]
            return value
        if arg.startswith("--profile="):
            del argv[index]
            return arg.split("=", 1)[1]
    return None


def _select_profile(requested: str | None, command: str) -> None:
    name = requested or os.environ.get("ATESTA_ID_WALLET_PROFILE")
    profiles = list_profiles()
    if name is None and command in ("issue", "present") and len(profiles) > 1 and sys.stdin.isatty():
        print(tr("Profiles: {list}", list=", ".join(f"{i}. {p}" for i, p in enumerate(profiles, 1))))
        answer = input(tr("Which profile? [Enter = default] ")).strip()
        if answer.isdigit() and 1 <= int(answer) <= len(profiles):
            name = profiles[int(answer) - 1]
        elif answer:
            name = answer
    name = name or DEFAULT_PROFILE
    if name not in profiles and command != "profiles":
        raise WalletError(tr("The profile '{name}' does not exist. Create it with: atesta-id-wallet profiles add {name}",
                             name=name))
    set_profile(name)
    if name != DEFAULT_PROFILE:
        log(tr("Profile: {name}", name=name))


def _run(argv: list[str]) -> int:
    parser = build_parser()
    requested_profile = _pop_profile(argv)
    global_flags = [a for a in argv if a in ("--verbose", "--pause", "--version", "-h", "--help")]
    positionals = [a for a in argv if not a.startswith("-")]
    if not positionals or positionals[0] not in SUBCOMMANDS:
        if any(a in ("--version", "-h", "--help") for a in global_flags):
            parser.parse_args(global_flags)
        # Modo automático: oferta -> issue, petición -> present.
        rest = [a for a in argv if a not in global_flags]
        entry = positionals[0] if positionals else None
        if entry is not None:
            rest.remove(entry)
        common.VERBOSE = "--verbose" in global_flags
        command, extra = route_input(entry if entry is not None else detect_input())
        argv = global_flags + [command] + extra + rest

    args = parser.parse_args(argv)
    common.VERBOSE = args.verbose
    if args.command == "profiles" and args.action in ("add", "remove") and not args.name:
        parser.error(tr("profiles {action} needs a NAME", action=args.action))
    if args.command == "trust" and args.action != "list" and not args.target:
        parser.error(tr("trust {action} needs an argument", action=args.action))
    _select_profile(requested_profile, args.command)
    for attr, file_attr in (("offer", "offer_file"), ("request", "request_file")):
        if getattr(args, file_attr, None):
            setattr(args, attr, Path(getattr(args, file_attr)).read_text(encoding="utf-8"))
    return args.func(args)


def cmd_language(args: argparse.Namespace) -> int:
    settings = load_settings()
    if args.code:
        settings["language"] = args.code
        save_settings(settings)
        i18n.set_language(i18n.resolve(args.code))
    preference = settings.get("language", i18n.AUTO)
    active = i18n.LANGUAGES[i18n.current()]
    print(tr("Language: {language} (setting: {preference})", language=active, preference=preference))
    return 0


def _tolerant_output() -> None:
    """Una consola o tubería que no es UTF-8 (cp1252 en Windows) no debe romper con '✔' o '·'."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except ValueError:
                pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    _tolerant_output()
    i18n.set_language(i18n.resolve(load_settings().get("language")))
    try:
        migrate_legacy_data()
        harden_permissions()
        code = _run(argv)
    except WalletError as exc:
        print("\n" + tr("ERROR: {error}", error=exc), file=sys.stderr)
        code = 1
    except requests.RequestException as exc:
        print("\n" + tr("NETWORK ERROR: {error}", error=exc), file=sys.stderr)
        code = 1
    except KeyboardInterrupt:
        print("\n" + tr("Cancelled."), file=sys.stderr)
        return 130
    except Exception as exc:  # respuesta inesperada de un servidor, fichero dañado...
        if common.VERBOSE:
            traceback.print_exc()
        print("\n" + tr("UNEXPECTED ERROR: {error} (repeat with --verbose for details)",
                         error=f"{type(exc).__name__}: {exc}"), file=sys.stderr)
        code = 1
    if "--pause" in argv:
        try:
            input("\n" + tr("Press Enter to close..."))
        except (EOFError, KeyboardInterrupt):
            pass
    return code

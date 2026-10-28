# -*- coding: utf-8 -*-
"""
Desktop wallet for OpenID4VCI 1.0 + OpenID4VP 1.0 (SD-JWT VC), without a smartphone.

Built for:
  * a Keycloak issuer (protocol/oid4vc) with authorization_code offers
    (issuer_state) or pre-authorized_code offers, format dc+sd-jwt;
  * OpenID4VP verifiers with request_uri (signed JWT, x509_san_dns / x509_hash),
    DCQL or Presentation Exchange, response_mode direct_post(.jwt).

Usage:
    atesta-id-wallet-gui [LINK|IMAGE]  # graphical interface (menu entry and link handler)
    atesta-id-wallet [LINK|IMAGE]      # terminal: detects an offer (issue) or a request (present);
                                    # no arguments: clipboard or latest screenshot with a QR code
    atesta-id-wallet issue   [--offer 'openid-credential-offer://...']
    atesta-id-wallet present [--request 'openid4vp://...' | --qr-image SCREENSHOT]
    atesta-id-wallet list | history | remove N | reset | backup F | restore F
    atesta-id-wallet profiles [add|remove NAME]   # separate identities (--profile NAME)
    atesta-id-wallet trust [add-ca PEM|remove-ca|forget CLIENT_ID]
    atesta-id-wallet language [auto|en|es|da]
    atesta-id-wallet update            # git pull + reinstall (installations made with install.sh)
    atesta-id-wallet install-handler   # open openid4vp:// and openid-credential-offer:// links

Local data (holder key, credentials, config.json; files 0600) lives in $ATESTA_ID_WALLET_HOME or
the platform data folder (~/.local/share/atesta-id-wallet on Linux); other profiles in profiles/NAME/.

Nothing is presented without showing who asks for which data and where it goes, and asking
for confirmation. See docs/SECURITY.md for the trust model.

Package layout: protocol modules (vci, vp) never talk to the user; they receive a
ui.Prompter, implemented by the terminal (ui.TerminalPrompter) and the GUI (gui.app).
"""

from .common import __version__

__all__ = ["__version__"]

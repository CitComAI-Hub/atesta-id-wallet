# -*- coding: utf-8 -*-
"""Verifier identity and trust (x509_san_dns, x509_hash, TOFU, CAs)."""

from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography import x509

from . import storage
from .common import WalletError, debug, host_of, jwt_decode_unverified, log, require_https
from .i18n import tr
from .jose import _dns_names, _verify_jws_with_cert, _x5c_chain, cert_fingerprint
from .storage import load_config, save_config


CLIENT_ID_PREFIXES = ("x509_san_dns", "x509_hash", "redirect_uri", "decentralized_identifier",
                      "verifier_attestation", "openid_federation", "origin")


@dataclass
class VerifierIdentity:
    client_id: str
    prefix: str  # x509_san_dns, x509_hash, redirect_uri, ... or "" (pre-registered)
    value: str  # client_id without prefix
    name: str  # what is shown to the user
    cert: x509.Certificate | None = None
    # trusted: chain up to a trusted CA · pinned: same certificate as last time
    # new: signed and consistent but never seen · changed: different from the remembered certificate
    # unverified: could not be authenticated
    trust: str = "unverified"


def load_trust_anchors() -> list[x509.Certificate]:
    anchors: list[x509.Certificate] = []
    for path, pem in storage.trusted_ca_files():
        try:
            anchors += x509.load_pem_x509_certificates(pem)
        except ValueError as exc:
            log(tr("Warning: {file} is not a valid PEM certificate: {error}", file=path.name, error=exc))
    return anchors


def chain_is_trusted(chain: list[x509.Certificate], dns_name: str | None) -> bool:
    anchors = load_trust_anchors()
    if not anchors or not chain:
        return False
    from cryptography.x509 import verification as xv

    # Verifier certificates do not always have the serverAuth EKU: it is not required.
    ee_policy = xv.ExtensionPolicy.permit_all()
    if dns_name:
        ee_policy = ee_policy.require_present(x509.SubjectAlternativeName, xv.Criticality.AGNOSTIC, None)
    builder = (
        xv.PolicyBuilder()
        .store(xv.Store(anchors))
        .extension_policies(ca_policy=xv.ExtensionPolicy.webpki_defaults_ca(), ee_policy=ee_policy)
    )
    verifier = builder.build_server_verifier(xv.DNSName(dns_name)) if dns_name else builder.build_client_verifier()
    try:
        verifier.verify(chain[0], chain[1:])
    except xv.VerificationError as exc:
        debug(f"Invalid chain: {exc}")
        return False
    return True


def split_client_id(client_id: str) -> tuple[str, str]:
    prefix, sep, value = client_id.partition(":")
    if sep and prefix in CLIENT_ID_PREFIXES:
        return prefix, value
    return "", client_id


def check_request_object(token: str, client_id: str) -> VerifierIdentity:
    """Authenticates the verifier from the signed request object (x509_san_dns / x509_hash)."""
    header, payload = jwt_decode_unverified(token)
    prefix, value = split_client_id(client_id)
    identity = VerifierIdentity(client_id, prefix, value, value)
    if isinstance(payload.get("exp"), (int, float)) and payload["exp"] < time.time():
        raise WalletError(tr("The verifier's request has expired; reload the QR code."),
                          hint=tr("The request has expired. Reload the page with the QR code and scan it again."))
    # The client_id the identity is checked against must be the signed one, not only the QR code's
    # (OpenID4VP 1.0 §5: the request object carries it).
    if header.get("x5c") and payload.get("client_id") != client_id:
        raise WalletError(tr("The client_id of the QR code and of the request object do not match."))
    chain = _x5c_chain(header)
    if not chain:
        log(tr("Warning: the request object has no x5c; the verifier cannot be verified."))
        return identity
    cert = chain[0]
    if not _verify_jws_with_cert(token, cert):
        raise WalletError(tr("The request object's signature is NOT valid with its x5c certificate."))
    debug("Valid request object signature (verifier x5c certificate).")

    if prefix == "x509_san_dns":
        dns_names = _dns_names(cert)
        if value.lower() not in dns_names:
            raise WalletError(tr("The certificate's DNS SAN {names} does not match {value}.", names=dns_names, value=value))
        trusted = chain_is_trusted(chain, value)
    elif prefix == "x509_hash":
        if cert_fingerprint(cert) != value:
            raise WalletError(tr("The x5c certificate hash does not match the x509_hash client_id."))
        # Named after where the data goes (check_response_uri), never after what the certificate says.
        trusted = chain_is_trusted(chain, None)
    else:
        # Other signed schemes (DID, attestation, federation) are not supported yet.
        return identity

    identity.cert = cert
    if trusted:
        identity.trust = "trusted"
    else:
        pinned = load_config().get("verifiers", {}).get(client_id, {}).get("cert_sha256")
        fingerprint = cert_fingerprint(cert)
        identity.trust = "new" if pinned is None else ("pinned" if pinned == fingerprint else "changed")
    return identity


def check_response_uri(identity: VerifierIdentity, response_uri: str) -> None:
    """
    Stops a request signed by A from sending the data to B. The rules of OpenID4VP 1.0 §5.9.3, and
    stricter: also for verifiers a trusted CA vouches for (any CA the user adds would otherwise vouch
    for any destination), and for x509_hash, whose certificate nobody needs to vouch for, so the name
    shown is where the data goes, not a name the certificate claims.
    """
    require_https(response_uri, "response_uri")
    target = host_of(response_uri)

    def refuse(signer: str) -> WalletError:
        return WalletError(tr("The request is signed by {signer} but asks to send the data to {target}. Aborting.",
                              signer=signer, target=target),
                           hint=tr("This request would send your data to a different website from the one asking "
                                   "for it, so the wallet stopped. Nothing was sent."))

    if identity.prefix == "x509_san_dns":
        if target != identity.value.lower():
            raise refuse(identity.value)
    elif identity.prefix == "x509_hash":
        names = _dns_names(identity.cert) if identity.cert is not None else []
        if names and target not in names:
            raise refuse(", ".join(names))
        identity.name = target
    elif identity.prefix == "redirect_uri" and response_uri != identity.value:
        raise WalletError(tr("response_uri ({uri}) does not match the client_id ({client_id}).", uri=response_uri,
                             client_id=identity.value))


def remember_verifier(identity: VerifierIdentity) -> None:
    if identity.cert is None:
        return
    config = load_config()
    config.setdefault("verifiers", {})[identity.client_id] = {
        "name": identity.name,
        "cert_sha256": cert_fingerprint(identity.cert),
        "last_used": int(time.time()),
    }
    save_config(config)

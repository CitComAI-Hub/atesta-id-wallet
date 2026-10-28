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
    if storage.TRUST_DIR.is_dir():
        for path in sorted(storage.TRUST_DIR.glob("*.pem")):
            try:
                anchors += x509.load_pem_x509_certificates(path.read_bytes())
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
        raise WalletError(tr("The verifier's request has expired; reload the QR code."))
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
        identity.name = (_dns_names(cert) or [value])[0]
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
    """Stops a request signed by A from sending the data to B (x509_san_dns rules in OpenID4VP 1.0)."""
    require_https(response_uri, "response_uri")
    if identity.prefix == "x509_san_dns" and identity.trust != "trusted":
        if host_of(response_uri) != identity.value.lower():
            raise WalletError(tr("The request is signed by {signer} but asks to send the data to {target}. Aborting.",
                                 signer=identity.value, target=host_of(response_uri)))
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

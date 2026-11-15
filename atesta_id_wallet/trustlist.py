# -*- coding: utf-8 -*-
"""
Trusted lists (ETSI TS 119 612): lists of trust service providers and the certificates of their
services, published and signed (XMLDSig/XAdES) by a scheme operator.

The user adds a list by its URL. The certificate that signs it is pinned when it is added (shown to
the user by its SHA-256 fingerprint, or given as a file), and every later download must be signed
by that certificate. From a list the wallet keeps the certificates of the services in force
(granted, recognised at national level...), until the list's NextUpdate.

Uses:
- an issuer whose signing certificate (x5c, or an mdoc's x5chain) chains to one of those
  certificates is shown as certified by that provider, in that list;
- DCQL trusted_authorities of type 'etsi_tl' (OpenID4VP 1.0 §6.1.1.2) are evaluated with the lists
  the user added; a list the user did not add is not downloaded (its address comes from the
  verifier), so it cannot be told and leaves nothing out.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import time
from dataclasses import dataclass
from typing import Any

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .common import WalletError, clean_text, debug, host_of, is_local_host, log, require_https
from .jose import _x5c_chain
from .i18n import tr
from .storage import load_config, save_config

TSL_NS = "http://uri.etsi.org/02231/v2#"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
MAX_BYTES = 16 * 1024 * 1024  # national lists run to a few MB
MAX_SERVICES = 5000
# Service statuses in force (TS 119 612 v2.1 and v2.2 / EU national lists, and the older ones).
IN_FORCE = ("granted", "recognisedatnationallevel", "accredited", "undersupervision", "supervisionincessation",
            "setbynationallaw")
DEFAULT_REFRESH = 7 * 24 * 3600  # when a list names no NextUpdate


class TrustListError(WalletError):
    """A trusted list that could not be fetched, read or verified."""


@dataclass
class Service:
    provider: str  # TSP name
    name: str  # service name
    kind: str  # ServiceTypeIdentifier
    certificates: list[x509.Certificate]


@dataclass
class TrustedList:
    url: str
    operator: str
    territory: str
    next_update: float
    services: list[Service]
    signer: x509.Certificate


def fingerprint(cert: x509.Certificate, lines: int = 1) -> str:
    """SHA-256 of the certificate, as hex pairs: what the user compares with the operator's (in 'lines' lines)."""
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    pairs = [digest[i:i + 2] for i in range(0, len(digest), 2)]
    step = -(-len(pairs) // lines)
    return "\n".join(":".join(pairs[i:i + step]) for i in range(0, len(pairs), step))


def _text(element: Any, path: str) -> str:
    found = element.find(path, {"t": TSL_NS})
    return (found.text or "").strip() if found is not None else ""


def _name(element: Any, path: str) -> str:
    """A multilingual name (English first)."""
    names = element.findall(f"{path}/t:Name", {"t": TSL_NS})
    english = [n for n in names if n.get("{http://www.w3.org/XML/1998/namespace}lang") == "en"]
    chosen = (english or names or [None])[0]
    return clean_text(chosen.text if chosen is not None else None) or ""


def _parser() -> Any:
    from lxml import etree
    # No DTDs, entities or network: a list is data, never instructions to the parser.
    return etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False,
                           remove_comments=True)


def signer_certificate(data: bytes) -> x509.Certificate:
    """The certificate in the list's signature (KeyInfo), not trusted yet: to show it before pinning."""
    from lxml import etree
    try:
        root = etree.fromstring(data, _parser())
    except etree.XMLSyntaxError as exc:
        raise TrustListError(tr("The trusted list is not valid: {problem}.", problem=f"not XML ({exc})")) from exc
    found = root.find(f"{{{DS_NS}}}Signature/{{{DS_NS}}}KeyInfo/{{{DS_NS}}}X509Data/{{{DS_NS}}}X509Certificate")
    if found is None or not (found.text or "").strip():
        raise TrustListError(tr("The trusted list is not valid: {problem}.", problem="it has no signing certificate"))
    try:
        return x509.load_der_x509_certificate(base64.b64decode("".join(found.text.split())))
    except ValueError as exc:
        raise TrustListError(tr("The trusted list is not valid: {problem}.", problem=str(exc))) from exc


def parse(data: bytes, url: str, signer: x509.Certificate, now: float | None = None) -> TrustedList:
    """
    A list signed by 'signer' (pinned), read only from what the signature covers: the whole document
    (enveloped, Reference URI=""). An expired signer or list is refused.
    """
    from lxml import etree
    from signxml import InvalidInput, InvalidSignature, SignatureConfiguration, XMLVerifier

    now = time.time() if now is None else now

    def invalid(problem: str) -> TrustListError:
        return TrustListError(tr("The trusted list is not valid: {problem}.", problem=problem))

    if len(data) > MAX_BYTES:
        raise invalid("it is too large")
    moment = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    if not signer.not_valid_before_utc <= moment <= signer.not_valid_after_utc:
        raise invalid(f"its signing certificate is not valid now (until {signer.not_valid_after_utc:%Y-%m-%d})")
    try:
        # XAdES adds a second reference (SignedProperties); only the one over the whole list is used.
        results = XMLVerifier().verify(data, x509_cert=signer, parser=_parser(),
                                       expect_config=SignatureConfiguration(expect_references=True))
    except (InvalidSignature, InvalidInput, etree.XMLSyntaxError, ValueError) as exc:
        raise TrustListError(tr("The trusted list {url} is not signed by its pinned certificate: {problem}",
                                url=url, problem=exc)) from exc
    results = results if isinstance(results, list) else [results]
    root = next((r.signed_xml for r in results if r.signed_xml is not None
                 and r.signed_xml.tag == f"{{{TSL_NS}}}TrustServiceStatusList"), None)
    if root is None:
        raise invalid("the signature does not cover the list")
    info = root.find("t:SchemeInformation", {"t": TSL_NS})
    if info is None:
        raise invalid("it has no SchemeInformation")
    next_update = _text(info, "t:NextUpdate/t:dateTime")
    try:
        when = datetime.datetime.fromisoformat(next_update.replace("Z", "+00:00")).timestamp() if next_update \
            else now + DEFAULT_REFRESH
    except ValueError:
        raise invalid(f"NextUpdate {next_update!r} is not a date") from None
    if when < now:
        raise invalid(f"it expired on {next_update}")
    services: list[Service] = []
    for provider in root.findall("t:TrustServiceProviderList/t:TrustServiceProvider", {"t": TSL_NS}):
        provider_name = _name(provider, "t:TSPInformation/t:TSPName")
        for service in provider.findall("t:TSPServices/t:TSPService/t:ServiceInformation", {"t": TSL_NS}):
            status = _text(service, "t:ServiceStatus").rstrip("/").rsplit("/", 1)[-1]
            if status not in IN_FORCE:
                continue
            certs = []
            for element in service.findall("t:ServiceDigitalIdentity/t:DigitalId/t:X509Certificate", {"t": TSL_NS}):
                try:
                    certs.append(x509.load_der_x509_certificate(base64.b64decode("".join((element.text or "").split()))))
                except ValueError:
                    debug(f"A certificate of {provider_name} in {url} could not be read; ignored.")
            if certs:
                services.append(Service(provider_name, _name(service, "t:ServiceName"),
                                        _text(service, "t:ServiceTypeIdentifier"), certs))
            if len(services) > MAX_SERVICES:
                raise invalid("it has too many services")
    return TrustedList(url, _name(info, "t:SchemeOperatorName") or host_of(url), _text(info, "t:SchemeTerritory"),
                       when, services, signer)


def download(session: requests.Session, url: str) -> bytes:
    require_https(url, "trusted list")
    if is_local_host(host_of(url)):
        raise TrustListError(tr("The trusted list is not valid: {problem}.", problem="it is on a local address"))
    with session.get(url, timeout=30, stream=True, allow_redirects=False,
                     headers={"Accept": "application/vnd.etsi.tsl+xml, application/xml, text/xml"}) as response:
        if response.status_code != 200:
            raise TrustListError(f"GET {url} -> HTTP {response.status_code}")
        data = response.raw.read(MAX_BYTES + 1, decode_content=True)
    if len(data) > MAX_BYTES:
        raise TrustListError(tr("The trusted list is not valid: {problem}.", problem="it is too large"))
    return data


# -- the lists of this profile ----------------------------------------------------


def configured() -> list[dict[str, Any]]:
    lists = load_config().get("trusted_lists")
    return [entry for entry in lists if isinstance(entry, dict)] if isinstance(lists, list) else []


def _stored(entry: dict[str, Any]) -> TrustedList | None:
    """The kept copy of a list, while its NextUpdate has not passed."""
    try:
        signer = x509.load_pem_x509_certificate(entry["signer"].encode("ascii"))
        services = [Service(s["provider"], s["name"], s["kind"],
                            [x509.load_der_x509_certificate(base64.b64decode(c)) for c in s["certificates"]])
                    for s in entry.get("services") or []]
        return TrustedList(entry["url"], entry.get("operator", ""), entry.get("territory", ""),
                           float(entry.get("next_update") or 0), services, signer)
    except (KeyError, TypeError, ValueError):
        return None


def _store(trusted: TrustedList) -> None:
    config = load_config()
    lists = [e for e in config.get("trusted_lists") or [] if isinstance(e, dict) and e.get("url") != trusted.url]
    lists.append({
        "url": trusted.url, "operator": trusted.operator, "territory": trusted.territory,
        "next_update": int(trusted.next_update), "fetched_at": int(time.time()),
        "signer": trusted.signer.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "services": [{"provider": s.provider, "name": s.name, "kind": s.kind,
                      "certificates": [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii")
                                       for c in s.certificates]} for s in trusted.services],
    })
    config["trusted_lists"] = lists
    save_config(config)


def preview(session: requests.Session, url: str, signer: x509.Certificate | None = None) -> TrustedList:
    """Downloads and checks a list before adding it: signed by 'signer', or by its own certificate (to show)."""
    data = download(session, url)
    return parse(data, url, signer or signer_certificate(data))


def add(trusted: TrustedList) -> None:
    """Adds a list the user has seen (preview), pinning its signing certificate."""
    _store(trusted)


def remove(url: str) -> bool:
    config = load_config()
    lists = config.get("trusted_lists") or []
    kept = [e for e in lists if isinstance(e, dict) and e.get("url") != url]
    if len(kept) == len(lists):
        return False
    config["trusted_lists"] = kept
    save_config(config)
    return True


def current(session: requests.Session | None, now: float | None = None) -> list[TrustedList]:
    """
    The lists of this profile that are in force: the kept copy, or a new download (signed by the
    pinned certificate) once its NextUpdate passed. A list that cannot be refreshed is left out
    (and logged): an outdated list does not certify anyone.
    """
    now = time.time() if now is None else now
    found = []
    for entry in configured():
        kept = _stored(entry)
        if kept is None:
            continue
        if kept.next_update > now:
            found.append(kept)
            continue
        if session is None:
            continue
        try:
            fresh = parse(download(session, kept.url), kept.url, kept.signer, now)
        except (WalletError, requests.RequestException) as exc:
            log(tr("Warning: the trusted list {url} could not be updated: {error}", url=kept.url, error=exc))
            continue
        _store(fresh)
        found.append(fresh)
    return found


def certification(credential: Any, lists: list[TrustedList]) -> tuple[TrustedList, Service] | None:
    """The list and service that certify a credential's issuer (an SdJwt's x5c, an Mdoc's x5chain), if any."""
    header = getattr(credential, "header", None)
    if not lists or not isinstance(header, dict) or not header.get("x5c"):
        return None
    try:
        chain = _x5c_chain(header)
    except WalletError:
        return None
    return certified_by(chain, lists)


def certified_by(chain: list[x509.Certificate], lists: list[TrustedList],
                 now: float | None = None) -> tuple[TrustedList, Service] | None:
    """
    The list and service that certify the signer of 'chain' (leaf first): a service certificate in
    the chain, or one that issued its last certificate; every link signed by the next and valid now.
    """
    if not chain:
        return None
    moment = datetime.datetime.fromtimestamp(time.time() if now is None else now, datetime.timezone.utc)

    def valid(cert: x509.Certificate) -> bool:
        return cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc

    usable: list[x509.Certificate] = []
    for cert in chain:
        if not valid(cert):
            break
        if usable:
            try:
                usable[-1].verify_directly_issued_by(cert)
            except (InvalidSignature, ValueError, TypeError):
                break
        usable.append(cert)
    if not usable:  # the signer's own certificate is not valid now
        return None
    encoded = [c.public_bytes(serialization.Encoding.DER) for c in usable]
    for trusted in lists:
        for service in trusted.services:
            for anchor in service.certificates:
                if anchor.public_bytes(serialization.Encoding.DER) in encoded:
                    return trusted, service
                if valid(anchor):
                    try:
                        usable[-1].verify_directly_issued_by(anchor)
                    except (InvalidSignature, ValueError, TypeError):
                        continue
                    return trusted, service
    return None

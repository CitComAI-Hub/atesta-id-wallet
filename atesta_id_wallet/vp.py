# -*- coding: utf-8 -*-
"""OpenID4VP: verifier request, DCQL / Presentation Exchange, and response."""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

import requests

from .common import (
    SD_JWT_FORMATS,
    WalletError,
    _http_error,
    _json,
    _last_deep_link,
    b64u,
    debug,
    host_of,
    jwt_decode_unverified,
    log,
    parse_json,
    require_https,
)
from .i18n import tr
from .jose import encrypt_response_jwe
from .sdjwt import SdJwt, _claim_at, _sd_digest, select_disclosures
from .storage import HolderKey, add_history, credential_name, is_expired
from .trust import VerifierIdentity, check_request_object, check_response_uri, remember_verifier, split_client_id
from .ui import consent_items


def build_sd_jwt_presentation(
    sd_jwt: SdJwt,
    key: HolderKey,
    *,
    audience: str,
    nonce: str,
    requested_paths: list[list[Any]] | None,
) -> str:
    """Devuelve <issuer-jwt>~<disclosures seleccionadas>~<KB-JWT>."""
    selected = select_disclosures(sd_jwt, requested_paths)
    debug("Disclosed: " + ", ".join(".".join(map(str, d.path)) for d in selected))

    without_kb = sd_jwt.issuer_jwt + "~" + "".join(d.encoded + "~" for d in selected)
    kb_jwt = key.sign_jwt(
        {"typ": "kb+jwt"},
        {
            "iat": int(time.time()),
            "aud": audience,
            "nonce": nonce,
            "sd_hash": _sd_digest(without_kb, sd_jwt.hash_alg),
        },
    )
    return without_kb + kb_jwt


def fetch_request(session: requests.Session, raw: str) -> tuple[dict[str, Any], VerifierIdentity]:
    raw = _last_deep_link(raw, "openid4vp://")
    if raw.startswith(("http://", "https://")):
        params = {"request_uri": [raw]}
    else:
        params = parse_qs(urlsplit(raw).query, keep_blank_values=True)
    qp = {k: v[0] for k, v in params.items()}
    client_id = qp.get("client_id", "")

    if "request" in qp:
        token = qp["request"]
    elif "request_uri" in qp:
        uri = qp["request_uri"]
        require_https(uri, "request_uri")
        accept = {"Accept": "application/oauth-authz-req+jwt, application/jwt, application/json"}
        if qp.get("request_uri_method", "get").lower() == "post":
            wallet_metadata = {
                "vp_formats_supported": {f: {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}
                                         for f in SD_JWT_FORMATS},
                "response_types_supported": ["vp_token"],
                "response_modes_supported": ["direct_post", "direct_post.jwt"],
            }
            response = session.post(
                uri, headers=accept, data={"wallet_metadata": json.dumps(wallet_metadata)}, timeout=20
            )
        else:
            response = session.get(uri, headers=accept, timeout=20)
        if response.status_code >= 400:
            raise _http_error("GET/POST", uri, response)
        token = response.text.strip()
    else:
        # Request by value (unsigned) in the URL itself.
        request = dict(qp)
        for key in ("dcql_query", "presentation_definition", "client_metadata"):
            if key in request:
                request[key] = parse_json(request[key], key)
        prefix, value = split_client_id(client_id)
        name = host_of(value) if prefix == "redirect_uri" else value
        return request, VerifierIdentity(client_id, prefix, value, name or tr("(unknown)"))

    if token.startswith("{"):
        request = parse_json(token, "request_uri")
        if not isinstance(request, dict):
            raise WalletError(tr("{what} is not valid JSON.", what="request_uri"))
        prefix, value = split_client_id(request.get("client_id") or client_id)
        identity = VerifierIdentity(request.get("client_id") or client_id, prefix, value, value)
    else:
        _, request = jwt_decode_unverified(token)
        identity = check_request_object(token, client_id or request.get("client_id", ""))
    if client_id and request.get("client_id") and request["client_id"] != client_id:
        raise WalletError(tr("The client_id of the QR code and of the request object do not match."))
    return request, identity


def _jsonpath_to_list(path: str) -> list[Any]:
    """$.a.b, $['a'].b, $.credentialSubject.x -> ['a','b']"""
    steps = re.findall(r"\['([^']+)'\]|\[(\d+)\]|\.([A-Za-z0-9_$@-]+)", path)
    out: list[Any] = []
    for quoted, index, plain in steps:
        out.append(int(index) if index else (quoted or plain))
    return out


def _filter_ok(value: Any, flt: dict[str, Any]) -> bool:
    candidates = value if isinstance(value, list) else [value]
    if "const" in flt:
        return flt["const"] in candidates
    if "enum" in flt:
        return any(c in flt["enum"] for c in candidates)
    if "pattern" in flt:
        return any(isinstance(c, str) and re.search(flt["pattern"], c) for c in candidates)
    if "contains" in flt:
        return any(_filter_ok(c, flt["contains"]) for c in candidates)
    return True


class NoMatchingCredential(WalletError):
    """The verifier asks for a credential that is not in the wallet."""

    def __init__(self, message: str, wanted: list[str]):
        super().__init__(message)
        self.detail = message  # technical version, for --verbose
        self.wanted = list(dict.fromkeys(wanted))  # requested types or names, without repetitions
        self.verifier: str | None = None

    def __str__(self) -> str:
        return tr("{verifier} asks for a credential you do not have in this profile: {wanted}.",
                  verifier=self.verifier or tr("The verifier"), wanted=", ".join(self.wanted) or "?")


def _dcql_description(query: dict[str, Any]) -> str:
    vcts = (query.get("meta") or {}).get("vct_values") or []
    return ", ".join(map(str, vcts)) or str(query.get("id"))


@dataclass
class Match:
    query_id: str
    record: dict[str, Any]
    paths: list[list[Any]] | None


# choose(query_id, candidates) -> the credential to use; by default the newest.
Chooser = Callable[[str, list[dict[str, Any]]], dict[str, Any]]


def _first(_query_id: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    return candidates[0]


def _usable(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if r.get("_sd") is not None and not is_expired(r)]


def _dcql_claims(query: dict[str, Any], claims: Any) -> list[dict[str, Any]] | None:
    """
    The claim queries the credential satisfies, or None if it does not (OpenID4VP 1.0 §6.4.1):
    with claim_sets, the first possible combination; without them, all of 'claims'.
    """
    claim_queries = [cq for cq in query.get("claims") or [] if isinstance(cq, dict)]
    ok = {}
    for index, cq in enumerate(claim_queries):
        present, value = _claim_at(claims, cq.get("path", []))
        ok[index] = present and ("values" not in cq or value in cq["values"])
    claim_sets = query.get("claim_sets")
    if not claim_sets:
        return claim_queries if all(ok.values()) else None
    by_id = {cq.get("id"): index for index, cq in enumerate(claim_queries) if cq.get("id") is not None}
    for option in claim_sets:
        indexes = [by_id.get(claim_id) for claim_id in option or []]
        if indexes and None not in indexes and all(ok[i] for i in indexes):
            return [claim_queries[i] for i in indexes]
    return None


def match_dcql(dcql: dict[str, Any], records: list[dict[str, Any]], disclose_all: bool,
               choose: Chooser = _first) -> list[Match]:
    queries = {q["id"]: q for q in dcql.get("credentials", []) if isinstance(q, dict) and "id" in q}
    if not queries:
        raise WalletError(tr("The DCQL query does not ask for any credential."))
    records = _usable(records)

    def find(query: dict[str, Any], strict_format: bool) -> list[dict[str, Any]]:
        fmt = query.get("format")
        vcts = (query.get("meta") or {}).get("vct_values")
        found = []
        for record in records:
            sd: SdJwt = record["_sd"]
            # dc+sd-jwt and vc+sd-jwt are the same format under different names;
            # they are only mixed when no query uses the exact name.
            if fmt and record.get("format") != fmt and (strict_format or fmt not in SD_JWT_FORMATS):
                continue
            if vcts and sd.claims.get("vct") not in vcts:
                continue
            if _dcql_claims(query, sd.claims) is not None:
                found.append(record)
        return found

    def to_match(query_id: str, record: dict[str, Any]) -> Match:
        # Without 'claims' the verifier asks for no selective data: only the mandatory parts are sent.
        claim_queries = _dcql_claims(queries[query_id], record["_sd"].claims) or []
        paths = None if disclose_all else [cq.get("path", []) for cq in claim_queries]
        return Match(query_id, record, paths)

    credential_sets = dcql.get("credential_sets")
    if not credential_sets:
        credential_sets = [{"options": [[qid]], "required": True} for qid in queries]

    matches: dict[str, Match] = {}
    for cset in credential_sets:
        chosen: dict[str, list[dict[str, Any]]] | None = None
        # Options with the exact format first; if none fits, the format is relaxed.
        for strict in (True, False):
            for option in cset.get("options", []):
                found = {qid: find(queries[qid], strict) for qid in option if qid in queries}
                if found and len(found) == len(option) and all(found.values()):
                    chosen = found
                    break
            if chosen:
                break
        if chosen is None:
            if cset.get("required", True):
                wanted = [_dcql_description(queries[q]) for option in cset.get("options", []) for q in option
                          if q in queries]
                raise NoMatchingCredential(f"No credential satisfies the DCQL credential_set: {cset}", wanted)
            continue
        for qid, candidates in chosen.items():
            if qid not in matches:
                matches[qid] = to_match(qid, choose(qid, candidates))
    return list(matches.values())


def match_presentation_definition(
    pd: dict[str, Any], records: list[dict[str, Any]], disclose_all: bool, choose: Chooser = _first
) -> list[Match]:
    matches: list[Match] = []
    records = _usable(records)
    for descriptor in pd.get("input_descriptors", []):
        constraints = descriptor.get("constraints") or {}
        fields = constraints.get("fields") or []
        found: list[tuple[dict[str, Any], list[list[Any]]]] = []
        for record in records:
            sd: SdJwt = record["_sd"]
            ok = True
            requested = []
            for fld in fields:
                hit = False
                for path in fld.get("path", []):
                    steps = _jsonpath_to_list(path)
                    present, value = _claim_at(sd.claims, steps)
                    if present and _filter_ok(value, fld.get("filter") or {}):
                        hit = True
                        requested.append(steps)
                        break
                if not hit and not fld.get("optional"):
                    ok = False
                    break
            if ok:
                found.append((record, requested))
        if not found:
            raise NoMatchingCredential(
                f"No credential satisfies the input_descriptor '{descriptor.get('id')}'.",
                [str(descriptor.get("name") or descriptor.get("id"))],
            )
        descriptor_id = str(descriptor.get("id", ""))
        record = choose(descriptor_id, [r for r, _ in found])
        requested = next(paths for r, paths in found if r is record)
        limited = constraints.get("limit_disclosure") == "required" and not disclose_all
        matches.append(Match(descriptor_id, record, requested if limited else None))
    return matches


@dataclass
class PreparedPresentation:
    """What will be sent, ready to ask for consent before signing anything."""
    request: dict[str, Any]
    identity: VerifierIdentity
    response_uri: str
    response_mode: str
    nonce: str
    matches: list[Match]
    presentation_definition: dict[str, Any] | None = None


def prepare_presentation(
    session: requests.Session,
    raw: str,
    records: list[dict[str, Any]],
    *,
    disclose_all: bool = False,
    allow_unverified: bool = False,
    choose: Chooser = _first,
) -> PreparedPresentation:
    """Downloads and validates the request and picks the credentials; sends nothing."""
    debug(f"Request: {raw}")
    request, identity = fetch_request(session, raw)
    debug(f"Request object: {json.dumps(request, ensure_ascii=False)[:2000]}")
    if identity.trust == "unverified" and not allow_unverified:
        raise WalletError(tr(
            "The identity of the verifier '{client_id}' cannot be verified (unsigned request or unsupported "
            "client_id scheme). If you trust it, repeat with --allow-unverified.", client_id=identity.client_id
        ))

    response_mode = request.get("response_mode", "fragment")
    response_uri = request.get("response_uri") or request.get("redirect_uri")
    nonce = request.get("nonce")
    if response_mode not in ("direct_post", "direct_post.jwt"):
        raise WalletError(tr("response_mode '{mode}' is not supported (only direct_post[.jwt]).", mode=response_mode))
    if not response_uri or not nonce:
        raise WalletError(tr("The request object has no response_uri or nonce."))
    check_response_uri(identity, response_uri)
    debug(f"response_uri: {response_uri} ({response_mode})")

    pd = None
    try:
        if "dcql_query" in request:
            matches = match_dcql(request["dcql_query"], records, disclose_all, choose)
        elif "presentation_definition" in request or "presentation_definition_uri" in request:
            pd = request.get("presentation_definition")
            if pd is None:
                pd_uri = request["presentation_definition_uri"]
                require_https(pd_uri, "presentation_definition_uri")
                pd = _json(session.get(pd_uri, timeout=20), "GET", pd_uri)
            matches = match_presentation_definition(pd, records, disclose_all, choose)
        else:
            raise WalletError(tr("The request contains neither dcql_query nor presentation_definition."))
    except NoMatchingCredential as exc:
        exc.verifier = identity.name
        debug(exc.detail)
        raise
    return PreparedPresentation(request, identity, response_uri, response_mode, nonce, matches, pd)


def build_response(prepared: PreparedPresentation, key: HolderKey, *, vp_token_style: str = "array") -> dict[str, str]:
    """Signs the presentations (KB-JWT) and builds the POST body for response_uri."""
    request, matches = prepared.request, prepared.matches
    presentations = [
        build_sd_jwt_presentation(
            m.record["_sd"], key, audience=prepared.identity.client_id, nonce=prepared.nonce,
            requested_paths=m.paths,
        )
        for m in matches
    ]
    for m in matches:
        debug(f"'{m.query_id}' <- {Path(m.record['_path']).name}")
    form: dict[str, Any] = {}
    if prepared.presentation_definition is None:
        form["vp_token"] = {
            m.query_id: vp if vp_token_style == "string" else [vp] for m, vp in zip(matches, presentations)
        }
    else:
        form["vp_token"] = presentations[0] if len(presentations) == 1 else presentations
        form["presentation_submission"] = {
            "id": b64u(secrets.token_bytes(8)),
            "definition_id": prepared.presentation_definition.get("id"),
            "descriptor_map": [
                {
                    "id": m.query_id,
                    "format": m.record.get("format", "vc+sd-jwt"),
                    "path": "$" if len(matches) == 1 else f"$[{index}]",
                }
                for index, m in enumerate(matches)
            ],
        }
    if request.get("state"):
        form["state"] = request["state"]

    if prepared.response_mode == "direct_post.jwt":
        body = {"response": encrypt_response_jwe(form, request, apv=prepared.nonce)}
        if request.get("state"):
            body["state"] = request["state"]
        return body
    return {k: v if isinstance(v, str) else json.dumps(v, separators=(",", ":")) for k, v in form.items()}


def send_presentation(
    session: requests.Session, prepared: PreparedPresentation, body: dict[str, str]
) -> str | None:
    """Sends the response; returns the verifier's redirect_uri, if any."""
    log(tr("Sending the presentation…"))
    response = session.post(prepared.response_uri, data=body, timeout=30)
    if response.status_code >= 400:
        raise _http_error("POST", prepared.response_uri, response)
    debug(f"Presentation accepted (HTTP {response.status_code}).")
    remember_verifier(prepared.identity)
    add_history(_history_event("presented", prepared))
    try:
        data = response.json()
    except ValueError:
        data = {}
    redirect_uri = data.get("redirect_uri") if isinstance(data, dict) else None
    if not redirect_uri and response.text.strip():
        debug(response.text[:500])
    if redirect_uri is None:
        return None
    # It is opened in the browser: never file://, javascript: or other local schemes.
    if not isinstance(redirect_uri, str) or urlsplit(redirect_uri).scheme not in ("https", "http"):
        log(tr("Warning: the verifier's redirect_uri is not a web address; it is not opened: {uri}",
               uri=redirect_uri))
        return None
    try:
        require_https(redirect_uri, "redirect_uri")
    except WalletError as exc:
        log(str(exc))
        return None
    return redirect_uri


def _history_event(kind: str, prepared: PreparedPresentation) -> dict[str, Any]:
    items = consent_items(prepared.matches)
    return {
        "type": kind,
        "party": prepared.identity.name,
        "party_id": prepared.identity.client_id,
        "trust": prepared.identity.trust,
        "credentials": [credential_name(m.record) for m in prepared.matches],
        "claims": [path for item in items for path, _ in item.claims],
    }


def record_declined(prepared: PreparedPresentation) -> None:
    """Records in the history that the user declined to share the data."""
    add_history(_history_event("declined", prepared))

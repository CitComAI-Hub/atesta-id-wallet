# -*- coding: utf-8 -*-
"""
Translation of the interface texts.

The source text (English) is in the code and is the fallback: tr("Wallet") returns the
translation for the active language if there is one and the text itself otherwise. Catalogs are
JSON files next to this module ({"messages": {source: translation}, "plurals": {singular: [one, many]}}).
"""

from __future__ import annotations

import json
import locale
import os
from pathlib import Path
from typing import Any

LANGUAGES = {"en": "English", "es": "Español", "da": "Dansk"}  # each language's name in that language
DEFAULT = "en"
AUTO = "auto"

_DIR = Path(__file__).resolve().parent
_messages: dict[str, str] = {}
_plurals: dict[str, list[str]] = {}
_current = DEFAULT


def load_catalog(code: str) -> dict[str, Any]:
    if code == DEFAULT:
        return {"messages": {}, "plurals": {}}
    return json.loads((_DIR / f"{code}.json").read_text(encoding="utf-8"))


def set_language(code: str) -> str:
    """Activates a language (English if it is not supported) and returns the active code."""
    global _messages, _plurals, _current
    code = code if code in LANGUAGES else DEFAULT
    catalog = load_catalog(code)
    _messages, _plurals, _current = catalog.get("messages", {}), catalog.get("plurals", {}), code
    return code


def current() -> str:
    return _current


def system_language(hint: str | None = None) -> str:
    """System language among the supported ones (hint: e.g. QLocale.system().name() in the GUI)."""
    candidates = [hint] if hint else []
    candidates += [os.environ.get(var) for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")]
    try:
        candidates.append(locale.getlocale()[0])
    except ValueError:
        pass
    names = {"spanish": "es", "español": "es", "danish": "da", "dansk": "da", "english": "en"}
    for candidate in candidates:
        for part in (candidate or "").split(":"):  # LANGUAGE may be a list: "da:en"
            code = part.strip().lower().replace("-", "_")
            if not code or code in ("c", "posix"):
                continue
            short = names.get(code.split("_")[0], code.split("_")[0][:2])
            if short in LANGUAGES:
                return short
    return DEFAULT


def resolve(preference: str | None, hint: str | None = None) -> str:
    """'auto' (or nothing) uses the system language; a supported code is used as is."""
    if preference and preference != AUTO and preference in LANGUAGES:
        return preference
    return system_language(hint)


def tr(text: str, **values: Any) -> str:
    translated = _messages.get(text) or text
    return translated.format(**values) if values else translated


def tr_n(singular: str, plural: str, n: int, **values: Any) -> str:
    """Singular or plural depending on n; {n} is available in the text."""
    forms = _plurals.get(singular)
    text = (forms[0] if n == 1 else forms[1]) if forms else (singular if n == 1 else plural)
    return text.format(n=n, **values)


def N_(text: str) -> str:  # noqa: N802
    """Marks a text for translation later (module constants); it is translated when used with tr()."""
    return text

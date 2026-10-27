# -*- coding: utf-8 -*-
"""
Traducción de los textos de la interfaz.

El texto fuente (en inglés) está en el código y es el fallback: tr("Wallet") devuelve la
traducción del idioma activo si existe y, si no, el propio texto. Los catálogos son JSON
junto a este módulo ({"messages": {fuente: traducción}, "plurals": {singular: [uno, varios]}}).
"""

from __future__ import annotations

import json
import locale
import os
from pathlib import Path
from typing import Any

LANGUAGES = {"en": "English", "es": "Español", "da": "Dansk"}  # el nombre de cada idioma en sí mismo
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
    """Activa un idioma (o el inglés si no está soportado) y devuelve el código activo."""
    global _messages, _plurals, _current
    code = code if code in LANGUAGES else DEFAULT
    catalog = load_catalog(code)
    _messages, _plurals, _current = catalog.get("messages", {}), catalog.get("plurals", {}), code
    return code


def current() -> str:
    return _current


def system_language(hint: str | None = None) -> str:
    """Idioma del sistema entre los soportados (hint: p. ej. QLocale.system().name() en la GUI)."""
    candidates = [hint] if hint else []
    candidates += [os.environ.get(var) for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")]
    try:
        candidates.append(locale.getlocale()[0])
    except ValueError:
        pass
    names = {"spanish": "es", "español": "es", "danish": "da", "dansk": "da", "english": "en"}
    for candidate in candidates:
        for part in (candidate or "").split(":"):  # LANGUAGE admite una lista: "da:en"
            code = part.strip().lower().replace("-", "_")
            if not code or code in ("c", "posix"):
                continue
            short = names.get(code.split("_")[0], code.split("_")[0][:2])
            if short in LANGUAGES:
                return short
    return DEFAULT


def resolve(preference: str | None, hint: str | None = None) -> str:
    """'auto' (o nada) usa el idioma del sistema; un código soportado se usa tal cual."""
    if preference and preference != AUTO and preference in LANGUAGES:
        return preference
    return system_language(hint)


def tr(text: str, **values: Any) -> str:
    translated = _messages.get(text) or text
    return translated.format(**values) if values else translated


def tr_n(singular: str, plural: str, n: int, **values: Any) -> str:
    """Singular o plural según n; {n} está disponible en el texto."""
    forms = _plurals.get(singular)
    text = (forms[0] if n == 1 else forms[1]) if forms else (singular if n == 1 else plural)
    return text.format(n=n, **values)


def N_(text: str) -> str:  # noqa: N802
    """Marca un texto para traducir más tarde (constantes de módulo); se traduce al usarlo con tr()."""
    return text

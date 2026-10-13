#!/usr/bin/env python3
"""Validate «Incidente en el GSEC» submission files (``respuestas.json`` / ``oleadaN.json``).

Standard library only (Python >= 3.10). It implements the JSON-Schema (2020-12) subset used by
the schemas shipped next to this script: ``type`` (also as a list), ``const``, ``enum``,
``required``, ``properties``, ``additionalProperties``, ``items``, ``minItems``/``maxItems``,
``uniqueItems``, ``minLength``/``maxLength``, ``minimum``/``maximum``, ``pattern``,
``format: date-time``, ``oneOf``/``anyOf`` and local ``$ref`` (``#/$defs/...``).

Hard limits are enforced *before* schema validation: UTF-8 encoding, 1 MiB per file, nesting
depth <= 10, no ``NaN``/``Infinity``, no duplicate keys, object at the top level.

Messages are in Spanish (participants read them); the code and comments are in English.

Usage::

    python3 validar_respuestas.py respuestas.json oleada1.json
    python3 validar_respuestas.py --all .            # every *.json of a directory (not recursive)
    python3 validar_respuestas.py --schema-dir starter-kit --json respuestas.json

Exit codes: 0 = every file is valid, 1 = at least one file is invalid, 2 = usage/schema error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

MAX_BYTES = 1024 * 1024  # 1 MiB
MAX_DEPTH = 10
SCHEMA_FILES = {"respuestas": "respuestas.schema.json", "oleada": "oleada.schema.json"}
FORMATO_PREFIX = "incidente-gsec/"
PLACEHOLDER_TEAM = "nombre-del-equipo"

_TYPE_NAMES_ES = {
    "object": "un objeto {…}",
    "array": "una lista […]",
    "string": "una cadena de texto",
    "integer": "un número entero",
    "number": "un número",
    "boolean": "un booleano (true/false)",
    "null": "null",
}
_DATETIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,6})?)?(Z|z|[+-]\d{2}:\d{2})?$"
)


class SchemaError(Exception):
    """The schema itself is malformed or uses an unsupported keyword."""


@dataclass
class Issue:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass
class Report:
    file: str
    kind: str | None = None
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    data: Any = None

    @property
    def ok(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------------------------------------
# Strict JSON parsing
# ---------------------------------------------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise ValueError(f"valor no permitido en JSON: {name}")


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"clave duplicada «{key}» en un objeto")
        obj[key] = value
    return obj


def _depth(node: Any) -> int:
    """Maximum nesting depth of ``node`` (iterative: hostile inputs may be very deep)."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(node, 1)]
    while stack:
        item, level = stack.pop()
        if level > deepest:
            deepest = level
        if isinstance(item, dict):
            stack.extend((v, level + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, level + 1) for v in item)
        if deepest > MAX_DEPTH:
            break
    return deepest


def parse_strict(data: bytes) -> tuple[Any, list[Issue], list[Issue]]:
    """Decode and parse ``data`` applying the hard limits. Returns (instance, errors, warnings)."""
    errors: list[Issue] = []
    warnings: list[Issue] = []
    if len(data) > MAX_BYTES:
        errors.append(Issue("$", f"el fichero ocupa {len(data)} bytes; máximo {MAX_BYTES} (1 MiB)"))
        return None, errors, warnings
    if data.startswith(b"\xef\xbb\xbf"):
        warnings.append(Issue("$", "el fichero empieza con BOM UTF-8; se ignora, pero es mejor guardarlo sin BOM"))
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        errors.append(Issue("$", f"el fichero no es UTF-8 válido (byte {exc.start})"))
        return None, errors, warnings
    try:
        instance = json.loads(text, object_pairs_hook=_pairs_hook, parse_constant=_reject_constant)
    except RecursionError:
        errors.append(Issue("$", f"anidamiento excesivo; máximo {MAX_DEPTH} niveles"))
        return None, errors, warnings
    except ValueError as exc:  # json.JSONDecodeError is a ValueError
        errors.append(Issue("$", f"JSON mal formado: {exc}"))
        return None, errors, warnings
    if not isinstance(instance, dict):
        errors.append(Issue("$", "el documento debe ser un objeto JSON {…} en el nivel superior"))
        return None, errors, warnings
    if _depth(instance) > MAX_DEPTH:
        errors.append(Issue("$", f"anidamiento excesivo; máximo {MAX_DEPTH} niveles"))
        return None, errors, warnings
    return instance, errors, warnings


# ---------------------------------------------------------------------------------------------
# JSON-Schema subset
# ---------------------------------------------------------------------------------------------


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "integer" if value.is_integer() else "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise SchemaError(f"tipo de valor no soportado: {type(value).__name__}")


def _matches_type(value: Any, expected: str) -> bool:
    actual = _json_type(value)
    if expected == "number":
        return actual in ("integer", "number")
    return actual == expected


def _json_equal(a: Any, b: Any) -> bool:
    """Equality with JSON semantics (``true`` is not ``1``; lists/objects compared recursively)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    return bool(a == b) and not (isinstance(a, list | dict) or isinstance(b, list | dict))


def _resolve_ref(ref: str, root: dict[str, Any]) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaError(f"$ref no soportado: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise SchemaError(f"$ref no resoluble: {ref}")
        node = node[part]
    if not isinstance(node, dict):
        raise SchemaError(f"$ref no apunta a un esquema: {ref}")
    return node


def _describe(schema: dict[str, Any]) -> str:
    desc = schema.get("description")
    return f" ({desc})" if isinstance(desc, str) and desc else ""


def _check_datetime(value: str) -> str | None:
    """Return an error message if ``value`` is not an ISO-8601 date-time with time zone."""
    m = _DATETIME_RE.match(value)
    if not m:
        return "fecha-hora inválida: usa ISO-8601, p. ej. 2026-10-28T16:05:00Z"
    if not m.group(7):
        return "la fecha-hora necesita zona horaria explícita (termina en Z o en +02:00)"
    normalised = value[:-1] + "+00:00" if value[-1] in "Zz" else value
    try:
        datetime.fromisoformat(normalised.replace("t", "T").replace(" ", "T"))
    except ValueError:
        return "fecha-hora inválida (día, hora o minuto fuera de rango)"
    return None


def validate_instance(instance: Any, schema: dict[str, Any], root: dict[str, Any] | None = None,
                      path: str = "$") -> list[Issue]:
    """Validate ``instance`` against ``schema`` (subset); returns the list of errors."""
    root = root if root is not None else schema
    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], root)
    errors: list[Issue] = []
    hint = _describe(schema)

    if "const" in schema and not _json_equal(instance, schema["const"]):
        return [Issue(path, f"el valor debe ser exactamente {json.dumps(schema['const'], ensure_ascii=False)}{hint}")]
    if "enum" in schema and not any(_json_equal(instance, v) for v in schema["enum"]):
        allowed = ", ".join(json.dumps(v, ensure_ascii=False) for v in schema["enum"])
        return [Issue(path, f"el valor debe ser uno de: {allowed}{hint}")]

    expected = schema.get("type")
    if expected is not None:
        types = expected if isinstance(expected, list) else [expected]
        if not any(_matches_type(instance, t) for t in types):
            wanted = " o ".join(_TYPE_NAMES_ES.get(str(t), str(t)) for t in types)
            got = _TYPE_NAMES_ES.get(_json_type(instance), "?")
            return [Issue(path, f"se esperaba {wanted}, no {got}{hint}")]

    for key in ("oneOf", "anyOf"):
        if key in schema:
            branches = schema[key]
            results = [validate_instance(instance, b, root, path) for b in branches]
            passed = [i for i, r in enumerate(results) if not r]
            if (key == "oneOf" and len(passed) != 1) or (key == "anyOf" and not passed):
                if len(passed) > 1:
                    errors.append(Issue(path, "el valor cumple más de una alternativa del esquema"))
                else:
                    # report the branch whose declared type matches the instance (or the last one)
                    actual = _json_type(instance)
                    pick = len(branches) - 1
                    for i, b in enumerate(branches):
                        b = _resolve_ref(b["$ref"], root) if "$ref" in b else b
                        bt = b.get("type")
                        bts = bt if isinstance(bt, list) else [bt]
                        if any(t == actual or (t == "number" and actual == "integer") for t in bts):
                            pick = i
                            break
                    errors.extend(results[pick])
                return errors

    if isinstance(instance, str):
        n = len(instance)
        if "minLength" in schema and n < schema["minLength"]:
            errors.append(Issue(path, f"longitud mínima {schema['minLength']} caracteres (tiene {n}){hint}"))
        if "maxLength" in schema and n > schema["maxLength"]:
            errors.append(Issue(path, f"longitud máxima {schema['maxLength']} caracteres (tiene {n}){hint}"))
        pattern = schema.get("pattern")
        if pattern is not None and n <= 10_000 and not re.search(pattern, instance):
            errors.append(Issue(path, f"no cumple el formato esperado{hint}"))
        fmt = schema.get("format")
        if fmt == "date-time":
            msg = _check_datetime(instance)
            if msg:
                errors.append(Issue(path, msg))
        elif fmt is not None:
            raise SchemaError(f"format no soportado: {fmt}")
    elif isinstance(instance, bool):
        pass
    elif isinstance(instance, int | float):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(Issue(path, f"el valor mínimo es {schema['minimum']}{hint}"))
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(Issue(path, f"el valor máximo es {schema['maximum']}{hint}"))
    elif isinstance(instance, list):
        n = len(instance)
        if "minItems" in schema and n < schema["minItems"]:
            errors.append(Issue(path, f"la lista debe tener al menos {schema['minItems']} elemento(s) (tiene {n})"))
        if "maxItems" in schema and n > schema["maxItems"]:
            errors.append(Issue(path, f"la lista admite como máximo {schema['maxItems']} elementos (tiene {n})"))
        if schema.get("uniqueItems"):
            seen: list[Any] = []
            for i, item in enumerate(instance):
                if item in seen:
                    errors.append(Issue(f"{path}[{i}]", "elemento repetido en la lista"))
                seen.append(item)
        if "items" in schema:
            for i, item in enumerate(instance):
                errors.extend(validate_instance(item, schema["items"], root, f"{path}[{i}]"))
    elif isinstance(instance, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(Issue(path, f"falta la propiedad obligatoria «{key}»"))
        for key, value in instance.items():
            sub = f"{path}.{key}" if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) else f"{path}[{json.dumps(key, ensure_ascii=False)}]"
            if key in props:
                errors.extend(validate_instance(value, props[key], root, sub))
            elif schema.get("additionalProperties", True) is False:
                known = ", ".join(sorted(props)) or "ninguna"
                errors.append(Issue(sub, f"propiedad no permitida «{key}» (permitidas: {known})"))
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(validate_instance(value, schema["additionalProperties"], root, sub))
    return errors


# ---------------------------------------------------------------------------------------------
# File-level validation (kind detection + semantic warnings)
# ---------------------------------------------------------------------------------------------


def detect_kind(instance: Any, filename: str) -> str | None:
    """``respuestas`` / ``oleada`` from the ``formato`` field, else from the file name."""
    formato = instance.get("formato") if isinstance(instance, dict) else None
    if isinstance(formato, str) and formato.startswith(FORMATO_PREFIX):
        kind = formato[len(FORMATO_PREFIX):].split("/", 1)[0]
        if kind in SCHEMA_FILES:
            return kind
    name = Path(filename).name.lower()
    if name.startswith("respuestas"):
        return "respuestas"
    if name.startswith("oleada"):
        return "oleada"
    return None


def _semantic_warnings(kind: str, instance: dict[str, Any], filename: str) -> list[Issue]:
    warnings: list[Issue] = []
    if instance.get("equipo") == PLACEHOLDER_TEAM:
        warnings.append(Issue("$.equipo", "sigue siendo el valor de la plantilla; pon el nombre de vuestro equipo"))
    if kind == "respuestas":
        answers = instance.get("respuestas")
        if isinstance(answers, dict):
            blank = [q for q, v in sorted(answers.items()) if not isinstance(v, dict) or _is_blank(v.get("respuesta"))]
            if len(blank) == len(answers):
                warnings.append(Issue("$.respuestas", "todas las respuestas están en blanco (null)"))
            elif blank:
                warnings.append(Issue("$.respuestas", f"respuestas en blanco (puntúan 0): {', '.join(blank)}"))
            if len(answers) < 12:
                missing = [f"q{i:02d}" for i in range(1, 13) if f"q{i:02d}" not in answers]
                if missing:
                    warnings.append(Issue("$.respuestas", f"preguntas ausentes (puntúan 0): {', '.join(missing)}"))
        if instance.get("generado") is None:
            warnings.append(Issue("$.generado", "sin fecha de generación; se usará la hora del push"))
    else:
        m = re.search(r"oleada(\d)", Path(filename).name.lower())
        if m and instance.get("oleada") != int(m.group(1)):
            warnings.append(Issue("$.oleada", f"el número de oleada no coincide con el nombre del fichero ({Path(filename).name})"))
        if instance.get("detectado_en") is None:
            warnings.append(Issue("$.detectado_en", "sin hora de detección; se usará la hora del push"))
        if instance.get("es_ataque") is True and not any(instance.get("entidades", {}).values()):
            warnings.append(Issue("$.entidades", "se reporta un ataque sin ninguna entidad (usuarios/equipos/ips/dominios)"))
        if not str(instance.get("resumen", "")).strip():
            warnings.append(Issue("$.resumen", "el resumen está vacío"))
    return warnings


def _is_blank(answer: Any) -> bool:
    if answer is None:
        return True
    return isinstance(answer, dict) and all(v is None for v in answer.values())


def load_schemas(schema_dir: Path) -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    for kind, name in SCHEMA_FILES.items():
        path = schema_dir / name
        if not path.is_file():
            raise SchemaError(f"no encuentro el esquema {path}")
        with path.open("rb") as fh:
            loaded = json.loads(fh.read().decode("utf-8"))
        if not isinstance(loaded, dict):
            raise SchemaError(f"esquema inválido: {path}")
        schemas[kind] = loaded
    return schemas


def validate_bytes(data: bytes, schemas: dict[str, dict[str, Any]], *, filename: str,
                   kind: str | None = None) -> Report:
    report = Report(file=filename)
    instance, errors, warnings = parse_strict(data)
    report.errors.extend(errors)
    report.warnings.extend(warnings)
    if instance is None:
        return report
    report.data = instance
    report.kind = kind or detect_kind(instance, filename)
    if report.kind is None:
        report.errors.append(Issue("$.formato", "no sé qué tipo de fichero es: «formato» debe ser "
                                   "incidente-gsec/respuestas/v1 o incidente-gsec/oleada/v1"))
        return report
    report.errors.extend(validate_instance(instance, schemas[report.kind]))
    if not report.errors:
        report.warnings.extend(_semantic_warnings(report.kind, instance, filename))
    return report


def validate_file(path: Path, schemas: dict[str, dict[str, Any]], kind: str | None = None) -> Report:
    if path.is_symlink():
        return Report(file=str(path), errors=[Issue("$", "no se aceptan enlaces simbólicos")])
    try:
        size = path.stat().st_size
    except OSError as exc:
        return Report(file=str(path), errors=[Issue("$", f"no se puede leer: {exc.strerror}")])
    if size > MAX_BYTES:
        return Report(file=str(path), errors=[Issue("$", f"el fichero ocupa {size} bytes; máximo {MAX_BYTES} (1 MiB)")])
    with path.open("rb") as fh:
        data = fh.read(MAX_BYTES + 1)
    return validate_bytes(data, schemas, filename=str(path), kind=kind)


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def _print_report(report: Report, quiet: bool) -> None:
    status = "OK" if report.ok else "KO"
    kind = f" [{report.kind}]" if report.kind else ""
    print(f"{status}{kind} {report.file}")
    for issue in report.errors:
        print(f"  ERROR  {issue}")
    if not quiet:
        for issue in report.warnings:
            print(f"  aviso  {issue}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Valida respuestas.json y oleadaN.json del reto «Incidente en el GSEC».")
    parser.add_argument("files", nargs="*", type=Path, help="ficheros JSON a validar")
    parser.add_argument("--all", type=Path, metavar="DIR", help="valida todos los *.json de un directorio (no recursivo)")
    parser.add_argument("--schema-dir", type=Path, default=Path(__file__).resolve().parent,
                        help="directorio con respuestas.schema.json y oleada.schema.json (por defecto, el de este script)")
    parser.add_argument("--tipo", choices=sorted(SCHEMA_FILES), help="fuerza el tipo de fichero")
    parser.add_argument("--quiet", action="store_true", help="no muestra los avisos")
    parser.add_argument("--json", action="store_true", help="salida en JSON (para integración)")
    args = parser.parse_args(argv)

    files = list(args.files)
    if args.all is not None:
        if not args.all.is_dir():
            print(f"ERROR: {args.all} no es un directorio", file=sys.stderr)
            return 2
        files.extend(sorted(p for p in args.all.iterdir() if p.suffix.lower() == ".json" and p.is_file()
                            and not p.name.endswith(".schema.json")))
    if not files:
        parser.print_usage(sys.stderr)
        print("ERROR: indica al menos un fichero o --all DIR", file=sys.stderr)
        return 2
    try:
        schemas = load_schemas(args.schema_dir)
        reports = [validate_file(p, schemas, args.tipo) for p in files]
    except SchemaError as exc:
        print(f"ERROR de esquema: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([{"file": r.file, "kind": r.kind, "ok": r.ok,
                           "errors": [str(i) for i in r.errors], "warnings": [str(i) for i in r.warnings]}
                          for r in reports], ensure_ascii=False, indent=2))
    else:
        for report in reports:
            _print_report(report, args.quiet)
        bad = sum(1 for r in reports if not r.ok)
        print(f"\n{len(reports) - bad} fichero(s) válido(s), {bad} con errores")
    return 0 if all(r.ok for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Load the public «Incidente en el GSEC» dataset (``output/public``) into one DuckDB file.

Standalone helper for participants: it needs only the Python standard library and the
``duckdb`` package (``pip install duckdb``). One table is created per data source, read
directly from the gzip CSV / JSONL files with explicit column types; UTC timestamps are parsed
into ``TIMESTAMP`` columns. A few physical lines in the streams are deliberately malformed, so
every reader runs with ``ignore_errors=true`` (the skipped lines are reported at the end).

Usage::

    python load_duckdb.py                       # reads ./output/public -> ./incidente_gsec.duckdb
    python load_duckdb.py --public /data/public --db /data/gsec.duckdb
    python load_duckdb.py --waves ./output/waves  # also loads waves/<id>/ bundles (optional)
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

try:
    import duckdb
except ImportError:  # pragma: no cover - friendly message for participants
    sys.stderr.write("duckdb is not installed: run 'pip install duckdb' and retry\n")
    sys.exit(2)

UTC_FORMAT = "%Y-%m-%dT%H:%M:%S.%gZ"  # 2026-09-11T06:40:00.123Z  (%g = milliseconds)
LOCAL_FORMAT = "%Y-%m-%d %H:%M:%S"  # badges: local Europe/Madrid time without zone

# ---- column contracts (SPEC §7) ------------------------------------------------------------
# (table name, relative glob, format, ordered column -> DuckDB type, timestamp format)
STREAMS: list[tuple[str, str, str, dict[str, str], str]] = [
    ("firewall", "firewall/fw_*.csv.gz", "csv", {
        "ts": "TIMESTAMP", "device": "VARCHAR", "src_ip": "VARCHAR", "src_port": "INTEGER",
        "dst_ip": "VARCHAR", "dst_port": "INTEGER", "proto": "VARCHAR", "action": "VARCHAR",
        "bytes_sent": "BIGINT", "bytes_recv": "BIGINT", "duration_ms": "BIGINT", "rule": "VARCHAR",
        "app": "VARCHAR", "src_zone": "VARCHAR", "dst_zone": "VARCHAR", "src_country": "VARCHAR",
        "dst_country": "VARCHAR",
    }, UTC_FORMAT),
    ("vpn", "vpn/vpn_events.csv.gz", "csv", {
        "ts": "TIMESTAMP", "event": "VARCHAR", "user": "VARCHAR", "src_ip": "VARCHAR",
        "src_country": "VARCHAR", "src_asn": "INTEGER", "assigned_ip": "VARCHAR",
        "mfa_method": "VARCHAR", "result": "VARCHAR", "reason": "VARCHAR", "session_id": "VARCHAR",
        "client_os": "VARCHAR",
    }, UTC_FORMAT),
    ("proxy", "proxy/proxy_*.csv.gz", "csv", {
        "ts": "TIMESTAMP", "client_ip": "VARCHAR", "user": "VARCHAR", "method": "VARCHAR",
        "scheme": "VARCHAR", "host": "VARCHAR", "path": "VARCHAR", "status": "INTEGER",
        "bytes_in": "BIGINT", "bytes_out": "BIGINT", "content_type": "VARCHAR", "category": "VARCHAR",
        "action": "VARCHAR", "user_agent": "VARCHAR", "referer": "VARCHAR",
    }, UTC_FORMAT),
    ("dns", "dns/dns_*.jsonl.gz", "json", {
        "ts": "TIMESTAMP", "client_ip": "VARCHAR", "qname": "VARCHAR", "qtype": "VARCHAR",
        "rcode": "VARCHAR", "answers": "VARCHAR[]", "resp_bytes": "INTEGER", "resolver": "VARCHAR",
    }, UTC_FORMAT),
    ("email", "email/gateway_events.csv.gz", "csv", {
        "ts": "TIMESTAMP", "msg_id": "VARCHAR", "direction": "VARCHAR", "from": "VARCHAR",
        "to": "VARCHAR", "subject": "VARCHAR", "attachments": "VARCHAR", "urls": "VARCHAR",
        "spf": "VARCHAR", "dkim": "VARCHAR", "verdict": "VARCHAR", "action": "VARCHAR",
        "size_bytes": "BIGINT",
    }, UTC_FORMAT),
    ("edr", "edr/edr_*.jsonl.gz", "json", {
        "ts": "TIMESTAMP", "host": "VARCHAR", "user": "VARCHAR", "event": "VARCHAR",
        "event_id": "INTEGER", "pid": "INTEGER", "ppid": "INTEGER", "image": "VARCHAR",
        "cmdline": "VARCHAR", "parent_image": "VARCHAR", "parent_cmdline": "VARCHAR",
        "sha256": "VARCHAR", "signed": "BOOLEAN", "signer": "VARCHAR", "integrity": "VARCHAR",
        "dst_ip": "VARCHAR", "dst_port": "INTEGER", "dst_host": "VARCHAR", "file_path": "VARCHAR",
        "target_object": "VARCHAR", "details": "VARCHAR",
    }, UTC_FORMAT),
    ("winsec", "winsec/winsec_*.jsonl.gz", "json", {
        "ts": "TIMESTAMP", "host": "VARCHAR", "channel": "VARCHAR", "event_id": "INTEGER",
        "subject_user": "VARCHAR", "target_user": "VARCHAR", "target_domain": "VARCHAR",
        "logon_type": "INTEGER", "logon_id": "VARCHAR", "src_ip": "VARCHAR", "src_host": "VARCHAR",
        "process_name": "VARCHAR", "status": "VARCHAR", "sub_status": "VARCHAR",
        "privileges": "VARCHAR", "group": "VARCHAR", "member": "VARCHAR", "task_name": "VARCHAR",
        "service_name": "VARCHAR", "file_path": "VARCHAR",
    }, UTC_FORMAT),
    ("dbaudit", "dbaudit/intel_audit_*.csv.gz", "csv", {  # PostgreSQL + pgaudit
        "ts": "TIMESTAMP", "db_user": "VARCHAR", "database": "VARCHAR", "client_ip": "VARCHAR",
        "client_host": "VARCHAR", "application_name": "VARCHAR", "session_id": "VARCHAR",
        "statement_id": "BIGINT", "class": "VARCHAR", "command": "VARCHAR",
        "object_schema": "VARCHAR", "object_name": "VARCHAR", "statement": "VARCHAR",
        "rows": "BIGINT", "result": "VARCHAR",
    }, UTC_FORMAT),
    ("sandbox", "sandbox/detonations_*.jsonl.gz", "json", {  # detonation farm (VLAN 60)
        "ts": "TIMESTAMP", "run_id": "VARCHAR", "vm": "VARCHAR", "vm_ip": "VARCHAR",
        "sample_sha256": "VARCHAR", "sample_name": "VARCHAR", "submitted_by": "VARCHAR",
        "case_id": "VARCHAR", "origin": "VARCHAR", "duration_s": "INTEGER", "verdict": "VARCHAR",
        "score": "INTEGER", "family": "VARCHAR", "observed_domains": "VARCHAR[]",
        "observed_ips": "VARCHAR[]", "observed_urls": "VARCHAR[]", "notes": "VARCHAR",
    }, UTC_FORMAT),
    ("badges", "badges/accesos_fisicos.csv.gz", "csv", {
        "ts_local": "TIMESTAMP", "badge_id": "VARCHAR", "user": "VARCHAR", "door_id": "VARCHAR",
        "door_name": "VARCHAR", "building": "VARCHAR", "direction": "VARCHAR", "result": "VARCHAR",
    }, LOCAL_FORMAT),
]

STATIC: list[tuple[str, str, dict[str, str], str | None]] = [
    ("tickets", "extras/tickets.csv", {
        "ticket_id": "VARCHAR", "created": "TIMESTAMP", "updated": "TIMESTAMP",
        "requester": "VARCHAR", "assignee": "VARCHAR", "category": "VARCHAR", "status": "VARCHAR",
        "subject": "VARCHAR", "body": "VARCHAR",
    }, UTC_FORMAT),
    ("ti_iocs", "ti/iocs.csv", {
        "indicator": "VARCHAR", "type": "VARCHAR", "threat": "VARCHAR", "confidence": "INTEGER",
        "source": "VARCHAR", "first_seen": "DATE", "last_seen": "DATE", "tags": "VARCHAR",
    }, None),
    ("inv_users", "inventory/users.csv", {
        "user": "VARCHAR", "nombre": "VARCHAR", "apellidos": "VARCHAR", "email": "VARCHAR",
        "departamento": "VARCHAR", "puesto": "VARCHAR", "host_principal": "VARCHAR",
        "badge_id": "VARCHAR", "fecha_alta": "DATE", "activo": "BOOLEAN", "grupos": "VARCHAR",
    }, None),
    ("inv_hosts", "inventory/hosts.csv", {
        "host": "VARCHAR", "ip": "VARCHAR", "mac": "VARCHAR", "os": "VARCHAR", "tipo": "VARCHAR",
        "departamento": "VARCHAR", "ubicacion": "VARCHAR", "vlan": "INTEGER", "propietario": "VARCHAR",
    }, None),
    ("inv_departamentos", "inventory/departamentos.csv", {
        "id": "VARCHAR", "nombre": "VARCHAR", "planta": "INTEGER", "responsable": "VARCHAR",
    }, None),
    ("inv_turnos", "inventory/turnos.csv", {
        "user": "VARCHAR", "fecha": "DATE", "turno": "VARCHAR",
    }, None),
    ("inv_servicios_externos", "inventory/servicios_externos.csv", {
        "servicio": "VARCHAR", "host": "VARCHAR", "ip": "VARCHAR", "proveedor": "VARCHAR",
        "descripcion": "VARCHAR",
    }, None),
    ("inv_socios", "inventory/socios.csv", {
        "socio_id": "VARCHAR", "nombre": "VARCHAR", "pais": "VARCHAR", "tipo": "VARCHAR",
        "tlp_por_defecto": "VARCHAR", "contacto": "VARCHAR",
    }, None),
    ("inv_casos", "inventory/casos.csv", {
        "case_id": "VARCHAR", "titulo": "VARCHAR", "socio_id": "VARCHAR", "tlp": "VARCHAR",
        "analista_asignado": "VARCHAR", "estado": "VARCHAR", "fecha_apertura": "DATE",
        "fecha_cierre": "DATE",
    }, None),
    ("inv_personas_objetivo", "inventory/personas_objetivo.csv", {
        "target_id": "VARCHAR", "nombre": "VARCHAR", "apellidos": "VARCHAR", "email": "VARCHAR",
        "organizacion": "VARCHAR", "pais": "VARCHAR", "case_id": "VARCHAR", "confidencial": "BOOLEAN",
    }, None),
    ("geoip", "extras/geoip_synthetic.csv", {
        "network_cidr": "VARCHAR", "country": "VARCHAR", "asn": "BIGINT", "as_name": "VARCHAR",
    }, None),
]
#: static tables that wave bundles may also ship (loaded into the wave schema when present)
WAVE_STATIC: frozenset[str] = frozenset({"tickets"})


def _ident(name: str) -> str:
    """Quote an SQL identifier (column names such as ``from``/``to``/``group`` are keywords)."""
    return '"' + name.replace('"', '""') + '"'


def _struct(columns: dict[str, str]) -> str:
    return "{" + ", ".join(f"'{name}': '{typ}'" for name, typ in columns.items()) + "}"


def _literal(value: str) -> str:
    """Quote an SQL string literal (single quotes doubled; backslashes are not special)."""
    return "'" + value.replace("'", "''") + "'"


def _json_spec(columns: dict[str, str]) -> str:
    """``json_transform`` structure: ``{"col": "TYPE", "list_col": ["TYPE"]}``."""
    parts = []
    for name, typ in columns.items():
        spec = f'["{typ[:-2]}"]' if typ.endswith("[]") else f'"{typ}"'
        parts.append(f'"{name}": {spec}')
    return "{" + ", ".join(parts) + "}"


def _reader_sql(fmt: str, files: list[Path], columns: dict[str, str],
                ts_format: str | None) -> str:
    """Table expression reading an explicit list of files.

    The paths are inlined as literals (not bound parameters) because table-function arguments
    must be constant at bind time in every DuckDB release.

    * CSV: ``read_csv`` with the exact column contract; ``strict_mode=false`` (DuckDB >= 1.2)
      plus ``ignore_errors`` drop the deliberately malformed physical lines.
    * JSONL: ``read_json`` aborts on a truncated object even with ``ignore_errors``, so the
      files are read as raw text lines (one VARCHAR column, delimiter that never occurs) and
      each valid line is parsed with ``json_transform`` into the typed struct.
    """
    paths = "[" + ", ".join(_literal(str(p)) for p in files) + "]"
    if fmt == "csv":
        opts = [f"columns={_struct(columns)}", "ignore_errors=true", "header=true", "delim=','",
                "quote='\"'", "escape='\"'", "nullstr=''", "max_line_size=1048576",
                "strict_mode=false"]
        if ts_format:
            opts.append(f"timestampformat='{ts_format}'")
        return f"read_csv({paths}, " + ", ".join(opts) + ")"
    lines = (f"read_csv({paths}, columns={{'line': 'VARCHAR'}}, delim='\\x01', quote='', escape='', "
             "header=false, ignore_errors=true, strict_mode=false, max_line_size=1048576)")
    # S608: the statement is built from code constants and quoted literals only (no user input)
    return (f"(SELECT unnest(json_transform(line, {_literal(_json_spec(columns))})) "  # noqa: S608
            f"FROM {lines} WHERE json_valid(line))")


def _count_physical_lines(path: Path) -> int:
    """Number of newline characters in a (possibly gzip) file - used for the skipped-lines hint."""
    import gzip

    n = 0
    with (gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb")) as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            n += chunk.count(b"\n")
    return n


def load_table(con: duckdb.DuckDBPyConnection, table: str, pattern: Path, fmt: str,
               columns: dict[str, str], ts_format: str | None, schema: str | None = None) -> int:
    files = sorted(pattern.parent.glob(pattern.name)) if any(ch in pattern.name for ch in "*?[") \
        else ([pattern] if pattern.is_file() else [])
    if not files:
        return -1
    target = f"{_ident(schema)}.{_ident(table)}" if schema else _ident(table)
    reader = _reader_sql(fmt, [p.resolve() for p in files], columns, ts_format)
    # S608: identifiers are quoted code constants; paths are quoted literals (see _reader_sql)
    con.execute(f"CREATE OR REPLACE TABLE {target} AS SELECT * FROM {reader}")  # noqa: S608
    row = con.execute(f"SELECT count(*) FROM {target}").fetchone()  # noqa: S608
    return int(row[0]) if row else 0


def load_bundle(con: duckdb.DuckDBPyConnection, public: Path, schema: str | None,
                include_static: bool) -> list[tuple[str, int, int]]:
    """Load every table found under ``public``; returns ``(table, rows, physical_lines)``."""
    report: list[tuple[str, int, int]] = []
    for table, rel, fmt, columns, ts_format in STREAMS:
        pattern = public / rel
        rows = load_table(con, table, pattern, fmt, columns, ts_format, schema)
        if rows < 0:
            continue
        files = sorted(pattern.parent.glob(pattern.name))
        physical = sum(_count_physical_lines(p) for p in files)
        if fmt == "csv":
            physical -= len(files)  # header lines
        report.append((table, rows, physical))
    if include_static:
        for table, rel, columns, static_ts in STATIC:
            rows = load_table(con, table, public / rel, "csv", columns, static_ts, schema)
            if rows >= 0:
                report.append((table, rows, rows))
    else:  # wave bundles only carry the incremental static tables (tickets)
        for table, rel, columns, static_ts in STATIC:
            if table in WAVE_STATIC:
                rows = load_table(con, table, public / rel, "csv", columns, static_ts, schema)
                if rows >= 0:
                    report.append((table, rows, rows))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--public", type=Path, default=Path("output/public"),
                        help="directory with the public dataset (default: output/public)")
    parser.add_argument("--db", type=Path, default=Path("incidente_gsec.duckdb"),
                        help="DuckDB database file to create/update (default: incidente_gsec.duckdb)")
    parser.add_argument("--waves", type=Path, default=None,
                        help="optional output/waves directory; each wave is loaded into its own "
                             "schema (wave1.proxy, wave1.edr, ...)")
    parser.add_argument("--threads", type=int, default=None, help="DuckDB worker threads")
    args = parser.parse_args(argv)

    public: Path = args.public
    if not (public / "README_DATASET_ES.md").is_file():
        sys.stderr.write(f"error: {public} does not look like output/public "
                         "(README_DATASET_ES.md not found)\n")
        return 1
    t0 = time.perf_counter()
    con = duckdb.connect(str(args.db))
    if args.threads:
        con.execute(f"SET threads={int(args.threads)}")
    con.execute("SET preserve_insertion_order=false")

    print(f"loading {public} -> {args.db}")
    report = load_bundle(con, public, None, include_static=True)
    total = 0
    for table, rows, physical in report:
        skipped = max(0, physical - rows)
        note = f"  ({skipped} physical lines skipped as malformed)" if skipped else ""
        print(f"  {table:<24}{rows:>14,} rows{note}")
        total += rows
    if args.waves and args.waves.is_dir():
        for wdir in sorted(p for p in args.waves.iterdir() if p.is_dir()):
            schema = wdir.name
            con.execute(f"CREATE SCHEMA IF NOT EXISTS {_ident(schema)}")
            wreport = load_bundle(con, wdir, schema, include_static=False)
            for table, rows, _ in wreport:
                print(f"  {schema}.{table:<16}{rows:>14,} rows")
                total += rows
    con.close()
    print(f"done: {total:,} rows in {time.perf_counter() - t0:.1f}s -> {args.db}")
    print("try:  duckdb incidente_gsec.duckdb  then  SELECT verdict, count(*) FROM sandbox GROUP BY 1;")
    return 0


if __name__ == "__main__":
    sys.exit(main())

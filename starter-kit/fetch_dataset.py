#!/usr/bin/env python3
"""Download and verify the «Incidente en el GSEC» dataset from the GitHub Releases of the challenge.

Standard library only (Python >= 3.10). Every asset is fetched anonymously from
``https://github.com/ORG/REPO/releases/download/TAG/ASSET`` (retries with back-off), its SHA-256
is checked against the ``SHA256SUMS`` of the release **before** anything is extracted, and the
tarballs are unpacked with a hardened extractor (no absolute paths, no ``..``, no links or
special files, fixed permissions, size caps). A local mirror (pendrive) works the same way with
``--from-dir``.

Resulting layout (what ``load_duckdb.py`` expects)::

    <dest>/public/<fuente>/...            release base   (default dest: ./output)
    <dest>/waves/wave<N>/<fuente>/...     release oleada-N (``--wave N``)
    <dest>/descargas/<tag>/               SHA256SUMS, manifest.json (and the archives with --keep)

Usage::

    python3 fetch_dataset.py                          # defaults from dataset_source.json
    python3 fetch_dataset.py --wave 1
    python3 fetch_dataset.py --only firewall,proxy,contexto
    python3 fetch_dataset.py --from-dir /Volumes/MALACKATHON [--wave 2]
    python3 fetch_dataset.py --repo ORG/REPO --tag dataset-v1.1 --dest datos

Exit codes: 0 ok · 1 usage/configuration · 2 download failed or release not available ·
3 integrity failure (checksum or unsafe archive) · 4 local file-system error.
Messages are in Spanish (participants read them); code and comments are in English.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

SOURCE_FILE = "dataset_source.json"
SUMS_NAME = "SHA256SUMS"
README_NAME = "README_DATASET_ES.md"
MANIFEST_NAME = "manifest.json"
USER_AGENT = f"incidente-gsec-fetch/{__version__} (python-urllib; +https://github.com)"
CHUNK = 1 << 20
MAX_SUMS_BYTES = 64 * 1024
MAX_MEMBERS = 20_000
MAX_MEMBER_BYTES = 4 << 30       # 4 GiB per file
MAX_TOTAL_BYTES = 16 << 30       # 16 GiB per archive
EXIT_OK, EXIT_USAGE, EXIT_DOWNLOAD, EXIT_INTEGRITY, EXIT_IO = 0, 1, 2, 3, 4

_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
_SOURCE_RE = re.compile(r"^[a-z0-9_]{1,40}$")


class FetchError(Exception):
    def __init__(self, message: str, code: int = EXIT_DOWNLOAD) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Source:
    repo: str | None
    tag_base: str
    wave_tag_prefix: str


def load_source_defaults(script_dir: Path) -> Source:
    """Defaults written by the organisers next to this script (missing file => no defaults)."""
    source = Source(repo=None, tag_base="dataset-v1", wave_tag_prefix="oleada-")
    path = script_dir / SOURCE_FILE
    if not path.is_file():
        return source
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FetchError(f"{path} no se puede leer: {exc}", EXIT_USAGE) from exc
    if not isinstance(loaded, dict):
        raise FetchError(f"{path}: se esperaba un objeto JSON", EXIT_USAGE)
    repo = loaded.get("repo")
    if isinstance(repo, str) and repo:
        source.repo = validate_repo(repo)
    if isinstance(loaded.get("tag_base"), str):
        source.tag_base = validate_tag(loaded["tag_base"])
    if isinstance(loaded.get("wave_tag_prefix"), str):
        source.wave_tag_prefix = validate_tag(loaded["wave_tag_prefix"] + "1")[:-1]
    return source


def validate_repo(value: str) -> str:
    if not _REPO_RE.match(value) or value.endswith((".", "/")):
        raise FetchError(f"repositorio inválido (se esperaba ORG/REPO): {value!r}", EXIT_USAGE)
    return value


def validate_tag(value: str) -> str:
    if not _TAG_RE.match(value) or ".." in value:
        raise FetchError(f"etiqueta de release inválida: {value!r}", EXIT_USAGE)
    return value


def human(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1000 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}".replace(".", ",")
        size /= 1000
    return f"{size:.1f} GB"


# ---------------------------------------------------------------------------------------------
# SHA256SUMS
# ---------------------------------------------------------------------------------------------


def parse_sums(text: str) -> dict[str, str]:
    """``{asset: sha256}`` from ``shasum``-style lines; refuses odd names (no paths, no spaces)."""
    sums: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        digest = parts[0].lower() if parts else ""
        name = parts[1].strip().lstrip("*") if len(parts) == 2 else ""
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or not _ASSET_RE.match(name):
            raise FetchError(f"{SUMS_NAME}: línea {number} inválida", EXIT_INTEGRITY)
        if name in sums:
            raise FetchError(f"{SUMS_NAME}: «{name}» aparece dos veces", EXIT_INTEGRITY)
        sums[name] = digest
    if not sums:
        raise FetchError(f"{SUMS_NAME} está vacío", EXIT_INTEGRITY)
    return sums


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------------------------
# HTTP (anonymous, retries with exponential back-off)
# ---------------------------------------------------------------------------------------------


class Downloader:
    def __init__(self, repo: str, tag: str, *, timeout: float, retries: int, quiet: bool) -> None:
        self.base = f"https://github.com/{repo}/releases/download/{tag}/"
        self.timeout = timeout
        self.retries = max(1, retries)
        self.quiet = quiet
        self._context: ssl.SSLContext | None = None

    # Some Python builds (notably python.org installers on macOS before running
    # "Install Certificates.command") ship WITHOUT a CA bundle, so every HTTPS request fails
    # with CERTIFICATE_VERIFY_FAILED. We never disable verification; instead we try, in order,
    # the default context, certifi (if installed) and the OS bundles, and explain the fix.
    _OS_BUNDLES = ("/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
                   "/etc/pki/tls/certs/ca-bundle.crt", "/usr/local/etc/openssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem")

    def _contexts(self) -> list[tuple[str, ssl.SSLContext]]:
        out: list[tuple[str, ssl.SSLContext]] = [("sistema", ssl.create_default_context())]
        try:
            import certifi  # type: ignore[import-not-found,unused-ignore]  # optional dependency
            out.append(("certifi", ssl.create_default_context(cafile=certifi.where())))
        except Exception:  # noqa: S110  (certifi absent or broken: simply not an option)
            pass
        for bundle in self._OS_BUNDLES:
            if os.path.isfile(bundle):
                try:
                    out.append((bundle, ssl.create_default_context(cafile=bundle)))
                except (ssl.SSLError, OSError):
                    continue
        return out

    def _open(self, name: str) -> Any:  # http.client.HTTPResponse (urllib's return type is private)
        url = self.base + name
        if not url.startswith("https://github.com/"):
            raise FetchError(f"URL no permitida: {url}", EXIT_USAGE)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,  # noqa: S310
                                                       "Accept": "application/octet-stream"})
        if self._context is not None:
            return urllib.request.urlopen(request, timeout=self.timeout, context=self._context)  # noqa: S310
        last: Exception | None = None
        for label, ctx in self._contexts():
            try:
                response = urllib.request.urlopen(request, timeout=self.timeout, context=ctx)  # noqa: S310  (https://github.com/ only)
                self._context = ctx
                if label != "sistema":
                    self.say(f"  TLS: usando el almacén de certificados «{label}» (el de Python no tiene raíces)")
                return response
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, ssl.SSLCertVerificationError):
                    last = exc
                    continue
                raise
        raise FetchError(
            "no se pudo verificar el certificado TLS de github.com porque este Python no tiene raíces de "
            "confianza instaladas. Soluciones: (1) macOS con Python de python.org: ejecuta "
            "«/Applications/Python 3.x/Install Certificates.command»; (2) `python3 -m pip install certifi` y "
            "vuelve a lanzar; (3) usa el pendrive: `--from-dir /Volumes/MALACKATHON`. "
            f"Detalle: {last}", EXIT_DOWNLOAD)

    def fetch(self, name: str, dest: Path | None, expected: str | None = None, *, max_bytes: int | None = None) -> bytes | str:
        """Download ``name``; return the bytes (``dest`` None) or the hex digest of the file written
        to ``dest`` (streamed, hashed on the fly). Permanent HTTP errors are not retried."""
        last: Exception | None = None
        for attempt in range(1, self.retries + 1):
            try:
                return self._fetch_once(name, dest, expected, max_bytes)
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403, 404, 410):
                    hint = " (¿todavía no se ha publicado esta release?)" if exc.code in (403, 404) else ""
                    raise FetchError(f"{name}: HTTP {exc.code}{hint}", EXIT_DOWNLOAD) from exc
                last = exc
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                last = exc
            if attempt < self.retries:
                wait = min(30, 2 ** attempt)
                self.say(f"  reintento {attempt}/{self.retries - 1} de {name} en {wait} s ({last})")
                time.sleep(wait)
        raise FetchError(f"{name}: no se pudo descargar tras {self.retries} intentos: {last}", EXIT_DOWNLOAD)

    def _fetch_once(self, name: str, dest: Path | None, expected: str | None, max_bytes: int | None) -> bytes | str:
        with self._open(name) as response:
            total = response.headers.get("Content-Length")
            size = int(total) if total and total.isdigit() else None
            if dest is None:
                data = bytes(response.read((max_bytes or MAX_SUMS_BYTES) + 1))
                if len(data) > (max_bytes or MAX_SUMS_BYTES):
                    raise FetchError(f"{name}: respuesta demasiado grande", EXIT_INTEGRITY)
                return data
            digest = hashlib.sha256()
            done = 0
            tmp = dest.with_name(dest.name + ".part")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with tmp.open("wb") as out:
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    out.write(chunk)
                    digest.update(chunk)
                    done += len(chunk)
                    if max_bytes is not None and done > max_bytes:
                        raise FetchError(f"{name}: supera el tamaño máximo permitido", EXIT_INTEGRITY)
                    self.progress(name, done, size)
            self.progress(name, done, size, final=True)
            if size is not None and done != size:
                tmp.unlink(missing_ok=True)
                raise ConnectionError(f"descarga incompleta ({done} de {size} bytes)")
            os.replace(tmp, dest)
            got = digest.hexdigest()
            if expected is not None and got != expected:
                dest.unlink(missing_ok=True)
                raise FetchError(f"{name}: la suma SHA-256 no coincide con {SUMS_NAME} (descarga corrupta o "
                                 "manipulada); vuelve a intentarlo o avisa a la organización", EXIT_INTEGRITY)
            return got

    def say(self, text: str) -> None:
        if not self.quiet:
            print(text, file=sys.stderr)

    def progress(self, name: str, done: int, size: int | None, *, final: bool = False) -> None:
        if self.quiet or not sys.stderr.isatty():
            return
        pct = f" {100 * done / size:3.0f}%" if size else ""
        end = "\n" if final else ""
        print(f"\r  {name}: {human(done)}{pct}   ", end=end, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------
# Hardened tar extraction
# ---------------------------------------------------------------------------------------------


def _safe_member_name(member: tarfile.TarInfo) -> str:
    """Normalised relative POSIX path of a member or ``FetchError`` when it is not acceptable."""
    name = member.name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    if not name or name.startswith("/") or "\x00" in name or re.match(r"^[A-Za-z]:", name):
        raise FetchError(f"miembro con ruta no permitida en el archivo: {member.name!r}", EXIT_INTEGRITY)
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise FetchError(f"miembro con ruta no permitida en el archivo: {member.name!r}", EXIT_INTEGRITY)
    return name


def validate_members(tar: tarfile.TarFile, dest: Path) -> list[tuple[tarfile.TarInfo, str]]:
    """Reject links, devices, FIFOs, traversal, oversize content; return ``(member, relpath)``."""
    members = tar.getmembers()
    if len(members) > MAX_MEMBERS:
        raise FetchError(f"el archivo tiene demasiados miembros ({len(members)})", EXIT_INTEGRITY)
    data_filter = getattr(tarfile, "data_filter", None)
    filter_error: type[BaseException] = getattr(tarfile, "FilterError", Exception)
    dest_real = os.path.realpath(dest)
    total = 0
    out: list[tuple[tarfile.TarInfo, str]] = []
    for member in members:
        if not (member.isreg() or member.isdir()):
            raise FetchError(f"miembro no permitido (enlace o fichero especial): {member.name!r}", EXIT_INTEGRITY)
        rel = _safe_member_name(member)
        if member.isreg():
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise FetchError(f"miembro demasiado grande: {member.name!r}", EXIT_INTEGRITY)
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise FetchError("el archivo descomprimido supera el límite de tamaño", EXIT_INTEGRITY)
        target = os.path.realpath(os.path.join(dest_real, rel))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise FetchError(f"el miembro {member.name!r} saldría del directorio de destino", EXIT_INTEGRITY)
        if data_filter is not None:  # Python >= 3.12 (and security back-ports): second opinion
            try:
                data_filter(member, dest_real)
            except filter_error as exc:
                raise FetchError(f"miembro rechazado por el filtro de seguridad: {member.name!r} ({exc})",
                                 EXIT_INTEGRITY) from exc
        out.append((member, rel))
    return out


def extract_archive(archive: Path, dest: Path) -> int:
    """Extract ``archive`` (already verified) into ``dest``; returns the number of files written."""
    written = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            plan = validate_members(tar, dest)
            for member, rel in plan:
                target = dest / rel
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.parent.is_symlink() or target.is_symlink():
                    raise FetchError(f"{target} es (o cuelga de) un enlace simbólico; elimínalo", EXIT_INTEGRITY)
                source = tar.extractfile(member)
                if source is None:
                    raise FetchError(f"no se puede leer el miembro {member.name!r}", EXIT_INTEGRITY)
                tmp = target.with_name(target.name + ".part")
                remaining = member.size
                with source, tmp.open("wb") as out:
                    while remaining > 0:
                        chunk = source.read(min(CHUNK, remaining))
                        if not chunk:
                            raise FetchError(f"miembro truncado: {member.name!r}", EXIT_INTEGRITY)
                        out.write(chunk)
                        remaining -= len(chunk)
                os.chmod(tmp, 0o644)
                os.replace(tmp, target)
                written += 1
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise FetchError(f"{archive.name}: archivo tar.gz dañado o ilegible ({exc})", EXIT_INTEGRITY) from exc
    return written


# ---------------------------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------------------------


def select_assets(sums: dict[str, str], only: list[str] | None) -> list[str]:
    """Assets to fetch: every tarball (or the ``--only`` subset) plus the small bare files."""
    tarballs = sorted(n for n in sums if n.endswith(".tar.gz"))
    others = sorted(n for n in sums if not n.endswith(".tar.gz"))
    if only is None:
        return tarballs + others
    available = {n[len("base_"):-len(".tar.gz")]: n for n in tarballs if n.startswith("base_")}
    chosen: list[str] = []
    for raw in only:
        key = raw.strip().lower()
        key = key[len("base_"):] if key.startswith("base_") else key
        key = key[:-len(".tar.gz")] if key.endswith(".tar.gz") else key
        if not _SOURCE_RE.match(key) or key not in available:
            raise FetchError(f"--only: fuente desconocida «{raw}». Disponibles: {', '.join(sorted(available))}",
                             EXIT_USAGE)
        if available[key] not in chosen:
            chosen.append(available[key])
    return chosen + others


def resolve_local_dir(root: Path, tag: str, is_wave: bool) -> Path:
    """Directory holding SHA256SUMS: ``root`` itself, ``root/release`` or ``root/waves/<tag>``."""
    candidates = [root, root / "waves" / tag if is_wave else root / "release"]
    for candidate in candidates:
        if (candidate / SUMS_NAME).is_file():
            return candidate
    raise FetchError(f"no encuentro {SUMS_NAME} en {root} (ni en {candidates[1]})", EXIT_USAGE)


def main(argv: list[str] | None = None) -> int:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Descarga y verifica el dataset «Incidente en el GSEC».")
    parser.add_argument("--repo", help="repositorio público ORG/REPO (por defecto, el de dataset_source.json)")
    parser.add_argument("--tag", help="etiqueta de la release (por defecto la base, o la de la oleada con --wave)")
    parser.add_argument("--wave", type=int, choices=(1, 2, 3), help="descargar la oleada N en <dest>/waves/waveN")
    parser.add_argument("--dest", type=Path, default=Path("output"), help="directorio raíz (por defecto: output)")
    parser.add_argument("--only", help="subconjunto de fuentes de la release base, p. ej. firewall,proxy,contexto")
    parser.add_argument("--from-dir", type=Path, help="copia local (pendrive/espejo) con SHA256SUMS y los archivos")
    parser.add_argument("--keep", action="store_true", help="conservar los .tar.gz descargados en <dest>/descargas")
    parser.add_argument("--timeout", type=float, default=60.0, help="segundos por conexión (60)")
    parser.add_argument("--retries", type=int, default=4, help="intentos por fichero (4)")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    def say(text: str) -> None:
        if not args.quiet:
            print(text, file=sys.stderr)

    try:
        source = load_source_defaults(script_dir)
        repo = validate_repo(args.repo) if args.repo else source.repo
        is_wave = args.wave is not None
        if args.tag:
            tag = validate_tag(args.tag)
            if not is_wave and tag.startswith(source.wave_tag_prefix) and tag[len(source.wave_tag_prefix):].isdigit():
                args.wave = int(tag[len(source.wave_tag_prefix):])
                is_wave = True
        else:
            tag = f"{source.wave_tag_prefix}{args.wave}" if is_wave else source.tag_base
        if is_wave and args.only:
            raise FetchError("--only solo se aplica a la release base (las oleadas son un único archivo)", EXIT_USAGE)
        only = [s.strip() for s in args.only.split(",") if s.strip()] if args.only is not None else None
        if only is not None and not only:
            raise FetchError("--only necesita al menos una fuente", EXIT_USAGE)
        if args.from_dir is None and repo is None:
            raise FetchError(f"indica --repo ORG/REPO (no hay {SOURCE_FILE} junto al script) o usa --from-dir", EXIT_USAGE)

        dest_root: Path = args.dest
        target = dest_root / "waves" / f"wave{args.wave}" if is_wave else dest_root / "public"
        cache = dest_root / "descargas" / tag
        target.mkdir(parents=True, exist_ok=True)
        cache.mkdir(parents=True, exist_ok=True)

        downloader: Downloader | None = None
        local: Path | None = None
        if args.from_dir is not None:
            local = resolve_local_dir(args.from_dir, tag, is_wave)
            say(f"Origen local: {local}")
            sums_text = (local / SUMS_NAME).read_text(encoding="utf-8")
        else:
            assert repo is not None
            downloader = Downloader(repo, tag, timeout=args.timeout, retries=args.retries, quiet=args.quiet)
            say(f"Release {tag} de https://github.com/{repo}")
            payload = downloader.fetch(SUMS_NAME, None)
            assert isinstance(payload, bytes)
            sums_text = payload.decode("utf-8")
        sums = parse_sums(sums_text)
        (cache / SUMS_NAME).write_text(sums_text, encoding="utf-8")
        assets = select_assets(sums, only)
        say(f"{len(assets)} ficheros: {', '.join(assets)}")

        extracted_files = 0
        for name in assets:
            expected = sums[name]
            if local is not None:
                path = local / name
                if not path.is_file():
                    raise FetchError(f"falta {path}", EXIT_USAGE)
                say(f"  {name}: verificando {human(path.stat().st_size)}…")
                if sha256_of(path) != expected:
                    raise FetchError(f"{name}: la suma SHA-256 no coincide con {SUMS_NAME} (copia corrupta o manipulada)",
                                     EXIT_INTEGRITY)
            else:
                assert downloader is not None
                path = cache / name
                downloader.fetch(name, path, expected, max_bytes=MAX_TOTAL_BYTES)
            if name.endswith(".tar.gz"):
                count = extract_archive(path, target)
                extracted_files += count
                say(f"  {name}: OK, {count} ficheros extraídos")
                if local is None and not args.keep:
                    path.unlink(missing_ok=True)
            elif name == README_NAME:
                shutil.copyfile(path, target / README_NAME)
                say(f"  {name}: OK")
            elif local is not None:
                shutil.copyfile(path, cache / name)
                say(f"  {name}: OK")
            else:
                say(f"  {name}: OK")
        say(f"Listo: {extracted_files} ficheros en {target}")
        if not is_wave:
            say(f"Siguiente paso: python3 {script_dir / 'load_duckdb.py'} --public {target}")
        else:
            say(f"Siguiente paso: python3 {script_dir / 'load_duckdb.py'} --public {dest_root / 'public'} "
                f"--waves {dest_root / 'waves'}")
        return EXIT_OK
    except FetchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print("\nInterrumpido.", file=sys.stderr)
        return EXIT_DOWNLOAD
    except OSError as exc:
        print(f"ERROR de disco/permisos: {exc}", file=sys.stderr)
        return EXIT_IO


if __name__ == "__main__":
    sys.exit(main())

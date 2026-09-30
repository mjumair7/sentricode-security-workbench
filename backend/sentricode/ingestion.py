"""Bounded archive handling. Uploaded source is data, never an executable job."""
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zlib
import lzma
from urllib.parse import quote, urlparse
from zipfile import BadZipFile, ZipFile
import httpx
from .config import Settings


class IngestionError(ValueError):
    pass


def parse_github_url(value: str) -> tuple[str, str]:
    try:
        parsed = urlparse(value)
    except ValueError:
        raise IngestionError("Use a valid HTTPS github.com owner/repository URL") from None
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or parsed.query or parsed.fragment or parsed.params:
        raise IngestionError("Use an HTTPS github.com owner/repository URL")
    match = re.fullmatch(r"/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})/?", parsed.path)
    if not match:
        raise IngestionError("Use a repository URL such as https://github.com/owner/project")
    owner, repo = match.groups()
    repo = repo.removesuffix(".git")
    if not repo or repo in {".", ".."}:
        raise IngestionError("Invalid repository name")
    return owner, repo


def validate_ref(ref: str | None) -> str:
    value = ref or "HEAD"
    if len(value) > 200 or not re.fullmatch(r"[A-Za-z0-9_./-]+", value) or ".." in value or value.startswith("/"):
        raise IngestionError("Invalid branch, tag, or commit reference")
    return value


def extract_zip(archive: Path, destination: Path, settings: Settings) -> Path:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    limit = settings.max_extracted_mb * 1024 * 1024
    try:
        with ZipFile(archive) as zipped:
            members = zipped.infolist()
            if len(members) > settings.max_files:
                raise IngestionError("Archive contains too many entries")
            planned = []
            total = 0
            seen = set()
            for member in members:
                name = member.filename
                path = PurePosixPath(name)
                if (not name or "\\" in name or "\x00" in name or path.is_absolute()
                        or any(part in {"..", "."} for part in name.split("/"))
                        or ":" in name or len(name) > 1024):
                    raise IngestionError("Archive contains an unsafe path")
                kind = stat.S_IFMT(member.external_attr >> 16)
                if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise IngestionError("Archive contains links or special files")
                if member.flag_bits & 1:
                    raise IngestionError("Encrypted archives are not supported")
                canonical = str(path).casefold()
                if canonical in seen:
                    raise IngestionError("Archive contains duplicate paths")
                seen.add(canonical)
                total += member.file_size
                if total > limit or member.file_size > 20 * 1024 * 1024:
                    raise IngestionError("Archive exceeds the expanded size limit (20 MB per file)")
                if member.file_size > 1024 * 1024 and member.file_size > max(1, member.compress_size) * 200:
                    raise IngestionError("Archive compression ratio exceeds the safety limit")
                target = destination.joinpath(*path.parts)
                if not target.resolve().is_relative_to(destination.resolve()):
                    raise IngestionError("Archive path escapes the scan directory")
                planned.append((member, target))
            written = 0
            for member, target in planned:
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with zipped.open(member) as source, target.open("xb") as output:
                    while chunk := source.read(64 * 1024):
                        written += len(chunk)
                        if written > limit:
                            raise IngestionError("Archive exceeds the expanded size limit")
                        output.write(chunk)
                target.chmod(0o600)
        children = list(destination.iterdir())
        if len(children) == 1 and children[0].is_dir():
            return children[0]
        return destination
    except IngestionError:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    except (BadZipFile, OSError, RuntimeError, NotImplementedError, ValueError, EOFError, zlib.error, lzma.LZMAError) as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise IngestionError("Archive is unreadable or contains conflicting paths") from exc


def download_github(url: str, ref: str | None, archive: Path, settings: Settings):
    owner, repo = parse_github_url(url)
    revision = validate_ref(ref)
    endpoint = f"https://api.github.com/repos/{owner}/{repo}/zipball/{quote(revision, safe='')}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "SentriCode/0.1"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    with httpx.Client(timeout=httpx.Timeout(90, connect=10), follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", endpoint, headers=headers) as response:
            if response.status_code not in {301, 302, 303, 307, 308}:
                raise IngestionError("GitHub could not provide this repository. Check its URL, ref, and token access.")
            location = response.headers.get("location", "")
            parsed = urlparse(location)
            if parsed.scheme != "https" or parsed.netloc != "codeload.github.com":
                raise IngestionError("GitHub returned an unexpected archive location")
        # The redirect can contain a short-lived GitHub download credential; never log it.
        with client.stream("GET", location, headers={"User-Agent": "SentriCode/0.1"}) as response:
            if response.status_code != 200:
                raise IngestionError("GitHub archive download failed")
            total = 0
            with archive.open("xb") as output:
                for chunk in response.iter_bytes(64 * 1024):
                    total += len(chunk)
                    if total > settings.max_upload_mb * 1024 * 1024:
                        raise IngestionError("GitHub archive exceeds the download limit")
                    output.write(chunk)


def write_demo(destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    (destination / "app.py").write_text('''# Intentionally unsafe sample. Scan it; do not run it.
import pickle
import subprocess
import requests
from flask import Flask, request
app = Flask(__name__)
API_KEY = "sc_demo_7f4b62d8c1a095e3_never_valid"  # Deliberately invalid example
@app.get("/users")
def users():
    name = request.args.get("name", "")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return "demo"
@app.post("/import")
def import_record():
    return pickle.loads(request.data)
@app.get("/ping")
def ping():
    return subprocess.run(request.args["host"], shell=True)
requests.get("https://example.com", verify=False)
app.run(debug=True)
''')
    (destination / "Dockerfile").write_text("FROM python:latest\nUSER root\nCOPY . /app\n")
    (destination / "requirements.txt").write_text("flask==0.12\nrequests==2.19.1\n")
    (destination / "README.md").write_text("Intentionally vulnerable SentriCode demonstration. Never deploy or execute it.\n")
    return destination

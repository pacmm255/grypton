"""Locked, atomic records, derived from Krypton's workspace ledger design.

Unlike the original ledger, malformed state is reported instead of skipped;
unique temporary files and locked reads prevent partial-read and rename races.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .config import GryptonError, Settings

MAX_EVIDENCE_BYTES = 160_000
MAX_TOTAL_EVIDENCE_BYTES = 600_000
MAX_EVIDENCE_FILES = 16
ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")


def private_dir(path: Path) -> None:
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise GryptonError("State paths must not contain symlinks.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)


@contextmanager
def locked(path: Path, *, blocking: bool = True):
    private_dir(path.parent)
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise GryptonError("Cannot open the workspace lock.") from exc
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError as exc:
            raise GryptonError("A review is already running for this case.") from exc
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_json(path: Path, value: dict) -> None:
    private_dir(path.parent)
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def read_json(path: Path) -> dict:
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict):
            raise ValueError("expected an object")
        return data
    except (OSError, ValueError) as exc:
        raise GryptonError(f"Cannot read valid state from {path.name}; restore the record before continuing.") from exc


def read_evidence(path: Path) -> tuple[str, str]:
    path = path.expanduser().absolute()
    if "targets" in path.parts or Path("/root/krypton") == path or Path("/root/krypton") in path.parents:
        raise GryptonError("Original-project and targets paths are excluded from evidence import.")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise GryptonError("Evidence must be a regular file with no symlink components.")
    path = path.resolve()
    if Path("/root/krypton") == path or Path("/root/krypton") in path.parents:
        raise GryptonError("Original-project paths are excluded from evidence import.")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise GryptonError("Evidence must be a regular text file.")
            raw = stream.read(MAX_EVIDENCE_BYTES + 1)
        if len(raw) > MAX_EVIDENCE_BYTES:
            raise GryptonError(f"Evidence exceeds {MAX_EVIDENCE_BYTES:,} bytes; supply a focused excerpt.")
        text = raw.decode("utf-8")
        if "\0" in text or not text.strip():
            raise GryptonError("Evidence must be nonempty UTF-8 text.")
        return text, hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError) as exc:
        raise GryptonError("Cannot import this evidence file as UTF-8 text.") from exc


class Store:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = settings.state / "cases"

    def directory(self, case_id: str) -> Path:
        if not ID.fullmatch(case_id):
            raise GryptonError("Invalid case ID; use the ID shown by grypton status.")
        path = self.root / case_id
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise GryptonError("Case paths must not contain symlinks.")
        return path

    def get(self, case_id: str) -> dict:
        path = self.directory(case_id)
        if not (path / "case.json").exists():
            raise GryptonError(f"Unknown case: {case_id}")
        with locked(path / ".lock"):
            value = read_json(path / "case.json")
        if value.get("id") != case_id or not isinstance(value.get("evidence"), list):
            raise GryptonError("Invalid case record; restore the state before continuing.")
        return value

    def list(self) -> list[dict]:
        if not self.root.exists():
            return []
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise GryptonError("State paths must not contain symlinks.")
        cases = [self.get(p.name) for p in self.root.iterdir() if p.is_dir() and ID.fullmatch(p.name)]
        return sorted(cases, key=lambda item: item["updated_at"], reverse=True)

    def create(self, title: str, claim: str) -> dict:
        title, claim = title.strip(), claim.strip()
        if not title or len(title) > 160 or not claim or len(claim) > 12_000:
            raise GryptonError("Provide a title (1–160 characters) and a claim (1–12,000 characters).")
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:48] or "review"
        case_id = f"{slug}-{uuid.uuid4().hex[:10]}"
        now = time.time()
        record = {"id": case_id, "title": title, "claim": claim, "created_at": now,
                  "updated_at": now, "status": "draft", "evidence": [], "runs": []}
        atomic_json(self.directory(case_id) / "case.json", record)
        return record

    def mutate(self, case_id: str, action) -> dict:
        path = self.directory(case_id)
        with locked(path / ".lock"):
            record = read_json(path / "case.json")
            action(record)
            record["updated_at"] = time.time()
            atomic_json(path / "case.json", record)
        return record

    def add_evidence(self, case_id: str, source: Path) -> dict:
        self.get(case_id)
        text, digest = read_evidence(source)
        def add(record):
            if any(item["sha256"] == digest for item in record["evidence"]):
                raise GryptonError("This evidence is already attached (same SHA-256).")
            size = sum(len(item["text"].encode("utf-8")) for item in record["evidence"])
            if len(record["evidence"]) >= MAX_EVIDENCE_FILES or size + len(text.encode("utf-8")) > MAX_TOTAL_EVIDENCE_BYTES:
                raise GryptonError("Evidence budget exceeded; use fewer, focused excerpts.")
            record["evidence"].append({"id": "ev-" + digest[:16], "name": source.name,
                                        "sha256": digest, "text": text, "added_at": time.time()})
            record["status"] = "draft"
        with locked(self.directory(case_id) / ".review.lock", blocking=False):
            return self.mutate(case_id, add)

    def run_lock(self, case_id: str):
        self.get(case_id)
        return locked(self.directory(case_id) / ".review.lock", blocking=False)

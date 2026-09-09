"""Locked, atomic records, derived from Krypton's workspace ledger design.

Unlike the original ledger, malformed state is reported instead of skipped;
unique temporary files and locked reads prevent partial-read and rename races.
"""
from __future__ import annotations

import copy
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
SCHEMA_VERSION = 2
SCOPE_KEYS = ("in_scope", "out_of_scope", "only_severities", "include_classes",
              "exclude_classes", "rules")


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:72] or "engagement"


def empty_scope(kind: str = "auto") -> dict:
    return {"type": kind, **{key: [] for key in SCOPE_KEYS}}


def normalize_case(record: dict) -> dict:
    """Add current fields in memory while keeping older case records readable."""
    record.setdefault("schema_version", SCHEMA_VERSION)
    record.setdefault("target", "")
    record.setdefault("brief", "")
    for key in ("messages", "standing_instructions", "observations", "surface",
                "findings", "resource_events"):
        record.setdefault(key, [])
        if not isinstance(record[key], list):
            raise GryptonError(f"Invalid case record field: {key}.")
    scope = record.setdefault("scope", empty_scope())
    if not isinstance(scope, dict):
        raise GryptonError("Invalid case scope record.")
    scope.setdefault("type", "auto")
    for key in SCOPE_KEYS:
        scope.setdefault(key, [])
        if not isinstance(scope[key], list):
            raise GryptonError(f"Invalid scope field: {key}.")
    return record


def _mark_context_changed(record: dict) -> None:
    if record.get("runs"):
        record["status"] = "draft"
    for finding in record.get("findings", []):
        if finding.get("status") in {"supported", "refuted", "inconclusive"}:
            finding["previous_status"] = finding["status"]
            finding["status"] = "outdated"
            finding["updated_at"] = time.time()


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
        if value.get("id") != case_id or not isinstance(value.get("evidence"), list) or not isinstance(value.get("runs"), list):
            raise GryptonError("Invalid case record; restore the state before continuing.")
        return normalize_case(value)

    def resolve(self, reference: str) -> str:
        """Resolve an exact ID, target, title, or unique ID prefix."""
        reference = reference.strip()
        if ID.fullmatch(reference) and (self.directory(reference) / "case.json").is_file():
            return reference
        wanted = slugify(reference)
        matches = [case for case in self.list()
                   if slugify(case.get("target", case["title"])) == wanted
                   or case["id"] == wanted or case["id"].startswith(wanted + "-")]
        if not matches:
            raise GryptonError(f"Unknown engagement: {reference}")
        if len(matches) > 1:
            ids = ", ".join(case["id"] for case in matches[:5])
            raise GryptonError(f"Engagement reference is ambiguous; use one of: {ids}")
        return matches[0]["id"]

    def list(self) -> list[dict]:
        if not self.root.exists():
            return []
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise GryptonError("State paths must not contain symlinks.")
        cases = [self.get(p.name) for p in self.root.iterdir() if p.is_dir() and ID.fullmatch(p.name)]
        return sorted(cases, key=lambda item: item["updated_at"], reverse=True)

    def create(self, title: str, claim: str, *, stable: bool = False,
               target: str = "", brief: str = "") -> dict:
        title, claim = title.strip(), claim.strip()
        if not title or len(title) > 160 or not claim or len(claim) > 12_000:
            raise GryptonError("Provide a title (1–160 characters) and a claim (1–12,000 characters).")
        slug = slugify(target or title)
        case_id = slug if stable else f"{slug[:48]}-{uuid.uuid4().hex[:10]}"
        if (self.directory(case_id) / "case.json").exists():
            raise GryptonError(f"Engagement {case_id!r} already exists; use `grypton resume {case_id}`.")
        now = time.time()
        record = {"id": case_id, "title": title, "claim": claim, "created_at": now,
                  "updated_at": now, "status": "draft", "evidence": [], "runs": [],
                  "target": target.strip(), "brief": brief.strip(), "messages": [],
                  "standing_instructions": [brief.strip()] if brief.strip() else [], "schema_version": SCHEMA_VERSION,
                  "scope": empty_scope(), "observations": [], "surface": [],
                  "findings": [], "resource_events": []}
        atomic_json(self.directory(case_id) / "case.json", record)
        return record

    def append_message(self, case_id: str, *, role: str, text: str,
                       remember: str = "", disposition: str = "") -> dict:
        text, remember = text.strip(), remember.strip()
        if role not in {"user", "manager", "worker", "system"} or not text or len(text) > 12_000:
            raise GryptonError("Conversation messages must have a valid role and 1–12,000 characters.")

        def append(record):
            messages = record.setdefault("messages", [])
            messages.append({"role": role, "text": text, "at": time.time(),
                             "disposition": disposition})
            del messages[:-200]
            if remember:
                instructions = record.setdefault("standing_instructions", [])
                if remember not in instructions:
                    instructions.append(remember)
                    del instructions[:-50]
                    _mark_context_changed(record)

        return self.mutate(case_id, append)

    def mutate(self, case_id: str, action) -> dict:
        path = self.directory(case_id)
        with locked(path / ".lock"):
            record = normalize_case(read_json(path / "case.json"))
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
            _mark_context_changed(record)
        with locked(self.directory(case_id) / ".review.lock", blocking=False):
            return self.mutate(case_id, add)

    def set_brief(self, case_id: str, brief: str) -> dict:
        brief = brief.strip()
        if not brief or len(brief) > 12_000:
            raise GryptonError("Brief must contain 1–12,000 characters.")
        def update(record):
            if record["brief"] == brief and brief in record["standing_instructions"]:
                return
            record["brief"] = brief
            if brief not in record["standing_instructions"]:
                record["standing_instructions"].append(brief)
                del record["standing_instructions"][:-50]
            _mark_context_changed(record)
        with locked(self.directory(case_id) / ".review.lock", blocking=False):
            return self.mutate(case_id, update)

    def set_target(self, case_id: str, target: str) -> dict:
        target = target.strip()
        if not target or len(target) > 160:
            raise GryptonError("Target/project label must contain 1–160 characters.")
        def update(record):
            if record["target"] == target:
                return
            record["target"] = target
            _mark_context_changed(record)
        with locked(self.directory(case_id) / ".review.lock", blocking=False):
            return self.mutate(case_id, update)

    def set_claim(self, case_id: str, claim: str) -> dict:
        claim = claim.strip()
        if not claim or len(claim) > 12_000:
            raise GryptonError("Claim must contain 1–12,000 characters.")
        def update(record):
            record["claim"] = claim
            _mark_context_changed(record)
        with locked(self.directory(case_id) / ".review.lock", blocking=False):
            return self.mutate(case_id, update)

    def set_scope(self, case_id: str, values: dict) -> dict:
        unknown = set(values) - ({"type"} | set(SCOPE_KEYS))
        if unknown:
            raise GryptonError("Unknown scope fields: " + ", ".join(sorted(unknown)))
        def update(record):
            scope = record["scope"]
            if "type" in values:
                kind = str(values["type"]).strip()
                if kind not in {"auto", "web", "apk", "network", "cidr", "binary", "contract", "code"}:
                    raise GryptonError("Unknown engagement type.")
                scope["type"] = kind
            for key in SCOPE_KEYS:
                if key not in values:
                    continue
                items = values[key]
                if not isinstance(items, list) or len(items) > 100:
                    raise GryptonError(f"Scope field {key} must be a bounded list.")
                cleaned = []
                for item in items:
                    text = str(item).strip()
                    if not text or len(text) > 500:
                        raise GryptonError(f"Scope field {key} contains an invalid item.")
                    if text not in cleaned:
                        cleaned.append(text)
                scope[key] = cleaned
            _mark_context_changed(record)
        with locked(self.directory(case_id) / ".review.lock", blocking=False):
            return self.mutate(case_id, update)

    @staticmethod
    def _next_id(items: list[dict], prefix: str) -> str:
        used = {item.get("id") for item in items}
        number = len(items) + 1
        while f"{prefix}-{number:04d}" in used:
            number += 1
        return f"{prefix}-{number:04d}"

    def append_record(self, case_id: str, kind: str, text: str, *, category: str = "note") -> dict:
        if kind not in {"observations", "surface"}:
            raise GryptonError("Record kind must be observations or surface.")
        text, category = text.strip(), category.strip().lower()
        if not text or len(text) > 12_000 or not ID.fullmatch(slugify(category)):
            raise GryptonError("Record text or category is invalid.")
        result = {}
        def append(record):
            items = record[kind]
            if len(items) >= 500:
                raise GryptonError(f"This engagement has reached its {kind} record limit.")
            item = {"id": self._next_id(items, "obs" if kind == "observations" else "surface"),
                    "category": slugify(category), "text": text, "created_at": time.time()}
            items.append(item)
            _mark_context_changed(record)
            result.update(copy.deepcopy(item))
        self.mutate(case_id, append)
        return result

    def add_finding(self, case_id: str, title: str, claim: str, *,
                    evidence_ids: list[str] | None = None, source: str = "operator") -> dict:
        title, claim = title.strip(), claim.strip()
        if not title or len(title) > 200 or not claim or len(claim) > 12_000:
            raise GryptonError("Finding title or claim is invalid.")
        result = {}
        def append(record):
            if len(record["findings"]) >= 200:
                raise GryptonError("This engagement has reached its 200-finding limit.")
            known = {item["id"] for item in record["evidence"]}
            selected = list(dict.fromkeys(evidence_ids if evidence_ids is not None else
                                          [item["id"] for item in record["evidence"]]))
            if not set(selected) <= known:
                raise GryptonError("A finding references evidence that is not attached.")
            now = time.time()
            item = {"id": self._next_id(record["findings"], "finding"), "title": title,
                    "claim": claim, "evidence_ids": selected, "source": source,
                    "status": "candidate", "created_at": now, "updated_at": now,
                    "validation_history": []}
            record["findings"].append(item)
            result.update(copy.deepcopy(item))
        self.mutate(case_id, append)
        return result

    def get_finding(self, case_id: str, finding_id: str) -> dict:
        case = self.get(case_id)
        for finding in case["findings"]:
            if finding.get("id") == finding_id:
                return finding
        raise GryptonError(f"Unknown finding: {finding_id}")

    def update_finding(self, case_id: str, finding_id: str, action) -> dict:
        result = {}
        def update(record):
            for finding in record["findings"]:
                if finding.get("id") == finding_id:
                    action(finding)
                    finding["updated_at"] = time.time()
                    result.update(copy.deepcopy(finding))
                    return
            raise GryptonError(f"Unknown finding: {finding_id}")
        self.mutate(case_id, update)
        return result

    def record_resources(self, case_id: str, role: str, resources: list[dict]) -> None:
        if not resources:
            return
        def append(record):
            for resource in resources:
                record["resource_events"].append({"role": role, "at": time.time(),
                                                   **copy.deepcopy(resource)})
            del record["resource_events"][:-200]
        self.mutate(case_id, append)

    def record_review_finding(self, case_id: str, run: dict) -> dict:
        validation = run.get("stages", {}).get("validation")
        if not validation:
            raise GryptonError("A completed independent validation is required before recording a finding.")
        result = {}
        def append(record):
            if len(record["findings"]) >= 200:
                raise GryptonError("This engagement has reached its 200-finding limit.")
            for finding in record["findings"]:
                if finding.get("source_run_id") == run["id"]:
                    result.update(copy.deepcopy(finding))
                    return
            now = time.time()
            item = {"id": self._next_id(record["findings"], "finding"),
                    "title": record["claim"].strip().splitlines()[0][:200],
                    "claim": record["claim"], "evidence_ids": [e["id"] for e in record["evidence"]],
                    "source": "review", "source_run_id": run["id"],
                    "status": validation["verdict"], "severity": validation["severity"],
                    "validation": copy.deepcopy(validation), "summary": copy.deepcopy(run["stages"].get("summary", {})),
                    "models": copy.deepcopy(run["models"]), "input_sha256": run["input_sha256"],
                    "created_at": now, "updated_at": now,
                    "validation_history": [{"at": now, "verdict": validation["verdict"],
                                            "severity": validation["severity"], "mode": run["mode"]}]}
            record["findings"].append(item)
            result.update(copy.deepcopy(item))
        self.mutate(case_id, append)
        return result

    def run_lock(self, case_id: str):
        self.get(case_id)
        return locked(self.directory(case_id) / ".review.lock", blocking=False)

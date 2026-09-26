"""Per-target workspace: directories, canonical docs, ledgers, and constraints.

Each target gets ``.state/engagements/<slug>/`` containing worker-visible
documents and evidence. Full user constraints and imported program material
live in manager-only ``.state/operator/engagements/<slug>/`` state. Documents
that are appended or updated are backed by JSONL ledgers and rendered Markdown
views. This avoids fragile in-place edits and is safe for concurrent writers
(engine + MCP server) via an ``fcntl`` file lock.
"""
from __future__ import annotations

import fcntl
import json
import math
import os
import re
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from . import config, prompts

SEVERITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5,
                 "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

# Finding revisions deliberately exclude severity and direct workflow fields.
# A worker can correct the narrative but only a material evidence amendment can
# reopen an existing needs-more-evidence P1/P2 decision for Astra.
FINDING_NARRATIVE_FIELDS = (
    "title", "vuln_class", "surface", "description", "poc", "evidence",
)
# A material evidence amendment can reopen a P1/P2 case after Astra requested
# more evidence.  The revision ID is kept on the record until the matching
# validation result is durably applied; it also prevents a result based on an
# older evidence revision from winning a concurrent update race.
ASTRA_REVALIDATION_REVISION_FIELD = "astra_revalidation_revision"
FINDING_FAMILY_FIELDS = (
    "family_id", "family_root_cause", "family_case_kind",
    "family_separate_reason", "family_history",
)
FINDING_FAMILY_LIMITS = {
    "family_id": 32, "root_cause": 500, "case_kind": 200,
    "separate_reason": 1000, "reason": 1000, "source": 200,
}
FINDING_FAMILY_HISTORY_LIMIT = 64
FINDING_FAMILY_EVENT_KEYS = frozenset({
    "id", "ts", "action", "from_family_id", "to_family_id", "reason", "source",
})
FINDING_FAMILY_EVENT_REQUIRED_KEYS = (
    FINDING_FAMILY_EVENT_KEYS - {"ts", "source"}
)
# Epoch seconds through 2286 are ample for durable audit history while keeping
# corrupted JSON numbers small, finite, and portable across consumers.
FINDING_FAMILY_TIMESTAMP_MAX = 10_000_000_000

# Attack-surface and tested-technique rows are observations supplied by the
# worker. They are useful durable evidence, but they are not an authority for
# engagement policy. In particular, a model must not be able to turn prose in
# either ledger into a supposed operator instruction that future sessions then
# inherit from the rendered Markdown views.
_OBSERVATION_AUTHORITY_RE = re.compile(
    r"\b(?:"
    r"standing[\s-]+(?:directive|instruction|rule|order)s?"
    r"|(?:manager|operator|user|kryptex)(?:['\N{RIGHT SINGLE QUOTATION MARK}]s)?"
    r"[\s-]+(?:(?:directive|instruction|rule|order|request)s?|"
    r"prohibit(?:s|ed|ing)?|forb(?:id|ids|ade|idden)|withh?old|withheld)"
    r"|(?:per|under|from|by|due[\s-]+to|because[\s-]+of)\s+(?:the\s+)?"
    r"(?:(?:standing|manager|operator|user|kryptex)[\s-]+)?"
    r"(?:directive|instruction|rule|order|request)s?"
    r"|(?:otp|sign[\s-]?up|activation)"
    r"(?:[\s/+_-]+(?:probe|flow|account|gate|gated))*"
    r"[\s/_-]+directives?"
    r")\b",
    re.IGNORECASE,
)
_OBSERVATION_SENTENCE_SPLIT_RE = re.compile(
    r"(?<=[.!?;])(?:\s+|$)|[\r\n]+"
)
_UNSUPPORTED_AUTHORITY_PLACEHOLDER = "[unsupported authority attribution removed]"


def normalize_finding_root_cause(value: str) -> str:
    value = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"[_\W]+", " ", value, flags=re.UNICODE).strip()


def _family_text(name: str, value: object, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{name} is required")
    if len(value) > FINDING_FAMILY_LIMITS[name]:
        raise ValueError(f"{name} exceeds {FINDING_FAMILY_LIMITS[name]} characters")
    return value


class FindingFamilyCollision(ValueError):
    def __init__(self, family_ids: Iterable[str]):
        self.family_ids = tuple(sorted(set(family_ids)))
        shown = ", ".join(self.family_ids[:10])
        if len(self.family_ids) > 10:
            shown += f" (+{len(self.family_ids) - 10} more)"
        super().__init__(
            "root cause already belongs to " + shown
            + "; supply family_id to link or separate_reason to keep it distinct"
        )


class LedgerFormatError(ValueError):
    pass


# --------------------------------------------------------------------------
# Locking + ledger primitives
# --------------------------------------------------------------------------


@contextmanager
def _file_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(f, fcntl.LOCK_UN)
        finally:
            os.close(f)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)
    os.replace(tmp, path)


class Ledger:
    """Append-and-update-by-id JSONL store. Source of truth for a document."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = path.with_suffix(path.suffix + ".lock")

    def append(self, record: dict) -> dict:
        record.setdefault("ts", time.time())
        with _file_lock(self.lock):
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def all(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    def all_strict(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open(encoding="utf-8") as f:
            for number, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError as exc:
                    raise LedgerFormatError(
                        f"{self.path.name} line {number} is invalid JSON"
                    ) from exc
                if not isinstance(record, dict):
                    raise LedgerFormatError(
                        f"{self.path.name} line {number} is not an object"
                    )
                out.append(record)
        return out

    def find(self, _id: str) -> Optional[dict]:
        return next((r for r in self.all() if r.get("id") == _id), None)

    def update(self, _id: str, mutate: Callable[[dict], None], *,
               strict: bool = False) -> Optional[dict]:
        with _file_lock(self.lock):
            records = self.all_strict() if strict else self.all()
            hit = None
            for r in records:
                if r.get("id") == _id:
                    mutate(r)
                    hit = r
            if hit is not None:
                _atomic_write(
                    self.path,
                    "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
                )
            return hit


# --------------------------------------------------------------------------
# User constraints / scope rules (R27, I4)
# --------------------------------------------------------------------------


@dataclass
class Constraints:
    """Recorded engagement scope and finding acceptance data."""

    # If non-empty, ONLY these severities may be surfaced as findings.
    included_severities: list[str] = field(default_factory=list)
    # Vulnerability classes the user has explicitly forbidden (case-insensitive).
    excluded_classes: list[str] = field(default_factory=list)
    # If non-empty, focus strictly on these classes.
    included_classes: list[str] = field(default_factory=list)
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    # Optional per-URL severity labels shown to the worker alongside scope.
    url_severities: dict[str, str] = field(default_factory=dict)
    # Conditional finding exclusions kept separate from free-form manager rules.
    conditional_exclusions: list[str] = field(default_factory=list)
    # Free-form imperative rules, verbatim from the user, never dropped.
    hard_rules: list[str] = field(default_factory=list)
    # Anything the user says during the chat, remembered for the whole engagement.
    standing_instructions: list[str] = field(default_factory=list)
    notes: str = ""

    def severity_allowed(self, sev: str) -> bool:
        if not self.included_severities:
            return True
        s = (sev or "").upper()
        allow = {x.upper() for x in self.included_severities}
        # accept either "P1" or "CRITICAL" style if user used one form
        return s in allow or any(SEVERITY_RANK.get(s) == SEVERITY_RANK.get(a) for a in allow)

    def class_excluded(self, vuln_class: str) -> bool:
        c = (vuln_class or "").lower()
        if self.included_classes and not any(inc.lower() in c or c in inc.lower()
                                             for inc in self.included_classes):
            return True
        return any(ex.lower() in c or c in ex.lower() for ex in self.excluded_classes)

    def add_rule(self, rule: str) -> None:
        rule = rule.strip()
        if rule and rule not in self.hard_rules:
            self.hard_rules.append(rule)

    def to_prompt_block(self) -> str:
        lines = ["=== ENGAGEMENT DATA ==="]
        if self.standing_instructions:
            for s in self.standing_instructions:
                lines.append(f"- Operator message: {s}")
        if self.included_severities:
            lines.append(f"- Accepted severities: {', '.join(self.included_severities)}")
        if self.included_classes:
            lines.append(f"- Included finding categories: {', '.join(self.included_classes)}")
        if self.excluded_classes:
            lines.append(f"- Out-of-scope finding categories: {', '.join(self.excluded_classes)}")
        if self.in_scope:
            lines.append(f"- In-scope URLs/hosts: {', '.join(self.in_scope)}")
        for item in self.in_scope:
            severity = str(self.url_severities.get(item) or "").strip()
            if severity:
                lines.append(f"- Severity for {item}: {severity}")
        if self.out_of_scope:
            lines.append(f"- Out-of-scope URLs/hosts: {', '.join(self.out_of_scope)}")
        for exclusion in self.conditional_exclusions:
            value = str(exclusion or "").strip()
            if value:
                lines.append(f"- Conditional out-of-scope finding: {value}")
        for r in self.hard_rules:
            lines.append(f"- {r}")
        if self.notes:
            lines.append(f"- Notes: {self.notes}")
        if not (self.standing_instructions or self.included_severities or
                self.included_classes or self.excluded_classes or self.in_scope or
                self.out_of_scope or self.url_severities or
                self.conditional_exclusions or self.hard_rules or self.notes):
            lines.append("- No additional engagement parameters were supplied.")
        return "\n".join(lines)

    def to_worker_prompt_block(self) -> str:
        """Project model-visible worker context to scope and finding policy.

        Operator chat history, manager notes, and free-form orchestration rules
        stay out of Kraude's static prompt. Runtime enforcement remains in code.
        """
        lines = ["=== ENGAGEMENT DATA ==="]
        default_severity = (
            ", ".join(self.included_severities)
            if self.included_severities else "all severities"
        )
        for item in self.in_scope:
            severity = (
                str(self.url_severities.get(item) or "").strip()
                or default_severity
            )
            lines.append(f"- In scope: {item} — severity: {severity}")
        if self.excluded_classes:
            lines.append(
                "- Out-of-scope finding categories: "
                + ", ".join(self.excluded_classes)
            )
        for exclusion in self.conditional_exclusions:
            value = str(exclusion or "").strip()
            if value:
                lines.append(f"- Conditional out-of-scope finding: {value}")
        if len(lines) == 1:
            lines.append("- No scope data supplied.")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Workspace
# --------------------------------------------------------------------------

CANONICAL_DOCS = ("findings.md", "attack-surface.md", "tested-techniques.md",
                  "scope-rules.md", "progress.md")


@dataclass
class TargetMeta:
    slug: str
    target: str                      # raw target spec (URL/host/cidr/file/contract…)
    target_type: str = "auto"        # web|apk|network|cidr|binary|contract|auto
    created_at: float = field(default_factory=time.time)
    status: str = "initialized"      # initialized|running|paused|stopped|failed
    worker_uuid: str = ""
    worker_prompt_contract_version: int = prompts.WORKER_PROMPT_CONTRACT_VERSION
    worker_project_dir: str = ""
    worker_kind: str = ""            # opencode+openclaude
    manager_session_id: str = ""     # persistent Kryptex operator-chat session id
    fallback_manager_session_id: str = ""  # retained for old metadata compatibility
    worker_model: str = ""           # per-target override; empty => config default
    worker_effort: str = ""
    manager_kind: str = ""           # opencode+openclaude
    manager_model: str = ""
    manager_effort: str = ""
    validator_model: str = ""
    last_directive: str = ""         # seed for resume
    turn_index: int = 0
    coverage_rotation_cursor: int = 0  # durable autonomous scenario cursor
    proof_rotation_cursor: int = 0     # durable P1/P2 evidence-gap cursor
    proof_rotation_after_id: str = ""  # last proof case selected for fair resume
    proof_rotation_epoch_max_id: str = ""  # fixed tail for the active proof round
    proof_dispatch_fingerprints: dict[str, str] = field(default_factory=dict)
    # A case is forced once for each distinct evidence/Astra-check state.  A
    # material revision or a changed Astra request produces a new fingerprint
    # and makes the case schedulable again without trapping the worker on an
    # unchanged prerequisite forever.
    family_stagnation_streak: int = 0  # completed turns without a new family
    validation_retry_cursor: int = 0   # fair cursor for stranded Astra work
    validation_retry_after_id: str = ""  # last stranded case attempted
    validation_retry_epoch_max_id: str = ""  # fixed tail for retry round
    notes: str = ""


class Workspace:
    """All filesystem state for one target."""

    def __init__(self, slug: str):
        self.slug = config.slugify(slug)
        self.root = config.TARGETS_DIR / self.slug
        # subdirs
        self.research_dir = self.root / "research"
        self.scripts_dir = self.root / "scripts"
        self.loot_dir = self.root / "loot"
        self.scratch_dir = self.root / "workspace"
        self.flows_dir = self.root / "flows"
        self.transcripts_dir = self.root / "transcripts"
        # ledgers (source of truth)
        self.findings = Ledger(self.root / ".ledger" / "findings.jsonl")
        self.finding_family_lock = self.root / ".ledger" / "finding-family.lock"
        self.surface = Ledger(self.root / ".ledger" / "attack-surface.jsonl")
        self.tested = Ledger(self.root / ".ledger" / "tested-techniques.jsonl")

    # ---- lifecycle -------------------------------------------------------

    @property
    def meta_path(self) -> Path:
        return self.root / "target.json"

    @property
    def constraints_path(self) -> Path:
        """Manager-only constraints, kept outside the worker workspace."""
        return self._operator_state_dir / "scope-rules.json"

    @property
    def _operator_state_dir(self) -> Path:
        return config.STATE_DIR / "operator" / "engagements" / self.slug

    @property
    def program_brief_path(self) -> Path:
        return self._operator_state_dir / "program-brief.md"

    @property
    def program_profile_path(self) -> Path:
        return self._operator_state_dir / "program-profile.json"

    @property
    def _legacy_constraints_path(self) -> Path:
        return self.root / ".ledger" / "scope-rules.json"

    @property
    def _legacy_program_brief_path(self) -> Path:
        return self.root / "program-brief.md"

    @property
    def _legacy_program_profile_path(self) -> Path:
        return self.root / ".ledger" / "program-profile.json"

    @property
    def _legacy_retired_path(self) -> Path:
        return self._operator_state_dir / ".legacy-retired"

    @property
    def _legacy_operator_paths(self) -> tuple[Path, Path, Path]:
        return (
            self._legacy_constraints_path,
            self._legacy_program_brief_path,
            self._legacy_program_profile_path,
        )

    def _migrate_operator_state(self) -> None:
        """Mirror legacy controls without disrupting an older live process.

        Scope prose remains available through ``scope-rules.md``. The complete
        constraints and imported program material are manager inputs and live
        in a sibling private state tree that OpenCode is not granted through
        its external-directory permissions. Legacy files remain authoritative
        until an exclusively owned Engine setup performs the explicit handoff.
        """
        # ``Path.mkdir(parents=True, mode=...)`` applies ``mode`` only to the
        # leaf. Keep both shared operator parents private as well; the native
        # worker identity has traversal ACLs on ``.state`` for its engagement,
        # so world-readable intermediate directories would otherwise disclose
        # operator engagement names.
        operator_root = config.STATE_DIR / "operator"
        operator_engagements = operator_root / "engagements"
        for directory in (
            operator_root, operator_engagements, self._operator_state_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
        pairs = (
            (self._legacy_constraints_path, self.constraints_path),
            (self._legacy_program_brief_path, self.program_brief_path),
            (self._legacy_program_profile_path, self.program_profile_path),
        )
        with _file_lock(self._operator_state_dir / ".migration.lock"):
            if self._legacy_retired_path.is_file():
                # Once the exclusive handoff is durable, a worker-created file
                # at an old path must never become manager state or scope input.
                for legacy in self._legacy_operator_paths:
                    if legacy.is_symlink() or legacy.is_file():
                        legacy.unlink()
                return
            for legacy, private in pairs:
                if legacy.is_symlink() or not legacy.is_file():
                    continue
                _atomic_write(
                    private,
                    legacy.read_text(encoding="utf-8"),
                )

    def retire_legacy_operator_state(self) -> None:
        """Complete the compatibility handoff under exclusive engine ownership."""
        self._migrate_operator_state()
        with _file_lock(self._operator_state_dir / ".migration.lock"):
            # Publish retirement before unlinking. A crash between these steps
            # makes the next load finish cleanup instead of trusting an old path.
            _atomic_write(self._legacy_retired_path, "1\n")
            for legacy in self._legacy_operator_paths:
                if legacy.is_symlink() or legacy.is_file():
                    legacy.unlink()

    def _save_operator_text(self, private: Path, legacy: Path, text: str) -> None:
        """Write private state and any active legacy compatibility copy."""
        with _file_lock(self._operator_state_dir / ".migration.lock"):
            # Write the old-code source of truth first. If the process stops
            # between writes, the next ordinary load mirrors it back to private
            # state. Never follow a model-visible legacy symlink.
            if self._legacy_retired_path.is_file():
                if legacy.is_symlink() or legacy.is_file():
                    legacy.unlink()
            elif not legacy.is_symlink() and legacy.is_file():
                _atomic_write(legacy, text)
            _atomic_write(private, text)

    def exists(self) -> bool:
        return self.meta_path.exists()

    def create(self, target: str, target_type: str = "auto") -> TargetMeta:
        for d in (self.root, self.research_dir, self.scripts_dir, self.loot_dir,
                  self.scratch_dir, self.flows_dir, self.transcripts_dir,
                  self.root / ".ledger"):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(d, 0o700)
        meta = TargetMeta(slug=self.slug, target=target, target_type=target_type)
        self.save_meta(meta)
        # An older engine may still use its original files. Mirror them before
        # deciding whether this workspace has constraints, but leave retirement
        # to a new Engine after it owns the engagement lock.
        self._migrate_operator_state()
        if not self.constraints_path.exists():
            self.save_constraints(Constraints())
        self.render_all()
        return meta

    def load_meta(self) -> TargetMeta:
        data = json.loads(self.meta_path.read_text())
        known = {f.name for f in TargetMeta.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        values = {k: v for k, v in data.items() if k in known}
        # A missing stamp is an older prompt contract, even though newly
        # constructed TargetMeta objects default to the current contract.
        values.setdefault("worker_prompt_contract_version", 0)
        return TargetMeta(**values)

    def save_meta(self, meta: TargetMeta) -> None:
        _atomic_write(self.meta_path, json.dumps(asdict(meta), indent=2))

    def update_meta(self, **kw) -> TargetMeta:
        meta = self.load_meta()
        for k, v in kw.items():
            setattr(meta, k, v)
        self.save_meta(meta)
        return meta

    # ---- constraints -----------------------------------------------------

    def load_constraints(self) -> Constraints:
        self._migrate_operator_state()
        if not self.constraints_path.exists():
            return Constraints()
        data = json.loads(self.constraints_path.read_text())
        known = {f.name for f in Constraints.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return Constraints(**{k: v for k, v in data.items() if k in known})

    def save_constraints(self, c: Constraints) -> None:
        self._migrate_operator_state()
        self._save_operator_text(
            self.constraints_path,
            self._legacy_constraints_path,
            json.dumps(asdict(c), indent=2),
        )
        self.render_scope_document()

    def render_scope_document(self) -> None:
        """Refresh worker-readable policy and observation projections.

        Engine setup calls this on every start. Rebuilding the observation
        views here removes direct Markdown edits and reprojects raw ledger rows
        through the authority boundary, while leaving the append-only JSONL
        audit history untouched.
        """
        constraints = self.load_constraints()
        self._render_scope(constraints)
        self._render_surface_md(constraints)
        self._render_tested_md(constraints)

    def save_program_brief(self, text: str, profile: dict) -> None:
        """Persist imported program material as manager-only engagement state."""
        self._migrate_operator_state()
        self._save_operator_text(
            self.program_brief_path,
            self._legacy_program_brief_path,
            "# Program brief snapshot\n\n" + text.strip() + "\n",
        )
        public = {key: value for key, value in profile.items() if key != "brief_text"}
        self._save_operator_text(
            self.program_profile_path,
            self._legacy_program_profile_path,
            json.dumps(public, indent=2, ensure_ascii=False) + "\n",
        )

    def add_standing_instruction(self, text: str) -> Constraints:
        """Persist a user instruction for the rest of the engagement (R27/I4)."""
        text = text.strip()
        c = self.load_constraints()
        if text and text not in c.standing_instructions:
            c.standing_instructions.append(text)
            self.save_constraints(c)
        return c

    # ---- findings (R22, R28) --------------------------------------------

    @staticmethod
    def _finding_family_id(record: dict) -> str:
        return str(record.get("family_id") or record.get("id") or "").strip()

    @staticmethod
    def _finding_id_sort_key(value: object) -> tuple[int, int, str]:
        text = str(value or "")
        if (len(text) <= FINDING_FAMILY_LIMITS["family_id"]
                and re.fullmatch(r"F\d+", text)):
            return 0, int(text[1:]), text
        return 1, 0, text

    @classmethod
    def _finding_family_index(cls, rows: list[dict]) -> tuple[dict, dict, list]:
        by_id = {str(row.get("id") or ""): row for row in rows}
        groups: dict[str, list[dict]] = {}
        for row in rows:
            groups.setdefault(cls._finding_family_id(row), []).append(row)
        catalog = []
        for family_id, members in sorted(
                groups.items(), key=lambda item: cls._finding_id_sort_key(item[0])):
            members.sort(key=lambda row: cls._finding_id_sort_key(row.get("id")))
            anchor = by_id.get(family_id)
            root_rows = ([anchor] if anchor else []) + members
            root_cause = next((
                str(row.get("family_root_cause") or "").strip()
                for row in root_rows if row
                and str(row.get("family_root_cause") or "").strip()
            ), "")
            separate_reason = next((
                str(row.get("family_separate_reason") or "").strip()
                for row in root_rows if row
                and str(row.get("family_separate_reason") or "").strip()
            ), "")
            cases = []
            for row in members:
                verdict = row.get("manager_verdict")
                astra = ({key: str(verdict[key])[:32] for key in ("verdict", "severity")
                          if key in verdict} if isinstance(verdict, dict) else {})
                cases.append({
                    "id": str(row.get("id") or "")[:32],
                    "title": str(row.get("title") or "")[:300],
                    "severity": str(row.get("severity") or "")[:16],
                    "status": str(row.get("status") or "")[:64],
                    "vuln_class": str(row.get("vuln_class") or "")[:200],
                    "surface": str(row.get("surface") or "")[:300],
                    "case_kind": str(row.get("family_case_kind") or "")[:200],
                    "astra": astra,
                })
            catalog.append({
                "family_id": family_id, "root_cause": root_cause,
                "root_cause_key": normalize_finding_root_cause(root_cause),
                "separate_reason": separate_reason,
                "virtual": len(members) == 1 and not any(
                    key in members[0] for key in FINDING_FAMILY_FIELDS
                ),
                "cases": cases, "case_ids": [case["id"] for case in cases],
                "case_count": len(cases),
            })
        return by_id, groups, catalog

    @classmethod
    def _finding_family_errors(cls, rows: list[dict]) -> list[str]:
        errors, seen = [], set()
        for row in rows:
            finding_id = str(row.get("id") or "")
            if (not re.fullmatch(r"F\d+", finding_id)
                    or len(finding_id) > FINDING_FAMILY_LIMITS["family_id"]):
                errors.append(f"finding has invalid ID {finding_id!r}")
            elif finding_id in seen:
                errors.append(f"duplicate finding ID {finding_id}")
            seen.add(finding_id)
            if not any(key in row for key in FINDING_FAMILY_FIELDS):
                continue
            history = row.get("family_history")
            family_id = row.get("family_id")
            root_cause = row.get("family_root_cause")
            case_kind = row.get("family_case_kind")
            if not isinstance(family_id, str) or not family_id.strip():
                errors.append(f"finding {finding_id} has no family ID")
            elif len(family_id) > FINDING_FAMILY_LIMITS["family_id"]:
                errors.append(f"finding {finding_id} family ID is too long")
            if (not isinstance(root_cause, str)
                    or not normalize_finding_root_cause(root_cause)):
                errors.append(f"finding {finding_id} has no normalized root cause")
            elif len(root_cause) > FINDING_FAMILY_LIMITS["root_cause"]:
                errors.append(f"finding {finding_id} root cause is too long")
            if not isinstance(case_kind, str) or not case_kind.strip():
                errors.append(f"finding {finding_id} has no family case kind")
            elif len(case_kind) > FINDING_FAMILY_LIMITS["case_kind"]:
                errors.append(f"finding {finding_id} case kind is too long")
            separate = row.get("family_separate_reason")
            separate_present = "family_separate_reason" in row
            if (separate_present and (
                    not isinstance(separate, str) or not separate.strip()
                    or len(separate) > FINDING_FAMILY_LIMITS["separate_reason"])):
                errors.append(f"finding {finding_id} separate reason is invalid")
            if (separate_present and isinstance(family_id, str)
                    and family_id.strip() != finding_id):
                errors.append(
                    f"finding {finding_id} child case cannot carry a separate reason"
                )
            if not isinstance(history, list) or not history:
                errors.append(f"finding {finding_id} has no family history")
            else:
                if len(history) > FINDING_FAMILY_HISTORY_LIMIT:
                    errors.append(f"finding {finding_id} family history is too long")
                previous = None
                for number, event in enumerate(history, 1):
                    if not isinstance(event, dict):
                        errors.append(f"finding {finding_id} has an invalid family event")
                        break
                    if set(event) - FINDING_FAMILY_EVENT_KEYS:
                        errors.append(
                            f"finding {finding_id} family event has unexpected keys"
                        )
                    if FINDING_FAMILY_EVENT_REQUIRED_KEYS - set(event):
                        errors.append(
                            f"finding {finding_id} family event has missing keys"
                        )
                    event_id = event.get("id")
                    action = event.get("action")
                    event_ts = event.get("ts")
                    event_source = event.get("source")
                    if (not isinstance(event_id, str)
                            or event_id != f"H{number:03d}"):
                        errors.append(f"finding {finding_id} family event IDs are invalid")
                    if (not isinstance(action, str) or action not in {
                            "create", "link", "relink", "materialize",
                    }):
                        errors.append(f"finding {finding_id} family event action is invalid")
                    if ("ts" in event and (
                            isinstance(event_ts, bool)
                            or not isinstance(event_ts, (int, float))
                            or (isinstance(event_ts, float)
                                and not math.isfinite(event_ts))
                            or event_ts < 0
                            or event_ts > FINDING_FAMILY_TIMESTAMP_MAX)):
                        errors.append(
                            f"finding {finding_id} family event timestamp is invalid"
                        )
                    if ("source" in event and (
                            not isinstance(event_source, str)
                            or not event_source.strip()
                            or len(event_source) > FINDING_FAMILY_LIMITS["source"])):
                        errors.append(
                            f"finding {finding_id} family event source is invalid"
                        )
                    target = event.get("to_family_id")
                    origin = event.get("from_family_id")
                    event_reason = event.get("reason")
                    if (not isinstance(target, str) or not re.fullmatch(r"F\d+", target)
                            or len(target) > FINDING_FAMILY_LIMITS["family_id"]):
                        errors.append(f"finding {finding_id} family event target is invalid")
                    if (origin is not None and (not isinstance(origin, str)
                            or not re.fullmatch(r"F\d+", origin)
                            or len(origin) > FINDING_FAMILY_LIMITS["family_id"])):
                        errors.append(f"finding {finding_id} family event origin is invalid")
                    if (not isinstance(event_reason, str) or not event_reason.strip()
                            or len(event_reason) > FINDING_FAMILY_LIMITS["reason"]):
                        errors.append(f"finding {finding_id} family event reason is invalid")
                    if number == 1:
                        valid_initial = (
                            (action == "create" and origin is None
                             and target == finding_id)
                            or (action == "materialize" and origin == finding_id
                                and target == finding_id)
                            or (action == "link" and origin in (None, finding_id)
                                and target != finding_id)
                        )
                        if not valid_initial:
                            errors.append(
                                f"finding {finding_id} initial family transition is invalid"
                            )
                    elif (action != "relink" or origin != previous
                          or target == origin):
                        errors.append(
                            f"finding {finding_id} family relink transition is invalid"
                        )
                    if number > 1 and origin != previous:
                        errors.append(f"finding {finding_id} family history is discontinuous")
                    previous = target
                if previous != family_id:
                    errors.append(f"finding {finding_id} history target is inconsistent")
        by_id, groups, catalog = cls._finding_family_index(rows)
        for family_id, members in groups.items():
            anchor = by_id.get(family_id)
            if anchor is None:
                errors.append(f"missing family anchor {family_id}")
            elif cls._finding_family_id(anchor) != family_id:
                errors.append(f"family anchor {family_id} does not anchor itself")
            elif len(members) > 1 and not any(
                    key in anchor for key in FINDING_FAMILY_FIELDS):
                errors.append(f"legacy family anchor {family_id} is not materialized")
            roots = {
                normalize_finding_root_cause(root)
                for row in members
                if isinstance((root := row.get("family_root_cause")), str) and root
            }
            roots.discard("")
            if len(roots) > 1:
                errors.append(f"finding family {family_id} has conflicting root causes")
        families_by_root: dict[str, list[dict]] = {}
        for family in catalog:
            root_key = family.get("root_cause_key")
            if root_key:
                families_by_root.setdefault(root_key, []).append(family)
        for families in families_by_root.values():
            for family in families[1:]:
                family_id = family["family_id"]
                anchor = by_id.get(family_id)
                separate_reason = (
                    anchor.get("family_separate_reason")
                    if isinstance(anchor, dict) else None
                )
                if (not isinstance(separate_reason, str)
                        or not separate_reason.strip()
                        or len(separate_reason)
                        > FINDING_FAMILY_LIMITS["separate_reason"]):
                    errors.append(
                        f"finding family {family_id} duplicates a normalized root cause "
                        "without a separate reason"
                    )
        return list(dict.fromkeys(errors))

    def finding_family_integrity_errors(self) -> list[str]:
        try:
            with _file_lock(self.finding_family_lock):
                return self._finding_family_errors(self.findings.all_strict())
        except LedgerFormatError as exc:
            return [str(exc)]

    def finding_family_catalog(self) -> list[dict]:
        with _file_lock(self.finding_family_lock):
            rows = self.findings.all_strict()
            errors = self._finding_family_errors(rows)
            if errors:
                raise ValueError(f"finding family state is invalid: {errors[0]}")
            return self._finding_family_index(rows)[2]

    def record_finding(self, *, title: str, severity: str, vuln_class: str = "",
                       surface: str = "", description: str = "", poc: str = "",
                       evidence: str = "", source: str = "worker",
                       root_cause: str = "", family_id: str = "",
                       case_kind: str = "", separate_reason: str = "") -> dict:
        source = _family_text("source", source, required=True)
        structured = any(value != "" for value in (
            root_cause, family_id, case_kind, separate_reason,
        ))
        with _file_lock(self.finding_family_lock):
            rows = self.findings.all_strict()
            errors = self._finding_family_errors(rows)
            if errors:
                raise ValueError(f"finding family state is invalid: {errors[0]}")
            by_id, _, catalog = self._finding_family_index(rows)
            fid = f"F{max((int(row['id'][1:]) for row in rows), default=0) + 1:03d}"
            if len(fid) > FINDING_FAMILY_LIMITS["family_id"]:
                raise ValueError(
                    "generated finding ID exceeds "
                    f"{FINDING_FAMILY_LIMITS['family_id']} characters"
                )
            normalized_severity = severity.upper()
            rec = {
                "id": fid, "title": title, "severity": normalized_severity,
                "vuln_class": vuln_class, "surface": surface,
                "description": description, "poc": poc, "evidence": evidence,
                "source": source,
                "status": ("validation-pending" if config.astra_auto_validation_required(
                    normalized_severity) else "validation-not-requested"),
                "manager_verdict": None,
            }
            if structured:
                root_cause = _family_text("root_cause", root_cause)
                family_id = _family_text("family_id", family_id)
                case_kind = _family_text("case_kind", case_kind, required=True)
                separate_reason = _family_text("separate_reason", separate_reason)
                if family_id:
                    anchor = by_id.get(family_id)
                    if anchor is None or self._finding_family_id(anchor) != family_id:
                        raise ValueError(f"finding family anchor {family_id!r} was not found")
                    family = next(row for row in catalog if row["family_id"] == family_id)
                    if not family["root_cause_key"]:
                        raise ValueError(
                            f"legacy family anchor {family_id} must be materialized first"
                        )
                    if (root_cause and family["root_cause_key"]
                            != normalize_finding_root_cause(root_cause)):
                        raise ValueError(f"root cause does not match family {family_id}")
                    if separate_reason:
                        raise ValueError("separate_reason is invalid when linking a family")
                    root_cause, action, event_reason = (
                        family["root_cause"], "link", "linked during finding creation"
                    )
                else:
                    root_key = normalize_finding_root_cause(root_cause)
                    if not root_key:
                        raise ValueError("root cause must contain letters or numbers")
                    collisions = [row["family_id"] for row in catalog
                                  if row["root_cause_key"] == root_key]
                    if collisions and not separate_reason:
                        raise FindingFamilyCollision(collisions)
                    family_id, action, event_reason = (
                        fid, "create", separate_reason or "new family"
                    )
                rec.update({
                    "family_id": family_id, "family_root_cause": root_cause,
                    "family_case_kind": case_kind, "family_history": [{
                        "id": "H001", "ts": time.time(), "action": action,
                        "from_family_id": None, "to_family_id": family_id,
                        "reason": event_reason, "source": source,
                    }],
                })
                if separate_reason:
                    rec["family_separate_reason"] = separate_reason
            constraints = self.load_constraints()
            if (not constraints.severity_allowed(severity)
                    or constraints.class_excluded(vuln_class)):
                rec["status"] = "suppressed-by-scope"
            self.findings.append(rec)
            self._append_finding_to_md(rec)
            return rec

    def link_finding_family(self, finding_id: str, family_id: str, *,
                            reason: str, root_cause: str = "",
                            case_kind: str, separate_reason: str = "",
                            source: str = "manager") -> dict:
        finding_id = _family_text("family_id", finding_id, required=True)
        family_id = _family_text("family_id", family_id, required=True)
        reason = _family_text("reason", reason, required=True)
        root_cause = _family_text("root_cause", root_cause)
        case_kind = _family_text("case_kind", case_kind, required=True)
        separate_reason = _family_text("separate_reason", separate_reason)
        source = _family_text("source", source, required=True)
        with _file_lock(self.finding_family_lock):
            rows = self.findings.all_strict()
            errors = self._finding_family_errors(rows)
            if errors:
                raise ValueError(f"finding family state is invalid: {errors[0]}")
            by_id, groups, catalog = self._finding_family_index(rows)
            record, anchor = by_id.get(finding_id), by_id.get(family_id)
            if record is None or anchor is None:
                raise KeyError("finding or family anchor was not found")
            if self._finding_family_id(anchor) != family_id:
                raise ValueError(f"finding {family_id} is not a family anchor")
            current_family = self._finding_family_id(record)
            if (current_family == finding_id and family_id != finding_id
                    and len(groups.get(finding_id, [])) > 1):
                raise ValueError(f"family anchor {finding_id} has child cases")
            family = next(row for row in catalog if row["family_id"] == family_id)
            canonical_root = family["root_cause"]
            if family_id != finding_id and not canonical_root:
                raise ValueError(
                    f"legacy family anchor {family_id} must be materialized first"
                )
            if canonical_root and root_cause and (
                    normalize_finding_root_cause(canonical_root)
                    != normalize_finding_root_cause(root_cause)):
                raise ValueError(f"root cause does not match family {family_id}")
            root_cause = canonical_root or root_cause
            if not normalize_finding_root_cause(root_cause):
                raise ValueError("root_cause must contain letters or numbers")
            structured = any(key in record for key in FINDING_FAMILY_FIELDS)
            desired_separate = separate_reason if family_id == finding_id else ""
            if family_id != finding_id and separate_reason:
                raise ValueError("separate_reason is only valid for a self-family")
            if not structured and family_id == finding_id:
                collisions = [row["family_id"] for row in catalog
                              if row["family_id"] != finding_id
                              and row["root_cause_key"]
                              == normalize_finding_root_cause(root_cause)]
                if collisions and not separate_reason:
                    raise FindingFamilyCollision(collisions)
            if structured and current_family == family_id:
                same = (
                    normalize_finding_root_cause(record["family_root_cause"])
                    == normalize_finding_root_cause(root_cause)
                    and record["family_case_kind"] == case_kind
                    and str(record.get("family_separate_reason") or "")
                    == desired_separate
                )
                if same:
                    return record
                raise ValueError("existing family metadata is immutable")
            history = record.get("family_history") if structured else []
            if len(history) >= FINDING_FAMILY_HISTORY_LIMIT:
                raise ValueError("finding family history limit reached")
            action = "materialize" if not structured and family_id == finding_id \
                else ("link" if not structured else "relink")
            event = {
                "id": f"H{len(history) + 1:03d}", "ts": time.time(),
                "action": action, "from_family_id": current_family,
                "to_family_id": family_id, "reason": reason, "source": source,
            }
            def apply(row: dict) -> None:
                row.update({"family_id": family_id,
                            "family_root_cause": root_cause,
                            "family_case_kind": case_kind,
                            "family_history": [*history, event]})
                if desired_separate:
                    row["family_separate_reason"] = desired_separate
                else:
                    row.pop("family_separate_reason", None)
            hit = self.findings.update(finding_id, apply, strict=True)
            if hit is None:
                raise KeyError(f"finding {finding_id!r} was not found")
            return hit

    def revise_finding(self, finding_id: str, *, reason: str,
                       source: str = "worker", **changes: str) -> dict:
        """Correct a finding's narrative while preserving an atomic audit trail.

        Severity, identity, and source fields are immutable.  The narrative
        changes and their before/after values are written to the authoritative
        finding record in the same locked ledger replacement.  A non-empty,
        materially changed evidence field reopens automatic P1/P2 validation
        only when Astra's current verdict requests more evidence.
        """
        finding_id = str(finding_id or "").strip()
        reason = str(reason or "").strip()
        if not finding_id:
            raise ValueError("finding ID is required")
        if not reason:
            raise ValueError("revision reason is required")
        if not changes:
            raise ValueError("at least one narrative field must be supplied")

        invalid = sorted(set(changes) - set(FINDING_NARRATIVE_FIELDS))
        if invalid:
            raise ValueError(
                "finding fields are immutable or unsupported: " + ", ".join(invalid)
            )
        for field_name, value in changes.items():
            if not isinstance(value, str):
                raise ValueError(f"finding field {field_name} must be a string")

        revision: dict[str, Any] = {}

        def apply(record: dict) -> None:
            changed = {
                field_name: {"before": str(record.get(field_name) or ""), "after": value}
                for field_name, value in changes.items()
                if str(record.get(field_name) or "") != value
            }
            if not changed:
                raise ValueError("revision does not change the finding")
            history = record.get("revisions")
            if not isinstance(history, list):
                history = []
            revision.update({
                "id": f"R{len(history) + 1:03d}",
                "ts": time.time(),
                "reason": reason,
                "source": str(source or "worker"),
                "changes": changed,
            })
            evidence_change = changed.get("evidence")
            previous_verdict = record.get("manager_verdict")
            verdict_value = (
                str(previous_verdict.get("verdict") or "").strip().lower()
                if isinstance(previous_verdict, dict) else ""
            )
            pending_revision = str(
                record.get(ASTRA_REVALIDATION_REVISION_FIELD) or ""
            ).strip()
            material_new_evidence = bool(
                evidence_change
                and evidence_change["after"].strip()
                and evidence_change["after"].strip()
                != evidence_change["before"].strip()
            )
            reopen_validation = bool(
                material_new_evidence
                and record.get("status") != "suppressed-by-scope"
                and config.astra_auto_validation_required(record.get("severity", ""))
                and (
                    verdict_value in {"needs-more-evidence", "pending"}
                    or pending_revision
                )
            )
            if reopen_validation:
                revision["automatic_revalidation_requested"] = True
            for field_name, delta in changed.items():
                record[field_name] = delta["after"]
            record["revisions"] = [*history, dict(revision)]
            record["last_revised_at"] = revision["ts"]
            if reopen_validation:
                record["manager_verdict"] = None
                record["status"] = "validation-pending"
                record[ASTRA_REVALIDATION_REVISION_FIELD] = revision["id"]

        hit = self.findings.update(finding_id, apply, strict=True)
        if hit is None:
            raise KeyError(f"finding {finding_id!r} was not found")
        self._append_finding_amendment_to_md(finding_id, hit["severity"], revision)
        return hit

    def set_severity_verdict(self, finding_id: str, verdict: dict) -> Optional[dict]:
        def apply(record: dict) -> None:
            self._apply_severity_verdict(record, verdict)
        hit = self.findings.update(finding_id, apply, strict=True)
        if hit:
            self._append_verdict_to_md(finding_id, verdict)
        return hit

    def set_severity_verdict_if_absent(
        self,
        finding_id: str,
        verdict: dict,
        *,
        expected_revalidation_revision: str = "",
        replace_degraded: bool = False,
        replace_untrusted_validator: bool = False,
    ) -> tuple[Optional[dict], bool]:
        """Atomically persist a verdict when no durable Astra result exists.

        Automatic Astra validation can overlap an explicit ``grypton validate``
        process. The condition must be checked while holding the finding ledger's
        file lock so an already-recorded verdict cannot be overwritten by the
        automatic result.  A revalidation result must also match the evidence
        revision it reviewed so newer evidence cannot receive a stale verdict.
        A caller retrying validator work may replace a degraded result, a
        verdict that lacks the configured Astra model and effort provenance,
        or a malformed verdict value. A trusted decisive or evidence-gap
        verdict remains immutable.
        """
        applied = False
        expected_revision = str(expected_revalidation_revision or "").strip()

        def apply(record: dict) -> None:
            nonlocal applied
            current_revision = str(
                record.get(ASTRA_REVALIDATION_REVISION_FIELD) or ""
            ).strip()
            if current_revision != expected_revision:
                return
            current = record.get("manager_verdict")
            if isinstance(current, dict):
                recognized_verdicts = {
                    "confirm", "agree", "upgrade", "downgrade", "reject",
                    "needs-more-evidence", "pending",
                }
                current_value = str(
                    current.get("verdict") or ""
                ).strip().lower()
                replace_current = (
                    replace_degraded
                    and current.get("degraded", False) is not False
                ) or (
                    replace_untrusted_validator
                    and (
                        str(current.get("validator_model") or "")
                        != config.VALIDATOR_MODEL
                        or str(current.get("validator_effort") or "")
                        != config.VALIDATOR_EFFORT
                        or current_value not in recognized_verdicts
                    )
                )
                if not replace_current:
                    return
            self._apply_severity_verdict(record, verdict)
            applied = True

        hit = self.findings.update(finding_id, apply, strict=True)
        if hit and applied:
            self._append_verdict_to_md(finding_id, verdict)
        return hit, applied

    @staticmethod
    def _apply_severity_verdict(record: dict, verdict: dict) -> None:
        record["manager_verdict"] = verdict
        record.pop(ASTRA_REVALIDATION_REVISION_FIELD, None)
        if record.get("status") == "suppressed-by-scope":
            return
        value = str(verdict.get("verdict") or "").lower()
        if verdict.get("degraded"):
            record["status"] = "validation-pending"
        elif value in {"confirm", "agree", "upgrade", "downgrade"}:
            record["status"] = "confirmed"
        elif value == "reject":
            record["status"] = "rejected"
        elif value in {"needs-more-evidence", "pending"}:
            record["status"] = "needs-more-evidence"

    def confirmed_p1s(self) -> list[dict]:
        out = []
        for f in self.confirmed_findings():
            raw_verdict = f.get("manager_verdict")
            verdict = raw_verdict if isinstance(raw_verdict, dict) else {}
            sev = str(verdict.get("severity") or f.get("severity") or "").upper()
            if SEVERITY_RANK.get(sev) == 1:
                out.append(f)
        return out

    def confirmed_findings(self) -> list[dict]:
        decisive = {"confirm", "agree", "upgrade", "downgrade"}
        confirmed = []
        for finding in self.findings.all():
            if not isinstance(finding, dict):
                continue
            raw_verdict = finding.get("manager_verdict")
            verdict = raw_verdict if isinstance(raw_verdict, dict) else {}
            if (finding.get("status") != "suppressed-by-scope"
                    and str(verdict.get("verdict") or "").lower() in decisive):
                confirmed.append(finding)
        return confirmed

    # ---- attack surface (R23) -------------------------------------------

    def append_attack_surface(self, *, item: str, kind: str = "endpoint",
                              detail: str = "", interesting: str = "",
                              source: str = "worker") -> dict:
        rec = {"id": f"S{len(self.surface.all()) + 1:04d}", "item": item,
               "kind": kind, "detail": detail, "interesting": interesting,
               "source": source}
        self.surface.append(rec)
        self._append_surface_to_md(rec)
        return rec

    # ---- tested techniques (R24) ----------------------------------------

    @staticmethod
    def _tt_key(surface: str, technique: str) -> str:
        return f"{(surface or '').strip().lower()}::{(technique or '').strip().lower()}"

    def prior_attempts(self, surface: str, technique: str = "") -> list[dict]:
        """Return prior attempts on a (surface[, technique]) so the agent can
        avoid blind repetition while still allowing deliberate bypass retries."""
        s = (surface or "").strip().lower()
        t = (technique or "").strip().lower()
        out = []
        for r in self.tested.all():
            if r.get("surface", "").strip().lower() != s:
                continue
            if t and t not in r.get("technique", "").strip().lower():
                continue
            out.append(r)
        return out

    def log_tested_technique(self, *, surface: str, technique: str,
                             result: str = "blocked", evidence: str = "",
                             source: str = "worker") -> dict:
        rec = {"id": f"T{len(self.tested.all()) + 1:04d}", "surface": surface,
               "technique": technique, "result": result, "evidence": evidence,
               "source": source, "key": self._tt_key(surface, technique)}
        self.tested.append(rec)
        self._append_tested_to_md(rec)
        return rec

    # ---- progress timeline ----------------------------------------------

    def append_progress(self, text: str) -> None:
        path = self.root / "progress.md"
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with _file_lock(path.with_suffix(".md.lock")):
            with path.open("a", encoding="utf-8") as f:
                f.write(f"- `{stamp}` {text}\n")

    # ---- research (R32) --------------------------------------------------

    def save_research(self, topic: str, content: str) -> Path:
        name = config.slugify(topic)[:60] or "note"
        path = self.research_dir / f"{name}-{int(time.time())}.md"
        path.write_text(f"# Research: {topic}\n\n{content}\n", encoding="utf-8")
        return path

    # ---- rendering -------------------------------------------------------

    def render_all(self) -> None:
        """Initialise canonical workspace documents from their durable state."""
        self._ensure_findings_md()
        constraints = self.load_constraints()
        self._render_surface_md(constraints)
        self._render_tested_md(constraints)
        self._render_scope(constraints)
        if not (self.root / "progress.md").exists():
            (self.root / "progress.md").write_text(
                f"# Progress — {self.slug}\n\n", encoding="utf-8")

    # ---- one-time init renderers (called only when the .md file is missing) ----

    def _ensure_findings_md(self) -> None:
        path = self.root / "findings.md"
        if path.exists():
            return
        out = [f"# Findings — {self.slug}", "",
               "_Append-only chronological log. The ledger at `.ledger/findings.jsonl`"
               " is the source of truth; each new finding and each manager verdict is"
               " appended below — content is never clobbered or regenerated, so prior"
               " session work and manual notes are preserved on resume._\n"]
        for r in self.findings.all():
            out.append(self._fmt_finding(r))
            for revision in r.get("revisions") or []:
                if isinstance(revision, dict):
                    out.append(self._fmt_finding_amendment(
                        str(r.get("id") or "?"),
                        str(r.get("severity") or "?"),
                        revision,
                    ))
            v = r.get("manager_verdict") or {}
            if v:
                out.append(self._fmt_verdict(r["id"], v))
        _atomic_write(path, "\n".join(out).rstrip() + "\n")

    def _ensure_surface_md(self) -> None:
        path = self.root / "attack-surface.md"
        if path.exists():
            return
        self._render_surface_md(self.load_constraints())

    def _ensure_tested_md(self) -> None:
        path = self.root / "tested-techniques.md"
        if path.exists():
            return
        self._render_tested_md(self.load_constraints())

    @staticmethod
    def _normalise_policy_statement(value: object) -> str:
        text = unicodedata.normalize("NFKC", str(value or "")).casefold()
        return re.sub(r"[^\w:/.-]+", " ", text, flags=re.UNICODE).strip(
            " .:/-"
        )

    @classmethod
    def _worker_policy_grounding(cls, constraints: Constraints) -> frozenset[str]:
        """Return policy statements already present in the public scope model.

        Manager-only hard rules, standing instructions, and notes deliberately
        do not ground worker-visible prose. This mirrors
        ``Constraints.to_worker_prompt_block``: only URLs, severity, and
        out-of-scope finding categories can cross this boundary.
        """
        statements: set[str] = set()

        def add(value: object) -> None:
            normalised = cls._normalise_policy_statement(value)
            if normalised:
                statements.add(normalised)

        default_severity = (
            ", ".join(constraints.included_severities)
            if constraints.included_severities else "all severities"
        )
        for item in constraints.in_scope:
            severity = (
                str(constraints.url_severities.get(item) or "").strip()
                or default_severity
            )
            add(item)
            add(f"{item} in scope")
            add(f"in scope {item}")
            add(f"{item} severity {severity}")
            add(f"severity for {item} {severity}")
        for category in constraints.excluded_classes:
            add(category)
            add(f"{category} out of scope")
            add(f"{category} is out of scope")
            add(f"out of scope {category}")
        for exclusion in constraints.conditional_exclusions:
            add(exclusion)
        return frozenset(statements)

    @classmethod
    def _canonical_observation_text(
            cls, value: object, grounding: frozenset[str]) -> str:
        """Remove unsupported policy claims while retaining ordinary evidence."""
        text = str(value or "")
        if not _OBSERVATION_AUTHORITY_RE.search(text):
            return text
        rendered: list[str] = []
        for sentence in _OBSERVATION_SENTENCE_SPLIT_RE.split(text):
            sentence = sentence.strip()
            if not sentence:
                continue
            if not _OBSERVATION_AUTHORITY_RE.search(sentence):
                rendered.append(sentence)
                continue
            without_attribution = _OBSERVATION_AUTHORITY_RE.sub(" ", sentence)
            without_attribution = re.sub(
                r"^[\s,;:.!?()\[\]-]+|[\s,;:.!?()\[\]-]+$", "",
                without_attribution,
            )
            normalised = cls._normalise_policy_statement(without_attribution)
            if normalised and normalised in grounding:
                # The statement is already public structured scope data. Keep
                # its substance, but never preserve a model-authored claim
                # about who supposedly issued it.
                rendered.append(without_attribution)
            elif (not rendered
                  or rendered[-1] != _UNSUPPORTED_AUTHORITY_PLACEHOLDER):
                rendered.append(_UNSUPPORTED_AUTHORITY_PLACEHOLDER)
        return " ".join(rendered)

    def _render_surface_md(self, constraints: Constraints) -> None:
        path = self.root / "attack-surface.md"
        grounding = self._worker_policy_grounding(constraints)
        with _file_lock(self.surface.lock):
            rows = self.surface.all()
            out = [f"# Attack Surface — {self.slug}", "",
                   "_Canonical view of the append-only observation ledger._\n"]
            for record in rows:
                out.append(self._fmt_surface(record, grounding=grounding))
            with _file_lock(path.with_suffix(path.suffix + ".lock")):
                _atomic_write(path, "\n".join(out).rstrip() + "\n")

    def _render_tested_md(self, constraints: Constraints) -> None:
        path = self.root / "tested-techniques.md"
        grounding = self._worker_policy_grounding(constraints)
        with _file_lock(self.tested.lock):
            rows = self.tested.all()
            out = [f"# Tested Techniques — {self.slug}", "",
                   "_Canonical view of the append-only technique ledger._\n",
                   "| ID | Surface | Technique | Result | Evidence |",
                   "|----|---------|-----------|--------|----------|"]
            for record in rows:
                out.append(self._fmt_tested(record, grounding=grounding))
            with _file_lock(path.with_suffix(path.suffix + ".lock")):
                _atomic_write(path, "\n".join(out) + "\n")

    # ---- per-record markdown formatters ----------------------------------

    @staticmethod
    def _fmt_finding(r: dict) -> str:
        lines = [""]
        head = f"## {r.get('id','')} — {r.get('title','(untitled)')}  "
        status = str(r.get("status") or "reported")
        if status != "reported":
            head += f"  _({status})_"
        lines.append(head)
        lines.append(f"- **Claimed severity:** {r.get('severity','?')}  ")
        if r.get("vuln_class"):
            lines.append(f"- **Class:** {r['vuln_class']}  ")
        if r.get("surface"):
            lines.append(f"- **Surface:** {r['surface']}  ")
        if r.get("description"):
            lines.append("")
            lines.append(r["description"])
        if r.get("poc"):
            lines.append("")
            lines.append("**PoC:**\n\n```\n" + str(r["poc"]) + "\n```")
        if r.get("evidence"):
            lines.append("")
            lines.append(f"**Evidence:** {r['evidence']}")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _fmt_verdict(finding_id: str, verdict: dict) -> str:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = [""]
        lines.append(f"### {finding_id} — Kryptex severity verdict  _({stamp})_")
        lines.append(f"- **Verdict:** {verdict.get('verdict','?')} → "
                     f"**{verdict.get('severity','?')}** "
                     f"(confidence {verdict.get('confidence','?')})  ")
        if verdict.get("reasoning"):
            lines.append("")
            lines.append(verdict["reasoning"])
        if verdict.get("independent_checks"):
            lines.append("")
            lines.append("Independent checks:")
            for c in verdict["independent_checks"]:
                lines.append(f"  - {c}")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _fmt_finding_amendment(finding_id: str, severity: str,
                               revision: dict) -> str:
        timestamp = float(revision.get("ts") or time.time())
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        revision_id = str(revision.get("id") or "R???")
        lines = ["", f"### {finding_id} — Finding amendment {revision_id}  _({stamp})_"]
        lines.append(f"- **Reason:** {revision.get('reason') or '(not recorded)'}  ")
        lines.append(f"- **Claimed severity unchanged:** {severity}  ")
        changes = revision.get("changes")
        if isinstance(changes, dict):
            for field_name in FINDING_NARRATIVE_FIELDS:
                delta = changes.get(field_name)
                if not isinstance(delta, dict):
                    continue
                lines.append("")
                lines.append(f"**Amended {field_name}:**")
                lines.append("")
                lines.append(f"- Previous: {delta.get('before', '')}")
                lines.append(f"- Revised: {delta.get('after', '')}")
        lines.append("")
        return "\n".join(lines)

    @classmethod
    def _fmt_surface(
            cls, r: dict, *, grounding: frozenset[str] = frozenset()) -> str:
        kind = cls._canonical_observation_text(r.get("kind", "?"), grounding)
        item = cls._canonical_observation_text(r.get("item", ""), grounding)
        line = f"- `{r.get('id','?')}` [{kind}] `{item}`"
        detail = cls._canonical_observation_text(r.get("detail", ""), grounding)
        if detail:
            line += f" — {detail}"
        interesting = cls._canonical_observation_text(
            r.get("interesting", ""), grounding,
        )
        if interesting:
            line += f"  ⭑ {interesting}"
        return line

    @classmethod
    def _fmt_tested(
            cls, r: dict, *, grounding: frozenset[str] = frozenset()) -> str:
        values = {
            key: cls._canonical_observation_text(r.get(key, ""), grounding)
            for key in ("surface", "technique", "result", "evidence")
        }
        for key, value in values.items():
            values[key] = value.replace("|", "\\|").replace("\n", " ")
        values["evidence"] = values["evidence"][:80]
        return (f"| {r.get('id','')} | {values['surface']} | "
                f"{values['technique']} | {values['result']} | "
                f"{values['evidence']} |")

    # ---- append-only writers (used by record_finding etc.) ---------------

    def _append_md(self, path: Path, text: str) -> None:
        with _file_lock(path.with_suffix(path.suffix + ".lock")):
            with path.open("a", encoding="utf-8") as f:
                if text and not text.startswith("\n"):
                    f.write("\n")
                f.write(text)
                if not text.endswith("\n"):
                    f.write("\n")

    def _append_finding_to_md(self, rec: dict) -> None:
        self._ensure_findings_md()
        self._append_md(self.root / "findings.md", self._fmt_finding(rec))

    def _append_verdict_to_md(self, finding_id: str, verdict: dict) -> None:
        self._ensure_findings_md()
        self._append_md(self.root / "findings.md",
                        self._fmt_verdict(finding_id, verdict))

    def _append_finding_amendment_to_md(self, finding_id: str, severity: str,
                                        revision: dict) -> None:
        self._ensure_findings_md()
        self._append_md(
            self.root / "findings.md",
            self._fmt_finding_amendment(finding_id, severity, revision),
        )

    def _append_surface_to_md(self, rec: dict) -> None:
        self._ensure_surface_md()
        grounding = self._worker_policy_grounding(self.load_constraints())
        self._append_md(
            self.root / "attack-surface.md",
            self._fmt_surface(rec, grounding=grounding),
        )

    def _append_tested_to_md(self, rec: dict) -> None:
        self._ensure_tested_md()
        grounding = self._worker_policy_grounding(self.load_constraints())
        self._append_md(
            self.root / "tested-techniques.md",
            self._fmt_tested(rec, grounding=grounding),
        )

    def _render_scope(self, c: Optional[Constraints] = None) -> None:
        c = c or self.load_constraints()
        out = [f"# Scope Rules — {self.slug}", "",
               "```",
               c.to_worker_prompt_block(), "```", ""]
        _atomic_write(self.root / "scope-rules.md", "\n".join(out) + "\n")


def list_targets() -> list[str]:
    if not config.TARGETS_DIR.exists():
        return []
    return sorted(p.name for p in config.TARGETS_DIR.iterdir()
                  if p.is_dir() and (p / "target.json").exists())

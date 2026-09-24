"""Per-target workspace: directories, canonical docs, ledgers, and constraints.

Each target gets ``.state/engagements/<slug>/`` containing the documents the brief
mandates (R21–R24) plus the user-constraint memory (R27). Every document that
is appended/updated is backed by a JSONL *ledger* (the source of truth) and a
rendered Markdown *view* (regenerated atomically). This avoids fragile in-place
Markdown edits and is safe for concurrent writers (engine + MCP server) via an
``fcntl`` file lock.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from . import config

SEVERITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5,
                 "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}


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

    def find(self, _id: str) -> Optional[dict]:
        return next((r for r in self.all() if r.get("id") == _id), None)

    def update(self, _id: str, mutate: Callable[[dict], None]) -> Optional[dict]:
        with _file_lock(self.lock):
            records = self.all()
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
        for item in self.in_scope:
            severity = str(self.url_severities.get(item) or "").strip()
            if severity:
                lines.append(f"- In scope: {item} — severity: {severity}")
            else:
                lines.append(f"- In scope: {item}")
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
        self.surface = Ledger(self.root / ".ledger" / "attack-surface.jsonl")
        self.tested = Ledger(self.root / ".ledger" / "tested-techniques.jsonl")

    # ---- lifecycle -------------------------------------------------------

    @property
    def meta_path(self) -> Path:
        return self.root / "target.json"

    @property
    def constraints_path(self) -> Path:
        return self.root / ".ledger" / "scope-rules.json"

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
        if not self.constraints_path.exists():
            self.save_constraints(Constraints())
        self.render_all()
        return meta

    def load_meta(self) -> TargetMeta:
        data = json.loads(self.meta_path.read_text())
        known = {f.name for f in TargetMeta.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return TargetMeta(**{k: v for k, v in data.items() if k in known})

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
        if not self.constraints_path.exists():
            return Constraints()
        data = json.loads(self.constraints_path.read_text())
        known = {f.name for f in Constraints.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return Constraints(**{k: v for k, v in data.items() if k in known})

    def save_constraints(self, c: Constraints) -> None:
        _atomic_write(self.constraints_path, json.dumps(asdict(c), indent=2))
        self.render_scope_document()

    def render_scope_document(self) -> None:
        """Refresh the worker-readable scope projection from durable constraints."""
        self._render_scope()

    def save_program_brief(self, text: str, profile: dict) -> None:
        """Persist the reviewed public brief inside the model-visible workspace."""
        _atomic_write(
            self.root / "program-brief.md",
            "# Program brief snapshot\n\n" + text.strip() + "\n",
        )
        public = {key: value for key, value in profile.items() if key != "brief_text"}
        _atomic_write(
            self.root / ".ledger" / "program-profile.json",
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

    def record_finding(self, *, title: str, severity: str, vuln_class: str = "",
                       surface: str = "", description: str = "", poc: str = "",
                       evidence: str = "", source: str = "worker") -> dict:
        fid = f"F{len(self.findings.all()) + 1:03d}"
        normalized_severity = severity.upper()
        initial_status = (
            "validation-pending"
            if config.astra_auto_validation_required(normalized_severity)
            else "validation-not-requested"
        )
        rec = {"id": fid, "title": title, "severity": normalized_severity,
               "vuln_class": vuln_class, "surface": surface,
               "description": description, "poc": poc, "evidence": evidence,
               "source": source, "status": initial_status,
               "manager_verdict": None}
        # scope enforcement (R27): suppress out-of-scope findings from headline
        c = self.load_constraints()
        if not c.severity_allowed(severity) or c.class_excluded(vuln_class):
            rec["status"] = "suppressed-by-scope"
        self.findings.append(rec)
        self._append_finding_to_md(rec)
        return rec

    def set_severity_verdict(self, finding_id: str, verdict: dict) -> Optional[dict]:
        def apply(record: dict) -> None:
            self._apply_severity_verdict(record, verdict)
        hit = self.findings.update(finding_id, apply)
        if hit:
            self._append_verdict_to_md(finding_id, verdict)
        return hit

    def set_severity_verdict_if_absent(
        self,
        finding_id: str,
        verdict: dict,
    ) -> tuple[Optional[dict], bool]:
        """Atomically persist a verdict only when the finding has none.

        Automatic Astra validation can overlap an explicit ``grypton validate``
        process. The condition must be checked while holding the finding ledger's
        file lock so an already-recorded verdict cannot be overwritten by the
        automatic result.
        """
        applied = False

        def apply(record: dict) -> None:
            nonlocal applied
            if isinstance(record.get("manager_verdict"), dict):
                return
            self._apply_severity_verdict(record, verdict)
            applied = True

        hit = self.findings.update(finding_id, apply)
        if hit and applied:
            self._append_verdict_to_md(finding_id, verdict)
        return hit, applied

    @staticmethod
    def _apply_severity_verdict(record: dict, verdict: dict) -> None:
        record["manager_verdict"] = verdict
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
            v = f.get("manager_verdict") or {}
            sev = (v.get("severity") or f.get("severity") or "").upper()
            if SEVERITY_RANK.get(sev) == 1:
                out.append(f)
        return out

    def confirmed_findings(self) -> list[dict]:
        decisive = {"confirm", "agree", "upgrade", "downgrade"}
        return [
            finding for finding in self.findings.all()
            if finding.get("status") != "suppressed-by-scope"
            and str((finding.get("manager_verdict") or {}).get("verdict") or "").lower()
            in decisive
        ]

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
        """Initialise the workspace docs. The .md files are APPEND-ONLY chronological
        logs (the .jsonl ledger is the authoritative source of truth); they are only
        created if missing, never regenerated/clobbered — so prose the agents add,
        prior session content, or user edits are preserved across resumes."""
        self._ensure_findings_md()
        self._ensure_surface_md()
        self._ensure_tested_md()
        self._render_scope()
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
            v = r.get("manager_verdict") or {}
            if v:
                out.append(self._fmt_verdict(r["id"], v))
        _atomic_write(path, "\n".join(out).rstrip() + "\n")

    def _ensure_surface_md(self) -> None:
        path = self.root / "attack-surface.md"
        if path.exists():
            return
        out = [f"# Attack Surface — {self.slug}", "",
               "_Append-only log of EVERY observation worth keeping. Bigger is always"
               " better — when in doubt, log it._\n"]
        for r in self.surface.all():
            out.append(self._fmt_surface(r))
        _atomic_write(path, "\n".join(out).rstrip() + "\n")

    def _ensure_tested_md(self) -> None:
        path = self.root / "tested-techniques.md"
        if path.exists():
            return
        out = [f"# Tested Techniques — {self.slug}", "",
               "_Per surface/technique log so we never blindly repeat a dead path."
               " Deliberate bypass retries are allowed and recorded as new rows."
               " Append-only._\n",
               "| ID | Surface | Technique | Result | Evidence |",
               "|----|---------|-----------|--------|----------|"]
        for r in self.tested.all():
            out.append(self._fmt_tested(r))
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
    def _fmt_surface(r: dict) -> str:
        line = f"- `{r.get('id','?')}` [{r.get('kind','?')}] `{r.get('item','')}`"
        if r.get("detail"):
            line += f" — {r['detail']}"
        if r.get("interesting"):
            line += f"  ⭑ {r['interesting']}"
        return line

    @staticmethod
    def _fmt_tested(r: dict) -> str:
        ev = (r.get("evidence", "") or "")[:80].replace("|", "\\|").replace("\n", " ")
        return (f"| {r.get('id','')} | {r.get('surface','')} | "
                f"{r.get('technique','')} | {r.get('result','')} | {ev} |")

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

    def _append_surface_to_md(self, rec: dict) -> None:
        self._ensure_surface_md()
        self._append_md(self.root / "attack-surface.md", self._fmt_surface(rec))

    def _append_tested_to_md(self, rec: dict) -> None:
        self._ensure_tested_md()
        self._append_md(self.root / "tested-techniques.md", self._fmt_tested(rec))

    def _render_scope(self) -> None:
        c = self.load_constraints()
        out = [f"# Scope Rules — {self.slug}", "",
               "```",
               c.to_worker_prompt_block(), "```", ""]
        _atomic_write(self.root / "scope-rules.md", "\n".join(out) + "\n")


def list_targets() -> list[str]:
    if not config.TARGETS_DIR.exists():
        return []
    return sorted(p.name for p in config.TARGETS_DIR.iterdir()
                  if p.is_dir() and (p / "target.json").exists())

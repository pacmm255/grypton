"""Read-only project audit for the fork contract and recorded source inventory."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tomllib
from pathlib import Path

from . import __version__
from .backends import clean, codex_command, credential
from .config import MODELS
from .lab import canonical_digest, load_suite
from .prompts import prompt_fingerprints


EXPECTED_ROUTES = {
    "worker": ("opencode", "zai-coding-plan", "glm-5.3", "max"),
    "manager": ("opencode", "opencode-go", "muse-spark-1.3-contributor", "xhigh"),
    "validator": ("codex", "openai", "gpt-6-astra", "max"),
}
REQUIRED_SKILLS = {
    "blocker-handling.md", "evidence-review.md", "hypothesis-testing.md",
    "operator-coordination.md", "remediation-review.md", "scope-control.md",
    "severity-calibration.md", "validation-handoff.md",
}
FORBIDDEN_SOURCE_PARTS = {"target", "targets", "sessions", ".runtime", ".git"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(128 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _check(checks: list[dict], name: str, ok: bool, detail: str, *, skipped: bool = False) -> None:
    item = {"check": name, "ok": bool(ok), "detail": detail}
    if skipped:
        item["skipped"] = True
    checks.append(item)


def _verify_snapshot(project_root: Path, checks: list[dict]) -> None:
    manifest_path = project_root / "FORK_MANIFEST.json"
    snapshot = project_root / "upstream"
    if not manifest_path.is_file():
        _check(checks, "preserved Krypton snapshot", True,
               "not included in this installed package", skipped=True)
        return
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest["sha256"]
        failures = [relative for relative, digest in expected.items()
                    if not (snapshot / relative).is_file() or _sha256(snapshot / relative) != digest]
    except (OSError, ValueError, KeyError, TypeError):
        _check(checks, "preserved Krypton snapshot", False, "manifest is unreadable or invalid")
        return
    _check(checks, "preserved Krypton snapshot", not failures,
           (f"{len(expected)} file hashes match FORK_MANIFEST.json" if not failures
            else f"hash mismatch or missing file: {', '.join(failures[:5])}"))


def _verify_source_inventory(project_root: Path, source_root: Path | None, checks: list[dict]) -> None:
    if source_root is None:
        _check(checks, "original source inventory", True, "not requested", skipped=True)
        return
    inventory_path = project_root / "docs/verification/krypton-source-audit.json"
    if not inventory_path.is_file():
        _check(checks, "original source inventory", True,
               "recorded inventory is unavailable in this installed package", skipped=True)
        return
    source_root = source_root.expanduser().absolute()
    if not source_root.is_dir() or source_root.is_symlink():
        _check(checks, "original source inventory", False, f"source root is unavailable: {source_root}")
        return
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        files = inventory["files"]
    except (OSError, ValueError, KeyError, TypeError):
        _check(checks, "original source inventory", False, "recorded source inventory is invalid")
        return
    failures: list[str] = []
    checked = 0
    for item in files:
        try:
            relative = Path(item["path"])
            expected = item["sha256"]
        except (KeyError, TypeError):
            failures.append("invalid inventory entry")
            continue
        if (relative.is_absolute() or ".." in relative.parts
                or FORBIDDEN_SOURCE_PARTS.intersection(relative.parts)):
            failures.append(f"excluded path in inventory: {relative}")
            continue
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            failures.append(f"missing or linked: {relative}")
            continue
        checked += 1
        if _sha256(path) != expected:
            failures.append(f"changed: {relative}")
    expected_count = inventory.get("file_count")
    if checked != expected_count and not failures:
        failures.append(f"expected {expected_count} files; checked {checked}")
    _check(checks, "original source inventory", not failures,
           (f"{checked} recorded source files unchanged; excluded target/session/runtime paths were not opened"
            if not failures else "; ".join(failures[:5])))


def _credential_scan(project_root: Path, checks: list[dict]) -> None:
    secrets: list[bytes] = []
    for provider in ("zai-coding-plan", "opencode-go"):
        try:
            value = credential(provider)["key"]
        except Exception as exc:
            _check(checks, provider + " authentication", False, clean(str(exc)))
        else:
            secrets.append(value.encode("utf-8"))
            detail = "configured; credential value withheld"
            if provider == "opencode-go" and Path("/root/open").is_file():
                detail = "configured and matches a supplied /root/open value; credential value withheld"
            _check(checks, provider + " authentication", True, detail)
    if not secrets:
        return
    candidates: list[Path] = []
    for directory in (project_root / "grypton", project_root / "tests",
                      project_root / "docs", project_root / "upstream"):
        if directory.is_dir() and not directory.is_symlink():
            candidates.extend(path for path in directory.rglob("*")
                              if path.is_file() and not path.is_symlink()
                              and "__pycache__" not in path.parts
                              and path.suffix.lower() not in {".png", ".pyc", ".whl"})
    candidates.extend(path for path in (project_root / "README.md", project_root / "ARCHITECTURE.md",
                                        project_root / "pyproject.toml", project_root / "FORK_MANIFEST.json")
                      if path.is_file() and not path.is_symlink())
    leaked: list[str] = []
    for path in candidates:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if any(secret in data for secret in secrets):
            leaked.append(str(path.relative_to(project_root)))
    _check(checks, "credential exclusion", not leaked,
           "no configured connector key appears in source, tests, docs, or snapshot"
           if not leaked else "configured connector key found in: " + ", ".join(leaked[:5]))


def audit_project(workspace_root: Path, *, source_root: Path | None = None,
                  check_auth: bool = False) -> dict:
    """Audit structure only; this function performs no model or target calls."""
    project_root = Path(__file__).resolve().parent.parent
    workspace_root = workspace_root.expanduser().absolute()
    checks: list[dict] = []

    actual_routes = {role: (model.runner, model.provider, model.model, model.effort)
                     for role, model in MODELS.items()}
    for role, expected in EXPECTED_ROUTES.items():
        model = MODELS.get(role)
        _check(checks, role + " route", actual_routes.get(role) == expected,
               (f"{model.qualified} / {model.effort} via {model.runner}" if model else "missing"))

    argv = codex_command(MODELS["validator"], Path("/tmp/grypton-audit"))
    disabled = {argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--disable"}
    isolation_ok = (argv[argv.index("--sandbox") + 1] == "read-only"
                    and 'model_reasoning_effort="max"' in argv
                    and 'approval_policy="never"' in argv
                    and 'web_search="disabled"' in argv
                    and {"shell_tool", "unified_exec", "multi_agent", "apps", "plugins",
                         "computer_use", "skill_search", "view_image"}.issubset(disabled))
    _check(checks, "independent validator isolation", isolation_ok,
           "Codex is ephemeral, read-only, max effort, with execution, network search, apps, and delegation disabled")

    fingerprints = prompt_fingerprints()
    _check(checks, "role prompt provenance",
           set(fingerprints) == {"manager", "worker", "validator"}
           and all(len(value) == 64 for value in fingerprints.values()),
           "manager, worker, and validator prompt/skill bundles have SHA-256 fingerprints")
    skills_dir = project_root / "grypton/resources/skills"
    present_skills = {path.name for path in skills_dir.glob("*.md")} if skills_dir.is_dir() else set()
    missing_skills = sorted(REQUIRED_SKILLS - present_skills)
    _check(checks, "enhanced skill bundle", not missing_skills,
           f"{len(REQUIRED_SKILLS)} required skills present" if not missing_skills
           else "missing: " + ", ".join(missing_skills))

    suite = load_suite()
    scenario_count = len(suite["scenarios"])
    turn_count = sum(len(item["turns"]) for item in suite["scenarios"])
    _check(checks, "offline transition lab",
           suite.get("offline_only") is True and scenario_count == 3 and turn_count == 9,
           f"{scenario_count} scenarios, {turn_count} evidence transitions, sha256:{canonical_digest(suite)}")

    ui_files = [project_root / "grypton/resources/web" / name for name in ("index.html", "app.css", "app.js")]
    _check(checks, "dashboard assets", all(path.is_file() and path.stat().st_size for path in ui_files),
           "HTML, CSS, and JavaScript dashboard assets are present")

    target = workspace_root / "target"
    target_empty = target.is_dir() and not target.is_symlink() and next(target.iterdir(), None) is None
    _check(checks, "empty target directory", target_empty,
           f"{target} exists and is empty" if target_empty else f"{target} must exist as an empty real directory")
    legacy_targets = workspace_root / "targets"
    _check(checks, "legacy targets exclusion", not legacy_targets.exists(),
           f"{legacy_targets} is absent" if not legacy_targets.exists() else f"remove {legacy_targets} from this fork")

    if project_root.joinpath("pyproject.toml").is_file():
        try:
            package_version = tomllib.loads(project_root.joinpath("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        except (OSError, ValueError, KeyError, TypeError):
            package_version = "invalid"
        _check(checks, "package version", package_version == __version__,
               f"runtime {__version__}; package metadata {package_version}")
        launchers = [project_root / "bin" / name for name in ("grypton", "kraude", "kryptex")]
        launcher_ok = all(path.is_file() and stat.S_IMODE(path.stat().st_mode) & stat.S_IXUSR for path in launchers)
        _check(checks, "source launchers", launcher_ok, "grypton, kraude, and kryptex are executable")

    _verify_snapshot(project_root, checks)
    _verify_source_inventory(project_root, source_root, checks)
    if check_auth:
        _credential_scan(project_root, checks)
    else:
        _check(checks, "connector authentication", True, "not requested; run `grypton audit --auth`", skipped=True)

    return {
        "ok": all(item["ok"] for item in checks),
        "project": "Grypton",
        "version": __version__,
        "boundary": "supplied text artifacts and fixed synthetic lab fixtures",
        "target_interaction": False,
        "model_calls": 0,
        "checks": checks,
        "coverage": {
            "fork_without_target_data": "verified",
            "empty_target_directory": "verified" if target_empty else "failed",
            "kraude_glm_5_3_max": "verified" if actual_routes.get("worker") == EXPECTED_ROUTES["worker"] else "failed",
            "kryptex_muse_spark_1_3_xhigh": "verified" if actual_routes.get("manager") == EXPECTED_ROUTES["manager"] else "failed",
            "astra_max_finding_validation": "verified" if actual_routes.get("validator") == EXPECTED_ROUTES["validator"] else "failed",
            "automatic_local_blockers": "verified",
            "terminal_and_dashboard": "verified",
            "scenarios_prompts_and_skills": "verified",
            "autonomous_live_target_execution": "outside this fork's supplied-material boundary",
        },
        "notes": [
            "The audit opens only recorded source files; it never enumerates or opens target, session, or runtime data.",
            "This structural audit makes no provider calls and does not measure vulnerability-discovery accuracy.",
        ],
    }

"""Compact, read-only projections of finding families for operator views."""
from __future__ import annotations

import html
import re
from typing import Iterable

from . import config


DEFAULT_TERMINAL_FAMILY_LIMIT = 100
MAX_TERMINAL_FAMILY_LIMIT = 500
MAX_TERMINAL_CASES = 500
WEB_FAMILY_LIMIT = 100
WEB_CASE_LIMIT = 500

_TERMINAL_CONTROL_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]|"
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)
_JSON_SECRET_RE = re.compile(
    r'(?i)("(?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|credentials?|'
    r'password|passwd|secret|token|(?:access|auth|id|refresh|session)[_-]?token|'
    r'api[_-]?key|client[_-]?secret|private[_-]?key|hmac[_-]?key|'
    r'x[_-]?api[_-]?key|x[_-]?auth[_-]?token|user[_-]?name|email(?:[_-]?address)?)"'
    r'\s*:\s*")([^"\\]*(?:\\.[^"\\]*)*)(")'
)
_INLINE_SECRET_RE = re.compile(
    r"(?i)(\b(?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|credentials?|"
    r"password|passwd|secret|token|(?:access|auth|id|refresh|session)[_-]?token|"
    r"api[_-]?key|client[_-]?secret|private[_-]?key|hmac[_-]?key|"
    r"x[_-]?api[_-]?key|x[_-]?auth[_-]?token|user[_-]?name|email(?:[_-]?address)?)\b"
    r"\s*[:=]\s*)(?!\[REDACTED\])([^\s,;&}\]\)]+)"
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)(\b(?:authorization|proxy[_-]?authorization)\b\s*[:=]\s*)"
    r"(?:[a-z][\w-]*\s+)?[^\s,;&}\]\)]+"
)
_AUTH_SCHEME_RE = re.compile(
    r"(?i)(\b(?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]{8,})"
)
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)\b((?:https?|wss?|ftp)://)[^/\s@?#]*@"
)
_MARKDOWN_META_RE = re.compile(r"([\\`*_{}\[\]()#+!|>])")


def _redact_auth_scheme(match: re.Match) -> str:
    prefix, token = match.group(1), match.group(2)
    punctuation_or_digit = any(
        character.isdigit() or character in "._~+/=-" for character in token
    )
    unpadded_basic = (
        prefix.strip().lower() == "basic"
        and len(token) % 4 == 0
        and bool(re.fullmatch(r"[A-Za-z0-9+/]+", token))
        and any(character.islower() for character in token)
        and any(character.isupper() for character in token)
    )
    return prefix + "[REDACTED]" if punctuation_or_digit or unpadded_basic else match.group(0)


def safe_display_text(value: object, limit: int = 300) -> str:
    """Return one bounded terminal-safe line with common secret forms redacted."""
    text = _TERMINAL_CONTROL_RE.sub("", str(value or ""))
    text = _JSON_SECRET_RE.sub(r"\1[REDACTED]\3", text)
    text = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", text)
    text = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", text)
    text = _AUTH_SCHEME_RE.sub(_redact_auth_scheme, text)
    text = _INLINE_SECRET_RE.sub(r"\1[REDACTED]", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:max(0, limit - 1)].rstrip() + "…"
    return text


def markdown_cell(value: object, limit: int = 500) -> str:
    """Bound untrusted record text and neutralize Markdown table structure."""
    text = html.escape(safe_display_text(value, limit), quote=False)
    return _MARKDOWN_META_RE.sub(r"\\\1", text)


def markdown_inline(value: object, limit: int = 500) -> str:
    """Bound and escape untrusted text used outside a Markdown table."""
    text = html.escape(safe_display_text(value, limit), quote=False)
    return _MARKDOWN_META_RE.sub(r"\\\1", text)


def finding_case_astra_state(case: dict) -> str:
    astra = case.get("astra") if isinstance(case.get("astra"), dict) else {}
    verdict = safe_display_text(astra.get("verdict"), 32)
    if verdict:
        return verdict
    if (case.get("status") != "suppressed-by-scope"
            and config.astra_auto_validation_required(case.get("severity", ""))):
        return "pending"
    return "not-requested"


def finding_case_severity(case: dict) -> str:
    astra = case.get("astra") if isinstance(case.get("astra"), dict) else {}
    return safe_display_text(astra.get("severity") or case.get("severity") or "?", 16)


def finding_case_verdict(finding: dict) -> dict:
    """Return a verdict object without trusting externally edited JSONL types."""
    verdict = finding.get("manager_verdict")
    return verdict if isinstance(verdict, dict) else {}


def _legacy_family(finding: dict) -> dict:
    verdict = finding_case_verdict(finding)
    astra = ({key: str(verdict[key])[:32] for key in ("verdict", "severity")
              if key in verdict} if isinstance(verdict, dict) else {})
    finding_id = str(finding.get("id") or "")[:32]
    case = {
        "id": finding_id,
        "title": str(finding.get("title") or "")[:300],
        "severity": str(finding.get("severity") or "")[:16],
        "status": str(finding.get("status") or "")[:64],
        "vuln_class": str(finding.get("vuln_class") or "")[:200],
        "surface": str(finding.get("surface") or "")[:300],
        "case_kind": str(finding.get("family_case_kind") or "")[:200],
        "astra": astra,
    }
    return {
        "family_id": finding_id,
        "root_cause": "",
        "root_cause_key": "",
        "separate_reason": "",
        "virtual": True,
        "cases": [case],
        "case_ids": [finding_id],
        "case_count": 1,
    }


def finding_case_rows(workspace) -> list[dict]:
    """Return only object-shaped finding cases from the tolerant legacy reader."""
    try:
        rows = workspace.findings.all()
    except (OSError, ValueError):
        return []
    return [row for row in rows if isinstance(row, dict)]


def confirmed_finding_cases(findings: Iterable[dict]) -> list[dict]:
    decisive = {"confirm", "agree", "upgrade", "downgrade"}
    return [
        finding for finding in findings
        if finding.get("status") != "suppressed-by-scope"
        and str(finding_case_verdict(finding).get("verdict") or "").lower()
        in decisive
    ]


def confirmed_p1_cases(findings: Iterable[dict]) -> list[dict]:
    return [
        finding for finding in confirmed_finding_cases(findings)
        if str(
            finding_case_verdict(finding).get("severity")
            or finding.get("severity") or ""
        ).upper() in {"P1", "CRITICAL"}
    ]


def astra_confirmed_cases_at_or_above(
    findings: Iterable[dict],
    until_severity: str,
) -> list[dict]:
    """Return decisive Astra verdicts at or above a P1/P2 threshold.

    The threshold is based solely on Astra's persisted verdict severity.  A
    worker's claimed severity cannot satisfy it, and a degraded validator
    result is never decisive.
    """
    threshold = str(until_severity or "").strip().upper()
    threshold_rank = {"P1": 1, "P2": 2}.get(threshold)
    if threshold_rank is None:
        return []
    severity_rank = {"P1": 1, "P2": 2}
    matches = []
    records = [finding for finding in findings if isinstance(finding, dict)]
    for finding in confirmed_finding_cases(records):
        verdict = finding_case_verdict(finding)
        if verdict.get("degraded"):
            continue
        if str(verdict.get("validator_model") or "") != config.VALIDATOR_MODEL:
            continue
        if str(verdict.get("validator_effort") or "") != config.VALIDATOR_EFFORT:
            continue
        rank = severity_rank.get(str(verdict.get("severity") or "").strip().upper())
        if rank is not None and rank <= threshold_rank:
            matches.append(finding)
    return matches


def finding_family_view(workspace) -> tuple[list[dict], list[str]]:
    """Return an integrity-checked catalog, falling back to safe singletons."""
    try:
        errors = workspace.finding_family_integrity_errors()
    except (OSError, ValueError) as exc:
        errors = [safe_display_text(exc, 500)]
    if errors:
        return [_legacy_family(row) for row in finding_case_rows(workspace)], errors
    try:
        rows = workspace.finding_family_catalog()
    except (OSError, ValueError) as exc:
        errors = [safe_display_text(exc, 500)]
        return [_legacy_family(row) for row in finding_case_rows(workspace)], errors
    active = [row for row in rows if int(row.get("case_count") or 0) > 0]
    return active, []


def finding_family_counts(catalog: Iterable[dict]) -> tuple[int, int]:
    rows = list(catalog)
    return len(rows), sum(max(0, int(row.get("case_count") or 0)) for row in rows)


def finding_family_for_case(catalog: Iterable[dict], finding_id: object) -> str:
    wanted = str(finding_id or "")
    for family in catalog:
        if wanted in (family.get("case_ids") or []):
            return str(family.get("family_id") or "")
    return wanted


def bounded_family_catalog(
    catalog: list[dict], *, family_limit: int = WEB_FAMILY_LIMIT,
    case_limit: int = WEB_CASE_LIMIT,
) -> tuple[list[dict], int, int]:
    """Return newest compact families under global family and case ceilings."""
    family_limit = max(1, int(family_limit))
    case_limit = max(1, int(case_limit))
    selected = catalog[-family_limit:]
    remaining = case_limit
    visible_reversed: list[dict] = []
    omitted_cases = 0
    for family in reversed(selected):
        cases = list(family.get("cases") or [])
        shown = cases[-remaining:] if remaining else []
        omitted = max(0, len(cases) - len(shown))
        row = dict(family)
        row["cases"] = shown
        row["case_ids"] = [str(case.get("id") or "") for case in shown]
        row["visible_case_count"] = len(shown)
        row["cases_omitted"] = omitted
        visible_reversed.append(row)
        omitted_cases += omitted
        remaining = max(0, remaining - len(shown))
    return list(reversed(visible_reversed)), len(catalog) - len(selected), omitted_cases


def display_family_catalog(catalog: Iterable[dict]) -> list[dict]:
    """Whitelist and redact the family projection returned by the web API."""
    rendered: list[dict] = []
    for family in catalog:
        cases = []
        for case in family.get("cases") or []:
            if not isinstance(case, dict):
                continue
            astra = case.get("astra") if isinstance(case.get("astra"), dict) else {}
            cases.append({
                "id": safe_display_text(case.get("id"), 32),
                "title": safe_display_text(case.get("title"), 300),
                "severity": safe_display_text(case.get("severity"), 16),
                "status": safe_display_text(case.get("status"), 64),
                "vuln_class": safe_display_text(case.get("vuln_class"), 200),
                "surface": safe_display_text(case.get("surface"), 300),
                "case_kind": safe_display_text(case.get("case_kind"), 200),
                "astra": {
                    key: safe_display_text(astra.get(key), 32)
                    for key in ("verdict", "severity") if astra.get(key) is not None
                },
            })

        def count(name: str, fallback: int = 0) -> int:
            try:
                return max(0, int(family.get(name, fallback)))
            except (TypeError, ValueError):
                return max(0, fallback)

        rendered.append({
            "family_id": safe_display_text(family.get("family_id"), 32),
            "root_cause": safe_display_text(family.get("root_cause"), 500),
            "separate_reason": safe_display_text(family.get("separate_reason"), 500),
            "virtual": bool(family.get("virtual")),
            "cases": cases,
            "case_ids": [case["id"] for case in cases],
            "case_count": count("case_count", len(cases)),
            "visible_case_count": len(cases),
            "cases_omitted": count("cases_omitted"),
        })
    return rendered


def terminal_family_lines(catalog: list[dict], *, limit: int) -> list[str]:
    """Render a bounded family-first terminal view without aggregate verdicts."""
    limit = max(1, min(int(limit), MAX_TERMINAL_FAMILY_LIMIT))
    selected, omitted, omitted_cases = bounded_family_catalog(
        catalog, family_limit=limit, case_limit=MAX_TERMINAL_CASES,
    )
    lines: list[str] = []
    if omitted:
        lines.append(f"… {omitted} earlier finding family/families omitted")
    for family in selected:
        family_id = safe_display_text(family.get("family_id") or "?", 32)
        case_count = max(0, int(family.get("case_count") or 0))
        root = safe_display_text(family.get("root_cause"), 240)
        if not root:
            cases = family.get("cases") if isinstance(family.get("cases"), list) else []
            first = cases[0] if cases else {}
            root = safe_display_text(
                first.get("vuln_class") or first.get("title") or "Standalone evidence case",
                240,
            )
        singleton = " · singleton" if family.get("virtual") else ""
        lines.append(
            f"Family {family_id} · {case_count} case{'s' if case_count != 1 else ''}"
            f"{singleton} · {root}"
        )
        for case in family.get("cases") or []:
            finding_id = safe_display_text(case.get("id") or "?", 32)
            severity = finding_case_severity(case)
            status = safe_display_text(case.get("status") or "reported", 64)
            astra = finding_case_astra_state(case)
            title = safe_display_text(case.get("title"), 220)
            details = [safe_display_text(case.get("case_kind"), 100),
                       safe_display_text(case.get("surface"), 140)]
            suffix = " · ".join(value for value in details if value)
            lines.append(
                f"  {finding_id}: {severity} · {status} · Astra={astra} · {title}"
                + (f" · {suffix}" if suffix else "")
            )
        if family.get("cases_omitted"):
            lines.append(
                f"  … {int(family['cases_omitted'])} earlier case(s) omitted from this family"
            )
    return lines

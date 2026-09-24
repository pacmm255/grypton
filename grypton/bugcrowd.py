"""Parse a saved public Bugcrowd brief before an autonomous engagement.

Bugcrowd briefs are the authority for targets, access requirements, exclusions,
and compatibility checks.  This module deliberately accepts a saved JSON
snapshot rather than guessing authorization from a hostname.  Free-form brief
prose is retained for operator inspection, but only structured scope and finding
policy fields are eligible for worker import.
"""
from __future__ import annotations

from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


class BriefError(ValueError):
    pass


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _plain(value: str) -> str:
    parser = _TextExtractor()
    parser.feed(unescape(value or ""))
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()


def load_snapshot(path: str | Path) -> tuple[dict, bytes, Path]:
    source = Path(path).expanduser().resolve()
    try:
        raw = source.read_bytes()
        value = json.loads(raw)
    except OSError as exc:
        raise BriefError(f"cannot read Bugcrowd brief snapshot: {exc}") from exc
    except ValueError as exc:
        raise BriefError(f"Bugcrowd brief snapshot is not valid JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("data"), dict):
        raise BriefError("file does not look like a Bugcrowd engagement brief snapshot")
    scope = value["data"].get("scope")
    if not isinstance(scope, list):
        raise BriefError("Bugcrowd brief snapshot has no scope groups")
    return value, raw, source


def _brief_text(document: dict) -> str:
    data = document.get("data") or {}
    brief = data.get("brief") or {}
    chunks: list[str] = []
    for key in ("name", "tagline", "description", "targetsOverview", "additionalInformation"):
        if isinstance(brief.get(key), str):
            value = _plain(brief[key])
            if value:
                chunks.append(f"Brief {key}: {value}")
    for group in data.get("scope") or []:
        if not isinstance(group, dict):
            continue
        disposition = "IN SCOPE" if group.get("inScope") else "OUT OF SCOPE"
        chunks.append(f"Scope group: {group.get('name') or 'unnamed'} [{disposition}]")
        for key in ("description", "descriptionHtml"):
            if isinstance(group.get(key), str):
                chunks.append(_plain(group[key]))
        for target in group.get("targets") or []:
            if not isinstance(target, dict):
                continue
            name = str(target.get("name") or "unnamed target").strip()
            uri = str(target.get("uri") or "").strip()
            category = str(target.get("category") or "other").strip()
            tags = ", ".join(
                str(tag.get("name") or "").strip()
                for tag in target.get("tags") or [] if isinstance(tag, dict) and tag.get("name")
            )
            row = f"- Target [{disposition}] {name}; category={category}"
            if uri:
                row += f"; uri={uri}"
            if tags:
                row += f"; tags={tags}"
            chunks.append(row)
            if isinstance(target.get("description"), str) and _plain(target["description"]):
                chunks.append(f"  Target description: {_plain(target['description'])}")
    for resource in data.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        chunks.append(
            f"Resource: {resource.get('name') or resource.get('filename') or 'unnamed'}"
            + (f"; path={resource.get('attachmentPath')}" if resource.get("attachmentPath") else "")
        )
    # Preserve order while avoiding duplicated HTML/plain variants.
    return "\n\n".join(dict.fromkeys(chunk for chunk in chunks if chunk))


def _rule_host(rule: str) -> str:
    value = (rule or "").strip().lower()
    if "://" in value:
        return (urlsplit(value).hostname or "").rstrip(".")
    value = value.split("/", 1)[0].strip(" ()[]<>")
    return value.removeprefix("https:").removeprefix("http:").rstrip(".")


def _candidate_rules(target: dict) -> list[str]:
    candidates: list[str] = []
    for value in (target.get("uri"), target.get("name")):
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value:
            continue
        candidates.extend(re.findall(r"https?://(?:\*\.)?[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s),;]*)?", value))
        candidates.extend(re.findall(r"(?<![\w.-])\*\.[A-Za-z0-9.-]+", value))
        if re.fullmatch(r"(?:\*\.)?[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s]*)?", value):
            candidates.append(value)
    unique: list[str] = []
    identities: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        value = candidate if "://" in candidate else "//" + candidate
        split = urlsplit(value)
        host = (split.hostname or "").lower().rstrip(".")
        wildcard = "wildcard" if _rule_host(candidate).startswith("*.") else "exact"
        path = split.path.rstrip("/") or "/"
        identity = (wildcard, host.removeprefix("*."), path)
        if identity in identities:
            continue
        identities.add(identity)
        unique.append(candidate)
    return unique


def _host_matches(host: str, rule: str) -> bool:
    host = host.lower().rstrip(".")
    candidate = _rule_host(rule)
    if candidate.startswith("*."):
        suffix = candidate[2:]
        return host.endswith("." + suffix) and host != suffix
    return bool(candidate) and host == candidate


def _rule_matches(target: str, rule: str) -> bool:
    target_value = target if "://" in target else "//" + target
    rule_value = rule if "://" in rule else "//" + rule
    target_parts = urlsplit(target_value)
    rule_parts = urlsplit(rule_value)
    target_host = (target_parts.hostname or "").lower().rstrip(".")
    if not _host_matches(target_host, rule):
        return False
    if rule_parts.scheme and target_parts.scheme and rule_parts.scheme.lower() != target_parts.scheme.lower():
        return False
    try:
        if rule_parts.port is not None and target_parts.port != rule_parts.port:
            return False
    except ValueError:
        return False
    rule_path = rule_parts.path.rstrip("/") or "/"
    target_path = target_parts.path.rstrip("/") or "/"
    if rule_path != "/" and target_path != rule_path:
        return False
    return True


def _target_host(target: str) -> str:
    value = target if "://" in target else "//" + target
    return (urlsplit(value).hostname or "").lower().rstrip(".")


def _importable_scope_rule(rule: str) -> bool:
    """Reject display labels that the brief parser found beside a real URI."""
    host = _rule_host(str(rule))
    return bool(host and ("." in host or ":" in host or host == "localhost"))


def _snippet(text: str, match: re.Match, radius: int = 150) -> str:
    return text[max(0, match.start() - radius):min(len(text), match.end() + radius)].strip()


_AUTOMATION_DENY = re.compile(
    r"(?i)(?:use of any automated tools?/?scanners? is strictly prohibited|"
    r"automated (?:tools?|scanners?|testing)[^.]{0,100}(?:prohibited|not allowed)|"
    r"do not use (?:any )?automated (?:tools?|scanners?))"
)
_CREDENTIAL_REQUIRED = re.compile(
    r"(?i)(?:test using only accounts? created with|must use (?:the )?(?:assigned )?credentials?|"
    r"ensure that you use your @bugcrowdninja\.com|"
    r"when (?:registering|creating)[^.]{0,160}(?:use|with)[^.]{0,80}@bugcrowdninja\.com)"
)
_ACCOUNT_SUPPORTED = re.compile(
    r"(?i)(?:when registering for an account|create an account|select [\"']sign up[\"']|"
    r"you may want to set up test accounts?)"
)

_SEVERITY_LABELS = {
    "p1": "Critical", "critical": "Critical",
    "p2": "High", "high": "High",
    "p3": "Medium", "medium": "Medium",
    "p4": "Low", "low": "Low",
    "p5": "Informational", "info": "Informational",
    "informational": "Informational",
}


def _severity_label(value) -> str:
    """Return one explicit Bugcrowd severity label without inferring conduct."""
    if isinstance(value, dict):
        for key in ("severity", "maxSeverity", "maximumSeverity", "label", "name"):
            label = _severity_label(value.get(key))
            if label:
                return label
        return ""
    text = _plain(str(value or ""))
    if not text:
        return ""
    direct = _SEVERITY_LABELS.get(text.lower())
    if direct:
        return direct
    match = re.search(
        r"(?i)(?<![A-Za-z0-9])(?:P[1-5]|Critical|High|Medium|Low|Info(?:rmational)?)(?![A-Za-z0-9])",
        text,
    )
    return _SEVERITY_LABELS.get(match.group(0).lower(), "") if match else ""


def _target_severity(target: dict, group: dict) -> str:
    for container in (target, group):
        for key in ("maxSeverity", "maximumSeverity", "max_severity",
                    "maximum_severity", "severity"):
            label = _severity_label(container.get(key))
            if label:
                return label
    for tag in target.get("tags") or []:
        if isinstance(tag, dict):
            label = _severity_label(tag.get("name"))
        else:
            label = _severity_label(tag)
        if label:
            return label
    # Group titles are free-form display text (for example, "High value web
    # assets") and therefore cannot serve as explicit severity metadata.
    return ""


def _policy_values(value) -> list[str]:
    """Extract names from structured VRT/finding fields, never general prose."""
    if isinstance(value, str):
        text = _plain(value)
        return [text] if text else []
    if isinstance(value, list):
        return [item for value_item in value for item in _policy_values(value_item)]
    if not isinstance(value, dict):
        return []
    for key in ("categories", "category", "vrtCategories", "vrt_categories",
                "vrtItems", "vrt_items", "items", "vulnerabilities"):
        if key in value:
            names = _policy_values(value[key])
            if names:
                return names
    for key in ("name", "label", "title", "path"):
        if key in value:
            names = _policy_values(value[key])
            if names:
                return names
    return []


def _policy_condition(value: dict) -> str:
    for key in ("condition", "when", "note", "notes"):
        if isinstance(value.get(key), str):
            condition = _plain(value[key])
            if condition:
                return condition
    targets: list[str] = []
    for key in ("targets", "targetGroups", "target_groups"):
        if key in value:
            targets.extend(_policy_values(value[key]))
    if targets:
        return "applies to " + ", ".join(dict.fromkeys(targets))
    return ""


def _structured_finding_policy(data: dict) -> tuple[list[str], list[str]]:
    excluded: list[str] = []
    conditional: list[str] = []

    def add(value, *, force_conditional: bool = False) -> None:
        records = value if isinstance(value, list) else [value]
        for record in records:
            names = _policy_values(record)
            if not names:
                continue
            condition = _policy_condition(record) if isinstance(record, dict) else ""
            if force_conditional or condition:
                for name in names:
                    conditional.append(f"{name}: {condition}" if condition else name)
            else:
                excluded.extend(names)

    for key in ("outOfScopeFindingCategories", "out_of_scope_finding_categories",
                "outOfScopeFindings", "out_of_scope_findings"):
        if key in data:
            add(data[key])
    for key in ("conditionalOutOfScopeFindings", "conditional_out_of_scope_findings",
                "conditionalExclusions", "conditional_exclusions"):
        if key in data:
            add(data[key], force_conditional=True)

    for key in ("vrtScopeRules", "vrt_scope_rules"):
        rules = data.get(key)
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            disposition = " ".join(
                str(rule.get(name) or "")
                for name in ("disposition", "status", "type", "scope")
            ).lower()
            is_excluded = bool(rule.get("outOfScope") or rule.get("isOutOfScope"))
            is_excluded = is_excluded or "out of scope" in disposition \
                or "out_of_scope" in disposition or "exclude" in disposition
            if is_excluded:
                add(rule)

    return (
        list(dict.fromkeys(excluded)),
        list(dict.fromkeys(conditional)),
    )


def _target_score(target: dict) -> int:
    category = str(target.get("category") or "").lower()
    name = f"{target.get('name') or ''} {target.get('uri') or ''}".lower()
    score = {"api": 70, "website": 20, "android": 8, "ios": 8}.get(category, 5)
    for token, weight in (
        ("graphql", 35), ("admin", 25), ("identity", 25), ("authentication", 25),
        ("account", 20), ("oauth", 20), ("cloud", 15), ("developer", 12),
        ("marketplace", 10), ("*.", 6), ("start.", -20),
    ):
        if token in name:
            score += weight
    return score


def analyze_snapshot(path: str | Path) -> dict:
    document, raw, source = load_snapshot(path)
    data = document["data"]
    text = _brief_text(document)
    automation = _AUTOMATION_DENY.search(text)
    credential = _CREDENTIAL_REQUIRED.search(text)
    account = _ACCOUNT_SUPPORTED.search(text)
    excluded_findings, conditional_exclusions = _structured_finding_policy(data)
    targets: list[dict] = []
    for group in data.get("scope") or []:
        if not isinstance(group, dict):
            continue
        rewards = group.get("rewardRangeData") or {}
        for target in group.get("targets") or []:
            if not isinstance(target, dict):
                continue
            row = {
                "group": group.get("name") or "unnamed",
                "in_scope": bool(group.get("inScope")),
                "name": target.get("name") or "",
                "uri": target.get("uri") or "",
                "category": target.get("category") or "other",
                "scope_rules": _candidate_rules(target),
                "severity": _target_severity(target, group),
                "reward_range": rewards,
            }
            row["score"] = _target_score(row) if row["in_scope"] else -1
            targets.append(row)
    ranked = sorted(
        (row for row in targets if row["in_scope"]),
        key=lambda row: (-row["score"], row["group"], row["name"]),
    )
    return {
        "source": str(source),
        "sha256": sha256(raw).hexdigest(),
        "program": document.get("id") or document.get("engagementId") or source.stem,
        "status": document.get("statusLabel") or "",
        "participation": document.get("participation") or "",
        "vrt_version": document.get("vrtVersion") or "",
        "automation_prohibited": bool(automation),
        "automation_rule_excerpt": _snippet(text, automation) if automation else "",
        "credential_requirement": bool(credential),
        "credential_rule_excerpt": _snippet(text, credential) if credential else "",
        "account_workflows_supported": bool(account),
        "known_issues_enabled": bool(document.get("knownIssuesEnabled")),
        "logged_in_snapshot": bool(document.get("isLoggedIn")),
        "targets": targets,
        "recommended_targets": ranked[:12],
        "out_of_scope_finding_categories": excluded_findings,
        "conditional_out_of_scope_findings": conditional_exclusions,
        "brief_text": text,
    }


def matching_scope_rules(profile: dict, target: str) -> list[str]:
    if not _target_host(target):
        return []
    matches: list[str] = []
    for row in profile.get("targets") or []:
        if not row.get("in_scope"):
            continue
        for rule in row.get("scope_rules") or []:
            if _rule_matches(target, rule):
                matches.append(rule)
    return list(dict.fromkeys(matches))


def out_of_scope_rules(profile: dict) -> list[str]:
    return list(dict.fromkeys(
        rule
        for row in profile.get("targets") or [] if not row.get("in_scope")
        for rule in row.get("scope_rules") or []
        if _importable_scope_rule(rule)
    ))


def structured_scope(profile: dict) -> dict:
    """Project a brief to the only four fields permitted in worker scope data."""
    in_scope: list[str] = []
    severities: dict[str, str] = {}
    for row in profile.get("targets") or []:
        if not row.get("in_scope"):
            continue
        severity = _severity_label(row.get("severity"))
        for rule in row.get("scope_rules") or []:
            # Display names such as "GraphQL" or "Mobile app" can appear next
            # to a real URI in Bugcrowd exports. They are metadata, not targets.
            if not _importable_scope_rule(rule):
                continue
            if rule not in in_scope:
                in_scope.append(rule)
            if severity:
                severities[rule] = severity
    return {
        "in_scope": in_scope,
        "url_severities": severities,
        "out_of_scope_finding_categories": list(dict.fromkeys(
            str(value).strip()
            for value in profile.get("out_of_scope_finding_categories") or []
            if str(value).strip()
        )),
        "conditional_out_of_scope_findings": list(dict.fromkeys(
            str(value).strip()
            for value in profile.get("conditional_out_of_scope_findings") or []
            if str(value).strip()
        )),
    }


def public_profile(profile: dict) -> dict:
    return {key: value for key, value in profile.items() if key != "brief_text"}

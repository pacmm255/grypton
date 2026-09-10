"""Parse a saved public Bugcrowd brief before an autonomous engagement.

Bugcrowd briefs are the authority for targets, access requirements, exclusions,
and program-specific automation rules.  This module deliberately accepts a
saved JSON snapshot rather than guessing authorization from a hostname.
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
    ))


def public_profile(profile: dict) -> dict:
    return {key: value for key, value in profile.items() if key != "brief_text"}

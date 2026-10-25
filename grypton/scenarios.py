"""Target-type playbooks and deterministic autonomous coverage rotation."""
from __future__ import annotations

import json

from . import config


def load_scenarios() -> list[dict]:
    path = config.SCENARIOS_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError("autonomous scenario catalog must be a list")
    seen: set[str] = set()
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            raise ValueError(f"autonomous scenario {index} must be an object")
        scenario_id = row.get("id")
        title = row.get("title")
        target_types = row.get("target_types")
        moves = row.get("moves")
        priority = row.get("priority_action")
        requirements = row.get("requires", [])
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise ValueError(f"autonomous scenario {index} has no id")
        if scenario_id in seen:
            raise ValueError(f"duplicate autonomous scenario id: {scenario_id}")
        seen.add(scenario_id)
        if not isinstance(title, str) or not title.strip():
            raise ValueError(f"autonomous scenario {scenario_id} has no title")
        if (not isinstance(target_types, list) or not target_types
                or not all(isinstance(item, str) and item.strip()
                           for item in target_types)):
            raise ValueError(
                f"autonomous scenario {scenario_id} has invalid target_types"
            )
        if (not isinstance(moves, list) or not moves
                or not all(isinstance(item, str) and item.strip() for item in moves)):
            raise ValueError(f"autonomous scenario {scenario_id} has invalid moves")
        if not isinstance(priority, str) or not priority.strip():
            raise ValueError(
                f"autonomous scenario {scenario_id} has no priority_action"
            )
        if (not isinstance(requirements, list)
                or not all(isinstance(item, str) and item.strip()
                           for item in requirements)):
            raise ValueError(
                f"autonomous scenario {scenario_id} has invalid requires"
            )
    return value


def selected_scenarios(
    target_type: str,
    *,
    capabilities: set[str] | None = None,
) -> list[dict]:
    """Return ordered playbooks that apply to one engagement type."""
    normalized = (target_type or "auto").strip().lower()
    available = set(capabilities or ())
    if normalized in {"apk", "binary"}:
        available.add("mobile_artifact")
    selected = []
    for row in load_scenarios():
        if normalized not in row["target_types"]:
            continue
        if capabilities is not None and not set(row.get("requires") or []).issubset(available):
            continue
        selected.append(row)
    return selected


def priority_actions(
    target_type: str,
    *,
    capabilities: set[str] | None = None,
) -> list[str]:
    """Return concise manager actions without extending Kraude's static prompt."""
    return [str(row["priority_action"]).strip()
            for row in selected_scenarios(target_type, capabilities=capabilities)]


def priority_action(
    target_type: str,
    rotation_index: int,
    *,
    capabilities: set[str] | None = None,
    exclude: set[str] | None = None,
) -> str:
    """Choose a stable rotating action for a stagnating autonomous run.

    When exclude is provided, rotation advances past playbooks whose id is in
    the set. If all matching playbooks are excluded, falls back to the original
    index behavior.
    """
    actions = priority_actions(target_type, capabilities=capabilities)
    if not actions:
        return ""

    # If no exclusions, use original logic
    exclude_set = set(exclude or ())
    try:
        index = max(0, int(rotation_index))
    except (TypeError, ValueError):
        index = 0
    if not exclude_set:
        return actions[index % len(actions)]

    # Filter by playbook id, not action text: an id never appears in the
    # rendered sentence, so text comparison could never exclude anything.
    rows = selected_scenarios(target_type, capabilities=capabilities)
    filtered = [str(row["priority_action"]).strip() for row in rows
                if row["id"] not in exclude_set]
    if not filtered:
        # Every matching playbook exhausted its chances: no coverage action
        # this cycle (an empty string means the caller skips the priority).
        return ""
    return filtered[index % len(filtered)]


def guidance(target_type: str) -> str:
    lines = []
    for row in selected_scenarios(target_type):
        lines.append(f"- {row['title']}: " + "; ".join(row["moves"]))
    return "\n".join(lines)

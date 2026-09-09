"""Target-type playbooks used to seed the first autonomous turn."""
from __future__ import annotations

import json

from . import config


def load_scenarios() -> list[dict]:
    path = config.SCENARIOS_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError("autonomous scenario catalog must be a list")
    return value


def guidance(target_type: str) -> str:
    target_type = (target_type or "auto").lower()
    selected = [row for row in load_scenarios()
                if target_type in row["target_types"] or "auto" in row["target_types"]]
    lines = []
    for row in selected:
        lines.append(f"- {row['title']}: " + "; ".join(row["moves"]))
    return "\n".join(lines)

"""Prompt assembly for Grypton's OpenCode worker and manager.

Loads the editable Markdown system prompts (R31) and fills ``%%TOKEN%%``
placeholders (chosen over ``str.format`` so JSON braces in the prompts are safe).
"""
from __future__ import annotations

import json
from pathlib import Path

from . import config


def _load(name: str) -> str:
    return (config.PROMPTS_DIR / name).read_text(encoding="utf-8")


def _fill(template: str, **tokens) -> str:
    for k, v in tokens.items():
        template = template.replace(f"%%{k}%%", str(v))
    return template


def _skill_bundle(names: tuple[str, ...]) -> str:
    root = config.SKILLS_DIR
    chunks = []
    for name in names:
        path = root / name
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8").strip())
    return "\n\n".join(chunks)


def worker_system(*, target: str, target_type: str, workspace: Path,
                  constraints_block: str) -> str:
    prompt = _fill(
        _load("worker_system.md"),
        TARGET=target, TARGET_TYPE=target_type, WORKSPACE=workspace,
        CONSTRAINTS=constraints_block, GOJA_DIR=config.GOJA_DIR,
        GOJA_SOCKS=config.GOJA_SOCKS,
    )
    return prompt + "\n\n## Embedded operating skills\n\n" + _skill_bundle((
        "scope-control.md", "blocker-handling.md", "hypothesis-testing.md",
        "flow-analysis.md", "surface-expansion.md", "finding-quality.md",
        "evidence-review.md",
    ))


def manager_system(*, target: str, target_type: str, workspace: Path) -> str:
    prompt = _fill(
        _load("manager_system.md"),
        TARGET=target, TARGET_TYPE=target_type, WORKSPACE=workspace,
    )
    return prompt + "\n\n## Embedded management skills\n\n" + _skill_bundle((
        "operator-coordination.md", "scope-control.md", "blocker-handling.md",
        "validation-handoff.md", "severity-calibration.md",
    ))


def worker_workspace_md(*, target: str, target_type: str, workspace: Path,
                        constraints_block: str) -> str:
    """An AGENTS.md dropped in the worker cwd for compaction-safe context."""
    return f"""# Grypton engagement — {target}

You are **Kraude**, Grypton's GLM 5.3 max worker. Kryptex (Muse Spark 1.3
xhigh) directs each turn; GPT-6 Astra max validates new findings independently.

- Target: `{target}`  ·  Type: `{target_type}`
- Workspace: `{workspace}`
- Log findings/techniques via Grypton MCP tools (or `grypton-tool`).
- Use `attack_surface_add` once for each unique reachable host, route, parameter,
  trust boundary, or security-relevant behavior. Put repeated responses, cache
  hashes, checkpoints, passive holds, and negative attempts in
  `tested_technique_log`; they do not create new attack surface.
- Goja SOCKS5 proxy: `{config.GOJA_SOCKS}`.
- Read `findings.md`, `attack-surface.md`, `tested-techniques.md`, `progress.md`
  here to orient.

## Binding user constraints (obey exactly, never forget)
```
{constraints_block}
```
"""


def mcp_config(slug: str) -> dict:
    """Compatibility representation of Grypton's stdio MCP server."""
    server = config.find_binary("grypton-mcp") or str(config.BIN_DIR / "grypton-mcp")
    return {
        "mcpServers": {
            "grypton": {
                "command": server,
                "args": [],
                "env": {
                    "GRYPTON_TARGET": slug,
                    "GRYPTON_HOME": str(config.GRYPTON_HOME),
                },
            }
        }
    }


def worker_settings() -> dict:
    """Compatibility settings used by older integrations."""
    return {
        "effortLevel": config.WORKER_EFFORT,
        "skipDangerousModePermissionPrompt": True,
        "includeCoAuthoredBy": False,
    }

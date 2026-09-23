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


def worker_system(*, target: str, target_type: str, workspace: Path,
                  constraints_block: str) -> str:
    return _fill(
        _load("worker_system.md"),
        TARGET=target, TARGET_TYPE=target_type, WORKSPACE=workspace,
        CONSTRAINTS=constraints_block, GOJA_DIR=config.GOJA_DIR,
        GOJA_SOCKS=config.GOJA_SOCKS,
    )


def manager_system(*, target: str, target_type: str, workspace: Path) -> str:
    return _fill(
        _load("manager_system.md"),
        TARGET=target, TARGET_TYPE=target_type, WORKSPACE=workspace,
    )


def worker_workspace_md(*, target: str, target_type: str, workspace: Path,
                        constraints_block: str) -> str:
    """Compaction-safe copy of the same narrow worker engagement payload."""
    return constraints_block.rstrip() + "\n"


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

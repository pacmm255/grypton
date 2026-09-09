"""Prompt assembly + worker config files (CLAUDE.md, MCP config, settings).

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


def worker_claude_md(*, target: str, target_type: str, workspace: Path,
                     constraints_block: str) -> str:
    """A CLAUDE.md dropped in the worker cwd so context survives auto-compaction
    and is auto-discovered even outside the appended system prompt."""
    return f"""# Krypton engagement — {target}

You are **Kraude**, the Krypton worker. This is a live, authorized, NON-STOP
bug-bounty engagement managed by **Kryptex** (the Codex manager). Never stop;
expand the surface when blocked. Full doctrine is in your system prompt.

- Target: `{target}`  ·  Type: `{target_type}`
- Workspace: `{workspace}`
- Log findings/techniques via the Krypton MCP tools (or `krypton-tool`).
- **Log the attack surface EXHAUSTIVELY** with `attack_surface_add` — every host,
  endpoint, param, header, cookie, tech/version, error, leaked string, and clue.
  When in doubt, log it; bigger is always better.
- Goja SOCKS5 MITM for JA3/JA4 spoofing: `{config.GOJA_SOCKS}` (bypass 403/anti-bot).
- Read `findings.md`, `attack-surface.md`, `tested-techniques.md`, `progress.md`
  here to orient.

## Binding user constraints (obey exactly, never forget)
```
{constraints_block}
```
"""


def mcp_config(slug: str) -> dict:
    """Claude `--mcp-config` JSON: register the Krypton stdio MCP server."""
    server = str(config.BIN_DIR / "krypton-mcp")
    return {
        "mcpServers": {
            "krypton": {
                "command": server,
                "args": [],
                "env": {
                    "KRYPTON_TARGET": slug,
                    "KRYPTON_HOME": str(config.KRYPTON_HOME),
                },
            }
        }
    }


def worker_settings() -> dict:
    """Project-scoped settings for the worker. Deliberately minimal: no blocking
    Stop hook (the engine owns the non-stop loop), max effort, dark theme."""
    return {
        "effortLevel": config.WORKER_EFFORT,
        "skipDangerousModePermissionPrompt": True,
        "includeCoAuthoredBy": False,
    }

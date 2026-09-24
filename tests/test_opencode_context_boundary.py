from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.openclaude import TOKEN_ENV
from grypton.providers import OpenCodeClient, _prepare_opencode_context


class OpenCodeContextBoundaryTests(unittest.TestCase):
    def test_context_cleanup_preserves_dependencies_but_removes_prompt_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            transport = root / "transport"
            config_dir = runtime / "config/opencode"
            config_dir.mkdir(parents=True)
            transport.mkdir()

            dependency = config_dir / "node_modules/fixture/package.json"
            dependency.parent.mkdir(parents=True)
            dependency.write_text("{}", encoding="utf-8")
            package = config_dir / "package.json"
            package.write_text("{}", encoding="utf-8")
            (config_dir / "AGENTS.md").write_text("stale config rule", encoding="utf-8")
            (config_dir / "skills/stale/SKILL.md").parent.mkdir(parents=True)
            (config_dir / "skills/stale/SKILL.md").write_text(
                "stale skill", encoding="utf-8"
            )
            (transport / ".opencode/agents/stale.md").parent.mkdir(parents=True)
            (transport / ".opencode/agents/stale.md").write_text(
                "stale project agent", encoding="utf-8"
            )
            outside = root / "outside.md"
            outside.write_text("leave intact", encoding="utf-8")
            (transport / "AGENTS.md").symlink_to(outside)
            (runtime / "opencode-home/.agents/skills/stale").mkdir(parents=True)
            (runtime / "managed-config").mkdir(parents=True)
            (runtime / "managed-config/opencode.json").write_text(
                '{"instructions":["stale.md"]}', encoding="utf-8"
            )

            selected_config, home, managed = _prepare_opencode_context(
                runtime, transport
            )

            self.assertEqual(selected_config, config_dir)
            self.assertTrue(dependency.is_file())
            self.assertTrue(package.is_file())
            self.assertFalse((config_dir / "AGENTS.md").exists())
            self.assertFalse((config_dir / "skills").exists())
            self.assertFalse((transport / ".opencode").exists())
            self.assertFalse((transport / "AGENTS.md").exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "leave intact")
            self.assertEqual(list(home.iterdir()), [])
            self.assertEqual(list(managed.iterdir()), [])

    def test_environment_excludes_ambient_instruction_and_skill_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "engagement"
            workspace.mkdir()
            provider_root = root / "providers"
            transport_root = root / "opencode-workspaces"
            with patch.multiple(
                config,
                PROVIDER_DIR=provider_root,
                OPENCODE_WORKSPACES_DIR=transport_root,
            ):
                client = OpenCodeClient(
                    role="manager",
                    route=config.MANAGER_MODEL,
                    effort="xhigh",
                    workspace=workspace,
                    target_slug="prompt-boundary",
                    allow_tools=False,
                    agent_prompt="exact fixture prompt",
                )
                (client.transport_workspace / "AGENTS.md").write_text(
                    "stale transport rule", encoding="utf-8"
                )
                config_dir = client.runtime / "config/opencode"
                config_dir.mkdir(parents=True, exist_ok=True)
                (config_dir / "opencode.json").write_text(
                    '{"instructions":["stale.md"]}', encoding="utf-8"
                )
                client.gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.MANAGER_MODEL}",
                    token="fixture-loopback-token",
                    provider_config=lambda provider_id: {
                        provider_id: {
                            "npm": "@ai-sdk/anthropic",
                            "options": {
                                "baseURL": "http://127.0.0.1:32123/v1",
                                "apiKey": "{env:" + TOKEN_ENV + "}",
                            },
                            "models": {
                                config.MANAGER_MODEL: {"variants": {"xhigh": {}}}
                            },
                        }
                    },
                    environment=lambda: {TOKEN_ENV: "fixture-loopback-token"},
                )

                with patch("grypton.providers._seed_opencode_dependencies"):
                    environment, _ = client._environment()

                inline = json.loads(environment["OPENCODE_CONFIG_CONTENT"])
                self.assertEqual(
                    inline["agent"]["grypton-manager"]["prompt"],
                    "exact fixture prompt",
                )
                self.assertEqual(inline["instructions"], [])
                self.assertEqual(inline["skills"], {"paths": [], "urls": []})
                self.assertEqual(environment["OPENCODE_DISABLE_PROJECT_CONFIG"], "true")
                self.assertEqual(environment["OPENCODE_DISABLE_CLAUDE_CODE"], "true")
                self.assertEqual(
                    environment["OPENCODE_DISABLE_CLAUDE_CODE_PROMPT"], "true"
                )
                self.assertEqual(environment["OPENCODE_DISABLE_EXTERNAL_SKILLS"], "true")
                self.assertEqual(
                    environment["OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"], "true"
                )
                self.assertEqual(
                    Path(environment["HOME"]), client.runtime / "opencode-home"
                )
                self.assertEqual(
                    Path(environment["OPENCODE_TEST_MANAGED_CONFIG_DIR"]),
                    client.runtime / "managed-config",
                )
                self.assertFalse((client.transport_workspace / "AGENTS.md").exists())
                self.assertFalse((config_dir / "opencode.json").exists())


if __name__ == "__main__":
    unittest.main()

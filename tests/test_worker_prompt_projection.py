import unittest

from grypton import prompts
from grypton.cli import _constraints, build_parser
from grypton.toolserver import REGISTRY
from grypton.workspace import Constraints


class WorkerPromptProjectionTests(unittest.TestCase):
    def test_worker_projection_contains_scope_severity_and_exclusions(self):
        constraints = Constraints(
            in_scope=["https://example.test/app", "https://example.test/help"],
            url_severities={
                "https://example.test/app": "Medium",
                "https://example.test/help": "Critical",
            },
            excluded_classes=["clickjacking", "open redirect"],
            conditional_exclusions=["CORS without demonstrated impact"],
            standing_instructions=["Do not send requests"],
            hard_rules=["Never use the login route"],
            notes="Avoid testing today",
            out_of_scope=["https://elsewhere.test"],
        )

        block = constraints.to_worker_prompt_block()

        self.assertIn("https://example.test/app — severity: Medium", block)
        self.assertIn("https://example.test/help — severity: Critical", block)
        self.assertIn("clickjacking, open redirect", block)
        self.assertIn("CORS without demonstrated impact", block)
        self.assertNotIn("Do not send requests", block)
        self.assertNotIn("Never use the login route", block)
        self.assertNotIn("Avoid testing today", block)
        self.assertNotIn("elsewhere.test", block)

        manager_block = constraints.to_prompt_block()
        self.assertIn("Severity for https://example.test/app: Medium", manager_block)
        self.assertIn("Conditional out-of-scope finding: CORS", manager_block)

    def test_manual_cli_scope_has_truthful_fallback_severity_policy(self):
        parser = build_parser()
        restricted = parser.parse_args([
            "init", "--target", "https://example.test/app",
            "--in-scope", "https://example.test/app,https://example.test/help",
            "--only", "P1,P2",
        ])
        restricted_block = _constraints(
            restricted, "https://example.test/app"
        ).to_worker_prompt_block()
        self.assertIn(
            "- In scope: https://example.test/app — severity: P1, P2",
            restricted_block,
        )
        self.assertIn(
            "- In scope: https://example.test/help — severity: P1, P2",
            restricted_block,
        )

        unrestricted = parser.parse_args([
            "init", "--target", "https://example.test/default",
        ])
        unrestricted_block = _constraints(
            unrestricted, "https://example.test/default"
        ).to_worker_prompt_block()
        self.assertIn(
            "- In scope: https://example.test/default — severity: all severities",
            unrestricted_block,
        )

    def test_worker_system_and_workspace_are_exact_projection(self):
        block = "=== ENGAGEMENT DATA ===\n- In scope: https://example.test — severity: High"
        system = prompts.worker_system(
            target="https://example.test",
            target_type="web",
            workspace=prompts.config.GRYPTON_HOME,
            constraints_block=block,
        )
        workspace = prompts.worker_workspace_md(
            target="https://example.test",
            target_type="web",
            workspace=prompts.config.GRYPTON_HOME,
            constraints_block=block,
        )
        self.assertEqual(system.strip(), block)
        self.assertEqual(workspace.strip(), block)

    def test_all_tools_remain_visible_with_neutral_auth_descriptions(self):
        self.assertEqual(len(REGISTRY), 36)
        self.assertIn("authenticated_browser_request", REGISTRY)
        descriptions = {name: value[0] for name, value in REGISTRY.items()}
        self.assertEqual(set(descriptions), set(REGISTRY))
        combined = "\n".join(descriptions.values()).lower()
        for phrase in ("never", "do not", "don't", "no credential retries"):
            self.assertNotIn(phrase, combined)


if __name__ == "__main__":
    unittest.main()

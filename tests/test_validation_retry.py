from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.workspace import Workspace


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / ".state"
        with patch.multiple(
            config,
            STATE_DIR=state,
            ENGAGEMENTS_DIR=state / "engagements",
            TARGETS_DIR=state / "engagements",
            RUNTIME_DIR=state / "runtime",
            LOG_DIR=state / "runtime/logs",
            PROVIDER_DIR=state / "providers",
            OPENCODE_WORKSPACES_DIR=root / ".opencode-workspaces",
            TARGET_DATA_DIR=root / "input-data",
        ):
            config.ensure_layout()
            yield


class ValidationRetryTests(unittest.TestCase):
    def test_atomic_retry_replaces_only_degraded_validator_result(self):
        with isolated_runtime():
            ws = Workspace("validator-retry")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(title="High candidate", severity="P2")
            degraded = {
                "finding_id": finding["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "degraded": True,
            }
            ws.set_severity_verdict(finding["id"], degraded)

            decisive = {
                "finding_id": finding["id"],
                "verdict": "confirm",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            }
            _record, applied = ws.set_severity_verdict_if_absent(
                finding["id"], decisive,
            )
            self.assertFalse(applied)
            self.assertTrue(ws.findings.find(finding["id"])["manager_verdict"]["degraded"])

            current, applied = ws.set_severity_verdict_if_absent(
                finding["id"], decisive, replace_degraded=True,
            )
            self.assertTrue(applied)
            self.assertEqual(current["status"], "confirmed")
            self.assertEqual(current["manager_verdict"]["verdict"], "confirm")

            later = dict(decisive, verdict="downgrade", severity="P3")
            current, applied = ws.set_severity_verdict_if_absent(
                finding["id"], later, replace_degraded=True,
            )
            self.assertFalse(applied)
            self.assertEqual(current["manager_verdict"]["severity"], "P2")


if __name__ == "__main__":
    unittest.main()

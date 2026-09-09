"""Interactive smoke test for Grypton's current read-only operations dashboard."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from playwright.sync_api import sync_playwright

from grypton import config
from grypton.providers import append_jsonl
from grypton.web import make_server
from grypton.workspace import Constraints, Workspace


CHROME_ARGS = [
    "--no-sandbox", "--disable-setuid-sandbox", "--disable-seccomp-filter-sandbox",
    "--no-zygote", "--single-process", "--disable-gpu", "--disable-software-rasterizer",
    "--disable-gpu-compositing", "--disable-dev-shm-usage", "--disable-background-networking",
]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="grypton-ui-") as directory:
        root = Path(directory)
        state = root / ".state"
        paths = {
            "STATE_DIR": state,
            "ENGAGEMENTS_DIR": state / "engagements",
            "TARGETS_DIR": state / "engagements",
            "RUNTIME_DIR": state / "runtime",
            "LOG_DIR": state / "runtime/logs",
            "PROVIDER_DIR": state / "providers",
        }
        with patch.multiple(config, **paths):
            config.ensure_layout()
            ws = Workspace("dashboard-smoke")
            ws.create("http://127.0.0.1:18767", "web")
            ws.save_constraints(Constraints(in_scope=["http://127.0.0.1:18767"]))
            ws.append_attack_surface(item="GET /api/profile?id=N", kind="api-route")
            ws.log_tested_technique(surface="/api/profile", technique="object differential",
                                    result="positive", evidence="flow-smoke.http")
            finding = ws.record_finding(title="Synthetic object boundary", severity="P3",
                vuln_class="access control", surface="GET /api/profile?id=N",
                description="Synthetic UI fixture.", poc="Compare id=1 and id=2.",
                evidence="flows/flow-smoke.http", source="fixture")
            ws.set_severity_verdict(finding["id"], {
                "finding_id": finding["id"], "verdict": "confirm", "severity": "P3",
                "confidence": 0.9, "reasoning": "Synthetic independent fixture verdict.",
                "independent_checks": [], "exploitability": "Synthetic fixture only.",
            })
            ws.flows_dir.mkdir(parents=True, exist_ok=True)
            (ws.flows_dir / "flow-smoke.http").write_text(
                "### REQUEST\nGET http://127.0.0.1:18767/api/profile?id=2\n\n### RESPONSE\nHTTP 200\n",
                encoding="utf-8",
            )
            for role, route, effort in (
                ("worker", config.WORKER_MODEL, config.WORKER_EFFORT),
                ("manager", config.MANAGER_MODEL, config.MANAGER_EFFORT),
                ("validator", config.VALIDATOR_MODEL, config.VALIDATOR_EFFORT),
            ):
                append_jsonl(ws.transcripts_dir / "provider-calls.jsonl", {
                    "role": role, "route": route, "effort": effort, "returncode": 0,
                })
            append_jsonl(ws.root / ".ledger/tool-calls.jsonl", {
                "tool": "http_request", "ok": True, "summary": "synthetic local capture",
            })
            ws.update_meta(status="stopped", turn_index=1)

            server = make_server(0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            errors: list[str] = []
            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(
                        headless=True, executable_path="/opt/google/chrome/chrome",
                        args=CHROME_ARGS,
                        ignore_default_args=["--enable-unsafe-swiftshader"],
                    )
                    page = browser.new_page(viewport={"width": 1440, "height": 1000})
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(f"http://127.0.0.1:{server.server_address[1]}")
                    page.get_by_text("Connected", exact=True).wait_for()
                    page.get_by_text("PINNED ROUTE ACTIVITY", exact=True).wait_for()
                    page.get_by_text("FINDINGS / ASTRA VERDICTS", exact=True).wait_for()
                    assert page.locator(".team-card").count() == 3
                    assert page.locator(".case-item").count() == 1
                    assert page.locator("#count-findings").inner_text() == "1/1"
                    assert page.get_by_text(config.WORKER_MODEL, exact=True).is_visible()
                    assert page.get_by_text(config.MANAGER_MODEL, exact=True).is_visible()
                    assert page.get_by_text(config.VALIDATOR_MODEL, exact=True).is_visible()
                    for width in (768, 390):
                        page.set_viewport_size({"width": width, "height": 844})
                        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                    browser.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            assert not errors, errors
            print(json.dumps({
                "ok": True,
                "models": [config.WORKER_MODEL, config.MANAGER_MODEL, config.VALIDATOR_MODEL],
                "checks": ["live API", "model cards", "engagement detail", "Astra verdict",
                           "tool and flow activity", "responsive widths", "no browser errors"],
            }))


if __name__ == "__main__":
    main()

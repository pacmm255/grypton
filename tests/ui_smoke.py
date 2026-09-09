"""Optional browser checks. Requires Playwright and an installed Chrome binary.

Run from the repository: python3 tests/ui_smoke.py
Uses synthetic state in a temporary directory; writes screenshots to docs/verification.
"""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from playwright.sync_api import sync_playwright
from grypton.backends import MockBackend
from grypton.config import Settings, resource
from grypton.engine import review
from grypton.storage import Store
from grypton.web import make_server


def main():
    output = Path(__file__).resolve().parents[1] / "docs/verification"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="grypton-ui-") as name:
        root = Path(name)
        store = Store(Settings.load(root))
        for index, scenario in enumerate(json.loads(resource("scenarios.json"))[:3]):
            case = store.create(scenario["title"], scenario["claim"])
            evidence = root / (scenario["id"] + ".txt")
            evidence.write_text(scenario["evidence"])
            store.add_evidence(case["id"], evidence)
            asyncio.run(review(store, case["id"], MockBackend()))
        store.create("Literal <b>markup</b> in a case title", "Markup is displayed as inert text.")
        server = make_server(store, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        errors = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
                page = browser.new_page(viewport={"width": 1440, "height": 1050}, device_scale_factor=1)
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(f"http://127.0.0.1:{server.server_address[1]}")
                page.get_by_text("Connected", exact=True).wait_for()
                page.locator(".case-item").nth(1).click()
                page.get_by_text("INDEPENDENT VERDICT", exact=True).wait_for()
                assert page.locator(".team-card").count() == 3
                assert page.locator(".case-item").count() == 4
                assert page.locator("#case-list b").count() == 0
                assert page.locator("#count-supported").inner_text() == "0"
                page.screenshot(path=str(output / "dashboard-desktop.png"), full_page=True)
                page.get_by_label("Search cases").fill("no matching case")
                assert page.get_by_text("No matching cases", exact=True).is_visible()
                page.get_by_label("Search cases").fill("")
                page.get_by_label("Filter by review status").select_option("draft")
                assert page.locator(".case-item").count() == 1
                page.get_by_label("Filter by review status").select_option("all")
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "dashboard-mobile.png"), full_page=True)
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                page.set_viewport_size({"width": 768, "height": 1024})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                page.get_by_role("button", name="Refresh", exact=False).click()
                page.wait_for_function("!document.getElementById('refresh').disabled")
                assert page.locator("#error-banner").is_hidden()
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        assert not errors, errors
        result = {"ok": True, "synthetic_only": True, "viewports": [1440, 768, 390],
                  "checks": ["case selection", "search", "status filter", "literal markup", "refresh", "no horizontal overflow", "no browser errors"]}
        (output / "browser-check.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))


if __name__ == "__main__":
    main()

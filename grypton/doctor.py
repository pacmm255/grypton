"""Read-only readiness checks; never print authentication contents."""
import json
import os
import shutil
import tempfile
from pathlib import Path

from .backends import clean, credential, run_process
from .config import MODELS


def extract_model(text: str, qualified: str) -> dict:
    marker = qualified + "\n"
    if marker not in text:
        raise ValueError("model not listed")
    rest = text.split(marker, 1)[1].lstrip()
    value, _ = json.JSONDecoder().raw_decode(rest)
    return value


async def doctor() -> dict:
    checks = []
    available = {binary: shutil.which(binary) for binary in ("opencode", "codex")}
    for binary, path in available.items():
        checks.append({"check": binary + " binary", "ok": bool(path), "detail": path or "not installed"})
    with tempfile.TemporaryDirectory(prefix="grypton-doctor-") as name:
        cwd = Path(name)
        for role in ("worker", "manager"):
            model = MODELS[role]
            try:
                credential(model.provider)
                checks.append({"check": model.provider + " authentication", "ok": True,
                               "detail": "configured; credential values withheld"})
            except Exception as exc:
                checks.append({"check": model.provider + " authentication", "ok": False, "detail": clean(str(exc))})
            if not available["opencode"]:
                continue
            try:
                code, stdout, _ = await run_process(["opencode", "models", model.provider, "--verbose", "--pure"],
                    cwd=cwd, env={**os.environ, "NO_COLOR": "1"}, timeout=30)
                metadata = extract_model(stdout, model.qualified) if code == 0 else {}
                ok = metadata.get("id") == model.model and model.effort in metadata.get("variants", {})
                checks.append({"check": role + " model / effort", "ok": ok,
                               "detail": model.qualified + " / " + model.effort + ("" if ok else " is not available in this CLI catalog")})
            except Exception:
                checks.append({"check": role + " model / effort", "ok": False, "detail": "Could not read OpenCode model metadata."})
        if available["codex"]:
            try:
                code, _, _ = await run_process(["codex", "login", "status"], cwd=cwd, env=dict(os.environ), timeout=15)
                checks.append({"check": "Codex authentication", "ok": code == 0, "detail": "configured" if code == 0 else "run codex login"})
                _, help_text, _ = await run_process(["codex", "exec", "--help"], cwd=cwd, env=dict(os.environ), timeout=15)
                ok = all(flag in help_text for flag in ("--ignore-user-config", "--ignore-rules", "--output-schema", "--ephemeral"))
                checks.append({"check": "Codex isolated validation flags", "ok": ok, "detail": "supported" if ok else "update Codex CLI"})
                path = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "models_cache.json"
                data = json.loads(path.read_text())
                model = next(m for m in data.get("models", []) if m.get("slug") == MODELS["validator"].model)
                ok = any(item.get("effort") == "max" for item in model.get("supported_reasoning_levels", []))
                checks.append({"check": "validator model / effort", "ok": ok, "detail": "gpt-6-astra / max (local catalog)"})
            except Exception:
                checks.append({"check": "Codex model readiness", "ok": False, "detail": "Refresh Codex model metadata, then rerun doctor."})
    return {"ok": all(check["ok"] for check in checks), "checks": checks,
            "notes": ["Catalog and credential checks do not prove current quota or provider availability.",
                      "Muse Spark 1.3 on Go is the Contributor variant; submitted data may be used for model training."]}

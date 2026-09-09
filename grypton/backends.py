"""Text-only provider adapters with isolated OpenCode settings and finite calls."""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import tempfile
from pathlib import Path

from .config import GryptonError, MODELS, Model, Settings
from .contracts import parse_output
from .storage import atomic_json, private_dir

MAX_OUTPUT_BYTES = 4_000_000
_CONTROL = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(text: str, secrets=()) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(bearer\s+)[\w.\-]+", r"\1[REDACTED]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}", "[REDACTED]", text)
    return _CONTROL.sub("", text)


def host_path(variable: str, default: str) -> Path:
    return Path(os.environ.get(variable, str(Path.home() / default)))


def credential(provider: str) -> dict:
    path = host_path("XDG_DATA_HOME", ".local/share") / "opencode/auth.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get(provider, {})
    except (OSError, ValueError, AttributeError) as exc:
        raise GryptonError("OpenCode credentials are unavailable; use opencode /connect for the required plan.") from exc
    if value.get("type") != "api" or not isinstance(value.get("key"), str) or not value["key"]:
        raise GryptonError(f"Connect {provider} in OpenCode before running a live review.")
    if provider == "opencode-go" and Path("/root/open").is_file():
        try:
            candidates = [line.strip() for line in Path("/root/open").read_text().splitlines()
                          if re.fullmatch(r"[A-Za-z0-9._-]{20,}", line.strip())]
        except OSError as exc:
            raise GryptonError("Cannot read the supplied Go credential file.") from exc
        if not candidates or value["key"] not in candidates:
            raise GryptonError("The installed OpenCode Go connector does not match the keys in /root/open.")
    return {"type": "api", "key": value["key"]}


async def terminate(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), 2)
    except asyncio.TimeoutError:
        pass
    finally:
        # Descendants may keep the pipes open after the parent has exited.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    await proc.wait()


async def run_process(argv: list[str], *, cwd: Path, env: dict, stdin: str = "", timeout: float = 600) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd, env=env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise GryptonError(f"Cannot start {Path(argv[0]).name}; run grypton doctor.") from exc

    async def read(stream):
        chunks, total = [], 0
        while chunk := await stream.read(16_384):
            total += len(chunk)
            if total > MAX_OUTPUT_BYTES:
                raise GryptonError("Provider output exceeded the bounded output limit.")
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")

    async def write():
        try:
            proc.stdin.write(stdin.encode("utf-8"))
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    tasks = [asyncio.create_task(write()), asyncio.create_task(read(proc.stdout)),
             asyncio.create_task(read(proc.stderr)), asyncio.create_task(proc.wait())]
    try:
        _, stdout, stderr, code = await asyncio.wait_for(asyncio.gather(*tasks), timeout)
        return code, stdout, stderr
    except asyncio.TimeoutError as exc:
        raise GryptonError(f"Provider call timed out after {timeout:g}s; the review can be retried.") from exc
    finally:
        await terminate(proc)
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def opencode_environment(directory: Path, model: Model) -> tuple[dict, str]:
    """Copy only this role's key to private, temporary XDG state; never into the repo."""
    auth = credential(model.provider)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("OPENCODE_", "OPENAI_", "ANTHROPIC_", "ZAI_", "ZHIPU_"))}
    for kind in ("CONFIG", "DATA", "CACHE", "STATE"):
        path = directory / kind.lower()
        private_dir(path)
        env[f"XDG_{kind}_HOME"] = str(path)
    atomic_json(directory / "data/opencode/auth.json", {model.provider: auth})
    cache = host_path("XDG_CACHE_HOME", ".cache") / "opencode/models.json"
    if cache.is_file():
        try:
            catalog = json.loads(cache.read_text())
            atomic_json(directory / "cache/opencode/models.json", {model.provider: catalog[model.provider]})
        except (OSError, ValueError, KeyError) as exc:
            raise GryptonError("Cannot load the installed OpenCode model catalog; refresh it with opencode models.") from exc
    inline = {
        "$schema": "https://opencode.ai/config.json", "enabled_providers": [model.provider],
        "model": model.qualified, "small_model": model.qualified,
        "default_agent": "grypton-review", "permission": "deny", "share": "disabled",
        "autoupdate": False, "plugin": [], "mcp": {},
        "agent": {"grypton-review": {"description": "Review supplied text only; no tools or external actions.",
                  "mode": "primary", "permission": "deny", "steps": 2,
                  "prompt": "Use the supplied workspace context. Make concrete progress without tool calls. Return the requested JSON."}},
    }
    env.update({"OPENCODE_CONFIG_CONTENT": json.dumps(inline),
                "OPENCODE_CONFIG_DIR": str(directory / "config/opencode"),
                "OPENCODE_DISABLE_CLAUDE_CODE": "true", "OPENCODE_DISABLE_PROJECT_CONFIG": "true",
                "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS": "true", "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
                "OPENCODE_PERMISSION": json.dumps({"*": "deny"}), "NO_COLOR": "1"})
    return env, auth["key"]


def opencode_text(stdout: str, secret: str = "") -> str:
    chunks = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError as exc:
            raise GryptonError("OpenCode emitted a malformed event; no result was accepted.") from exc
        if not isinstance(event, dict):
            raise GryptonError("OpenCode emitted an invalid event object.")
        if event.get("type") == "error":
            error = event.get("error", {})
            detail = json.dumps(error, ensure_ascii=False) if isinstance(error, dict) else str(error)
            raise GryptonError("OpenCode: " + clean(detail, (secret,))[:600])
        if event.get("type") == "tool_use":
            raise GryptonError("A provider attempted tool use in a text-only review; result rejected.")
        if event.get("type") == "text":
            part = event.get("part", {})
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(part["text"])
    if not chunks:
        raise GryptonError("OpenCode produced no final text; check the configured model and quota.")
    return clean("".join(chunks), (secret,))


def codex_command(model: Model, directory: Path) -> list[str]:
    argv = ["codex", "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
            "--skip-git-repo-check", "--sandbox", "read-only", "--model", model.model,
            "--json", "--color", "never", "--output-schema", str(directory / "schema.json"),
            "--output-last-message", str(directory / "answer.json"),
            "-c", f'model_reasoning_effort="{model.effort}"', "-c", 'approval_policy="never"',
            "-c", 'web_search="disabled"', "-c", "project_doc_max_bytes=0"]
    for feature in ("shell_tool", "unified_exec", "multi_agent", "apps", "plugins", "computer_use",
                    "skill_search", "shell_snapshot", "view_image"):
        argv.extend(["--disable", feature])
    return argv + ["-"]


class LiveBackend:
    mock = False

    def __init__(self, settings: Settings):
        self.settings = settings

    async def call(self, role: str, stage: str, prompt: str, schema: dict, payload: dict) -> dict:
        model = MODELS[role]
        if not shutil.which(model.runner):
            raise GryptonError(f"{model.runner} is not installed; run grypton doctor.")
        with tempfile.TemporaryDirectory(prefix="grypton-provider-") as name:
            directory = Path(name)
            if model.runner == "opencode":
                env, secret = opencode_environment(directory, model)
                argv = ["opencode", "run", "--pure", "--format", "json", "--model", model.qualified,
                        "--variant", model.effort, "--agent", "grypton-review", "--title", f"Grypton {role} {stage}"]
                code, stdout, stderr = await run_process(argv, cwd=directory, env=env, stdin=prompt, timeout=self.settings.timeout)
                if code:
                    raise GryptonError(f"{model.name} exited with code {code}: " + clean(stderr, (secret,))[-600:])
                return parse_output(opencode_text(stdout, secret), schema)
            atomic_json(directory / "schema.json", schema)
            env = {key: value for key, value in os.environ.items() if not key.startswith("OPENCODE_")}
            code, stdout, stderr = await run_process(codex_command(model, directory), cwd=directory,
                                                     env=env, stdin=prompt, timeout=self.settings.timeout)
            if code:
                raise GryptonError(f"Codex exited with code {code}: " + clean(stderr)[-600:])
            for line in stdout.splitlines():
                try:
                    event = json.loads(line)
                except ValueError as exc:
                    raise GryptonError("Codex emitted an invalid event; result rejected.") from exc
                if event.get("type") in ("error", "turn.failed"):
                    raise GryptonError("Codex reported a failed validation; no verdict was accepted.")
                item = event.get("item", {})
                if item.get("type") in ("command_execution", "mcp_tool_call", "web_search", "file_change"):
                    raise GryptonError("Codex attempted tool use in a text-only review; result rejected.")
            path = directory / "answer.json"
            if not path.is_file() or path.stat().st_size > MAX_OUTPUT_BYTES:
                raise GryptonError("Codex did not produce a bounded final validation response.")
            return parse_output(clean(path.read_text(encoding="utf-8")), schema)


class MockBackend:
    """A transport-free walkthrough; its verdict is always explicitly inconclusive."""
    mock = True

    async def call(self, role: str, stage: str, prompt: str, schema: dict, payload: dict) -> dict:
        await asyncio.sleep(0)
        if stage == "chat":
            label = "Kryptex" if role == "manager" else "Kraude"
            return {"reply": f"{label} received the message in offline mock mode.",
                    "remember": payload.get("user_message", "") if role == "manager" else "",
                    "disposition": "apply-now" if role == "manager" else "reply-only",
                    "worker_note": payload.get("user_message", "") if role == "manager" else "",
                    "requirements": []}
        if stage in {"plan", "finding_plan"}:
            return {"summary": "Offline demonstration of an evidence review.",
                    "checks": ["Map the claim to supplied evidence.", "Identify missing context and remediation criteria."],
                    "requirements": ["existing_evidence"]}
        if role == "worker":
            return {"assessment": "inconclusive", "rationale": "Mock analysis; no model was called.",
                    "evidence_ids": [item["id"] for item in payload["evidence"]],
                    "remediation": ["Review the supplied configuration with its owner."], "requirements": []}
        if role == "validator":
            return {"verdict": "inconclusive", "severity": "unknown", "rationale": "Mock validation is not evidence of a defect.",
                    "evidence_ids": [item["id"] for item in payload["evidence"]],
                    "limitations": ["No model, network request, or program execution was used."],
                    "remediation": ["Arrange an owner review of the configuration and defensive checks."]}
        return {"summary": "Offline review completed. The claim remains inconclusive because this was a mock run.",
                "next_steps": ["Attach relevant owner-supplied evidence before requesting a live review."]}

"""Finite, checkpointed evidence review; no autonomous target execution."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid

from .config import GryptonError, MODELS
from .contracts import ASSESSMENT, PLAN, SUMMARY, VERDICT, check_references, validate
from .prompts import build
from .storage import Store, atomic_json, private_dir


def resolve_requirements(requirements: list[str], case: dict, directory) -> list[dict]:
    resolved = []
    for kind in dict.fromkeys(requirements):
        if kind == "existing_evidence":
            result = {"kind": kind, "status": "resolved", "detail": [e["id"] for e in case["evidence"]]}
        elif kind == "offline_email":
            result = {"kind": kind, "status": "resolved", "detail": "fixture@grypton.invalid (synthetic; no delivery or real account)"}
        elif kind == "scratch_directory":
            private_dir(directory / "scratch")
            result = {"kind": kind, "status": "resolved", "detail": "A private local scratch directory has been allocated."}
        else:
            result = {"kind": kind, "status": "unavailable", "detail": "Continue independent evidence review and record this gap."}
        resolved.append(result)
    return resolved


def evidence_snapshot(case: dict) -> dict:
    return {"claim": case["claim"], "evidence": [
        {key: e[key] for key in ("id", "name", "sha256", "text")} for e in case["evidence"]]}


async def review(store: Store, case_id: str, backend, *, resume: bool = False, emit=None) -> dict:
    with store.run_lock(case_id):
        case = store.get(case_id)
        if not case["evidence"]:
            raise GryptonError("Attach at least one evidence file before requesting a review.")
        snapshot = evidence_snapshot(case)
        digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
        route = {role: model.public() for role, model in MODELS.items()}
        mode = "mock" if backend.mock else "live"
        if resume:
            if not case["runs"] or case["runs"][-1]["status"] == "complete":
                raise GryptonError("There is no interrupted or failed review to resume.")
            run = case["runs"][-1]
            if run["input_sha256"] != digest or run["mode"] != mode or run["models"] != route:
                raise GryptonError("Evidence, backend, or model configuration changed; start a new review.")
        else:
            if len(case["runs"]) >= 100:
                raise GryptonError("This case has reached its 100-review limit; create a new case.")
            run = {"id": uuid.uuid4().hex, "created_at": time.time(), "status": "running", "mode": mode,
                   "input_sha256": digest, "models": route, "stages": {}, "events": [], "resources": []}
            store.mutate(case_id, lambda value: value["runs"].append(run))
        run["status"] = "running"
        run.pop("error", None)
        stop_path = store.directory(case_id) / ".stop.json"
        stop_path.unlink(missing_ok=True)

        def save():
            def update(record):
                record["status"] = run["status"]
                for index, old in enumerate(record["runs"]):
                    if old["id"] == run["id"]:
                        record["runs"][index] = run
                        break
                else:
                    raise GryptonError("The active review checkpoint is missing.")
            store.mutate(case_id, update)

        def event(stage: str, status: str, detail: str):
            value = {"stage": stage, "status": status, "detail": detail, "at": time.time()}
            run["events"].append(value)
            save()
            if emit:
                emit(value)

        async def perform(stage: str, role: str, schema: dict, payload: dict):
            if stop_path.exists():
                raise asyncio.CancelledError()
            if stage in run["stages"]:
                result = run["stages"][stage]
                validate(result, schema)
                if role in ("worker", "validator"):
                    check_references(result, snapshot["evidence"])
                event(stage, "reused", "Using the completed checkpoint.")
                return result
            event(stage, "running", f"{MODELS[role].name}: {MODELS[role].qualified} / {MODELS[role].effort}")
            task = asyncio.create_task(backend.call(role, stage, build(role, stage, payload, schema), schema, payload))
            try:
                while not task.done():
                    if stop_path.exists():
                        raise asyncio.CancelledError()
                    await asyncio.wait({task}, timeout=0.2)
                result = await task
                validate(result, schema)
                if role in ("worker", "validator"):
                    check_references(result, snapshot["evidence"])
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            run["stages"][stage] = result
            event(stage, "complete", f"{MODELS[role].name} returned a valid structured response.")
            return result

        try:
            save()
            plan = await perform("plan", "manager", PLAN, snapshot)
            run["resources"] = resolve_requirements(plan["requirements"], case, store.directory(case_id))
            save()
            assessment = await perform("assessment", "worker", ASSESSMENT,
                                       {**snapshot, "checklist": plan, "resources": run["resources"]})
            if assessment["requirements"]:
                already_available = {"existing_evidence"} | {item["kind"] for item in run["resources"]
                                                               if item["status"] == "resolved"}
                resources = resolve_requirements(assessment["requirements"], case, store.directory(case_id))
                run["resources"].extend(resources)
                event("requirements", "complete", "Local requirements resolved; unavailable resources recorded.")
                if any(item["status"] == "resolved" and item["kind"] not in already_available for item in resources):
                    assessment = await perform("assessment_followup", "worker", ASSESSMENT,
                                               {**snapshot, "checklist": plan, "previous_assessment": assessment,
                                                "resources": run["resources"], "remaining_followups": 0})
                    # This is the last worker call. Preserve any outstanding request as a gap.
                    if assessment["requirements"]:
                        run["resources"].extend({"kind": kind, "status": "unavailable",
                            "detail": "Bounded review follow-up exhausted; no further worker call."}
                            for kind in assessment["requirements"])
                        save()
            # Always independent: never pass the worker's verdict, rationale, or severity to Codex.
            verdict = await perform("validation", "validator", VERDICT, snapshot)
            await perform("summary", "manager", SUMMARY,
                          {"claim": case["claim"], "assessment": assessment, "validation": verdict,
                           "resources": run["resources"], "review_mode": mode})
            run["status"] = "complete"
            run["finished_at"] = time.time()
            event("review", "complete", "Independent evidence review completed.")
            return run
        except asyncio.CancelledError:
            run["status"] = "interrupted"
            event("review", "interrupted", "Review stopped. Completed stages are available to resume.")
            raise
        except Exception as exc:
            run["status"] = "failed"
            run["error"] = str(exc) if isinstance(exc, GryptonError) else "Unexpected review failure; no final verdict was accepted."
            event("review", "failed", run["error"])
            if isinstance(exc, GryptonError):
                raise
            raise GryptonError(run["error"]) from exc


def stop(store: Store, case_id: str) -> dict:
    case = store.get(case_id)
    if case["status"] != "running":
        raise GryptonError("This case does not have a running review.")
    atomic_json(store.directory(case_id) / ".stop.json", {"requested_at": time.time()})
    return {"id": case_id, "status": "stop_requested"}

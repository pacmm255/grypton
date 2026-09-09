"""Finite, checkpointed evidence review; no autonomous target execution."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid

from .config import GryptonError, MODELS
from .contracts import ASSESSMENT, PLAN, SUMMARY, VERDICT, check_references, validate
from .prompts import build, prompt_fingerprints
from .storage import Store, atomic_json, private_dir


def resolve_requirements(requirements: list[str], case: dict, directory) -> list[dict]:
    resolved = []
    for kind in dict.fromkeys(requirements):
        if kind == "existing_evidence":
            ids = [e["id"] for e in case["evidence"]]
            result = ({"kind": kind, "status": "resolved", "detail": ids} if ids else
                      {"kind": kind, "status": "unavailable", "detail": "No evidence is attached yet."})
        elif kind == "offline_email":
            label = re.sub(r"[^a-z0-9]+", "-", str(case.get("id", "review")).lower()).strip("-")[:48]
            result = {"kind": kind, "status": "resolved",
                      "detail": f"review+{label}@grypton.invalid (synthetic; no delivery or real account)"}
        elif kind == "offline_identity":
            result = {"kind": kind, "status": "resolved",
                      "detail": "grypton-synthetic-operator (local fixture; no external identity or authority)"}
        elif kind == "temporary_text_fixture":
            result = {"kind": kind, "status": "resolved",
                      "detail": "grypton-local-fixture (synthetic placeholder; no external system or account)"}
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


def canonical_sha256(value) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def review_context(case: dict, snapshot: dict) -> dict:
    return {**snapshot, "target": case.get("target", ""), "brief": case.get("brief", ""),
            "standing_instructions": case.get("standing_instructions", []),
            "scope": case.get("scope", {}),
            "observations": case.get("observations", [])[-50:],
            "surface": case.get("surface", [])[-50:]}


async def review(store: Store, case_id: str, backend, *, resume: bool = False, emit=None) -> dict:
    with store.run_lock(case_id):
        case = store.get(case_id)
        if not case["evidence"]:
            raise GryptonError("Attach at least one evidence file before requesting a review.")
        snapshot = evidence_snapshot(case)
        context = review_context(case, snapshot)
        digest = canonical_sha256(context)
        route = {role: model.public() for role, model in MODELS.items()}
        prompts = prompt_fingerprints()
        mode = "mock" if backend.mock else "live"
        if resume:
            if not case["runs"] or case["runs"][-1]["status"] == "complete":
                raise GryptonError("There is no interrupted or failed review to resume.")
            run = case["runs"][-1]
            if (run.get("input_sha256") != digest or run.get("mode") != mode or run.get("models") != route
                    or run.get("prompt_fingerprints") != prompts):
                raise GryptonError("Evidence, context, prompts, backend, or model configuration changed; start a new review.")
        else:
            if len(case["runs"]) >= 100:
                raise GryptonError("This case has reached its 100-review limit; create a new case.")
            run = {"id": uuid.uuid4().hex, "created_at": time.time(), "status": "running", "mode": mode,
                   "input_sha256": digest, "models": route, "prompt_fingerprints": prompts,
                   "stages": {}, "events": [], "resources": [], "calls": []}
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
            prompt = build(role, stage, payload, schema)
            started_at = time.time()
            started = time.monotonic()
            audit = {"stage": stage, "role": role, "started_at": started_at,
                     "route": MODELS[role].public(), "input_sha256": canonical_sha256(payload),
                     "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest()}
            task = asyncio.create_task(backend.call(role, stage, prompt, schema, payload))
            try:
                while not task.done():
                    if stop_path.exists():
                        raise asyncio.CancelledError()
                    await asyncio.wait({task}, timeout=0.2)
                result = await task
                validate(result, schema)
                if role in ("worker", "validator"):
                    check_references(result, snapshot["evidence"])
                audit.update({"status": "complete", "duration_ms": round((time.monotonic() - started) * 1000),
                              "output_sha256": canonical_sha256(result)})
            except BaseException:
                audit.update({"status": "failed", "duration_ms": round((time.monotonic() - started) * 1000)})
                raise
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                run.setdefault("calls", []).append(audit)
            run["stages"][stage] = result
            event(stage, "complete", f"{MODELS[role].name} returned a valid structured response.")
            return result

        try:
            save()
            plan = await perform("plan", "manager", PLAN, context)
            run["resources"] = resolve_requirements(plan["requirements"], case, store.directory(case_id))
            save()
            assessment = await perform("assessment", "worker", ASSESSMENT,
                                       {**context, "checklist": plan, "resources": run["resources"]})
            if assessment["requirements"]:
                already_available = {"existing_evidence"} | {item["kind"] for item in run["resources"]
                                                               if item["status"] == "resolved"}
                resources = resolve_requirements(assessment["requirements"], case, store.directory(case_id))
                run["resources"].extend(resources)
                event("requirements", "complete", "Local requirements resolved; unavailable resources recorded.")
                if any(item["status"] == "resolved" and item["kind"] not in already_available for item in resources):
                    assessment = await perform("assessment_followup", "worker", ASSESSMENT,
                                               {**context, "checklist": plan, "previous_assessment": assessment,
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
                           "resources": run["resources"], "review_mode": mode,
                           "scope": case.get("scope", {})})
            run["status"] = "complete"
            run["finished_at"] = time.time()
            event("review", "complete", "Independent evidence review completed.")
            store.record_review_finding(case_id, run)
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


async def validate_finding(store: Store, case_id: str, finding_id: str, backend, *, emit=None) -> dict:
    """Kryptex coordinates one independent Astra validation of a ledger finding."""
    with store.run_lock(case_id):
        case = store.get(case_id)
        previous_case_status = "draft" if case["status"] == "running" else case["status"]
        finding = store.get_finding(case_id, finding_id)
        wanted = set(finding.get("evidence_ids", []))
        evidence = [{key: item[key] for key in ("id", "name", "sha256", "text")}
                    for item in case["evidence"] if item["id"] in wanted]
        if not evidence:
            raise GryptonError("Attach and select at least one evidence artifact before validating this finding.")
        if {item["id"] for item in evidence} != wanted:
            raise GryptonError("The finding references evidence that is no longer attached.")
        snapshot = {"claim": finding["claim"], "evidence": evidence}
        context = {**review_context(case, snapshot), "finding_id": finding_id,
                   "finding_title": finding["title"]}
        route = {role: model.public() for role, model in MODELS.items()}
        mode = "mock" if backend.mock else "live"
        run = {"id": uuid.uuid4().hex, "created_at": time.time(), "status": "running",
               "mode": mode, "input_sha256": canonical_sha256(context), "models": route,
               "prompt_fingerprints": prompt_fingerprints(), "stages": {}, "events": [],
               "resources": [], "calls": []}
        stop_path = store.directory(case_id) / ".stop.json"
        stop_path.unlink(missing_ok=True)

        def set_case_status(status: str):
            store.mutate(case_id, lambda record: record.update(status=status))

        def save_finding(status: str | None = None, error: str = ""):
            def update(item):
                if status:
                    item["status"] = status
                item["validation_run"] = run
                if error:
                    item["validation_error"] = error
                else:
                    item.pop("validation_error", None)
            store.update_finding(case_id, finding_id, update)

        def event(stage: str, status: str, detail: str):
            value = {"stage": stage, "status": status, "detail": detail, "at": time.time()}
            run["events"].append(value)
            save_finding()
            if emit:
                emit(value)

        async def perform(stage: str, role: str, schema: dict, payload: dict):
            if stop_path.exists():
                raise asyncio.CancelledError()
            prompt = build(role, stage, payload, schema)
            started_at, started = time.time(), time.monotonic()
            audit = {"stage": stage, "role": role, "started_at": started_at,
                     "route": MODELS[role].public(), "input_sha256": canonical_sha256(payload),
                     "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest()}
            event(stage, "running", f"{MODELS[role].name}: {MODELS[role].qualified} / {MODELS[role].effort}")
            task = asyncio.create_task(backend.call(role, stage, prompt, schema, payload))
            try:
                while not task.done():
                    if stop_path.exists():
                        raise asyncio.CancelledError()
                    await asyncio.wait({task}, timeout=0.2)
                result = await task
                validate(result, schema)
                if role == "validator":
                    check_references(result, snapshot["evidence"])
                audit.update({"status": "complete", "duration_ms": round((time.monotonic() - started) * 1000),
                              "output_sha256": canonical_sha256(result)})
            except BaseException:
                audit.update({"status": "failed", "duration_ms": round((time.monotonic() - started) * 1000)})
                raise
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                run["calls"].append(audit)
            run["stages"][stage] = result
            event(stage, "complete", f"{MODELS[role].name} returned a valid structured response.")
            return result

        try:
            set_case_status("running")
            save_finding("validating")
            plan = await perform("finding_plan", "manager", PLAN, context)
            run["resources"] = resolve_requirements(plan["requirements"], case, store.directory(case_id))
            # Independence boundary: manager output is deliberately absent here.
            verdict = await perform("finding_validation", "validator", VERDICT, snapshot)
            summary = await perform("finding_summary", "manager", SUMMARY,
                                    {"claim": finding["claim"], "validation": verdict,
                                     "resources": run["resources"], "review_mode": mode})
            run["status"] = "complete"
            run["finished_at"] = time.time()
            event("finding", "complete", "Kryptex completed independent Astra validation.")

            def complete(item):
                item["status"] = verdict["verdict"]
                item["severity"] = verdict["severity"]
                item["validation"] = verdict
                item["summary"] = summary
                item["manager_plan"] = plan
                item["models"] = route
                item["input_sha256"] = run["input_sha256"]
                history = item.setdefault("validation_history", [])
                history.append({"at": run["finished_at"], "verdict": verdict["verdict"],
                                "severity": verdict["severity"], "mode": mode,
                                "run_id": run["id"]})
                del history[:-20]
            result = store.update_finding(case_id, finding_id, complete)
            set_case_status(previous_case_status)
            stop_path.unlink(missing_ok=True)
            return result
        except asyncio.CancelledError:
            run["status"] = "interrupted"
            save_finding("candidate", "Validation interrupted; retry when ready.")
            set_case_status(previous_case_status)
            stop_path.unlink(missing_ok=True)
            raise
        except Exception as exc:
            run["status"] = "failed"
            message = str(exc) if isinstance(exc, GryptonError) else "Unexpected finding validation failure."
            save_finding("candidate", message)
            set_case_status(previous_case_status)
            stop_path.unlink(missing_ok=True)
            if isinstance(exc, GryptonError):
                raise
            raise GryptonError(message) from exc


def stop(store: Store, case_id: str) -> dict:
    case = store.get(case_id)
    if case["status"] != "running":
        raise GryptonError("This case does not have a running review.")
    atomic_json(store.directory(case_id) / ".stop.json", {"requested_at": time.time()})
    return {"id": case_id, "status": "stop_requested"}

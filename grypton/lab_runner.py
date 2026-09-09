"""Run the packaged synthetic evidence transitions through the Grypton pipeline."""
from __future__ import annotations

import copy
import hashlib
import tempfile
import time
from pathlib import Path

from .backends import LiveBackend, MockBackend
from .config import GryptonError, Settings
from .engine import review
from .lab import load_suite, score_scenario, score_suite, score_turn
from .storage import Store


class TracedBackend:
    def __init__(self, backend):
        self.backend = backend
        self.mock = backend.mock
        self.calls = 0
        self.validator_payload_keys: list[str] | None = None

    async def call(self, role, stage, prompt, schema, payload):
        self.calls += 1
        if role == "validator":
            self.validator_payload_keys = sorted(payload)
        return await self.backend.call(role, stage, prompt, schema, payload)


def _fixture_evidence(turn: dict) -> list[dict]:
    now = time.time()
    return [{"id": item["id"], "name": item["name"],
             "sha256": hashlib.sha256(item["text"].encode("utf-8")).hexdigest(),
             "text": item["text"], "added_at": now}
            for item in turn["evidence"]]


async def run_lab(settings: Settings, *, scenario_id: str | None = None,
                  live: bool = False, emit=None) -> dict:
    """Evaluate fixed package fixtures; never reads a target or caller workspace."""
    suite = load_suite()
    scenarios = [item for item in suite["scenarios"]
                 if scenario_id is None or item["id"] == scenario_id]
    if not scenarios:
        raise GryptonError(f"Unknown lab scenario: {scenario_id}")
    results: dict[str, dict[str, dict]] = {}
    with tempfile.TemporaryDirectory(prefix="grypton-lab-run-") as name:
        lab_settings = Settings.load(Path(name), timeout=settings.timeout)
        store = Store(lab_settings)
        for scenario in scenarios:
            scenario_results = {}
            for turn in scenario["turns"]:
                case = store.create(f"{scenario['id']} {turn['id']}", scenario["claim"],
                                    target=f"synthetic:{scenario['id']}:{turn['id']}")

                def attach(record):
                    record["evidence"] = _fixture_evidence(turn)
                    record["scope"]["type"] = "code"
                    record["scope"]["in_scope"] = ["packaged synthetic fixture"]
                    record["scope"]["rules"] = ["No target, tool, or external-system interaction."]
                store.mutate(case["id"], attach)
                traced = TracedBackend(LiveBackend(lab_settings) if live else MockBackend())
                if emit:
                    emit({"scenario": scenario["id"], "turn": turn["id"],
                          "status": "running"})
                run = await review(store, case["id"], traced)
                run = copy.deepcopy(run)
                run["lab_trace"] = {"validator_payload_keys": traced.validator_payload_keys,
                                    "model_calls": traced.calls, "tool_calls": 0,
                                    "network_calls": traced.calls if live else 0}
                scenario_results[turn["id"]] = run
                if emit:
                    emit({"scenario": scenario["id"], "turn": turn["id"],
                          "status": "complete", "score": score_turn(scenario, turn, run)["score"]})
            results[scenario["id"]] = scenario_results
    if scenario_id:
        score = score_scenario(scenarios[0], results[scenario_id])
    else:
        score = score_suite(results, suite)
    return {"suite_id": suite["suite_id"], "mode": "live" if live else "mock",
            "scenario_count": len(scenarios),
            "turn_count": sum(len(item["turns"]) for item in scenarios),
            "score": score, "results": results, "target_interaction": False}

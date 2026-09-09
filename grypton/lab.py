"""Deterministic scoring for bundled, offline evidence-review fixtures.

This module deliberately has no transport or execution adapter.  It accepts run
records produced elsewhere and compares them with fixed package data.  Loading
the suite, hashing fixtures, and scoring results cannot invoke a model, tool,
subprocess, network service, or target workspace.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from .config import GryptonError, resource
from .contracts import ASSESSMENT, PLAN, SUMMARY, VERDICT, check_references, validate


SCHEMA_VERSION = 1
EVALUATOR_VERSION = "1.0"
OUTCOMES = {"supported", "refuted", "inconclusive"}
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
REQUIREMENTS = {
    "existing_evidence", "offline_email", "scratch_directory", "external_account",
    "missing_evidence", "network_access",
}
ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
STAGE_SCHEMAS = {"plan": PLAN, "assessment": ASSESSMENT, "validation": VERDICT, "summary": SUMMARY}
COMPONENTS = (
    "plan_contract", "assessment_contract", "validation_contract", "summary_contract",
    "assessment_outcome", "validator_outcome", "severity_discipline",
    "assessment_citations", "validator_citations", "requirements_discipline",
    "rationale_grounding", "remediation_quality", "hallucination_guard",
)


def canonical_digest(value: Any) -> str:
    """Return a stable digest for JSON-compatible fixture or result data."""
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _bounded_text(value: Any, path: str, *, maximum: int = 20_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise GryptonError(f"{path}: expected nonempty bounded text.")
    return value


def _id(value: Any, path: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise GryptonError(f"{path}: expected a stable lowercase ID.")
    return value


def _concept_groups(value: Any, path: str) -> list[list[str]]:
    if not isinstance(value, list) or not value:
        raise GryptonError(f"{path}: expected a nonempty list of concept groups.")
    groups: list[list[str]] = []
    for index, group in enumerate(value):
        if not isinstance(group, list) or not group:
            raise GryptonError(f"{path}[{index}]: expected one or more alternative phrases.")
        groups.append([_bounded_text(item, f"{path}[{index}][]", maximum=160).casefold() for item in group])
    return groups


def validate_suite(suite: Any) -> dict:
    """Validate the complete lab format and return it with no normalization."""
    if not isinstance(suite, dict) or set(suite) != {"schema_version", "suite_id", "offline_only", "scenarios"}:
        raise GryptonError("Lab suite must contain exactly schema_version, suite_id, offline_only, and scenarios.")
    if suite["schema_version"] != SCHEMA_VERSION or suite["offline_only"] is not True:
        raise GryptonError("Lab suite must use the supported schema and declare offline_only=true.")
    _id(suite["suite_id"], "suite_id")
    if not isinstance(suite["scenarios"], list) or not suite["scenarios"]:
        raise GryptonError("Lab suite must contain at least one scenario.")
    scenario_ids: set[str] = set()
    for scenario_index, scenario in enumerate(suite["scenarios"]):
        path = f"scenarios[{scenario_index}]"
        required = {"id", "title", "claim", "turns"}
        if not isinstance(scenario, dict) or set(scenario) != required:
            raise GryptonError(f"{path}: unexpected scenario fields.")
        scenario_id = _id(scenario["id"], path + ".id")
        if scenario_id in scenario_ids:
            raise GryptonError(f"{path}: duplicate scenario ID.")
        scenario_ids.add(scenario_id)
        _bounded_text(scenario["title"], path + ".title", maximum=160)
        _bounded_text(scenario["claim"], path + ".claim", maximum=12_000)
        turns = scenario["turns"]
        if not isinstance(turns, list) or len(turns) < 2 or len(turns) > 12:
            raise GryptonError(f"{path}.turns: expected 2-12 ordered turns.")
        turn_ids: set[str] = set()
        previous_ids: set[str] = set()
        for turn_index, turn in enumerate(turns):
            turn_path = f"{path}.turns[{turn_index}]"
            if not isinstance(turn, dict) or set(turn) != {"id", "evidence", "expected"}:
                raise GryptonError(f"{turn_path}: unexpected turn fields.")
            turn_id = _id(turn["id"], turn_path + ".id")
            if turn_id in turn_ids:
                raise GryptonError(f"{turn_path}: duplicate turn ID.")
            turn_ids.add(turn_id)
            evidence = turn["evidence"]
            if not isinstance(evidence, list) or not evidence or len(evidence) > 16:
                raise GryptonError(f"{turn_path}.evidence: expected 1-16 fixed artifacts.")
            evidence_ids: set[str] = set()
            for evidence_index, item in enumerate(evidence):
                item_path = f"{turn_path}.evidence[{evidence_index}]"
                if not isinstance(item, dict) or set(item) != {"id", "name", "text"}:
                    raise GryptonError(f"{item_path}: unexpected evidence fields.")
                evidence_id = _id(item["id"], item_path + ".id")
                if evidence_id in evidence_ids:
                    raise GryptonError(f"{item_path}: duplicate evidence ID.")
                evidence_ids.add(evidence_id)
                _bounded_text(item["name"], item_path + ".name", maximum=240)
                _bounded_text(item["text"], item_path + ".text")
            if not previous_ids.issubset(evidence_ids):
                raise GryptonError(f"{turn_path}: later turns must retain prior evidence IDs.")
            previous_ids = evidence_ids
            expected = turn["expected"]
            expected_fields = {
                "assessment", "verdict", "severity", "required_citations", "requirements",
                "rationale_concepts", "remediation_concepts", "forbidden_fragments",
            }
            if not isinstance(expected, dict) or set(expected) != expected_fields:
                raise GryptonError(f"{turn_path}.expected: unexpected expectation fields.")
            if expected["assessment"] not in OUTCOMES or expected["verdict"] not in OUTCOMES:
                raise GryptonError(f"{turn_path}.expected: invalid expected outcome.")
            if expected["severity"] not in SEVERITIES:
                raise GryptonError(f"{turn_path}.expected: invalid expected severity.")
            if expected["verdict"] != "supported" and expected["severity"] != "unknown":
                raise GryptonError(f"{turn_path}.expected: non-supported verdicts require unknown severity.")
            citations = expected["required_citations"]
            if not isinstance(citations, dict) or set(citations) != {"assessment", "validation"}:
                raise GryptonError(f"{turn_path}.expected.required_citations: expected both review roles.")
            for role, ids in citations.items():
                if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)) or not set(ids) <= evidence_ids:
                    raise GryptonError(f"{turn_path}.expected.required_citations.{role}: invalid fixture IDs.")
            requirements = expected["requirements"]
            if not isinstance(requirements, list) or len(requirements) != len(set(requirements)) or not set(requirements) <= REQUIREMENTS:
                raise GryptonError(f"{turn_path}.expected.requirements: invalid requirement set.")
            _concept_groups(expected["rationale_concepts"], turn_path + ".expected.rationale_concepts")
            _concept_groups(expected["remediation_concepts"], turn_path + ".expected.remediation_concepts")
            fragments = expected["forbidden_fragments"]
            if not isinstance(fragments, list) or not fragments:
                raise GryptonError(f"{turn_path}.expected.forbidden_fragments: expected a nonempty list.")
            for index, fragment in enumerate(fragments):
                _bounded_text(fragment, f"{turn_path}.expected.forbidden_fragments[{index}]", maximum=240)
    return suite


def load_suite() -> dict:
    """Load and validate the immutable package fixture suite."""
    try:
        suite = json.loads(resource("lab_scenarios.json"))
    except (ValueError, TypeError) as exc:
        raise GryptonError("The packaged lab scenario suite is invalid JSON.") from exc
    return validate_suite(suite)


def fixture_payload(scenario: Mapping[str, Any], turn: Mapping[str, Any]) -> dict:
    """Build the exact claim/evidence payload used for an offline lab turn."""
    return {"claim": scenario["claim"], "evidence": [dict(item) for item in turn["evidence"]]}


def _has_concepts(text: str, groups: list[list[str]]) -> bool:
    folded = text.casefold()
    return all(any(alternative in folded for alternative in group) for group in groups)


def _stage_valid(stage: str, value: Any, evidence: list[dict]) -> bool:
    try:
        validate(value, STAGE_SCHEMAS[stage])
        if stage in {"assessment", "validation"}:
            check_references(value, evidence)
        return True
    except (GryptonError, KeyError, TypeError):
        return False


def _citation_score(value: Any, key: str, required: list[str], allowed: set[str]) -> float:
    if not isinstance(value, dict) or not isinstance(value.get("evidence_ids"), list):
        return 0.0
    cited = set(value["evidence_ids"])
    return float(cited <= allowed and set(required) <= cited and key in value)


def _trace_diagnostics(run: Mapping[str, Any]) -> dict:
    trace = run.get("lab_trace")
    if not isinstance(trace, Mapping):
        return {"measured": False, "validator_isolated": None, "offline": None, "bounded_calls": None}
    keys = trace.get("validator_payload_keys")
    calls = trace.get("model_calls")
    tool_calls = trace.get("tool_calls")
    network_calls = trace.get("network_calls")
    return {
        "measured": True,
        "validator_isolated": isinstance(keys, list) and sorted(keys) == ["claim", "evidence"],
        "offline": tool_calls == 0 and network_calls == 0,
        "bounded_calls": isinstance(calls, int) and not isinstance(calls, bool) and 0 <= calls <= 5,
    }


def score_turn(scenario: Mapping[str, Any], turn: Mapping[str, Any], run: Mapping[str, Any] | None) -> dict:
    """Score one run against one turn using 13 equally weighted components."""
    run = run if isinstance(run, Mapping) else {}
    stages = run.get("stages") if isinstance(run.get("stages"), Mapping) else {}
    evidence = [dict(item) for item in turn["evidence"]]
    expected = turn["expected"]
    plan = stages.get("plan")
    assessment = stages.get("assessment_followup", stages.get("assessment"))
    validation_result = stages.get("validation")
    summary = stages.get("summary")
    valid = {
        "plan": _stage_valid("plan", plan, evidence),
        "assessment": _stage_valid("assessment", assessment, evidence),
        "validation": _stage_valid("validation", validation_result, evidence),
        "summary": _stage_valid("summary", summary, evidence),
    }
    allowed = {item["id"] for item in evidence}
    rationale = " ".join(str(value) for value in (
        assessment.get("rationale", "") if isinstance(assessment, Mapping) else "",
        validation_result.get("rationale", "") if isinstance(validation_result, Mapping) else "",
    ))
    remediation_parts: list[str] = []
    for value, key in ((assessment, "remediation"), (validation_result, "remediation"), (summary, "next_steps")):
        if isinstance(value, Mapping) and isinstance(value.get(key), list):
            remediation_parts.extend(str(item) for item in value[key])
    serialized = json.dumps(run, ensure_ascii=False, sort_keys=True, default=str).casefold()
    components = {
        "plan_contract": float(valid["plan"]),
        "assessment_contract": float(valid["assessment"]),
        "validation_contract": float(valid["validation"]),
        "summary_contract": float(valid["summary"]),
        "assessment_outcome": float(valid["assessment"] and assessment.get("assessment") == expected["assessment"]),
        "validator_outcome": float(valid["validation"] and validation_result.get("verdict") == expected["verdict"]),
        "severity_discipline": float(valid["validation"] and validation_result.get("severity") == expected["severity"]),
        "assessment_citations": _citation_score(assessment, "assessment", expected["required_citations"]["assessment"], allowed),
        "validator_citations": _citation_score(validation_result, "verdict", expected["required_citations"]["validation"], allowed),
        "requirements_discipline": float(valid["assessment"] and set(assessment.get("requirements", [])) == set(expected["requirements"])),
        "rationale_grounding": float(_has_concepts(rationale, _concept_groups(expected["rationale_concepts"], "expected.rationale_concepts"))),
        "remediation_quality": float(_has_concepts(" ".join(remediation_parts), _concept_groups(expected["remediation_concepts"], "expected.remediation_concepts"))),
        "hallucination_guard": float(bool(stages) and not any(
            fragment.casefold() in serialized for fragment in expected["forbidden_fragments"]
        )),
    }
    earned = sum(components.values())
    return {
        "scenario_id": scenario["id"],
        "turn_id": turn["id"],
        "fixture_digest": canonical_digest(fixture_payload(scenario, turn)),
        "score": round(earned / len(COMPONENTS), 6),
        "earned_points": earned,
        "available_points": len(COMPONENTS),
        "components": components,
        "trace": _trace_diagnostics(run),
    }


def score_scenario(scenario: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]]) -> dict:
    """Score all ordered turns and report whether output follows evidence changes."""
    if not isinstance(results, Mapping):
        raise GryptonError("Scenario results must map each turn ID to one run record.")
    known = {turn["id"] for turn in scenario["turns"]}
    if not set(results) <= known:
        raise GryptonError(f"Unknown turn result for scenario {scenario['id']}.")
    turn_scores = [score_turn(scenario, turn, results.get(turn["id"])) for turn in scenario["turns"]]
    transitions = 0
    adapted = 0
    for previous, current in zip(scenario["turns"], scenario["turns"][1:]):
        before = previous["expected"]
        after = current["expected"]
        if (before["assessment"], before["verdict"], before["severity"]) == (after["assessment"], after["verdict"], after["severity"]):
            continue
        transitions += 1
        prior_run = results.get(previous["id"], {})
        current_run = results.get(current["id"], {})
        prior_stages = prior_run.get("stages", {}) if isinstance(prior_run, Mapping) else {}
        current_stages = current_run.get("stages", {}) if isinstance(current_run, Mapping) else {}
        prior_assessment = prior_stages.get("assessment_followup", prior_stages.get("assessment", {}))
        current_assessment = current_stages.get("assessment_followup", current_stages.get("assessment", {}))
        prior_validation = prior_stages.get("validation", {})
        current_validation = current_stages.get("validation", {})
        actual_before = (prior_assessment.get("assessment"), prior_validation.get("verdict"), prior_validation.get("severity"))
        actual_after = (current_assessment.get("assessment"), current_validation.get("verdict"), current_validation.get("severity"))
        if actual_before == (before["assessment"], before["verdict"], before["severity"]) and actual_after == (after["assessment"], after["verdict"], after["severity"]):
            adapted += 1
    score = sum(item["score"] for item in turn_scores) / len(turn_scores)
    return {
        "scenario_id": scenario["id"],
        "scenario_digest": canonical_digest(scenario),
        "score": round(score, 6),
        "turns_present": sum(turn["id"] in results for turn in scenario["turns"]),
        "turns_expected": len(scenario["turns"]),
        "transition_adaptation": round(adapted / transitions, 6) if transitions else None,
        "transitions_expected": transitions,
        "turns": turn_scores,
    }


def score_suite(results: Mapping[str, Mapping[str, Mapping[str, Any]]], suite: dict | None = None) -> dict:
    """Score a complete or partial result map with deterministic ordering."""
    suite = validate_suite(suite) if suite is not None else load_suite()
    if not isinstance(results, Mapping):
        raise GryptonError("Lab results must map scenario IDs to turn-result maps.")
    known = {scenario["id"] for scenario in suite["scenarios"]}
    if not set(results) <= known:
        raise GryptonError("Lab results contain an unknown scenario ID.")
    scenarios = [score_scenario(scenario, results.get(scenario["id"], {})) for scenario in suite["scenarios"]]
    turn_scores = [turn["score"] for scenario in scenarios for turn in scenario["turns"]]
    transitions = [scenario["transition_adaptation"] for scenario in scenarios if scenario["transition_adaptation"] is not None]
    return {
        "schema_version": SCHEMA_VERSION,
        "evaluator_version": EVALUATOR_VERSION,
        "suite_id": suite["suite_id"],
        "suite_digest": canonical_digest(suite),
        "score": round(sum(turn_scores) / len(turn_scores), 6),
        "transition_adaptation": round(sum(transitions) / len(transitions), 6) if transitions else None,
        "component_names": list(COMPONENTS),
        "scenarios": scenarios,
    }

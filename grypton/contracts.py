"""Small, explicit structured-output contracts shared by all three roles."""
from __future__ import annotations

import json

from .config import GryptonError


def obj(properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


TEXT = {"type": "string", "minLength": 1, "maxLength": 12_000}
TEXTS = {"type": "array", "items": TEXT, "maxItems": 24}
REQUIREMENTS = {"type": "array", "maxItems": 8, "items": {"type": "string", "enum": [
    "existing_evidence", "offline_email", "offline_identity", "temporary_text_fixture",
    "scratch_directory", "external_account", "missing_evidence", "network_access"]}}
OPTIONAL_TEXT = {"type": "string", "maxLength": 12_000}
PLAN = obj({"summary": TEXT, "checks": TEXTS, "requirements": REQUIREMENTS})
ASSESSMENT = obj({
    "assessment": {"type": "string", "enum": ["supported", "refuted", "inconclusive"]},
    "rationale": TEXT, "evidence_ids": TEXTS, "remediation": TEXTS, "requirements": REQUIREMENTS,
})
VERDICT = obj({
    "verdict": {"type": "string", "enum": ["supported", "refuted", "inconclusive"]},
    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info", "unknown"]},
    "rationale": TEXT, "evidence_ids": TEXTS, "limitations": TEXTS, "remediation": TEXTS,
})
SUMMARY = obj({"summary": TEXT, "next_steps": TEXTS})
CHAT = obj({
    "reply": TEXT,
    "remember": OPTIONAL_TEXT,
    "disposition": {"type": "string", "enum": ["reply-only", "apply-now", "apply-next-review", "remember-only"]},
    "worker_note": OPTIONAL_TEXT,
    "requirements": REQUIREMENTS,
})


def validate(value, schema: dict, path: str = "response") -> None:
    expected = schema["type"]
    if expected == "object":
        if not isinstance(value, dict) or set(value) != set(schema["required"]):
            raise GryptonError(f"{path}: expected exactly the documented object fields.")
        for key, spec in schema["properties"].items():
            validate(value[key], spec, f"{path}.{key}")
    elif expected == "array":
        if not isinstance(value, list) or len(value) > schema["maxItems"]:
            raise GryptonError(f"{path}: expected a bounded list.")
        for item in value:
            validate(item, schema["items"], path + "[]")
    elif expected == "string":
        if not isinstance(value, str) or not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 12_000):
            raise GryptonError(f"{path}: expected a bounded string.")
        if schema.get("minLength", 0) and not value.strip():
            raise GryptonError(f"{path}: an empty string is not allowed.")
        if "enum" in schema and value not in schema["enum"]:
            raise GryptonError(f"{path}: unexpected value.")


def parse_output(text: str, schema: dict) -> dict:
    text = text.strip()
    if text.startswith("```json\n") and text.endswith("\n```"):
        text = text[8:-4]
    elif text.startswith("```\n") and text.endswith("\n```"):
        text = text[4:-4]
    def unique(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise ValueError("duplicate JSON key")
            data[key] = value
        return data
    try:
        value = json.loads(text, object_pairs_hook=unique,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, TypeError, RecursionError) as exc:
        raise GryptonError("The model returned invalid JSON; no review result was accepted.") from exc
    validate(value, schema)
    return value


def check_references(result: dict, evidence: list[dict]) -> None:
    known = {item["id"] for item in evidence}
    if not set(result.get("evidence_ids", [])).issubset(known):
        raise GryptonError("The model cited evidence that was not supplied; result rejected.")
    status = result.get("verdict", result.get("assessment"))
    if status in ("supported", "refuted") and not result.get("evidence_ids"):
        raise GryptonError("A conclusive assessment must cite supplied evidence.")
    if "severity" in result and result["verdict"] != "supported" and result["severity"] != "unknown":
        raise GryptonError("Severity must remain unknown when the claim is not supported.")

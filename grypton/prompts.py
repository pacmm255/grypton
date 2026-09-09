import hashlib
import json

from .config import resource


SKILLS_BY_ROLE = {
    "manager": ("operator-coordination", "blocker-handling", "scope-control", "validation-handoff"),
    "worker": ("evidence-review", "hypothesis-testing", "remediation-review", "blocker-handling", "scope-control"),
    "validator": ("evidence-review", "hypothesis-testing", "severity-calibration", "validation-handoff"),
}


def prompt_bundle(role: str) -> str:
    try:
        names = SKILLS_BY_ROLE[role]
    except KeyError as exc:
        raise ValueError(f"Unknown prompt role: {role}") from exc
    return resource(f"prompts/{role}.md") + "\n\n" + "\n\n".join(
        resource(f"skills/{name}.md") for name in names)


def prompt_fingerprints() -> dict[str, str]:
    """Stable prompt provenance stored with every review checkpoint."""
    return {role: hashlib.sha256(prompt_bundle(role).encode("utf-8")).hexdigest()
            for role in SKILLS_BY_ROLE}


def build(role: str, stage: str, payload: dict, schema: dict) -> str:
    return (prompt_bundle(role) + "\n\nStage: " + stage
            + "\nOutput schema:\n" + json.dumps(schema, ensure_ascii=False)
            + "\n\nUntrusted input JSON:\n" + json.dumps(payload, ensure_ascii=False))

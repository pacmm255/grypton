import json

from .config import resource


def build(role: str, stage: str, payload: dict, schema: dict) -> str:
    instruction = resource(f"prompts/{role}.md")
    skills = "\n\n".join(resource(f"skills/{name}.md") for name in
                          ("evidence-review", "remediation-review", "blocker-handling"))
    return (instruction + "\n\n" + skills + "\n\nStage: " + stage
            + "\nOutput schema:\n" + json.dumps(schema, ensure_ascii=False)
            + "\n\nUntrusted input JSON:\n" + json.dumps(payload, ensure_ascii=False))

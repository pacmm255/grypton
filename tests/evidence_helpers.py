"""Shared synthesis helpers for evidence-package tests.

These write real captures through ``tools._save_flow`` so evidence packages
reference genuine flow files, exactly like a live capture session would.
"""
from __future__ import annotations

from grypton import tools

REQUEST_METHOD = "GET"
REQUEST_URL = "https://example.test/api/v2/users/2"
REQUEST_HEADERS = {"Accept": "application/json"}
POSITIVE_BODY = '{"user": "2", "email": "other@example.test"}'
CONTROL_BODY = '{"error": "forbidden"}'
_REASONS = {200: "OK", 403: "Forbidden"}


def _response(status: int, body: str) -> str:
    reason = _REASONS.get(status, "Status")
    return (f"HTTP/1.1 {status} {reason}\n"
            "Content-Type: application/json\n"
            f"\n{body}")


def write_evidence_package(ws, *, status_positive=200, status_control=403) -> dict:
    """Write the four captures one evidence package references and return it.

    The positive capture is saved first, the control second, and both replay
    captures are written the way ``flow_replay`` records a machine replay
    (``transport=f"replay:{positive_id}"``) with an identical request, so the
    returned package passes ``tools.verify_evidence_package`` unless the
    caller corrupts the captures afterwards.
    """
    positive_path = tools._save_flow(
        ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
        _response(status_positive, POSITIVE_BODY), transport="curl", returncode=0)
    positive_id = positive_path.stem
    control_path = tools._save_flow(
        ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
        _response(status_control, CONTROL_BODY), transport="curl", returncode=0)
    replay_path = tools._save_flow(
        ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
        _response(status_positive, POSITIVE_BODY),
        transport=f"replay:{positive_id}", returncode=0)
    second_path = tools._save_flow(
        ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
        _response(status_positive, POSITIVE_BODY),
        transport=f"replay:{positive_id}", returncode=0)
    return {
        "positive_flow_id": positive_id,
        "control_flow_id": control_path.stem,
        "replay_flow_id": replay_path.stem,
        "second_run_flow_id": second_path.stem,
        "differential_claim": {
            "dimension": "status",
            "predicate": "differs",
            "positive_value": str(status_positive),
            "control_value": str(status_control),
        },
        "changed_variable": "session principal (owned vs other user token)",
        "precondition_notes": "authenticated as user 1; user 2 is another principal",
        "environment_notes": "single origin, cache disabled, one time window",
    }

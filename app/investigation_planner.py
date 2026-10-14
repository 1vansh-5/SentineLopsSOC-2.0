
"""Bounded read-only investigation planner."""

from .evidence_tools import ALLOWED_TOOLS, retrieve_evidence


def investigate_evidence(alert: dict, max_steps: int = 4) -> dict:
    """Retrieve each permitted evidence category at most once."""

    if not isinstance(max_steps, int) or not 1 <= max_steps <= 4:
        raise ValueError("max_steps must be between 1 and 4")

    event_type = alert.get("event_type")

    if event_type in ("failed_login", "successful_login"):
        priority = [
            "authentication_logs",
            "asset_inventory",
            "vulnerability_lookup",
            "application_logs",
        ]
    else:
        priority = [
            "application_logs",
            "asset_inventory",
            "vulnerability_lookup",
            "authentication_logs",
        ]

    trace = []
    for tool_name in priority[:max_steps]:
        if tool_name not in ALLOWED_TOOLS:
            continue

        result = retrieve_evidence(tool_name, alert)
        trace.append({
            "step": len(trace) + 1,
            "tool": tool_name,
            "result": result,
        })

    return {
        "investigation_status": "evidence_collection_completed",
        "steps_taken": len(trace),
        "trace": trace,
        "conclusion": "INCONCLUSIVE",
        "note": (
            "Synthetic placeholders are not independent proof "
            "of attack success or failure."
        ),
    }

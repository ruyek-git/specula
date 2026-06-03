"""Correlation agent.

Decides whether this alert is part of a larger pattern by looking at recent
cases. Read-only: it links, it does not act. Its output can *raise* severity
(e.g. a single failed login is low; a burst across many accounts is not), which
is one of the few ways the pipeline escalates rather than de-escalates.
"""

from __future__ import annotations

import json

from core.llm import LLMClient

SYSTEM = """You are a SOC correlation agent. Given the current alert and a short
list of recent alerts, decide whether they form a related pattern (same actor,
same source, coordinated burst). Respond with ONLY JSON:
{ "linked": "related" | "none", "escalate": true | false, "rationale": "one sentence" }"""


def run(alert: dict, recent: list[dict], llm: LLMClient) -> dict:
    user = (
        "Current alert:\n"
        f"{json.dumps(alert, indent=2)}\n\n"
        "Recent alerts:\n"
        f"{json.dumps(recent, indent=2)}"
    )
    resp = llm.complete(system=SYSTEM, user=user, temperature=0.0)
    try:
        out = json.loads(resp.text)
    except json.JSONDecodeError:
        out = {"linked": "none", "escalate": False, "rationale": "unparseable"}
    return out

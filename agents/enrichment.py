"""Enrichment agent.

Gathers context for an alert by proposing READ-ONLY tool calls. It never
asserts a fact of its own - it calls a tool and reports what the tool returned.
This is the defence against hallucination: the agent does not "know" the geo of
an IP, it calls lookup_geo_ip and reports the result.

It holds only read-only tools, so even a fully compromised enrichment agent can
gather context but cannot change anything.
"""

from __future__ import annotations

import json

from core.guardrails import READONLY_TOOLS
from core.llm import LLMClient
from core.tools import READONLY_TOOL_SCHEMAS, TOOL_IMPLEMENTATIONS

SYSTEM = """You are a SOC enrichment agent. Your job is to gather context for an
alert by calling read-only tools. You do not assert facts from memory - you call
a tool and use its result. Propose the tool calls that would best contextualise
this alert (geo of source IPs, identity baseline for involved users, threat
intel on indicators)."""


def run(alert: dict, llm: LLMClient) -> dict:
    user = (
        "Propose read-only enrichment tool calls for this alert:\n\n"
        f"{json.dumps(alert, indent=2)}"
    )
    resp = llm.complete(
        system=SYSTEM, user=user, tools=READONLY_TOOL_SCHEMAS, temperature=0.0
    )

    results = {}
    for call in resp.tool_calls:
        # Defence in depth: even though only read-only schemas were offered,
        # verify the proposed call is actually on the read-only allowlist.
        if call.name not in READONLY_TOOLS:
            results[call.name] = {"error": "not a read-only tool; refused"}
            continue
        impl = TOOL_IMPLEMENTATIONS.get(call.name)
        if impl is None:
            results[call.name] = {"error": "no implementation"}
            continue
        # Fill obvious args from the alert when the model omitted them.
        args = dict(call.arguments)
        results[call.name] = impl(**_safe_args(impl, args, alert))

    return {"enrichment": results, "rationale": resp.text}


def _safe_args(impl, args: dict, alert: dict) -> dict:
    """Best-effort fill of an IP/user from the alert if the model didn't pass one."""
    import inspect

    params = set(inspect.signature(impl).parameters)
    if "ip" in params and not args.get("ip"):
        args["ip"] = alert.get("sourceIPAddress") or (
            alert.get("client", {}).get("ipAddress", "")
        )
    if "user" in params and not args.get("user"):
        ui = alert.get("userIdentity", {})
        actor = alert.get("actor", {})
        args["user"] = ui.get("userName") or actor.get("alternateId", "")
    args.setdefault("reason", "automated enrichment")
    return {k: v for k, v in args.items() if k in params}

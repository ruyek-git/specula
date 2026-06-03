"""Tools an agent can propose.

Two families:
  - Read-only enrichment tools: gather context, change nothing. Safe to call freely.
  - Autonomous action tools: the bounded, reversible actions an agent may take
    on a low-severity, high-confidence event.

Every action here is MOCKED. disable_detection() logs what it *would* do; it
does not touch a real detection platform. This keeps the repo safe to clone and
run, while the surrounding architecture (gating, auditing, fencing) is exactly
what a production wiring would use. The tool *schemas* below are also what the
LLMClient hands to the model, so this file is the single source of truth for
what the model is even allowed to know about.
"""

from __future__ import annotations

from typing import Any


# --------------------------------------------------------------------------- #
# Tool schemas handed to the model (OpenAI-style; the Anthropic backend         #
# remaps them). description fields double as guidance to the model.            #
# --------------------------------------------------------------------------- #

READONLY_TOOL_SCHEMAS = [
    {
        "name": "lookup_geo_ip",
        "description": "Return the geolocation and ASN for an IP. Read-only.",
        "parameters": {
            "type": "object",
            "properties": {"ip": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
    {
        "name": "get_identity_context",
        "description": "Return baseline behaviour for a user: usual geos, devices, "
        "typical sign-in hours. Read-only.",
        "parameters": {
            "type": "object",
            "properties": {"user": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
    {
        "name": "query_threat_intel",
        "description": "Check an indicator against threat intel feeds. Read-only.",
        "parameters": {
            "type": "object",
            "properties": {"indicator": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
]

ACTION_TOOL_SCHEMAS = [
    {
        "name": "disable_detection",
        "description": "Disable a noisy detection rule by ID. Reversible. Use only "
        "for high-false-positive, low-severity rules.",
        "parameters": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["rule_id", "reason"],
        },
    },
    {
        "name": "tag_benign",
        "description": "Tag a low-severity alert as benign with a rationale. Reversible.",
        "parameters": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["alert_id", "reason"],
        },
    },
]


# --------------------------------------------------------------------------- #
# Mock implementations. Each returns a structured result and records intent.   #
# --------------------------------------------------------------------------- #


def lookup_geo_ip(ip: str = "", reason: str = "") -> dict[str, Any]:
    # Deterministic fake geo so demos are stable.
    known = {
        "203.0.113.7": {"country": "US", "asn": "AS_EXAMPLE", "is_tor": False},
        "198.51.100.23": {"country": "RU", "asn": "AS_SUSPECT", "is_tor": True},
    }
    return known.get(ip, {"country": "unknown", "asn": "unknown", "is_tor": False})


def get_identity_context(user: str = "", reason: str = "") -> dict[str, Any]:
    return {
        "user": user,
        "usual_countries": ["US"],
        "usual_hours_utc": [13, 22],
        "mfa_enrolled": True,
    }


def query_threat_intel(indicator: str = "", reason: str = "") -> dict[str, Any]:
    bad = {"198.51.100.23"}
    return {"indicator": indicator, "known_bad": indicator in bad}


def disable_detection(rule_id: str = "", reason: str = "") -> dict[str, Any]:
    return {
        "would_have": "disabled detection",
        "rule_id": rule_id,
        "reason": reason,
        "executed": False,  # mock - nothing real changed
        "reversible": True,
    }


def tag_benign(alert_id: str = "", reason: str = "") -> dict[str, Any]:
    return {
        "would_have": "tagged benign",
        "alert_id": alert_id,
        "reason": reason,
        "executed": False,
        "reversible": True,
    }


# Registry the orchestrator uses to actually invoke a vetted tool by name.
TOOL_IMPLEMENTATIONS = {
    "lookup_geo_ip": lookup_geo_ip,
    "get_identity_context": get_identity_context,
    "query_threat_intel": query_threat_intel,
    "disable_detection": disable_detection,
    "tag_benign": tag_benign,
}

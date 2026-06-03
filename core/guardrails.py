"""Guardrails - the deterministic layer between an agent's proposal and execution.

This is the heart of Specula's security model. An agent only ever *proposes* a
tool call. Nothing the agent proposes runs until it has cleared every check
here. These checks are plain Python with no model in the loop, because you
cannot secure a system by asking a model to please behave - the enforcement has
to live in code you control.

Layers implemented here (see README "Guardrails" table):
  1. Input fencing      - neutralise instruction-like text in attacker-controlled fields
  2. Action allowlist   - only known, vetted actions may run at all
  3. Reversibility      - autonomous actions must be reversible by construction
  4. Rate limiting       - a circuit breaker caps how often an action can fire
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# 1. Input fencing                                                            #
# --------------------------------------------------------------------------- #

# Patterns that look like an attempt to talk to the agent rather than describe
# an event. This is a defence-in-depth signal, NOT the primary defence - the
# primary defence is that untrusted fields are never concatenated into the
# instruction block in the first place (see fence_untrusted()).
_INJECTION_PATTERNS = [
    re.compile(r"(ignore|disregard|forget).{0,40}(instruction|previous|above|prior)", re.I),
    re.compile(r"(you are now|act as|pretend to be|new role)", re.I),
    re.compile(r"(mark|classify|treat).{0,20}(this|it).{0,20}(benign|safe|resolved)", re.I),
    re.compile(r"(system prompt|developer message|<\s*/?\s*system\s*>)", re.I),
]


@dataclass
class FenceResult:
    fenced_text: str
    flagged: bool
    matches: list[str] = field(default_factory=list)


def fence_untrusted(value: str) -> FenceResult:
    """Wrap an attacker-controllable field so it is unambiguously data, not
    instruction, and flag it if it contains instruction-like text.

    The wrapping is the real protection: the agent prompt presents this inside a
    clearly delimited block labelled as untrusted data. The flag is a signal the
    triage agent uses to *lower confidence*, which pushes the alert toward a
    human rather than toward autonomous action.
    """
    flagged = False
    matches: list[str] = []
    for pat in _INJECTION_PATTERNS:
        m = pat.search(value or "")
        if m:
            flagged = True
            matches.append(m.group(0))
    fenced = f"<untrusted_data>\n{value}\n</untrusted_data>"
    return FenceResult(fenced_text=fenced, flagged=flagged, matches=matches)


# --------------------------------------------------------------------------- #
# 2. Action allowlist + 3. Reversibility                                      #
# --------------------------------------------------------------------------- #

# The ONLY actions an agent may take autonomously. Anything not in this dict is
# refused outright - an agent cannot invent a new capability. Every entry is
# reversible by construction; we deliberately do not register irreversible
# autonomous actions. Identity / privilege changes are intentionally absent:
# those are always human-in-the-loop (see README "Identity is a hard line").
AUTONOMOUS_ACTIONS = {
    "disable_detection": {"reversible": True, "max_per_window": 5},
    "enrich_case": {"reversible": True, "max_per_window": 100},
    "tag_benign": {"reversible": True, "max_per_window": 50},
    "suppress_duplicate": {"reversible": True, "max_per_window": 100},
    "throttle_nonprod_resource": {"reversible": True, "max_per_window": 10},
}

# Read-only enrichment tools the enrichment agent may call. These change nothing,
# so they are allowed freely - but still enumerated, so the agent cannot reach
# beyond them.
READONLY_TOOLS = {
    "lookup_geo_ip",
    "get_identity_context",
    "query_threat_intel",
    "get_recent_cases",
}


@dataclass
class GateDecision:
    allow: bool
    reason: str


# --------------------------------------------------------------------------- #
# 4. Rate limiting (circuit breaker)                                          #
# --------------------------------------------------------------------------- #


class RateLimiter:
    """Sliding-window cap per action type. Prevents an agent from taking a wrong
    autonomous action at machine speed and scale - the worst-case failure mode."""

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._events: dict[str, list[float]] = {}

    def allow(self, action: str, limit: int) -> bool:
        now = time.time()
        bucket = self._events.setdefault(action, [])
        cutoff = now - self.window
        bucket[:] = [t for t in bucket if t > cutoff]
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


# --------------------------------------------------------------------------- #
# The gate the orchestrator actually calls                                    #
# --------------------------------------------------------------------------- #


class Guardrails:
    def __init__(self, rate_limiter: RateLimiter | None = None):
        self.rate_limiter = rate_limiter or RateLimiter()

    def check_action(
        self,
        action: str,
        severity: str,
        confidence: float,
        confidence_threshold: float = 0.85,
    ) -> GateDecision:
        """Decide whether a proposed action may run autonomously.

        Order matters: cheapest / most categorical checks first.
        """
        # Read-only tools are always permitted; they cannot cause harm.
        if action in READONLY_TOOLS:
            return GateDecision(True, "read-only tool")

        spec = AUTONOMOUS_ACTIONS.get(action)
        if spec is None:
            return GateDecision(False, f"action {action!r} not on allowlist")

        if not spec["reversible"]:
            # Defensive: we never register these, but never autonomously run one.
            return GateDecision(False, "action is not reversible")

        if severity != "low":
            return GateDecision(False, f"severity {severity!r} requires a human")

        if confidence < confidence_threshold:
            return GateDecision(
                False,
                f"confidence {confidence:.2f} below threshold {confidence_threshold:.2f}",
            )

        if not self.rate_limiter.allow(action, spec["max_per_window"]):
            return GateDecision(False, f"rate limit tripped for {action!r}")

        return GateDecision(True, "passed all guardrails")

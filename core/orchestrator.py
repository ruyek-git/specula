"""Orchestrator - the conductor.

Runs the pipeline for one alert:
    triage -> enrichment -> correlation -> decision gate -> (autonomous | human)

This is the ONLY place an autonomous action executes, and it executes only after
Guardrails.check_action approves it. Every stage is written to the audit log
before the next stage runs. The agents propose; the orchestrator disposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agents import correlation, enrichment, triage
from core.audit import AuditLog
from core.guardrails import Guardrails
from core.llm import LLMClient
from core.tools import TOOL_IMPLEMENTATIONS


@dataclass
class PipelineResult:
    alert_id: str
    severity: str
    confidence: float
    outcome: str           # "autonomous" | "human"
    action: str | None     # action taken, if autonomous
    gate_reason: str
    injection_flagged: bool = False
    trace: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(
        self,
        llm: LLMClient | None = None,
        guardrails: Guardrails | None = None,
        audit: AuditLog | None = None,
        confidence_threshold: float = 0.85,
    ):
        self.llm = llm or LLMClient()
        self.guardrails = guardrails or Guardrails()
        self.audit = audit or AuditLog()
        self.confidence_threshold = confidence_threshold

    def process(self, alert: dict, recent: list[dict] | None = None) -> PipelineResult:
        alert_id = alert.get("id") or alert.get("eventID") or alert.get("uuid", "unknown")
        trace: list[str] = []

        # 1. Triage
        verdict = triage.run(alert, self.llm)
        severity = verdict.get("severity", "high")
        confidence = float(verdict.get("confidence", 0.0))
        injection = bool(verdict.get("injection_flagged", False))
        self.audit.record(
            alert_id, "triage", f"severity={severity}", verdict, severity, confidence
        )
        trace.append(
            f"triage: severity={severity} confidence={confidence:.2f}"
            + (" [INJECTION FLAGGED]" if injection else "")
        )

        # 2. Enrichment (read-only; never changes the outcome's safety, only context)
        enr = enrichment.run(alert, self.llm)
        self.audit.record(alert_id, "enrichment", "context_gathered", enr)
        trace.append(f"enrichment: {len(enr.get('enrichment', {}))} tool(s) called")

        # 3. Correlation (can escalate severity)
        corr = correlation.run(alert, recent or [], self.llm)
        if corr.get("escalate"):
            severity = "high"
            trace.append("correlation: escalated to high")
        self.audit.record(alert_id, "correlation", corr.get("linked", "none"), corr)

        # 4. Decision gate -> pick the autonomous action only if one fits.
        proposed_action = self._propose_action(verdict, severity)
        if proposed_action is None:
            return self._route_human(alert_id, severity, confidence, injection,
                                     "no autonomous action applicable", trace)

        decision = self.guardrails.check_action(
            proposed_action, severity, confidence, self.confidence_threshold
        )
        if not decision.allow:
            return self._route_human(alert_id, severity, confidence, injection,
                                     decision.reason, trace)

        # 5. Execute the (bounded, reversible, gated) autonomous action.
        impl = TOOL_IMPLEMENTATIONS[proposed_action]
        result = impl(alert_id=alert_id, reason=verdict.get("rationale", "auto"))
        self.audit.record(
            alert_id, "action", proposed_action, {"result": result},
            severity, confidence,
        )
        trace.append(f"action: {proposed_action} (autonomous)")
        return PipelineResult(
            alert_id=alert_id, severity=severity, confidence=confidence,
            outcome="autonomous", action=proposed_action,
            gate_reason=decision.reason, injection_flagged=injection, trace=trace,
        )

    def _propose_action(self, verdict: dict, severity: str) -> str | None:
        """Map a verdict to a candidate autonomous action. Conservative: only
        low-severity verdicts get a candidate at all."""
        if severity != "low":
            return None
        return "tag_benign"

    def _route_human(self, alert_id, severity, confidence, injection, reason, trace):
        self.audit.record(
            alert_id, "gate", "route_human", {"reason": reason}, severity, confidence
        )
        trace.append(f"gate: routed to human ({reason})")
        return PipelineResult(
            alert_id=alert_id, severity=severity, confidence=confidence,
            outcome="human", action=None, gate_reason=reason,
            injection_flagged=injection, trace=trace,
        )

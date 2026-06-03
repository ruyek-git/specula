"""Detection quality metrics.

Treats detection as a software discipline: measure precision, false-positive
rate, and - because agents are non-deterministic - verdict stability across
repeated runs of the same alert. Instability is itself a quality signal worth
surfacing to the tuning loop.

Labels in the synthetic set are the ground truth; in production these come from
analyst dispositions feeding back from the audit log.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from core.llm import LLMClient
from core.orchestrator import Orchestrator


@dataclass
class QualityReport:
    total: int
    precision: float          # of alerts we auto-actioned, fraction truly benign
    false_positive_rate: float  # of truly-benign alerts, fraction wrongly escalated
    auto_action_rate: float   # fraction handled without a human
    verdict_stability: float  # fraction of alerts whose severity was stable across runs


def evaluate(
    labeled_alerts: list[tuple[dict, str]],
    orchestrator: Orchestrator,
    stability_runs: int = 3,
) -> QualityReport:
    """labeled_alerts: list of (alert, ground_truth) where ground_truth is
    'benign' or 'malicious'."""
    total = len(labeled_alerts)
    auto_actions = 0
    auto_correct = 0          # auto-actioned AND truly benign
    benign_total = 0
    benign_escalated = 0      # truly benign BUT routed to human

    severity_runs: dict[str, list[str]] = {}

    for alert, truth in labeled_alerts:
        if truth == "benign":
            benign_total += 1
        # Multiple runs for stability.
        severities = []
        last = None
        for _ in range(stability_runs):
            r = orchestrator.process(alert)
            severities.append(r.severity)
            last = r
        severity_runs[last.alert_id] = severities

        if last.outcome == "autonomous":
            auto_actions += 1
            if truth == "benign":
                auto_correct += 1
        if truth == "benign" and last.outcome == "human":
            benign_escalated += 1

    precision = (auto_correct / auto_actions) if auto_actions else 1.0
    fpr = (benign_escalated / benign_total) if benign_total else 0.0
    auto_rate = (auto_actions / total) if total else 0.0
    stable = sum(1 for s in severity_runs.values() if len(set(s)) == 1)
    stability = (stable / total) if total else 1.0

    return QualityReport(
        total=total,
        precision=round(precision, 3),
        false_positive_rate=round(fpr, 3),
        auto_action_rate=round(auto_rate, 3),
        verdict_stability=round(stability, 3),
    )

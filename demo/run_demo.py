"""Specula demo - terminal runner.

    SOC_LLM_BACKEND=mock python demo/run_demo.py

Loads synthetic CloudTrail + Okta telemetry, runs each alert through the full
pipeline, prints the per-alert trace (triage -> enrichment -> correlation ->
gate -> outcome), then prints a detection-quality report.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.audit import AuditLog, reset
from core.llm import LLMClient
from core.metrics import evaluate
from core.orchestrator import Orchestrator
from data.loader import load_all

# Ground-truth labels for the synthetic set (id -> benign|malicious).
GROUND_TRUTH = {
    "ct-0001-benign-describe": "benign",
    "ct-0002-stoplogging": "malicious",
    "ct-0003-root-console-login": "malicious",
    "ct-0004-injection-username": "malicious",
    "ct-0005-benign-getobject": "benign",
    "okta-0001-normal-signin": "benign",
    "okta-0002-impossible-travel": "malicious",
    "okta-0003-mfa-deny": "malicious",
    "okta-0004-injection-displayname": "malicious",
    "okta-0005-normal-app": "benign",
}

GREEN, RED, YEL, DIM, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[2m", "\033[0m"


def main() -> None:
    backend = os.getenv("SOC_LLM_BACKEND", "mock")
    print(f"\nSpecula demo  -  LLM backend: {backend}\n" + "=" * 56)

    reset("specula_audit.db")
    orch = Orchestrator(llm=LLMClient(backend=backend), audit=AuditLog("specula_audit.db"))

    alerts = load_all()
    for alert in alerts:
        r = orch.process(alert)
        colour = GREEN if r.outcome == "autonomous" else YEL
        tag = "AUTONOMOUS" if r.outcome == "autonomous" else "-> HUMAN"
        flag = f" {RED}[INJECTION CONTAINED]{RESET}" if r.injection_flagged else ""
        print(f"\n{alert['id']}  ({alert['source']}){flag}")
        print(f"  {colour}{tag}{RESET}  sev={r.severity} conf={r.confidence:.2f}  {DIM}{r.gate_reason}{RESET}")
        for step in r.trace:
            print(f"    {DIM}{step}{RESET}")

    # Quality report
    labeled = [(a, GROUND_TRUTH.get(a["id"], "malicious")) for a in alerts]
    report = evaluate(labeled, orch)
    print("\n" + "=" * 56)
    print("Detection quality report")
    print("-" * 56)
    print(f"  alerts evaluated      : {report.total}")
    print(f"  precision             : {report.precision}")
    print(f"  false-positive rate   : {report.false_positive_rate}")
    print(f"  auto-action rate      : {report.auto_action_rate}")
    print(f"  verdict stability     : {report.verdict_stability}")
    print("=" * 56 + "\n")

    orch.audit.close()


if __name__ == "__main__":
    main()

"""Specula dashboard - optional Streamlit UI for screen-sharing a demo.

    pip install streamlit
    SOC_LLM_BACKEND=mock streamlit run demo/dashboard.py

The terminal runner (run_demo.py) is the portable core; this is purely a nicer
surface for walking someone through the pipeline live. It reuses the exact same
orchestrator and guardrails - no logic is duplicated here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from core.audit import AuditLog, reset
from core.llm import LLMClient
from core.metrics import evaluate
from core.orchestrator import Orchestrator
from data.loader import load_all
from demo.run_demo import GROUND_TRUTH

st.set_page_config(page_title="Specula", layout="wide")
st.title("Specula")
st.caption("Agentic SOC triage - agents propose, the gate disposes, every action is audited.")

backend = st.sidebar.selectbox("LLM backend", ["mock", "anthropic", "openai", "ollama"],
                               index=["mock", "anthropic", "openai", "ollama"].index(
                                   os.getenv("SOC_LLM_BACKEND", "mock")))
threshold = st.sidebar.slider("Confidence threshold for autonomy", 0.5, 0.99, 0.85, 0.01)

if st.sidebar.button("Run pipeline", type="primary"):
    reset("specula_audit.db")
    orch = Orchestrator(llm=LLMClient(backend=backend),
                        audit=AuditLog("specula_audit.db"),
                        confidence_threshold=threshold)
    alerts = load_all()
    results = [orch.process(a) for a in alerts]

    auto = sum(1 for r in results if r.outcome == "autonomous")
    human = sum(1 for r in results if r.outcome == "human")
    contained = sum(1 for r in results if r.injection_flagged)

    c1, c2, c3 = st.columns(3)
    c1.metric("Autonomous", auto)
    c2.metric("Routed to human", human)
    c3.metric("Injections contained", contained)

    for alert, r in zip(alerts, results):
        icon = "🟢" if r.outcome == "autonomous" else "🟡"
        flag = "  ⚠️ INJECTION CONTAINED" if r.injection_flagged else ""
        with st.expander(f"{icon} {alert['id']}  ({alert['source']})  -  {r.outcome}{flag}"):
            st.write(f"**Severity:** {r.severity}  |  **Confidence:** {r.confidence:.2f}")
            st.write(f"**Gate reason:** {r.gate_reason}")
            st.code("\n".join(r.trace))

    labeled = [(a, GROUND_TRUTH.get(a["id"], "malicious")) for a in alerts]
    report = evaluate(labeled, orch)
    st.subheader("Detection quality")
    q1, q2, q3, q4 = st.columns(4)
    q1.metric("Precision", report.precision)
    q2.metric("False-positive rate", report.false_positive_rate)
    q3.metric("Auto-action rate", report.auto_action_rate)
    q4.metric("Verdict stability", report.verdict_stability)
    orch.audit.close()
else:
    st.info("Set a backend and threshold in the sidebar, then click **Run pipeline**.")

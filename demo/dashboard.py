"""Specula dashboard - optional Streamlit UI.

    pip install streamlit
    SOC_LLM_BACKEND=mock streamlit run demo/dashboard.py

Three sections:
  1. Pipeline - run the built-in synthetic set OR an uploaded log file through
     the full triage -> enrichment -> correlation -> gate flow. Each alert has a
     copy button so you can lift its log into the assistant below.
  2. Analyst assistant - paste a log and ask a freeform question
     ("explain this and why it's anomalous"). READ-ONLY: it holds no tools and
     cannot trigger an action. Deliberately separate from the pipeline.

It reuses the exact same orchestrator, guardrails and assistant module - no
logic is duplicated here.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from core.assistant import explain
from core.audit import AuditLog, reset
from core.llm import LLMClient
from core.metrics import evaluate
from core.orchestrator import Orchestrator
from data.loader import load_all, parse_upload
from demo.run_demo import GROUND_TRUTH

st.set_page_config(page_title="Specula", layout="wide")
st.title("Specula")
st.caption("Agentic SOC triage - agents propose, the gate disposes, every action is audited.")

backend = st.sidebar.selectbox(
    "LLM backend", ["mock", "anthropic", "openai", "ollama"],
    index=["mock", "anthropic", "openai", "ollama"].index(os.getenv("SOC_LLM_BACKEND", "mock")),
)
threshold = st.sidebar.slider("Confidence threshold for autonomy", 0.5, 0.99, 0.85, 0.01)
st.sidebar.caption("Mock backend is keyless and deterministic. Real backends give real analysis.")

tab_pipeline, tab_assistant = st.tabs(["Pipeline", "Analyst assistant (read-only)"])

# --------------------------------------------------------------------------- #
# Tab 1: Pipeline                                                             #
# --------------------------------------------------------------------------- #
with tab_pipeline:
    src = st.radio("Alert source", ["Built-in synthetic set", "Upload my own logs"], horizontal=True)

    alerts = None
    labeled = True
    if src == "Built-in synthetic set":
        alerts = load_all()
    else:
        up = st.file_uploader("Upload a log file (.json or .txt)", type=["json", "txt", "log"])
        pasted = st.text_area("...or paste logs here (JSON or one log line per row)", height=140)
        labeled = False
        if up is not None:
            alerts = parse_upload(up.read().decode("utf-8", errors="replace"), up.name)
        elif pasted.strip():
            alerts = parse_upload(pasted)

    if alerts and st.button("Run pipeline", type="primary"):
        reset("specula_audit.db")
        orch = Orchestrator(llm=LLMClient(backend=backend),
                            audit=AuditLog("specula_audit.db"),
                            confidence_threshold=threshold)
        results = [orch.process(a) for a in alerts]

        auto = sum(1 for r in results if r.outcome == "autonomous")
        human = sum(1 for r in results if r.outcome == "human")
        contained = sum(1 for r in results if r.injection_flagged)
        c1, c2, c3 = st.columns(3)
        c1.metric("Autonomous", auto)
        c2.metric("Routed to human", human)
        c3.metric("Injections contained", contained)

        for alert, r in zip(alerts, results):
            icon = "[AUTO]" if r.outcome == "autonomous" else "[HUMAN]"
            flag = "  !! INJECTION CONTAINED" if r.injection_flagged else ""
            with st.expander(f"{icon} {alert['id']}  ({alert.get('source','?')})  -  {r.outcome}{flag}"):
                st.write(f"**Severity:** {r.severity}  |  **Confidence:** {r.confidence:.2f}")
                st.write(f"**Gate reason:** {r.gate_reason}")
                st.code("\n".join(r.trace))
                # Copy icon: show the raw log so it can be copied into the assistant.
                raw = json.dumps(alert, indent=2)
                st.caption("Log (use the copy icon, top-right of the box, then paste into the Analyst assistant tab):")
                st.code(raw, language="json")

        if labeled:
            lbl = [(a, GROUND_TRUTH.get(a["id"], "malicious")) for a in alerts]
            report = evaluate(lbl, orch)
            st.subheader("Detection quality")
            q1, q2, q3, q4 = st.columns(4)
            q1.metric("Precision", report.precision)
            q2.metric("False-positive rate", report.false_positive_rate)
            q3.metric("Auto-action rate", report.auto_action_rate)
            q4.metric("Verdict stability", report.verdict_stability)
        else:
            st.info("Quality metrics are skipped for uploaded logs (no ground-truth labels).")
        orch.audit.close()
    elif not alerts:
        st.info("Pick the built-in set or upload/paste logs, then click Run pipeline.")

# --------------------------------------------------------------------------- #
# Tab 2: Analyst assistant (read-only, no tools, walled off from actions)     #
# --------------------------------------------------------------------------- #
with tab_assistant:
    st.write("Paste a log and ask about it. This assistant is **read-only** - it "
             "explains, it cannot take any action on an alert.")
    log_text = st.text_area("Log entry", height=180,
                            placeholder='Paste a CloudTrail/Okta record or any log line here')
    question = st.text_input("Your question",
                             value="Explain this log and why it might be anomalous.")
    if st.button("Ask", type="primary"):
        if not log_text.strip():
            st.warning("Paste a log first.")
        else:
            res = explain(log_text, question, LLMClient(backend=backend))
            if res["injection_warning"]:
                st.error(f"Prompt-injection-like text detected in the log and neutralised: {res['matches']}")
            st.markdown(res["answer"])

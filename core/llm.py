"""Pluggable LLM backend for Specula.

The pipeline never talks to a vendor SDK directly. It talks to LLMClient, which
exposes one method: complete(). Swap the backend with SOC_LLM_BACKEND; no agent
code changes.

Backends:
    anthropic  - requires ANTHROPIC_API_KEY
    openai     - any OpenAI-compatible endpoint (OpenAI, vLLM, LM Studio, gateways)
                 honours OPENAI_BASE_URL and OPENAI_API_KEY
    ollama     - fully local, no key, honours OLLAMA_HOST (default localhost:11434)
    mock       - deterministic, keyless; used for demos and CI

Design note: every backend returns the same shape - an LLMResponse with .text
and an optional list of .tool_calls. Agents are written against that shape and
are completely decoupled from which model produced it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """A structured action the model proposed. The model does NOT execute this;
    the orchestrator validates and runs it (see core/guardrails.py)."""

    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient:
    """Facade over whichever backend is configured."""

    def __init__(self, backend: str | None = None, model: str | None = None):
        self.backend = (backend or os.getenv("SOC_LLM_BACKEND", "mock")).lower()
        self.model = model or os.getenv("SOC_LLM_MODEL")
        self._impl = self._build_impl()

    def _build_impl(self):
        if self.backend == "anthropic":
            return _AnthropicBackend(self.model)
        if self.backend == "openai":
            return _OpenAIBackend(self.model)
        if self.backend == "ollama":
            return _OllamaBackend(self.model)
        if self.backend == "mock":
            return _MockBackend(self.model)
        raise ValueError(
            f"Unknown SOC_LLM_BACKEND={self.backend!r}. "
            "Use one of: anthropic, openai, ollama, mock."
        )

    def complete(
        self,
        system: str,
        user: str,
        tools: list[dict] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Send one turn. temperature defaults to 0.0 because classification
        wants determinism, not creativity (see README: non-determinism roadblock)."""
        return self._impl.complete(system, user, tools or [], temperature)


# --------------------------------------------------------------------------- #
# Real backends. Imports are local so the repo runs with `mock` and zero deps. #
# --------------------------------------------------------------------------- #


class _AnthropicBackend:
    def __init__(self, model: str | None):
        import anthropic  # noqa: local import keeps mock dependency-free

        self.client = anthropic.Anthropic()
        self.model = model or "claude-sonnet-4-20250514"

    def complete(self, system, user, tools, temperature):
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 1024,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t["parameters"],
                }
                for t in tools
            ]
        resp = self.client.messages.create(**kwargs)
        out = LLMResponse()
        for block in resp.content:
            if block.type == "text":
                out.text += block.text
            elif block.type == "tool_use":
                out.tool_calls.append(ToolCall(block.name, dict(block.input)))
        return out


class _OpenAIBackend:
    def __init__(self, model: str | None):
        from openai import OpenAI  # noqa: local import

        self.client = OpenAI(
            base_url=os.getenv("OPENAI_BASE_URL"),  # None -> api.openai.com
            api_key=os.getenv("OPENAI_API_KEY", "not-needed-for-local"),
        )
        self.model = model or os.getenv("SOC_LLM_MODEL", "gpt-4o-mini")

    def complete(self, system, user, tools, temperature):
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = [
                {"type": "function", "function": t} for t in tools
            ]
        resp = self.client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        out = LLMResponse(text=msg.content or "")
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                args = {}
            out.tool_calls.append(ToolCall(tc.function.name, args))
        return out


class _OllamaBackend:
    def __init__(self, model: str | None):
        self.host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model or os.getenv("SOC_LLM_MODEL", "llama3.1")

    def complete(self, system, user, tools, temperature):
        import urllib.request  # noqa: local import, stdlib only

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": temperature},
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": t} for t in tools]
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
        msg = data.get("message", {})
        out = LLMResponse(text=msg.get("content", ""))
        for tc in msg.get("tool_calls", []):
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            out.tool_calls.append(ToolCall(fn.get("name", ""), args))
        return out


class _MockBackend:
    """Deterministic, keyless backend.

    It does NOT call a model. It applies a few transparent heuristics so the
    pipeline produces stable, explainable output for demos and CI. The point is
    to exercise the *plumbing and guardrails* without a model in the loop - the
    interesting security behaviour (gating, fencing, auditing) is identical
    whether the verdict came from a real model or from here.
    """

    def __init__(self, model: str | None):
        self.model = "mock-deterministic"

    def complete(self, system, user, tools, temperature):
        role = self._infer_role(system)
        if role == "triage":
            return self._triage(user)
        if role == "enrichment":
            return self._enrichment(user, tools)
        if role == "correlation":
            return self._correlation(user)
        return LLMResponse(text="{}")

    @staticmethod
    def _infer_role(system: str) -> str:
        s = system.lower()
        if "triage" in s:
            return "triage"
        if "enrich" in s:
            return "enrichment"
        if "correlat" in s:
            return "correlation"
        return "unknown"

    def _triage(self, user: str) -> LLMResponse:
        text = user.lower()
        # Severity heuristics keyed off realistic CloudTrail + Okta signals.
        high = any(
            k in text
            for k in (
                "consolelogin",
                "deletetrail",
                "stoplogging",
                "authorizesecuritygroupingress",
                '"result": "deny"',
                "risklevel",
                "anomalous location",
                "velocity",
                '"type": "root"',
                "iam::123456789012:root",
            )
        )
        # Confidence drops when the record shows signs of tampering / injection.
        suspicious_input = bool(
            re.search(r"(ignore|disregard).{0,30}(instruction|previous)", text)
        )
        confidence = 0.4 if suspicious_input else (0.92 if not high else 0.78)
        severity = "high" if high else "low"
        verdict = {
            "severity": severity,
            "confidence": round(confidence, 2),
            "category": "identity" if "okta" in text or "signin" in text else "cloud",
            "rationale": (
                "Heuristic mock verdict. Severity from action signature; "
                "confidence reduced if record shows instruction-like text."
            ),
        }
        return LLMResponse(text=json.dumps(verdict))

    def _enrichment(self, user: str, tools: list[dict]) -> LLMResponse:
        # Enrichment never asserts facts; it proposes read-only tool calls.
        calls = []
        if "sourceipaddress" in user.lower() or "ip" in user.lower():
            calls.append(ToolCall("lookup_geo_ip", {"reason": "locate source"}))
        if "okta" in user.lower() or "user" in user.lower():
            calls.append(ToolCall("get_identity_context", {"reason": "baseline user"}))
        return LLMResponse(text="Proposing read-only enrichment.", tool_calls=calls)

    def _correlation(self, user: str) -> LLMResponse:
        linked = "related" if "burst" in user.lower() else "none"
        return LLMResponse(
            text=json.dumps({"linked": linked, "rationale": "Mock correlation."})
        )

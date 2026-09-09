from __future__ import annotations

from abc import ABC, abstractmethod
import json

import httpx

from .schema import NormalizedAlert, Severity, TriageResult

SYSTEM_PROMPT = """You triage security alerts for a small-business owner with no security background.
Respond only with JSON: severity (low|medium|high|critical), explanation (2-3 plain-English sentences),
recommended_action (one concrete step), and optional reasoning (technical evidence for an analyst)."""


class TriageModel(ABC):
    @abstractmethod
    async def triage(self, alert: NormalizedAlert) -> TriageResult: ...


class OllamaTriageModel(TriageModel):
    def __init__(self, model: str = "qwen3:8b", base_url: str = "http://localhost:11434"):
        self.model, self.base_url = model, base_url.rstrip("/")

    async def triage(self, alert: NormalizedAlert) -> TriageResult:
        payload = {"model": self.model, "format": "json", "stream": False,
                   "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": alert.model_dump_json()}]}
        last_error: Exception | None = None
        for _ in range(2):
            try:
                async with httpx.AsyncClient(timeout=90) as client:
                    response = await client.post(f"{self.base_url}/api/chat", json=payload)
                    response.raise_for_status()
                return TriageResult.model_validate(json.loads(response.json()["message"]["content"]))
            except (httpx.HTTPError, KeyError, json.JSONDecodeError, ValueError) as error:
                last_error = error
        return TriageResult(severity=Severity.UNKNOWN,
                            explanation="The local AI could not validate this alert. Review the technical details.",
                            recommended_action="Have a technical user review this alert before taking action.",
                            reasoning=f"Model validation failed: {last_error}")


class FixtureTriageModel(TriageModel):
    """Deterministic local stand-in used by tests and fixture demos only."""
    async def triage(self, alert: NormalizedAlert) -> TriageResult:
        title = alert.title.lower()
        severity = Severity.HIGH if any(word in title for word in ("scan", "malware", "brute")) else Severity.MEDIUM
        return TriageResult(severity=severity, explanation=f"GUARD detected: {alert.title}.",
                            recommended_action="Review the affected device and its recent activity.",
                            reasoning="Fixture model output; replace with Ollama for live triage.")

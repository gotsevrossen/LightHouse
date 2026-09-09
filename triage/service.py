from __future__ import annotations

from time import perf_counter

from .db import Database
from .llm import TriageModel
from .schema import NormalizedAlert, TriageResult, max_severity


class TriageService:
    def __init__(self, db: Database, model: TriageModel):
        self.db, self.model = db, model

    async def process(self, alert: NormalizedAlert) -> tuple[int, bool]:
        duplicate = self.db.is_duplicate(alert)
        if duplicate:
            self.db.suppress(duplicate, alert.raw)
            return duplicate, True
        started = perf_counter()
        result = await self.model.triage(alert)
        latency_ms = int((perf_counter() - started) * 1000)
        floored = apply_sensor_floor(alert, result)
        return self.db.store(alert, floored, type(self.model).__name__, latency_ms), False


def apply_sensor_floor(alert: NormalizedAlert, result: TriageResult) -> TriageResult:
    """Clamp the model's severity to the floor the sensor already established.

    This is the control that survives prompt injection. Text inside an alert can
    steer the model's wording, and it can persuade the model to return "low" for an
    intrusion the attacker triggered themselves. It cannot move this line: the
    stored severity is max(sensor floor, model severity) by rank, computed outside
    the model. The model may raise severity and owns the plain-English text; it can
    never lower risk below what the detector reported.
    """
    final = max_severity(alert.sensor_severity, result.severity)
    if final == result.severity:
        return result
    return result.model_copy(update={"severity": final})

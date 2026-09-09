from __future__ import annotations

from time import perf_counter

from .db import Database
from .llm import TriageModel
from .schema import NormalizedAlert


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
        return self.db.store(alert, result, type(self.model).__name__, int((perf_counter() - started) * 1000)), False

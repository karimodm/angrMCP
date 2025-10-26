"""Exploration helpers for managing simulation resource usage."""

from __future__ import annotations

from typing import Dict, Iterable, Optional

import angr


class StateBudgetExceeded(RuntimeError):
    """Raised when a simulation manager exceeds the configured state budget."""

    def __init__(self, stash_counts: Dict[str, int], budget: int):
        self.stash_counts = dict(stash_counts)
        self.budget = int(budget)
        self.total = sum(stash_counts.values())
        super().__init__(f"state budget exceeded: {self.total} states > budget {self.budget}")


class StateBudgetLimiter(angr.exploration_techniques.ExplorationTechnique):
    """Exploration technique that enforces an upper bound on tracked states."""

    def __init__(self, budget: int, *, stashes: Optional[Iterable[str]] = None):
        super().__init__()
        if budget <= 0:
            raise ValueError("budget must be positive")
        self.budget = int(budget)
        self.stashes = tuple(stashes or ("active", "deferred", "found", "avoid", "errored", "deadended"))
        self.last_counts: Dict[str, int] = {}

    # The exploration technique lifecycle hooks below mirror angr's expectations:
    # - setup runs once when the technique is installed.
    # - step/after_step guard each simulation step, regardless of explore/run.
    # - complete fires after exploration converges or terminates.
    # This ensures we catch budget overruns as soon as they happen.

    def setup(self, simgr: angr.SimulationManager) -> angr.SimulationManager:  # type: ignore[override]
        self._check(simgr)
        return simgr

    def step(  # type: ignore[override]
        self,
        simgr: angr.SimulationManager,
        stash: str = "active",
        **kwargs,
    ) -> angr.SimulationManager:
        simgr = simgr.step(stash=stash, **kwargs)
        self._check(simgr)
        return simgr

    def after_step(self, simgr: angr.SimulationManager) -> angr.SimulationManager:  # type: ignore[override]
        self._check(simgr)
        return simgr

    def complete(self, simgr: angr.SimulationManager) -> angr.SimulationManager:  # type: ignore[override]
        self._check(simgr)
        return simgr

    # ------------------------------------------------------------------
    def _check(self, simgr: angr.SimulationManager) -> None:
        counts = {stash: len(getattr(simgr, stash, []) or []) for stash in self.stashes}
        total = sum(counts.values())
        self.last_counts = counts
        if total > self.budget:
            raise StateBudgetExceeded(counts, self.budget)

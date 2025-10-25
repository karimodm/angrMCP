"""Stateful registry keeping track of angr projects, states, and analyses."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import angr


@dataclass
class HookDescriptor:
    """Metadata describing an installed hook."""

    target: str
    address: Optional[int]
    symbol: Optional[str]
    length: Optional[int]
    description: str


@dataclass
class ProjectContext:
    """Holds runtime information for a loaded angr project."""

    project: angr.Project
    metadata: Dict[str, Any]
    states: Dict[str, angr.SimState] = field(default_factory=dict)
    sim_managers: Dict[str, angr.SimulationManager] = field(default_factory=dict)
    hooks: Dict[str, HookDescriptor] = field(default_factory=dict)
    cfg_cache: Dict[str, Any] = field(default_factory=dict)
    analyses: Dict[str, Any] = field(default_factory=dict)
    monitors: Dict[str, Any] = field(default_factory=dict)


class Registry:
    """Central repository for all MCP server state."""

    def __init__(self) -> None:
        self._projects: Dict[str, ProjectContext] = {}

    # -- project management -------------------------------------------------
    def new_project(self, project: angr.Project, metadata: Dict[str, Any]) -> str:
        project_id = str(uuid.uuid4())
        self._projects[project_id] = ProjectContext(project=project, metadata=metadata)
        return project_id

    def get_project(self, project_id: str) -> ProjectContext:
        if project_id not in self._projects:
            raise KeyError(f"unknown project_id: {project_id}")
        return self._projects[project_id]

    def reset(self) -> None:
        """Clear all tracked projects. Intended for testing."""
        self._projects.clear()

    # -- state management ---------------------------------------------------
    def register_state(self, project_id: str, state: angr.SimState) -> str:
        ctx = self.get_project(project_id)
        state_id = str(uuid.uuid4())
        ctx.states[state_id] = state
        return state_id

    def get_state(self, project_id: str, state_id: str) -> angr.SimState:
        ctx = self.get_project(project_id)
        if state_id not in ctx.states:
            raise KeyError(f"unknown state_id: {state_id}")
        return ctx.states[state_id]

    # -- simulation manager management -------------------------------------
    def register_simmanager(self, project_id: str, simgr: angr.SimulationManager) -> str:
        ctx = self.get_project(project_id)
        simgr_id = str(uuid.uuid4())
        ctx.sim_managers[simgr_id] = simgr
        return simgr_id

    def get_simmanager(self, project_id: str, simgr_id: str) -> angr.SimulationManager:
        ctx = self.get_project(project_id)
        if simgr_id not in ctx.sim_managers:
            raise KeyError(f"unknown simmanager_id: {simgr_id}")
        return ctx.sim_managers[simgr_id]

    # -- hooks --------------------------------------------------------------
    def register_hook(
        self,
        project_id: str,
        hook_id: str,
        descriptor: HookDescriptor,
    ) -> None:
        ctx = self.get_project(project_id)
        ctx.hooks[hook_id] = descriptor

    def remove_hook(self, project_id: str, hook_id: str) -> None:
        ctx = self.get_project(project_id)
        if hook_id in ctx.hooks:
            del ctx.hooks[hook_id]

    def list_hooks(self, project_id: str) -> Dict[str, HookDescriptor]:
        return dict(self.get_project(project_id).hooks)


registry = Registry()

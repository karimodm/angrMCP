"""Stateful registry keeping track of angr projects, states, alerts, and jobs."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

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
    monitors: Dict[str, "MonitorRecord"] = field(default_factory=dict)
    jobs: Dict[str, "JobContext"] = field(default_factory=dict)


@dataclass
class AlertRecord:
    """Structured alert captured during execution monitoring."""

    alert_id: str
    state_id: str
    type: str
    address: Optional[int]
    details: Dict[str, Any]
    timestamp: str


@dataclass
class MonitorRecord:
    """Events and alerts recorded for a monitored state."""

    state_id: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[AlertRecord] = field(default_factory=list)


@dataclass
class JobContext:
    """Metadata describing a persisted symbolic execution job."""

    job_id: str
    simgr_id: str
    project_id: str
    state_ids: List[str]
    metadata: Dict[str, Any]
    created_at: str
    updated_at: str
    backing_path: Optional[str] = None


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
    def register_state(
        self,
        project_id: str,
        state: angr.SimState,
        *,
        state_id: Optional[str] = None,
    ) -> str:
        ctx = self.get_project(project_id)
        identifier = state_id or str(uuid.uuid4())
        ctx.states[identifier] = state
        return identifier

    def get_state(self, project_id: str, state_id: str) -> angr.SimState:
        ctx = self.get_project(project_id)
        if state_id not in ctx.states:
            raise KeyError(f"unknown state_id: {state_id}")
        return ctx.states[state_id]

    # -- monitor + alert management ----------------------------------------
    def ensure_monitor(self, project_id: str, state_id: str) -> MonitorRecord:
        ctx = self.get_project(project_id)
        if state_id not in ctx.monitors:
            ctx.monitors[state_id] = MonitorRecord(state_id=state_id)
        return ctx.monitors[state_id]

    def record_event(self, project_id: str, state_id: str, event: Dict[str, Any]) -> None:
        monitor = self.ensure_monitor(project_id, state_id)
        monitor.events.append(event)

    def record_alert(
        self,
        project_id: str,
        state_id: str,
        alert_type: str,
        *,
        address: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
        alert_id: Optional[str] = None,
    ) -> AlertRecord:
        monitor = self.ensure_monitor(project_id, state_id)
        ts = timestamp or datetime.utcnow().isoformat(timespec="seconds")
        record = AlertRecord(
            alert_id=alert_id or str(uuid.uuid4()),
            state_id=state_id,
            type=alert_type,
            address=address,
            details=dict(details or {}),
            timestamp=ts,
        )
        monitor.alerts.append(record)
        return record

    def list_alerts(self, project_id: str, state_ids: Optional[Iterable[str]] = None) -> List[AlertRecord]:
        ctx = self.get_project(project_id)
        records: List[AlertRecord] = []
        for sid, monitor in ctx.monitors.items():
            if state_ids is not None and sid not in state_ids:
                continue
            records.extend(monitor.alerts)
        return records

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

    # -- job management -----------------------------------------------------
    def register_job(
        self,
        project_id: str,
        simgr_id: str,
        *,
        state_ids: Optional[Iterable[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        job_id: Optional[str] = None,
        backing_path: Optional[str] = None,
    ) -> JobContext:
        ctx = self.get_project(project_id)
        job_identifier = job_id or str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat(timespec="seconds")
        job = JobContext(
            job_id=job_identifier,
            project_id=project_id,
            simgr_id=simgr_id,
            state_ids=list(state_ids or []),
            metadata=dict(metadata or {}),
            created_at=timestamp,
            updated_at=timestamp,
            backing_path=backing_path,
        )
        ctx.jobs[job.job_id] = job
        return job

    def get_job(self, project_id: str, job_id: str) -> JobContext:
        ctx = self.get_project(project_id)
        if job_id not in ctx.jobs:
            raise KeyError(f"unknown job_id: {job_id}")
        return ctx.jobs[job_id]

    def update_job(
        self,
        project_id: str,
        job_id: str,
        *,
        state_ids: Optional[Iterable[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        backing_path: Optional[str] = None,
    ) -> JobContext:
        job = self.get_job(project_id, job_id)
        if state_ids is not None:
            job.state_ids = list(state_ids)
        if metadata is not None:
            job.metadata.update(metadata)
        if backing_path is not None:
            job.backing_path = backing_path
        job.updated_at = datetime.utcnow().isoformat(timespec="seconds")
        return job

    def delete_job(self, project_id: str, job_id: str) -> None:
        ctx = self.get_project(project_id)
        if job_id in ctx.jobs:
            del ctx.jobs[job_id]

    def list_jobs(self, project_id: str) -> Dict[str, JobContext]:
        ctx = self.get_project(project_id)
        return dict(ctx.jobs)

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

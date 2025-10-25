"""High-level MCP server exposing angr functionality as tool handlers."""

from __future__ import annotations

import importlib
import importlib.util
import pathlib
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import angr
import claripy

import angr.exploration_techniques

from .registry import HookDescriptor, registry


@dataclass
class RunResult:
    simgr_id: str
    active: List[str]
    deadended: List[str]
    found: List[str]
    avoided: List[str]
    errored: List[str]
    errors: List[Dict[str, str]]


class AngrMCPServer:
    """Implements the MCP tool surface for driving angr analyses."""

    def __init__(self) -> None:
        self._technique_cache: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Core helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _project_metadata(project: angr.Project) -> Dict[str, Any]:
        loader = project.loader
        objects = []
        for obj in loader.all_objects:
            objects.append(
                {
                    "min_addr": obj.min_addr,
                    "max_addr": obj.max_addr,
                    "binary": getattr(obj, "binary", None),
                    "entry": getattr(obj, "entry", None),
                    "segments": [
                        {
                            "vaddr": getattr(seg, "vaddr", None),
                            "memsize": getattr(seg, "memsize", None),
                            "flags": getattr(seg, "flags", None),
                        }
                        for seg in getattr(obj, "segments", [])
                    ],
                }
            )

        return {
            "arch": project.arch.name,
            "bits": project.arch.bits,
            "entry": project.entry,
            "filename": project.filename,
            "objects": objects,
        }

    # ------------------------------------------------------------------
    def load_project(
        self,
        binary_path: str,
        *,
        auto_load_libs: bool = True,
        load_options: Optional[Dict[str, Any]] = None,
        exclude_sim_procedures_list: Optional[Iterable[str]] = None,
        exclude_sim_procedures_func: Optional[str] = None,
        use_sim_procedures: bool = True,
    ) -> Dict[str, Any]:
        """Load a binary into angr and return a project identifier plus metadata."""

        load_options = dict(load_options or {})
        project = angr.Project(
            binary_path,
            auto_load_libs=auto_load_libs,
            load_options=load_options,
            exclude_sim_procedures_list=list(exclude_sim_procedures_list or []),
            exclude_sim_procedures_func=exclude_sim_procedures_func,
            use_sim_procedures=use_sim_procedures,
        )

        metadata = self._project_metadata(project)
        project_id = registry.new_project(project, metadata)
        return {"project_id": project_id, "metadata": metadata}

    # ------------------------------------------------------------------
    def setup_symbolic_context(
        self,
        project_id: str,
        *,
        kind: str = "entry",
        addr: Optional[int] = None,
        args: Optional[List[Any]] = None,
        argv: Optional[List[Any]] = None,
        env: Optional[Dict[str, Any]] = None,
        stdin_symbolic: Optional[int] = None,
        symbolic_memory: Optional[List[Dict[str, Any]]] = None,
        symbolic_registers: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Create and register a symbolic state."""

        ctx = registry.get_project(project_id)
        project = ctx.project
        factory = project.factory

        if kind == "entry":
            state = factory.entry_state(args=argv, env=env)
        elif kind == "full_init":
            state = factory.full_init_state(args=argv, env=env)
        elif kind == "blank":
            state = factory.blank_state(addr=addr)
        elif kind == "call":
            if addr is None:
                raise ValueError("call state requires addr")
            call_args = [] if args is None else list(args)
            state = factory.call_state(addr, *call_args)
        else:
            raise ValueError(f"unknown state kind: {kind}")

        if stdin_symbolic:
            sym_stdin = claripy.BVS(f"stdin_{uuid.uuid4().hex}", stdin_symbolic * 8)
            stdin_stream = state.posix.stdin
            size_bv = claripy.BVV(stdin_symbolic, state.arch.bits)
            stdin_stream.content = [(sym_stdin, size_bv)]
            stdin_stream.pos = 0
            stdin_stream.write_mode = False

        for spec in symbolic_memory or []:
            name = spec.get("name", f"mem_{spec['address']:#x}")
            size = spec["size"]
            addr_spec = spec["address"]
            sym = claripy.BVS(f"{name}_{uuid.uuid4().hex}", size * 8)
            state.memory.store(addr_spec, sym)

        for spec in symbolic_registers or []:
            reg_name = spec["name"]
            size = spec.get("size", project.arch.bytes)
            sym = claripy.BVS(f"{reg_name}_{uuid.uuid4().hex}", size * 8)
            setattr(state.regs, reg_name, sym)

        state_id = registry.register_state(project_id, state)

        solver = state.solver
        register_snapshot = {
            "ip": solver.eval(state.regs.ip),
            "sp": solver.eval(state.regs.sp),
            "bp": solver.eval(state.regs.bp) if hasattr(state.regs, "bp") else None,
        }

        return {
            "state_id": state_id,
            "registers": register_snapshot,
        }

    # ------------------------------------------------------------------
    def instrument_environment(
        self,
        project_id: str,
        hooks: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        ctx = registry.get_project(project_id)
        project = ctx.project
        applied: Dict[str, Dict[str, Any]] = {}

        for hook_spec in hooks:
            hook_id = hook_spec.get("hook_id") or str(uuid.uuid4())
            address = hook_spec.get("address")
            symbol = hook_spec.get("symbol")
            length = hook_spec.get("length")

            description = ""
            if hook_spec.get("simprocedure"):
                simproc = self._resolve_simprocedure(hook_spec["simprocedure"])
                proc_instance = simproc()
                if address is not None:
                    project.hook(address, proc_instance)
                    description = f"simprocedure:{hook_spec['simprocedure']}"
                elif symbol is not None:
                    project.hook_symbol(symbol, proc_instance)
                    description = f"simprocedure:{hook_spec['simprocedure']}"
                else:
                    raise ValueError("hook requires address or symbol")
            elif hook_spec.get("python_callable"):
                func = hook_spec["python_callable"]
                if not callable(func):
                    raise TypeError("python_callable must be callable")
                if address is None:
                    raise ValueError("python hook requires address")
                project.hook(address, func, length=length)
                description = "callable"
            else:
                raise ValueError("unsupported hook specification")

            descriptor = HookDescriptor(
                target="symbol" if symbol else "address",
                address=address,
                symbol=symbol,
                length=length,
                description=description,
            )
            registry.register_hook(project_id, hook_id, descriptor)
            applied[hook_id] = {
                "address": address,
                "symbol": symbol,
                "description": description,
            }

        return {"hooks": applied}

    # ------------------------------------------------------------------
    def run_symbolic_search(
        self,
        project_id: str,
        *,
        state_id: Optional[str] = None,
        simgr_id: Optional[str] = None,
        mode: str = "explore",
        find: Optional[List[int]] = None,
        avoid: Optional[List[int]] = None,
        step_count: int = 1,
        techniques: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        ctx = registry.get_project(project_id)
        project = ctx.project

        if simgr_id:
            simgr = registry.get_simmanager(project_id, simgr_id)
        else:
            if state_id is None:
                raise ValueError("state_id required when creating new sim manager")
            state = registry.get_state(project_id, state_id)
            simgr = project.factory.simulation_manager(state)
            simgr_id = registry.register_simmanager(project_id, simgr)

        for tech_name in techniques or []:
            technique = self._load_technique(tech_name, project)
            if technique is not None:
                simgr.use_technique(technique)

        caught_errors: List[Dict[str, str]] = []
        try:
            if mode == "step":
                for _ in range(step_count):
                    simgr.step()
            elif mode == "explore":
                simgr.explore(find=find, avoid=avoid)
            else:
                raise ValueError(f"unknown mode: {mode}")
        except Exception as exc:  # pylint:disable=broad-except
            caught_errors.append({"type": type(exc).__name__, "message": str(exc)})

        result = self._collect_run_result(project_id, simgr_id, simgr, extra_errors=caught_errors)
        return {"run": result.__dict__}

    # ------------------------------------------------------------------
    def monitor_for_vulns(
        self,
        project_id: str,
        state_id: str,
        events: List[str],
    ) -> Dict[str, Any]:
        state = registry.get_state(project_id, state_id)
        log: List[Dict[str, Any]] = []

        def make_callback(event_name: str):
            def _callback(state: angr.SimState) -> None:
                solver = state.solver
                entry = {"event": event_name, "addr": solver.eval(state.regs.ip)}
                if event_name == "mem_write":
                    addr_ast = state.inspect.mem_write_address
                    length_ast = state.inspect.mem_write_length
                    entry["address"] = solver.eval(addr_ast)
                    entry["length"] = solver.eval(length_ast)
                log.append(entry)

            return _callback

        for event_name in events:
            state.inspect.b(event_name, when=angr.BP_AFTER, action=make_callback(event_name))

        registry.get_project(project_id).monitors[state_id] = log
        return {"monitored_events": events}

    # ------------------------------------------------------------------
    def inspect_state(
        self,
        project_id: str,
        state_id: str,
        *,
        registers: Optional[List[str]] = None,
        memory: Optional[List[Dict[str, int]]] = None,
        include_constraints: bool = False,
        include_events: bool = False,
    ) -> Dict[str, Any]:
        state = registry.get_state(project_id, state_id)
        data: Dict[str, Any] = {}

        regs = {}
        for reg_name in registers or []:
            regs[reg_name] = int(getattr(state.regs, reg_name))
        if regs:
            data["registers"] = regs

        mem_dump = []
        for mem in memory or []:
            addr = mem["address"]
            size = mem["size"]
            content = state.memory.load(addr, size)
            try:
                concrete = state.solver.eval(content, cast_to=bytes)
            except Exception:
                concrete = None
            mem_dump.append(
                {
                    "address": addr,
                    "size": size,
                    "concrete": concrete,
                }
            )
        if mem_dump:
            data["memory"] = mem_dump

        if include_constraints:
            constraints = [str(c) for c in state.solver.constraints]
            data["constraints"] = constraints

        if include_events:
            ctx = registry.get_project(project_id)
            data["events"] = ctx.monitors.get(state_id, [])

        return data

    # ------------------------------------------------------------------
    def solve_constraints(
        self,
        project_id: str,
        state_id: str,
        queries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        state = registry.get_state(project_id, state_id)
        results = []
        for query in queries:
            kind = query["kind"]
            if kind == "memory":
                addr = query["address"]
                size = query["size"]
                ast = state.memory.load(addr, size)
            elif kind == "register":
                reg = query["name"]
                ast = getattr(state.regs, reg)
            else:
                raise ValueError(f"unsupported query kind: {kind}")

            item = {"kind": kind}
            item["value"] = state.solver.eval(ast)
            if query.get("minmax"):
                item["min"] = state.solver.min(ast)
                item["max"] = state.solver.max(ast)
            results.append(item)

        return {"results": results}

    # ------------------------------------------------------------------
    def analyze_control_flow(
        self,
        project_id: str,
        *,
        force_fast: bool = False,
        keep_state: bool = False,
    ) -> Dict[str, Any]:
        ctx = registry.get_project(project_id)
        project = ctx.project
        if force_fast:
            cfg = project.analyses.CFGFast()
            kind = "CFGFast"
        else:
            cfg = project.analyses.CFGEmulated(keep_state=keep_state)
            kind = "CFGEmulated"

        ctx.cfg_cache[kind] = cfg
        functions = [
            {
                "addr": func.addr,
                "name": func.name,
                "returning": func.returning,
                "has_unresolved_calls": func.has_unresolved_calls,
            }
            for func in cfg.kb.functions.values()
        ]
        return {
            "analysis": kind,
            "node_count": len(cfg.graph.nodes()),
            "edge_count": len(cfg.graph.edges()),
            "functions": functions,
        }

    # ------------------------------------------------------------------
    def trace_dataflow(
        self,
        project_id: str,
        *,
        target_addr: int,
        target_stmt: int = -1,
        use_ddg: bool = False,
        use_cdg: bool = False,
    ) -> Dict[str, Any]:
        ctx = registry.get_project(project_id)
        project = ctx.project
        cfg = ctx.cfg_cache.get("CFGEmulated") or project.analyses.CFGEmulated(keep_state=True)
        node = cfg.model.get_any_node(target_addr)
        if node is None:
            raise ValueError(f"target address {target_addr:#x} not present in CFG")

        cdg = project.analyses.CDG(cfg) if use_cdg else None
        ddg = project.analyses.DDG(cfg) if use_ddg else None

        bs = project.analyses.BackwardSlice(
            cfg,
            cdg=cdg,
            ddg=ddg,
            targets=[(node, target_stmt)],
            control_flow_slice=cdg is None and ddg is None,
        )

        result = {
            "runs_in_slice": list(bs.runs_in_slice.nodes()) if hasattr(bs, "runs_in_slice") else [],
            "cfg_nodes_in_slice": list(bs.cfg_nodes_in_slice.nodes()) if hasattr(bs, "cfg_nodes_in_slice") else [],
        }
        if hasattr(bs, "chosen_statements"):
            result["chosen_statements"] = {
                hex(addr): stmts for addr, stmts in bs.chosen_statements.items()
            }
        if hasattr(bs, "chosen_exits"):
            result["chosen_exits"] = {
                hex(addr): exits for addr, exits in bs.chosen_exits.items()
            }
        return result

    # ------------------------------------------------------------------
    def _collect_run_result(
        self,
        project_id: str,
        simgr_id: str,
        simgr: angr.SimulationManager,
        extra_errors: Optional[List[Dict[str, str]]] = None,
    ) -> RunResult:
        def register_states(states: Iterable[angr.SimState]) -> List[str]:
            ids = []
            for st in states:
                state_id = registry.register_state(project_id, st)
                ids.append(state_id)
            return ids

        def stash_states(name: str) -> Iterable[angr.SimState]:
            try:
                return getattr(simgr, name)
            except AttributeError:
                return []

        active_ids = register_states(stash_states("active"))
        dead_ids = register_states(stash_states("deadended"))
        found_ids = register_states(stash_states("found"))
        avoid_ids = register_states(stash_states("avoid"))
        errored_iter = (err.state for err in stash_states("errored"))
        errored_ids = register_states(errored_iter)

        return RunResult(
            simgr_id=simgr_id,
            active=active_ids,
            deadended=dead_ids,
            found=found_ids,
            avoided=avoid_ids,
            errored=errored_ids,
            errors=extra_errors or [],
        )

    # ------------------------------------------------------------------
    def _resolve_simprocedure(self, dotted_name: str):
        parts = dotted_name.split(".")
        if len(parts) != 2:
            raise ValueError("simprocedure must be in the form '<library>.<name>'")
        lib, name = parts
        if lib not in angr.SIM_PROCEDURES:
            raise KeyError(f"unknown simprocedure library: {lib}")
        if name not in angr.SIM_PROCEDURES[lib]:
            raise KeyError(f"unknown simprocedure: {dotted_name}")
        return angr.SIM_PROCEDURES[lib][name]

    def _load_technique(self, name: str, project: angr.Project):
        name = name.lower()
        if name in self._technique_cache:
            factory = self._technique_cache[name]
            return factory()

        base_path = pathlib.Path("awesome-angr/ExplorationTechniques")
        mapping = {
            "simgr_viz": base_path / "SimgrViz" / "SimgrViz.py",
            "mem_limiter": base_path / "MemLimiter" / "MemLimiter.py",
            "explosion_detector": base_path / "ExplosionDetector" / "ExplosionDetector.py",
            "loop_exhaustion": base_path / "LoopExhaustion" / "LoopExhaustion.py",
            "stochastic_search": base_path / "StochasticSearch" / "StocasticSearch.py",
            "klee_random": base_path / "KLEERandomSearch" / "KLEERandomSearch.py",
            "klee_coverage": base_path / "KLEECoverageOptimizeSearch" / "KLEECoverageOS.py",
            "heart_beat": base_path / "HeartBeat" / "heartbeat.py",
        }
        if name not in mapping:
            return None

        path = mapping[name]
        if not path.exists():
            raise FileNotFoundError(f"exploration technique file not found: {path}")
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load technique from {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[assignment]

        technique_cls = None
        if hasattr(module, "factory") and callable(module.factory):
            self._technique_cache[name] = module.factory
            return module.factory()

        for attr in module.__dict__.values():
            if isinstance(attr, type) and issubclass(attr, angr.exploration_techniques.ExplorationTechnique):
                technique_cls = attr
                break

        if technique_cls is None:
            raise AttributeError(f"no exploration technique found in {path}")

        self._technique_cache[name] = technique_cls
        return technique_cls()

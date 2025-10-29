"""High-level MCP server exposing angr functionality as tool handlers."""

from __future__ import annotations

import base64
import itertools
import importlib
import importlib.util
import json
import pathlib
import pickle
import uuid
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import angr
import claripy

import angr.exploration_techniques
from angr.storage.file import SimFile

from ..registry import AlertRecord, HookDescriptor, JobContext, ProjectContext, registry
from ..utils import (
    SYMBOL_STORE_KEY,
    StateBudgetExceeded,
    StateBudgetLimiter,
    StateMutationResult,
    mutate_registers,
    mutate_stack,
    new_symbolic_bitvector,
)
from .taint_engine import TaintTracker, apply_taint, is_tainted, new_tainted_value
from .taint_engine.dfs import DFS


def _format_addr(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return f"0x{value:x}"


@dataclass
class RunResult:
    simgr_id: str
    active: List[str]
    deadended: List[str]
    found: List[str]
    avoided: List[str]
    errored: List[str]
    errors: List[Dict[str, str]]
    alerts: List[Dict[str, Any]]
    job_id: Optional[str] = None
    stashes: Optional[Dict[str, List[str]]] = None
    streams: Dict[str, Dict[str, str]] = field(default_factory=dict)
    predicate_matches: List[Dict[str, Any]] = field(default_factory=list)
    state_pressure: Optional[Dict[str, Any]] = None
    taint_hits: List[Dict[str, Any]] = field(default_factory=list)


class PredicateEngine:
    """Compile structured predicate descriptors into angr-compatible callables."""

    def __init__(self, role: str, descriptors: Sequence[Dict[str, Any]]):
        self.role = role
        self.descriptors = list(descriptors)
        self._address_map: Dict[int, List[Dict[str, Any]]] = {}
        self._predicate_specs: List[Dict[str, Any]] = []
        self._pending: Dict[int, List[Dict[str, Any]]] = {}
        self.matches: List[Dict[str, Any]] = []

        for descriptor in self.descriptors:
            if descriptor["kind"] == "address":
                addr = int(descriptor["address"])
                self._address_map.setdefault(addr, []).append(descriptor)
            else:
                self._predicate_specs.append(descriptor)

    def has_predicates(self) -> bool:
        return bool(self._address_map or self._predicate_specs)

    def as_callable(self) -> Optional[Callable[[angr.SimState], bool]]:
        if not self.has_predicates():
            return None

        def _predicate(state: angr.SimState) -> bool:
            matched = False
            state_addr = int(getattr(state, "addr", 0) or 0)
            if state_addr in self._address_map:
                for descriptor in self._address_map[state_addr]:
                    self._record_match(descriptor, state, {"address": state_addr})
                matched = True

            for descriptor in self._predicate_specs:
                if self._evaluate_descriptor(state, descriptor):
                    matched = True

            return matched

        return _predicate

    def bind_state(self, state: angr.SimState, state_id: str) -> None:
        """Associate pending predicate matches with a concrete state identifier."""

        bucket = self._pending.pop(id(state), [])
        for entry in bucket:
            entry["state_id"] = state_id
            self.matches.append(entry)

    # ------------------------------------------------------------------
    def _record_match(self, descriptor: Dict[str, Any], state: angr.SimState, details: Dict[str, Any]) -> None:
        state_addr = int(getattr(state, "addr", 0) or 0)
        details = dict(details)
        if "address" in details and details["address"] is not None:
            details["address"] = _format_addr(int(details["address"]))

        entry = {
            "predicate_id": descriptor["id"],
            "kind": descriptor["kind"],
            "role": self.role,
            "state_id": None,
            "state_addr": _format_addr(state_addr),
            "details": details,
        }
        self._pending.setdefault(id(state), []).append(entry)

    def _evaluate_descriptor(self, state: angr.SimState, descriptor: Dict[str, Any]) -> bool:
        kind = descriptor["kind"]
        if kind in {"stdout_contains", "stdout_not_contains"}:
            stream_name = descriptor.get("stream", "stdout")
            fd = 1 if stream_name == "stdout" else 2
            try:
                data = state.posix.dumps(fd)
            except Exception:  # pylint:disable=broad-except
                data = b""

            needle: bytes = descriptor["needle"]
            contains = needle in data
            matched = contains
            violation = False
            if kind == "stdout_not_contains":
                violation = contains
                matched = contains
            if matched:
                snippet = data[-64:]
                details = {
                    "stream": stream_name,
                    "needle_b64": base64.b64encode(needle).decode("ascii"),
                    "snippet_b64": base64.b64encode(snippet).decode("ascii"),
                }
                if violation:
                    details["violation"] = True
                self._record_match(descriptor, state, details)
            return matched

        raise ValueError(f"unsupported predicate kind: {kind}")


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
                    "min_addr": _format_addr(getattr(obj, "min_addr", None)),
                    "max_addr": _format_addr(getattr(obj, "max_addr", None)),
                    "binary": getattr(obj, "binary", None),
                    "entry": _format_addr(getattr(obj, "entry", None)),
                    "segments": [
                        {
                            "vaddr": _format_addr(getattr(seg, "vaddr", None)),
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
            "entry": _format_addr(project.entry),
            "filename": project.filename,
            "objects": objects,
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _option_name(option: Any) -> str:
        return getattr(option, "name", str(option))

    def _resolve_state_options(self, options: Optional[Iterable[Any]]) -> List[Any]:
        resolved: List[Any] = []
        for opt in options or []:
            if isinstance(opt, str):
                if not hasattr(angr.options, opt):
                    raise ValueError(f"unknown angr option: {opt}")
                resolved.append(getattr(angr.options, opt))
            else:
                resolved.append(opt)
        return resolved

    def _normalize_predicate_specs(
        self,
        specs: Optional[Sequence[Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        runtime: List[Dict[str, Any]] = []
        serialized: List[Dict[str, Any]] = []
        for entry in specs or []:
            descriptor: Dict[str, Any]
            if isinstance(entry, int):
                descriptor = {
                    "id": str(uuid.uuid4()),
                    "kind": "address",
                    "address": int(entry),
                    "description": f"address:{entry:#x}",
                }
            elif isinstance(entry, dict):
                kind = entry.get("kind")
                if kind == "address":
                    address = int(entry["address"])
                    descriptor = {
                        "id": entry.get("id", str(uuid.uuid4())),
                        "kind": "address",
                        "address": address,
                        "description": entry.get("description", f"address:{address:#x}"),
                    }
                elif kind in {"stdout_contains", "stdout_not_contains"}:
                    text = entry.get("text") or entry.get("value") or entry.get("needle")
                    if isinstance(text, bytes):
                        needle = text
                        text_str = text.decode("utf-8", errors="replace")
                    else:
                        text_str = str(text)
                        needle = text_str.encode("utf-8")
                    descriptor = {
                        "id": entry.get("id", str(uuid.uuid4())),
                        "kind": kind,
                        "needle": needle,
                        "text": text_str,
                        "stream": entry.get("stream", "stdout"),
                    }
                else:
                    raise ValueError(f"unsupported predicate descriptor: {entry}")
            else:
                raise TypeError(f"unsupported predicate entry: {entry!r}")

            runtime.append(descriptor)
            serialized.append(self._serialize_predicate_descriptor(descriptor))

        return runtime, serialized

    @staticmethod
    def _serialize_predicate_descriptor(descriptor: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "id": descriptor["id"],
            "kind": descriptor["kind"],
        }
        if descriptor["kind"] == "address":
            payload["address"] = _format_addr(int(descriptor["address"]))
            payload["description"] = descriptor.get("description")
        else:
            payload["text"] = descriptor.get("text")
            payload["stream"] = descriptor.get("stream")
            payload["needle_b64"] = base64.b64encode(descriptor["needle"]).decode("ascii")
        return payload

    @staticmethod
    def _apply_symbolic_memory(state: angr.SimState, specs: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for spec in specs or []:
            address = int(spec["address"])
            size = int(spec["size"])
            label = spec.get("label", f"mem_{address:#x}")
            bits = size * 8
            symbol, metadata = new_symbolic_bitvector(state, label, bits, handle_prefix="mem")
            state.memory.store(address, symbol)
            entry = {"address": _format_addr(address), "size": size}
            entry.update(metadata)
            entries.append(entry)
        return entries

    @staticmethod
    def _seed_filesystem(state: angr.SimState, specs: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for spec in specs or []:
            path = spec["path"]
            symbolic_spec = spec.get("symbolic")
            content = spec.get("content")

            if symbolic_spec is not None:
                if symbolic_spec is False:
                    symbolic_spec = {}
                elif symbolic_spec is True:
                    symbolic_spec = {}

                size = spec.get("size") or symbolic_spec.get("size")
                bits = symbolic_spec.get("bits")
                if size is None and bits is None:
                    raise ValueError("symbolic file entry requires either size or bits")
                if bits is None and size is not None:
                    bits = int(size) * 8
                if size is None and bits is not None:
                    if int(bits) % 8 != 0:
                        raise ValueError("symbolic file bit-width must be byte aligned")
                    size = int(bits) // 8
                size = int(size)
                bits = int(bits)
                if size <= 0 or bits <= 0:
                    raise ValueError("symbolic file entry requires positive size")
                label = symbolic_spec.get("label", path)
                symbol, metadata = new_symbolic_bitvector(state, label, bits, handle_prefix="file")
                simfile = SimFile(path, content=symbol, size=size)
                state.fs.insert(path, simfile)
                entry = {"path": path, "size": size}
                entry.update(metadata)
                entries.append(entry)
                continue

            if content is not None:
                if isinstance(content, str):
                    data = content.encode("utf-8")
                elif isinstance(content, bytes):
                    data = content
                else:
                    raise TypeError("filesystem content must be bytes or str")
                simfile = SimFile(path, content=data)
                state.fs.insert(path, simfile)
                entries.append({"path": path, "size": len(data), "content_b64": base64.b64encode(data).decode("ascii")})
                continue

            raise ValueError(f"unsupported filesystem specification: {spec!r}")

        return entries

    @staticmethod
    def _dump_streams(state: angr.SimState) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        for fd, name in ((0, "stdin"), (1, "stdout"), (2, "stderr")):
            try:
                data = state.posix.dumps(fd)
            except Exception:  # pylint:disable=broad-except
                data = b""
            if not data:
                continue
            mapping[name] = base64.b64encode(data).decode("ascii")
        return mapping

    @staticmethod
    def _resolve_symbol_handle(state: angr.SimState, handle: str) -> claripy.ast.BV:
        store = state.globals.get(SYMBOL_STORE_KEY, {})
        if handle not in store:
            raise KeyError(f"unknown symbolic handle: {handle}")
        return store[handle]

    @staticmethod
    def _coerce_constraint_value(state: angr.SimState, value: Any, expected_bits: int) -> claripy.ast.BV:
        raw = value
        if isinstance(value, dict):
            if "handle" in value:
                handle = value["handle"]
                return AngrMCPServer._resolve_symbol_handle(state, handle)
            if "bytes_b64" in value:
                raw = base64.b64decode(value["bytes_b64"])
            elif "bytes" in value:
                raw = value["bytes"]
            elif "string" in value:
                raw = value["string"]
            elif "value" in value:
                raw = int(value["value"])
            else:
                raise ValueError(f"unsupported constraint value spec: {value!r}")

        if isinstance(raw, claripy.ast.Base):
            bv = raw
        elif isinstance(raw, bytes):
            bv = claripy.BVV(raw)
        elif isinstance(raw, str):
            bv = claripy.BVV(raw.encode("utf-8"))
        elif isinstance(raw, int):
            bits = expected_bits or max(raw.bit_length(), 1)
            bv = claripy.BVV(raw, bits)
        else:
            raise TypeError(f"unsupported constraint value type: {type(raw)!r}")

        if expected_bits and bv.size() != expected_bits:
            if bv.size() > expected_bits:
                raise ValueError("constraint value width larger than target width")
            extension = expected_bits - bv.size()
            bv = claripy.ZeroExt(extension, bv)

        return bv

    @staticmethod
    def _serialize_global_value(value: Any) -> Any:
        if isinstance(value, (type(None), int, float, str, bool)):
            return value
        if isinstance(value, bytes):
            return {
                "type": "bytes",
                "value_b64": base64.b64encode(value).decode("ascii"),
            }
        if isinstance(value, claripy.ast.Base):
            return {
                "type": "claripy_ast",
                "bits": value.size(),
                "repr": repr(value),
            }
        if isinstance(value, list):
            return [AngrMCPServer._serialize_global_value(item) for item in value]
        if isinstance(value, dict):
            return {
                key: AngrMCPServer._serialize_global_value(val)
                for key, val in value.items()
            }
        return repr(value)

    # ------------------------------------------------------------------
    def load_project(
        self,
        binary_path: str,
        *,
        auto_load_libs: bool = False,
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
            main_opts={"base_addr": 0x00100000}  # To align with Ghidra
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
        stack_mutations: Optional[List[Dict[str, Any]]] = None,
        filesystem: Optional[List[Dict[str, Any]]] = None,
        add_options: Optional[Iterable[Any]] = None,
        remove_options: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """Create and register a symbolic state."""

        ctx = registry.get_project(project_id)
        project = ctx.project
        factory = project.factory

        add_opts = set(self._resolve_state_options(add_options))
        remove_opts = set(self._resolve_state_options(remove_options))
        state_kwargs: Dict[str, Any] = {}
        if add_opts:
            state_kwargs["add_options"] = add_opts
        if remove_opts:
            state_kwargs["remove_options"] = remove_opts

        if kind == "entry":
            state = factory.entry_state(args=argv, env=env, **state_kwargs)
        elif kind == "full_init":
            state = factory.full_init_state(args=argv, env=env, **state_kwargs)
        elif kind == "blank":
            state = factory.blank_state(addr=addr, **state_kwargs)
        elif kind == "call":
            if addr is None:
                raise ValueError("call state requires addr")
            call_args = [] if args is None else list(args)
            state = factory.call_state(addr, *call_args, **state_kwargs)
        else:
            raise ValueError(f"unknown state kind: {kind}")

        if stdin_symbolic:
            sym_stdin, stdin_meta = new_symbolic_bitvector(
                state,
                f"stdin_{uuid.uuid4().hex}",
                stdin_symbolic * 8,
                handle_prefix="stdin",
            )
            stdin_stream = state.posix.stdin
            size_bv = claripy.BVV(stdin_symbolic, state.arch.bits)
            stdin_stream.content = [(sym_stdin, size_bv)]
            stdin_stream.pos = 0
            stdin_stream.write_mode = False
            stdin_entry = {
                "stream": "stdin",
                "bits": stdin_symbolic * 8,
            }
            stdin_entry.update(stdin_meta)
        else:
            stdin_entry = None

        mutation_summary = StateMutationResult()
        if add_opts or remove_opts:
            mutation_summary.add_options(
                added=[self._option_name(opt) for opt in add_opts],
                removed=[self._option_name(opt) for opt in remove_opts],
            )

        mem_entries = self._apply_symbolic_memory(state, symbolic_memory)
        file_entries = self._seed_filesystem(state, filesystem)

        if symbolic_registers:
            mutate_registers(state, symbolic_registers, result=mutation_summary)

        if stack_mutations:
            mutate_stack(state, stack_mutations, result=mutation_summary)

        state_id = registry.register_state(project_id, state)

        solver = state.solver

        def safe_reg(reg_attr: Any) -> Optional[str]:
            try:
                return _format_addr(int(solver.eval(reg_attr)))
            except Exception:  # pylint:disable=broad-except
                return None

        register_snapshot = {
            "ip": safe_reg(state.regs.ip),
            "sp": safe_reg(state.regs.sp),
            "bp": safe_reg(getattr(state.regs, "bp", None)) if hasattr(state.regs, "bp") else None,
        }

        symbolic_payload: Dict[str, Any] = {}
        if stdin_entry:
            symbolic_payload.setdefault("stdin", []).append(stdin_entry)
        register_symbols = [entry for entry in mutation_summary.registers if entry.get("handle")]
        if register_symbols:
            symbolic_payload["registers"] = register_symbols
        stack_symbols = [
            entry.as_dict() for entry in mutation_summary.stack if entry.handle is not None
        ]
        if stack_symbols:
            symbolic_payload["stack"] = stack_symbols
        if mem_entries:
            symbolic_payload["memory"] = mem_entries
        if file_entries:
            symbolic_payload["filesystem"] = file_entries

        response = {
            "state_id": state_id,
            "registers": register_snapshot,
        }
        mutations_dict = mutation_summary.to_dict()
        if mutations_dict:
            for entry in mutations_dict.get("memory", []):
                if entry.get("address") is not None:
                    entry["address"] = _format_addr(int(entry["address"]))
            for entry in mutations_dict.get("stack", []):
                if entry.get("stack_pointer") is not None:
                    entry["stack_pointer"] = _format_addr(int(entry["stack_pointer"]))
            response["mutations"] = mutations_dict
        if symbolic_payload:
            response["symbolic"] = symbolic_payload

        return response

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
            sim_spec = hook_spec.get("simprocedure") or hook_spec.get("simprocedure_class")
            if sim_spec is not None:
                proc_instance, description = self._instantiate_simprocedure(
                    sim_spec,
                    args=hook_spec.get("simprocedure_args"),
                    kwargs=hook_spec.get("simprocedure_kwargs"),
                )
                if address is not None:
                    project.hook(address, proc_instance)
                elif symbol is not None:
                    project.hook_symbol(symbol, proc_instance)
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
                "address": _format_addr(address) if address is not None else None,
                "symbol": symbol,
                "description": description,
            }

        return {"hooks": applied}

    # ------------------------------------------------------------------
    def mutate_state(
        self,
        project_id: str,
        state_id: str,
        *,
        registers: Optional[List[Dict[str, Any]]] = None,
        stack: Optional[List[Dict[str, Any]]] = None,
        memory: Optional[List[Dict[str, Any]]] = None,
        add_options: Optional[Iterable[Any]] = None,
        remove_options: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        state = registry.get_state(project_id, state_id)
        mutation_summary = StateMutationResult()

        if registers:
            mutate_registers(state, registers, result=mutation_summary)
        if stack:
            mutate_stack(state, stack, result=mutation_summary)

        memory_entries: List[Dict[str, Any]] = []
        for spec in memory or []:
            address = int(spec["address"])
            size = int(spec["size"])
            if "value" in spec:
                value = int(spec["value"])
                bv = claripy.BVV(value, size * 8)
                state.memory.store(address, bv)
                memory_entries.append({"address": address, "size": size, "value": value})
            elif "symbolic" in spec:
                sym_spec = dict(spec["symbolic"])
                label = sym_spec.get("label", f"mem_{address:#x}")
                bits = int(sym_spec.get("bits", size * 8))
                symbol, metadata = new_symbolic_bitvector(state, label, bits, handle_prefix="mem")
                state.memory.store(address, symbol)
                entry = {"address": address, "size": size}
                entry.update(metadata)
                memory_entries.append(entry)
            else:
                raise ValueError(f"unsupported memory mutation: {spec!r}")
        for entry in memory_entries:
            mutation_summary.add_memory_entry(entry)

        add_opts = set(self._resolve_state_options(add_options))
        remove_opts = set(self._resolve_state_options(remove_options))
        if add_opts:
            state.options.update(add_opts)
        if remove_opts:
            state.options.difference_update(remove_opts)
        if add_opts or remove_opts:
            mutation_summary.add_options(
                added=[self._option_name(opt) for opt in add_opts],
                removed=[self._option_name(opt) for opt in remove_opts],
            )

        response = mutation_summary.to_dict()

        symbolic_payload: Dict[str, Any] = {}
        register_symbols = [entry for entry in mutation_summary.registers if entry.get("handle")]
        if register_symbols:
            symbolic_payload["registers"] = register_symbols
        stack_symbols = [
            entry.as_dict() for entry in mutation_summary.stack if entry.handle is not None
        ]
        if stack_symbols:
            symbolic_payload["stack"] = stack_symbols
        memory_symbols = [entry for entry in mutation_summary.memory if entry.get("handle")]
        if memory_symbols:
            symbolic_payload["memory"] = memory_symbols
        if symbolic_payload:
            response["symbolic"] = symbolic_payload

        return response

    # ------------------------------------------------------------------
    def add_constraints(
        self,
        project_id: str,
        state_id: str,
        constraints: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        state = registry.get_state(project_id, state_id)
        applied: List[Dict[str, Any]] = []

        for spec in constraints:
            kind = spec.get("kind")
            if kind is None:
                raise ValueError("constraint specification missing 'kind'")

            if kind == "expression":
                expr = spec.get("expression")
                if expr is None:
                    raise ValueError("expression constraint requires 'expression'")
                state.add_constraints(expr)
                applied.append({"kind": kind})
                continue

            target_ast: claripy.ast.Base
            descriptor: Dict[str, Any] = {"kind": kind}

            if kind == "symbol":
                handle = spec["handle"]
                target_ast = self._resolve_symbol_handle(state, handle)
                descriptor["handle"] = handle
            elif kind == "memory":
                address = int(spec["address"])
                size = int(spec["size"])
                target_ast = state.memory.load(address, size)
                descriptor.update({"address": address, "size": size})
            elif kind == "register":
                reg_name = spec["name"]
                target_ast = getattr(state.regs, reg_name)
                descriptor["name"] = reg_name
            else:
                raise ValueError(f"unsupported constraint target kind: {kind!r}")

            equals = spec.get("equals")
            if equals is None:
                raise ValueError(f"constraint kind {kind!r} requires 'equals'")

            value_ast = self._coerce_constraint_value(state, equals, target_ast.size())
            constraint = target_ast == value_ast
            state.add_constraints(constraint)
            applied.append(descriptor)

        return {"applied": applied, "count": len(applied)}

    # ------------------------------------------------------------------
    def run_symbolic_search(
        self,
        project_id: str,
        *,
        state_id: Optional[str] = None,
        simgr_id: Optional[str] = None,
        job_id: Optional[str] = None,
        mode: str = "explore",
        find: Optional[List[int]] = None,
        avoid: Optional[List[int]] = None,
        step_count: int = 1,
        techniques: Optional[List[str]] = None,
        state_budget: Optional[int] = None,
        budget_stashes: Optional[Sequence[str]] = None,
        persist_job: bool = False,
        job_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx = registry.get_project(project_id)
        project = ctx.project

        job_ctx: Optional[JobContext] = None
        technique_names = [name.lower() for name in (techniques or [])]
        handled_techniques: Set[str] = set()

        find_runtime, find_serialized = self._normalize_predicate_specs(find)
        avoid_runtime, avoid_serialized = self._normalize_predicate_specs(avoid)
        find_engine = PredicateEngine("find", find_runtime)
        avoid_engine = PredicateEngine("avoid", avoid_runtime)
        find_callable = find_engine.as_callable()
        avoid_callable = avoid_engine.as_callable()

        if job_id:
            try:
                job_ctx = registry.get_job(project_id, job_id)
            except KeyError:
                job_ctx = self._load_job_from_disk(project_id, job_id)

        if job_ctx is not None:
            simgr_id = job_ctx.simgr_id

        if simgr_id:
            simgr = registry.get_simmanager(project_id, simgr_id)
            if job_ctx is None:
                job_ctx = self._find_job_by_simgr(project_id, simgr_id)
        else:
            if state_id is None:
                raise ValueError("state_id required when creating new sim manager")
            state = registry.get_state(project_id, state_id)
            simgr_kwargs: Dict[str, Any] = {}
            if "veritesting" in technique_names:
                simgr_kwargs["veritesting"] = True
                handled_techniques.add("veritesting")
            simgr = project.factory.simulation_manager(state, **simgr_kwargs)
            simgr_id = registry.register_simmanager(project_id, simgr)
            if job_ctx is None and job_id:
                # a job was requested but no persisted state existed; initialize a new job context shell
                job_ctx = registry.register_job(
                    project_id,
                    simgr_id,
                    job_id=job_id,
                    metadata={"note": "job initialized from fresh state"},
                )

        state_pressure: Optional[Dict[str, Any]] = None
        budget_limiter: Optional[StateBudgetLimiter] = None
        budget_error: Optional[StateBudgetExceeded] = None

        if state_budget is not None:
            budget_limiter = StateBudgetLimiter(state_budget, stashes=budget_stashes)
            simgr.use_technique(budget_limiter)

        if "veritesting" in technique_names and "veritesting" not in handled_techniques:
            try:
                from angr.exploration_techniques.veritesting import Veritesting as _Veritesting

                if not any(isinstance(t, _Veritesting) for t in getattr(simgr, "_techniques", [])):
                    simgr.use_technique(_Veritesting())
            except ImportError:
                pass
            handled_techniques.add("veritesting")

        for tech_name in techniques or []:
            if tech_name.lower() in handled_techniques:
                continue
            technique = self._load_technique(tech_name, project)
            if technique is not None:
                simgr.use_technique(technique)

        state_callbacks: List[Callable[[angr.SimState, str], None]] = []
        for engine in (find_engine, avoid_engine):
            if engine.has_predicates():
                state_callbacks.append(engine.bind_state)

        caught_errors: List[Dict[str, str]] = []
        try:
            if mode == "step":
                for _ in range(step_count):
                    simgr.step()
            elif mode == "explore":
                explore_kwargs: Dict[str, Any] = {}
                if find_engine.has_predicates():
                    explore_kwargs["find"] = find_callable
                if avoid_engine.has_predicates():
                    explore_kwargs["avoid"] = avoid_callable
                simgr.explore(**explore_kwargs)
            else:
                raise ValueError(f"unknown mode: {mode}")
        except StateBudgetExceeded as exc:
            budget_error = exc
            caught_errors.append(
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
        except Exception as exc:  # pylint:disable=broad-except
            caught_errors.append({"type": type(exc).__name__, "message": str(exc)})

        if budget_limiter is not None or budget_error is not None:
            if budget_error is not None:
                counts = dict(budget_error.stash_counts)
                total = budget_error.total
                status = "exceeded"
            else:
                counts = dict(budget_limiter.last_counts)
                total = sum(counts.values())
                status = "ok"
            state_pressure = {
                "status": status,
                "budget": state_budget,
                "total": total,
                "stashes": counts,
            }

        result = self._collect_run_result(
            project_id,
            simgr_id,
            simgr,
            extra_errors=caught_errors,
            state_callbacks=state_callbacks,
            state_pressure=state_pressure,
        )
        predicate_matches: List[Dict[str, Any]] = []
        if find_engine.has_predicates():
            predicate_matches.extend(find_engine.matches)
        if avoid_engine.has_predicates():
            predicate_matches.extend(avoid_engine.matches)
        result.predicate_matches = predicate_matches

        stash_map = result.stashes or {
            "active": result.active,
            "deadended": result.deadended,
            "found": result.found,
            "avoided": result.avoided,
            "errored": result.errored,
        }
        all_state_ids = sorted({sid for sids in stash_map.values() for sid in sids})

        metadata_payload = {
            "last_run": {
                "mode": mode,
                "step_count": step_count,
                "find": find_serialized,
                "avoid": avoid_serialized,
                "techniques": list(techniques or []),
                "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
                "alerts": result.alerts,
                "errors": result.errors,
            },
            "stashes": stash_map,
            "predicates": {
                "find": find_serialized,
                "avoid": avoid_serialized,
                "matches": predicate_matches,
            },
        }
        if state_pressure:
            metadata_payload["last_run"]["state_pressure"] = state_pressure
            metadata_payload["state_pressure"] = state_pressure
        if job_metadata:
            metadata_payload.update(job_metadata)

        if job_ctx is None:
            job_ctx = registry.register_job(
                project_id,
                simgr_id,
                state_ids=all_state_ids,
                metadata=metadata_payload,
            )
        else:
            merged_state_ids = sorted(set(job_ctx.state_ids).union(all_state_ids))
            job_ctx = registry.update_job(
                project_id,
                job_ctx.job_id,
                state_ids=merged_state_ids,
                metadata=metadata_payload,
            )

        if persist_job:
            self._persist_job(project_id, job_ctx, stash_map)
            job_ctx = registry.update_job(
                project_id,
                job_ctx.job_id,
                metadata={"persisted": True},
            )

        result.job_id = job_ctx.job_id
        result.stashes = stash_map

        run_payload = dict(result.__dict__)
        return {"run": run_payload}

    # ------------------------------------------------------------------
    def run_taint_analysis(
        self,
        project_id: str,
        *,
        state_id: str,
        tracker_options: Optional[Dict[str, Any]] = None,
        sources: Optional[Sequence[Dict[str, Any]]] = None,
        sinks: Optional[Sequence[Dict[str, Any]]] = None,
        use_dfs: bool = True,
        techniques: Optional[Sequence[str]] = None,
        stop_on_first_hit: bool = False,
        max_sink_hits: Optional[int] = None,
        state_budget: Optional[int] = None,
        budget_stashes: Optional[Sequence[str]] = None,
        max_steps: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not state_id:
            raise ValueError("state_id required for taint analysis")

        ctx = registry.get_project(project_id)
        project = ctx.project
        base_state = registry.get_state(project_id, state_id)
        state = base_state.copy()
        simgr = project.factory.simulation_manager(state)
        simgr_id = registry.register_simmanager(project_id, simgr)

        tracker_kwargs = dict(tracker_options or {})
        tracker = TaintTracker(**tracker_kwargs)

        def _coerce_int(value: Any, name: str) -> int:
            if isinstance(value, str):
                return int(value, 0)
            if value is None:
                raise ValueError(f"{name} is required")
            return int(value)

        def _sanitize_check(spec: Dict[str, Any]) -> Dict[str, Any]:
            kind = spec.get("kind")
            if kind == "register":
                return {"kind": "register", "name": spec["name"]}
            if kind == "memory":
                addr = _coerce_int(spec["address"], "address")
                size = int(spec.get("size", 1))
                return {"kind": "memory", "address": _format_addr(addr), "size": size}
            if kind == "pointer":
                size = int(spec.get("size", 1))
                return {"kind": "pointer", "register": spec["register"], "size": size}
            raise ValueError(f"unsupported sink check kind: {spec!r}")

        memory_monitors: List[Callable[[angr.SimState], None]] = []
        source_records: List[Dict[str, Any]] = []

        for index, source_spec in enumerate(sources or []):
            kind = source_spec.get("kind")
            source_id = source_spec.get("id", f"source_{index}")
            label = source_spec.get("label")

            if kind == "memory":
                address = _coerce_int(source_spec.get("address"), "address")
                size = int(source_spec.get("size", 1))
                if size <= 0:
                    raise ValueError("memory source size must be positive")
                label = label or f"mem_{address:#x}"
                apply_taint(state, address, taint_id=label, bits=size * 8)

                monitor_writes = bool(source_spec.get("monitor_writes", False))

                if monitor_writes:

                    def _memory_callback(
                        st: angr.SimState,
                        *,
                        base_addr: int = address,
                        span: int = size,
                        tag: str = label,
                    ) -> None:
                        addr_ast = st.inspect.mem_write_address
                        if addr_ast is None:
                            return
                        try:
                            write_addr = int(st.solver.eval(addr_ast))
                        except Exception:  # pylint:disable=broad-except
                            return
                        length_ast = st.inspect.mem_write_length
                        if length_ast is not None:
                            try:
                                write_len = int(st.solver.eval(length_ast))
                            except Exception:  # pylint:disable=broad-except
                                write_len = span
                        else:
                            write_len = span
                        overlap_start = max(write_addr, base_addr)
                        overlap_end = min(write_addr + write_len, base_addr + span)
                        if overlap_start >= overlap_end:
                            return
                        chunk = overlap_end - overlap_start
                        apply_taint(st, overlap_start, taint_id=f"{tag}@{overlap_start:#x}", bits=chunk * 8)

                    memory_monitors.append(_memory_callback)

                source_records.append(
                    {
                        "id": source_id,
                        "kind": "memory",
                        "address": _format_addr(address),
                        "size": size,
                        "label": label,
                        "monitor_writes": monitor_writes,
                    }
                )
                continue

            if kind == "memory_pointer":
                reg_name = source_spec.get("register")
                if reg_name is None:
                    raise ValueError("memory_pointer source requires 'register'")
                range_size = source_spec.get("size")
                explicit_size = int(range_size) if range_size is not None else None
                label = label or f"ptr_{reg_name}"

                def _pointer_callback(
                    st: angr.SimState,
                    *,
                    reg: str = reg_name,
                    span: Optional[int] = explicit_size,
                    tag: str = label,
                ) -> None:
                    addr_ast = st.inspect.mem_write_address
                    if addr_ast is None:
                        return
                    try:
                        write_addr = int(st.solver.eval(addr_ast))
                    except Exception:  # pylint:disable=broad-except
                        return

                    try:
                        ptr_base = int(st.solver.eval(getattr(st.regs, reg)))
                    except Exception:  # pylint:disable=broad-except
                        ptr_base = None
                    if ptr_base is None:
                        return

                    length_ast = st.inspect.mem_write_length
                    if length_ast is not None:
                        try:
                            write_len = int(st.solver.eval(length_ast))
                        except Exception:  # pylint:disable=broad-except
                            write_len = span or 1
                    else:
                        write_len = span or 1
                    if write_len <= 0:
                        write_len = span or 1

                    ptr_span = span or write_len
                    ptr_end = ptr_base + ptr_span
                    overlap_start = max(write_addr, ptr_base)
                    overlap_end = min(write_addr + write_len, ptr_end)

                    if overlap_start >= overlap_end:
                        return

                    chunk = overlap_end - overlap_start
                    apply_taint(st, overlap_start, taint_id=f"{tag}@{overlap_start:#x}", bits=chunk * 8)

                memory_monitors.append(_pointer_callback)
                source_records.append(
                    {
                        "id": source_id,
                        "kind": "memory_pointer",
                        "register": reg_name,
                        "size": explicit_size,
                        "label": label,
                    }
                )
                continue

            if kind == "register":
                reg_name = source_spec.get("name")
                if reg_name is None:
                    raise ValueError("register source requires 'name'")
                reg_meta = state.arch.registers.get(reg_name)
                reg_bits = None
                if reg_meta is not None:
                    reg_bits = int(reg_meta[1]) * 8
                bits = int(source_spec.get("bits", reg_bits or state.arch.bits))
                if bits <= 0:
                    raise ValueError("register source bits must be positive")
                label = label or f"reg_{reg_name}"
                tainted = new_tainted_value(label, bits=bits)
                setattr(state.regs, reg_name, tainted)
                source_records.append(
                    {
                        "id": source_id,
                        "kind": "register",
                        "name": reg_name,
                        "bits": bits,
                        "label": label,
                    }
                )
                continue

            raise ValueError(f"unsupported taint source kind: {kind!r}")

        for callback in memory_monitors:
            tracker.add_callback(callback, "mem_write", angr.BP_AFTER)

        class _TaintSinkMonitor:
            def __init__(
                self,
                specs: Sequence[Dict[str, Any]],
                *,
                tracker_obj: TaintTracker,
                stop_first: bool,
                max_hits_value: Optional[int],
            ) -> None:
                self._tracker = tracker_obj
                self._stop_first = stop_first
                self._max_hits = max_hits_value
                self._address_map: Dict[int, List[Dict[str, Any]]] = {}
                self._sinks: List[Dict[str, Any]] = []
                self.hits: List[Dict[str, Any]] = []
                self._recorded_keys: set[Tuple[str, int, Optional[int]]] = set()

                for idx, spec in enumerate(specs):
                    addr_value = _coerce_int(spec.get("address"), "address")
                    sink_id = spec.get("id", f"sink_{idx}")
                    mode = spec.get("mode", "any").lower()
                    if mode not in {"any", "all"}:
                        raise ValueError(f"unsupported sink mode: {mode}")

                    checks_internal: List[Dict[str, Any]] = []
                    checks_summary: List[Dict[str, Any]] = []
                    for check_spec in spec.get("checks", []):
                        kind = check_spec.get("kind")
                        if kind == "register":
                            entry = {
                                "kind": "register",
                                "name": check_spec["name"],
                            }
                        elif kind == "memory":
                            entry = {
                                "kind": "memory",
                                "address": _coerce_int(check_spec.get("address"), "address"),
                                "size": int(check_spec.get("size", 1)),
                            }
                            if entry["size"] <= 0:
                                raise ValueError("memory sink check size must be positive")
                        elif kind == "pointer":
                            entry = {
                                "kind": "pointer",
                                "register": check_spec["register"],
                                "size": int(check_spec.get("size", 1)),
                            }
                            if entry["size"] <= 0:
                                raise ValueError("pointer sink check size must be positive")
                        else:
                            raise ValueError(f"unsupported sink check kind: {kind!r}")
                        checks_internal.append(entry)
                        checks_summary.append(_sanitize_check(check_spec))

                    entry = {
                        "id": sink_id,
                        "address": addr_value,
                        "address_hex": _format_addr(addr_value),
                        "description": spec.get("description"),
                        "mode": mode,
                        "checks_internal": checks_internal,
                        "checks": checks_summary,
                        "hits": 0,
                    }
                    self._sinks.append(entry)
                    self._address_map.setdefault(addr_value, []).append(entry)

            def register(self) -> None:
                if not self._sinks:
                    return
                self._tracker.add_callback(self._on_block, "irsb", angr.BP_BEFORE)

            def describe(self) -> List[Dict[str, Any]]:
                return [
                    {
                        "id": sink["id"],
                        "address": sink["address_hex"],
                        "description": sink.get("description"),
                        "mode": sink["mode"],
                        "checks": sink["checks"],
                        "hits": sink["hits"],
                    }
                    for sink in self._sinks
                ]

            def process_state(self, state: angr.SimState) -> None:
                for sink in self._matching_sinks(state):
                    self._evaluate_and_record(state, sink)

            def _matching_sinks(self, state: angr.SimState) -> List[Dict[str, Any]]:
                addr_candidates = {int(getattr(state, "addr", 0) or 0)}
                hist_addr = getattr(getattr(state, "history", None), "addr", None)
                if hist_addr is not None:
                    addr_candidates.add(int(hist_addr))

                matching_ids = set()
                for addr in addr_candidates:
                    for sink in self._address_map.get(addr, []):
                        matching_ids.add(id(sink))
                if not matching_ids:
                    return []

                return [sink for sink in self._sinks if id(sink) in matching_ids]

            def _evaluate_check(self, state: angr.SimState, spec: Dict[str, Any]) -> Dict[str, Any]:
                kind = spec["kind"]
                details: Dict[str, Any]
                tainted = False
                if kind == "register":
                    reg_name = spec["name"]
                    value = getattr(state.regs, reg_name)
                    tainted = bool(is_tainted(value, state))
                    details = {"register": reg_name}
                    try:
                        details["value"] = _format_addr(int(state.solver.eval(value)))
                    except Exception:  # pylint:disable=broad-except
                        pass
                elif kind == "memory":
                    address = spec["address"]
                    size = spec["size"]
                    value = state.memory.load(address, size)
                    tainted = bool(is_tainted(value, state))
                    details = {"address": _format_addr(address), "size": size}
                elif kind == "pointer":
                    reg_name = spec["register"]
                    size = spec["size"]
                    ptr = getattr(state.regs, reg_name)
                    details = {"register": reg_name, "size": size}
                    try:
                        ptr_addr = int(state.solver.eval(ptr))
                    except Exception:  # pylint:disable=broad-except
                        ptr_addr = None
                    if ptr_addr is not None:
                        details["deref_address"] = _format_addr(ptr_addr)
                        value = state.memory.load(ptr_addr, size)
                    tainted = bool(is_tainted(value, state))
                else:
                    raise ValueError(f"unsupported sink check kind: {kind!r}")
                return {"kind": kind, "tainted": tainted, "details": details}

            def _on_block(self, state: angr.SimState) -> None:
                for sink in self._matching_sinks(state):
                    self._evaluate_and_record(state, sink)

            def _evaluate_and_record(self, state: angr.SimState, sink: Dict[str, Any]) -> None:
                check_specs = sink["checks_internal"]
                check_results = [self._evaluate_check(state, spec) for spec in check_specs]
                if check_specs:
                    if sink["mode"] == "all":
                        triggered = all(item["tainted"] for item in check_results)
                    else:
                        triggered = any(item["tainted"] for item in check_results)
                else:
                    triggered = True
                if not triggered:
                    return

                state_addr = int(getattr(state, "addr", 0) or 0)
                hist_addr = getattr(getattr(state, "history", None), "addr", None)
                key = (sink["id"], state_addr, int(hist_addr) if hist_addr is not None else None)
                if key in self._recorded_keys:
                    return
                self._recorded_keys.add(key)

                sink["hits"] += 1
                snapshot = state.copy()
                record = {
                    "sink_id": sink["id"],
                    "sink_address": sink["address_hex"],
                    "description": sink.get("description"),
                    "mode": sink["mode"],
                    "checks": check_results,
                    "state_addr": _format_addr(state_addr),
                    "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
                    "state_snapshot": snapshot,
                }
                self.hits.append(record)
                if self._stop_first:
                    self._tracker.stop()
                if self._max_hits is not None and len(self.hits) >= self._max_hits:
                    self._tracker.stop()

        monitor = _TaintSinkMonitor(
            sinks or [],
            tracker_obj=tracker,
            stop_first=stop_on_first_hit,
            max_hits_value=max_sink_hits,
        )
        monitor.register()

        if use_dfs:
            simgr.use_technique(DFS())

        for tech_name in techniques or []:
            technique = self._load_technique(tech_name, project)
            if technique is not None:
                simgr.use_technique(technique)

        simgr.use_technique(tracker)

        budget_limiter: Optional[StateBudgetLimiter] = None
        budget_error: Optional[StateBudgetExceeded] = None
        state_pressure: Optional[Dict[str, Any]] = None
        errors: List[Dict[str, str]] = []

        if state_budget is not None:
            budget_limiter = StateBudgetLimiter(state_budget, stashes=budget_stashes)
            simgr.use_technique(budget_limiter)

        try:
            if max_steps is not None:
                simgr.run(n=max_steps)
            else:
                simgr.run()
        except StateBudgetExceeded as exc:
            budget_error = exc
            errors.append({"type": type(exc).__name__, "message": str(exc)})
        except Exception as exc:  # pylint:disable=broad-except
            errors.append({"type": type(exc).__name__, "message": str(exc)})

        if budget_limiter is not None or budget_error is not None:
            if budget_error is not None:
                counts = dict(budget_error.stash_counts)
                total = budget_error.total
                status = "exceeded"
            else:
                counts = dict(budget_limiter.last_counts)
                total = sum(counts.values())
                status = "ok"
            state_pressure = {
                "status": status,
                "budget": state_budget,
                "total": total,
                "stashes": counts,
            }

        for stash_name in ("active", "deadended", "found", "avoid"):
            for st in getattr(simgr, stash_name, []) or []:
                monitor.process_state(st)
        for err in getattr(simgr, "errored", []) or []:
            monitor.process_state(err.state)

        result = self._collect_run_result(
            project_id,
            simgr_id,
            simgr,
            extra_errors=errors or None,
            state_pressure=state_pressure,
        )

        sink_hits: List[Dict[str, Any]] = []
        for hit in monitor.hits:
            snapshot = hit.pop("state_snapshot")
            snapshot_id = registry.register_state(project_id, snapshot)
            streams = self._dump_streams(snapshot)
            if streams:
                result.streams[snapshot_id] = streams
            alerts = self._run_alert_detectors(ctx, project_id, snapshot_id, snapshot)
            if alerts:
                result.alerts.extend(alerts)
            hit["state_id"] = snapshot_id
            sink_hits.append(hit)

        result.taint_hits = sink_hits

        run_payload = dict(result.__dict__)
        run_payload["taint_hits"] = sink_hits

        taint_summary = {
            "sources": source_records,
            "sinks": monitor.describe(),
            "hits": sink_hits,
        }
        if state_pressure is not None:
            taint_summary["state_pressure"] = state_pressure

        return {"run": run_payload, "taint": taint_summary}

    # ------------------------------------------------------------------
    def monitor_for_vulns(
        self,
        project_id: str,
        state_id: str,
        events: List[str],
    ) -> Dict[str, Any]:
        state = registry.get_state(project_id, state_id)
        monitor = registry.ensure_monitor(project_id, state_id)
        monitor.events.clear()

        def make_callback(event_name: str):
            def _callback(state: angr.SimState) -> None:
                solver = state.solver
                try:
                    ip_value = int(solver.eval(state.regs.ip))
                except Exception:  # pylint:disable=broad-except
                    ip_value = None
                entry = {"event": event_name, "addr": _format_addr(ip_value)}
                if event_name == "mem_write":
                    addr_ast = state.inspect.mem_write_address
                    length_ast = state.inspect.mem_write_length
                    address_value = None
                    if addr_ast is not None:
                        try:
                            address_value = int(solver.eval(addr_ast))
                        except Exception:  # pylint:disable=broad-except
                            address_value = None
                    entry["address"] = _format_addr(address_value)
                    if length_ast is not None:
                        try:
                            entry["length"] = int(solver.eval(length_ast))
                        except Exception:  # pylint:disable=broad-except
                            entry["length"] = None
                registry.record_event(project_id, state_id, entry)

            return _callback

        for event_name in events:
            state.inspect.b(event_name, when=angr.BP_AFTER, action=make_callback(event_name))

        return {"monitored_events": events}

    # ------------------------------------------------------------------
    def list_jobs(self, project_id: str) -> Dict[str, Any]:
        jobs = [self._job_to_dict(job) for job in registry.list_jobs(project_id).values()]
        return {"jobs": jobs}

    # ------------------------------------------------------------------
    def resume_job(self, project_id: str, job_id: str) -> Dict[str, Any]:
        try:
            job_ctx = registry.get_job(project_id, job_id)
        except KeyError:
            job_ctx = self._load_job_from_disk(project_id, job_id)

        return {
            "job": self._job_to_dict(job_ctx),
            "simgr_id": job_ctx.simgr_id,
        }

    # ------------------------------------------------------------------
    def delete_job(self, project_id: str, job_id: str, *, remove_disk: bool = False) -> Dict[str, Any]:
        job_ctx = registry.get_job(project_id, job_id)
        if remove_disk and job_ctx.backing_path:
            path = pathlib.Path(job_ctx.backing_path)
            if path.exists():
                path.unlink()
        registry.delete_job(project_id, job_id)
        return {"deleted": job_id}

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
        include_alerts: bool = False,
        include_globals: bool = False,
        globals_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        state = registry.get_state(project_id, state_id)
        data: Dict[str, Any] = {}

        regs = {}
        for reg_name in registers or []:
            reg_ast = getattr(state.regs, reg_name)
            try:
                if isinstance(reg_ast, claripy.ast.Base):
                    regs[reg_name] = state.solver.eval(reg_ast)
                else:
                    regs[reg_name] = int(reg_ast)
            except Exception:  # pylint:disable=broad-except
                regs[reg_name] = None
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
                    "address": _format_addr(addr),
                    "size": size,
                    "concrete": concrete,
                }
            )
        if mem_dump:
            data["memory"] = mem_dump

        if include_constraints:
            constraints = [str(c) for c in state.solver.constraints]
            data["constraints"] = constraints

        if include_events or include_alerts:
            ctx = registry.get_project(project_id)
            monitor = ctx.monitors.get(state_id)
            if include_events:
                data["events"] = monitor.events if monitor else []
            if include_alerts:
                alerts = monitor.alerts if monitor else []
                data["alerts"] = [self._alert_to_dict(alert) for alert in alerts]

        if include_globals:
            keys = list(globals_keys or state.globals.keys())
            globals_payload: Dict[str, Any] = {}
            for key in keys:
                if key not in state.globals:
                    continue
                value = state.globals[key]
                if key == SYMBOL_STORE_KEY:
                    store = state.globals.get(SYMBOL_STORE_KEY, {})
                    globals_payload[key] = [
                        {"handle": handle, "bits": ast.size()}
                        for handle, ast in store.items()
                    ]
                    continue
                globals_payload[key] = self._serialize_global_value(value)
            if globals_payload:
                data["globals"] = globals_payload

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
                item = {"kind": kind, "address": _format_addr(addr), "size": size}
            elif kind == "register":
                reg = query["name"]
                ast = getattr(state.regs, reg)
                item = {"kind": kind, "name": reg}
            elif kind == "symbol":
                handle = query["handle"]
                ast = self._resolve_symbol_handle(state, handle)
                item = {"kind": kind, "handle": handle, "bits": ast.size()}
            else:
                raise ValueError(f"unsupported query kind: {kind}")

            item["value"] = state.solver.eval(ast)
            if query.get("minmax"):
                item["min"] = state.solver.min(ast)
                item["max"] = state.solver.max(ast)
            if query.get("format") == "bytes" or query.get("include_bytes"):
                try:
                    concrete_bytes = state.solver.eval(ast, cast_to=bytes)
                except Exception:  # pylint:disable=broad-except
                    concrete_bytes = None
                if concrete_bytes is not None:
                    item["bytes_b64"] = base64.b64encode(concrete_bytes).decode("ascii")
            results.append(item)

        return {"results": results}

    # ------------------------------------------------------------------
    def analyze_call_chain(
        self,
        project_id: str,
        *,
        source: Any,
        target: Any,
        max_paths: int = 10,
        max_depth: Optional[int] = None,
        use_fast: bool = True,
        keep_state: bool = True,
    ) -> Dict[str, Any]:
        import networkx as nx  # type: ignore

        ctx = registry.get_project(project_id)
        project = ctx.project
        if max_paths <= 0:
            raise ValueError("max_paths must be positive")
        if max_depth is not None and max_depth <= 0:
            raise ValueError("max_depth must be positive when provided")
        cfg_key = "CFGFast" if use_fast else "CFGEmulated"
        cfg = ctx.cfg_cache.get(cfg_key)
        if cfg is None:
            if use_fast:
                cfg = project.analyses.CFGFast()
            else:
                cfg = project.analyses.CFGEmulated(keep_state=keep_state)
            ctx.cfg_cache[cfg_key] = cfg

        callgraph = cfg.kb.callgraph
        if callgraph is None:
            raise RuntimeError("call graph unavailable even after generating the CFG")

        def resolve(identifier: Any) -> Tuple[int, Any]:
            addr: Optional[int] = None
            name: Optional[str] = None
            if isinstance(identifier, dict):
                if "address" in identifier and identifier["address"] is not None:
                    addr = int(identifier["address"])
                if "name" in identifier and identifier["name"]:
                    name = str(identifier["name"])
                if name is None and "symbol" in identifier and identifier["symbol"]:
                    name = str(identifier["symbol"])
            elif isinstance(identifier, str):
                name = identifier
            else:
                addr = int(identifier)

            func_obj = None
            if addr is not None:
                func_obj = cfg.kb.functions.get(addr) or cfg.kb.functions.function(addr)
            if func_obj is None and name is not None:
                func_obj = cfg.kb.functions.function(name=name)
            if func_obj is None and name is not None:
                symbol = project.loader.find_symbol(name)
                if symbol is not None:
                    addr = symbol.rebased_addr
                    func_obj = cfg.kb.functions.get(addr) or cfg.kb.functions.function(addr)
            if func_obj is None:
                raise ValueError(f"function identifier {identifier!r} not resolved in call graph")
            return func_obj.addr, func_obj

        def summarize(addr: int) -> Dict[str, Any]:
            func = cfg.kb.functions.get(addr)
            summary = {
                "addr": _format_addr(addr),
                "name": func.name if func else f"sub_{addr:x}",
            }
            if func is not None:
                summary["returning"] = func.returning
                summary["has_unresolved_calls"] = func.has_unresolved_calls
                if hasattr(func, "block_addrs_set"):
                    summary["block_count"] = len(func.block_addrs_set)
            return summary

        src_addr, _ = resolve(source)
        dst_addr, _ = resolve(target)

        cutoff = max_depth if max_depth is not None else None
        try:
            path_iter = nx.all_simple_paths(callgraph, src_addr, dst_addr, cutoff=cutoff)
        except nx.NodeNotFound as exc:
            raise ValueError("either source or target not present in call graph") from exc
        raw_paths = list(itertools.islice(path_iter, max_paths + 1))
        has_more = len(raw_paths) > max_paths
        if has_more:
            raw_paths = raw_paths[:max_paths]

        adjacency: Dict[str, set[str]] = {}
        paths_payload: List[Dict[str, Any]] = []
        for path in raw_paths:
            node_entries = [summarize(addr) for addr in path]
            paths_payload.append({
                "length": len(path),
                "nodes": node_entries,
            })
            for head, tail in zip(path, path[1:]):
                adjacency.setdefault(_format_addr(head), set()).add(_format_addr(tail))

        adjacency_payload = {key: sorted(value) for key, value in adjacency.items()}

        return {
            "analysis": cfg_key,
            "source": summarize(src_addr),
            "target": summarize(dst_addr),
            "paths": paths_payload,
            "has_more_paths": has_more,
            "adjacency": adjacency_payload,
            "callgraph_nodes": len(callgraph.nodes()),
            "callgraph_edges": len(callgraph.edges()),
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

        def format_node(node: Any) -> Any:
            if isinstance(node, int):
                return _format_addr(node)
            if hasattr(node, "addr"):
                addr_value = getattr(node, "addr")
                if isinstance(addr_value, int):
                    return _format_addr(addr_value)
            return node

        def format_node_list(nodes: Iterable[Any]) -> List[Any]:
            return [format_node(node) for node in nodes]

        bs = project.analyses.BackwardSlice(
            cfg,
            cdg=cdg,
            ddg=ddg,
            targets=[(node, target_stmt)],
            control_flow_slice=cdg is None and ddg is None,
        )

        result = {
            "runs_in_slice": format_node_list(bs.runs_in_slice.nodes()) if hasattr(bs, "runs_in_slice") else [],
            "cfg_nodes_in_slice": format_node_list(bs.cfg_nodes_in_slice.nodes())
            if hasattr(bs, "cfg_nodes_in_slice") else [], }
        if hasattr(bs, "chosen_statements"):
            result["chosen_statements"] = {
                _format_addr(addr): stmts for addr, stmts in bs.chosen_statements.items()
            }
        if hasattr(bs, "chosen_exits"):
            result["chosen_exits"] = {
                _format_addr(addr): exits for addr, exits in bs.chosen_exits.items()
            }
        return result

    # ------------------------------------------------------------------
    def _collect_run_result(
        self,
        project_id: str,
        simgr_id: str,
        simgr: angr.SimulationManager,
        extra_errors: Optional[List[Dict[str, str]]] = None,
        *,
        state_callbacks: Optional[Sequence[Callable[[angr.SimState, str], None]]] = None,
        state_pressure: Optional[Dict[str, Any]] = None,
    ) -> RunResult:
        ctx = registry.get_project(project_id)
        alert_entries: List[Dict[str, Any]] = []
        callbacks = list(state_callbacks or [])
        streams: Dict[str, Dict[str, str]] = {}

        def register_states(states: Iterable[angr.SimState]) -> List[str]:
            ids = []
            for st in states:
                state_id = registry.register_state(project_id, st)
                ids.append(state_id)
                dump = self._dump_streams(st)
                if dump:
                    streams[state_id] = dump
                alert_entries.extend(self._run_alert_detectors(ctx, project_id, state_id, st))
                for callback in callbacks:
                    callback(st, state_id)
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

        stashes = {
            "active": active_ids,
            "deadended": dead_ids,
            "found": found_ids,
            "avoided": avoid_ids,
            "errored": errored_ids,
        }

        return RunResult(
            simgr_id=simgr_id,
            active=active_ids,
            deadended=dead_ids,
            found=found_ids,
            avoided=avoid_ids,
            errored=errored_ids,
            errors=extra_errors or [],
            alerts=alert_entries,
            stashes=stashes,
            state_pressure=state_pressure,
            streams=streams,
        )

    # ------------------------------------------------------------------
    def _run_alert_detectors(
        self,
        ctx: ProjectContext,
        project_id: str,
        state_id: str,
        state: angr.SimState,
    ) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for record in self._detect_unconstrained_ip(ctx, project_id, state_id, state):
            alerts.append(self._alert_to_dict(record))
        for record in self._detect_suspicious_writes(ctx, project_id, state_id, state):
            alerts.append(self._alert_to_dict(record))
        return alerts

    def _detect_unconstrained_ip(
        self,
        ctx: ProjectContext,
        project_id: str,
        state_id: str,
        state: angr.SimState,
    ) -> List[AlertRecord]:
        try:
            symbolic_ip = state.solver.symbolic(state.regs.ip)
        except Exception:  # pylint:disable=broad-except
            symbolic_ip = False
        if not symbolic_ip:
            return []

        details: Dict[str, Any] = {
            "solver_cardinality": None,
            "samples": [],
            "stack_pointer": None,
        }
        try:
            cardinality = state.solver.cardinality(state.regs.ip)
            details["solver_cardinality"] = None if cardinality is None else int(cardinality)
            if cardinality is not None and cardinality <= 4:
                return []
        except Exception:  # pylint:disable=broad-except
            details["solver_cardinality"] = None

        try:
            details["samples"] = [int(val) for val in state.solver.eval_upto(state.regs.ip, 3)]
        except Exception:  # pylint:disable=broad-except
            details["samples"] = []

        try:
            details["stack_pointer"] = int(state.solver.eval(state.regs.sp))
        except Exception:  # pylint:disable=broad-except
            details["stack_pointer"] = None

        try:
            address_value = int(state.solver.eval(state.regs.ip))
        except Exception:  # pylint:disable=broad-except
            address_value = None

        details["constraint_count"] = len(getattr(state.solver, "constraints", []))
        record = registry.record_alert(
            project_id,
            state_id,
            "unconstrained_ip",
            address=address_value,
            details=details,
        )
        return [record]

    def _detect_suspicious_writes(
        self,
        ctx: ProjectContext,
        project_id: str,
        state_id: str,
        state: angr.SimState,
    ) -> List[AlertRecord]:
        alerts: List[AlertRecord] = []
        recent_actions = []
        try:
            recent_actions = list(getattr(state.history, "recent_actions", []) or [])
        except Exception:  # pylint:disable=broad-except
            recent_actions = []

        if not recent_actions:
            recent_actions = list(getattr(state.globals, "get", lambda *_: [])("_mcp_recent_actions", []))

        if not recent_actions:
            return alerts

        sp_value: Optional[int]
        try:
            sp_value = int(state.solver.eval(state.regs.sp))
        except Exception:  # pylint:disable=broad-except
            sp_value = None

        sensitive_ranges = self._sensitive_memory_ranges(ctx)

        for action in recent_actions:
            action_type = getattr(action, "type", None)
            action_kind = getattr(action, "action", None)
            if action_type != "mem" or action_kind != "write":
                continue

            addr_ast = getattr(action, "addr", None)
            length = getattr(action, "size", None)
            try:
                address = int(state.solver.eval(addr_ast)) if addr_ast is not None else None
            except Exception:  # pylint:disable=broad-except
                address = None

            if address is None:
                continue

            stack_hit = False
            if sp_value is not None:
                stack_hit = sp_value - 0x40 <= address <= sp_value + 0x100

            segment_hit = None
            for seg_name, start, end in sensitive_ranges:
                if start <= address <= end:
                    segment_hit = seg_name
                    break

            if not stack_hit and segment_hit is None:
                continue

            try:
                length_value = int(state.solver.eval(length)) if length is not None else None
            except Exception:  # pylint:disable=broad-except
                length_value = None

            data_ast = getattr(action, "data", None)
            try:
                symbolic_data = bool(data_ast is not None and state.solver.symbolic(data_ast))
            except Exception:  # pylint:disable=broad-except
                symbolic_data = False

            details = {
                "stack_hit": stack_hit,
                "segment": segment_hit,
                "length": length_value,
                "symbolic_data": symbolic_data,
            }
            alerts.append(
                registry.record_alert(
                    project_id,
                    state_id,
                    "mem_write",
                    address=address,
                    details=details,
                )
            )

        return alerts

    def _sensitive_memory_ranges(self, ctx: ProjectContext) -> List[tuple[str, int, int]]:
        cached = ctx.metadata.get("_mcp_sensitive_ranges")
        if cached:
            return list(cached)

        ranges: List[tuple[str, int, int]] = []
        loader = ctx.project.loader
        for obj in loader.all_objects:
            for section in getattr(obj, "sections", []):
                name = getattr(section, "name", "")
                if not name:
                    continue
                lowered = name.lower()
                if "got" in lowered or "plt" in lowered:
                    start = getattr(section, "min_addr", None)
                    end = getattr(section, "max_addr", None)
                    if start is not None and end is not None:
                        ranges.append((name, int(start), int(end)))
        ctx.metadata["_mcp_sensitive_ranges"] = list(ranges)
        return ranges

    @staticmethod
    def _alert_to_dict(alert: AlertRecord) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "alert_id": alert.alert_id,
            "state_id": alert.state_id,
            "type": alert.type,
            "timestamp": alert.timestamp,
        }
        if alert.address is not None:
            data["address"] = _format_addr(alert.address)
        if alert.details:
            details = dict(alert.details)
            if "stack_pointer" in details and details["stack_pointer"] is not None:
                details["stack_pointer"] = _format_addr(int(details["stack_pointer"]))
            if "samples" in details and isinstance(details["samples"], list):
                details["samples"] = [
                    _format_addr(int(sample)) if sample is not None else None
                    for sample in details["samples"]
                ]
            data["details"] = details
        return data

    # ------------------------------------------------------------------
    def _persist_job(
        self,
        project_id: str,
        job_ctx: JobContext,
        stash_map: Dict[str, List[str]],
    ) -> None:
        storage_dir = self._job_storage_dir()
        storage_dir.mkdir(exist_ok=True)
        path = storage_dir / f"{job_ctx.job_id}.json"

        state_blobs: Dict[str, str] = {}
        for state_id in sorted({sid for sids in stash_map.values() for sid in sids}):
            try:
                state = registry.get_state(project_id, state_id)
            except KeyError:
                continue
            try:
                blob = pickle.dumps(state, protocol=pickle.HIGHEST_PROTOCOL)
                state_blobs[state_id] = base64.b64encode(blob).decode("ascii")
            except Exception:  # pylint:disable=broad-except
                continue

        ctx = registry.get_project(project_id)
        job_ctx.metadata.setdefault("persisted", True)

        payload = {
            "job_id": job_ctx.job_id,
            "project_id": project_id,
            "created_at": job_ctx.created_at,
            "updated_at": job_ctx.updated_at,
            "metadata": job_ctx.metadata,
            "stashes": stash_map,
            "states": state_blobs,
            "project": ctx.metadata,
            "persisted_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "format": "angr-mcp-job-v1",
        }

        with path.open("w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2)

        registry.update_job(project_id, job_ctx.job_id, backing_path=str(path))

    def _load_job_from_disk(self, project_id: str, job_id: str) -> JobContext:
        path = self._job_storage_dir() / f"{job_id}.json"
        if not path.exists():
            raise KeyError(f"persisted job {job_id} not found on disk")

        with path.open("r", encoding="utf-8") as fp:
            payload = json.load(fp)

        stash_map: Dict[str, List[str]] = {
            k: list(v) for k, v in (payload.get("stashes") or {}).items()
        }
        state_records: Dict[str, angr.SimState] = {}
        ctx = registry.get_project(project_id)
        for state_id, encoded in (payload.get("states") or {}).items():
            try:
                state = pickle.loads(base64.b64decode(encoded))
                state.project = ctx.project
                state_records[state_id] = state
                registry.register_state(project_id, state, state_id=state_id)
            except Exception:  # pylint:disable=broad-except
                continue

        active_states = [state_records[sid] for sid in stash_map.get("active", []) if sid in state_records]
        simgr = angr.SimulationManager(ctx.project, active_states=active_states)
        for stash_name, ids in stash_map.items():
            if stash_name == "active":
                continue
            states = [state_records[sid] for sid in ids if sid in state_records]
            if not states:
                continue
            simgr._store_states(stash_name, states)

        simgr_id = registry.register_simmanager(project_id, simgr)
        job_ctx = registry.register_job(
            project_id,
            simgr_id,
            state_ids=list(state_records.keys()),
            metadata=payload.get("metadata", {}),
            job_id=job_id,
            backing_path=str(path),
        )
        job_ctx.created_at = payload.get("created_at", job_ctx.created_at)
        job_ctx.updated_at = payload.get("updated_at", job_ctx.updated_at)
        job_ctx.metadata.setdefault("persisted", True)
        job_ctx.metadata.setdefault("stashes", stash_map)
        return job_ctx

    @staticmethod
    def _job_storage_dir() -> pathlib.Path:
        return pathlib.Path(".mcp_jobs")

    @staticmethod
    def _job_to_dict(job: JobContext) -> Dict[str, Any]:
        return {
            "job_id": job.job_id,
            "simgr_id": job.simgr_id,
            "project_id": job.project_id,
            "state_ids": list(job.state_ids),
            "metadata": job.metadata,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
            "backing_path": job.backing_path,
        }

    @staticmethod
    def _find_job_by_simgr(project_id: str, simgr_id: str) -> Optional[JobContext]:
        for job in registry.list_jobs(project_id).values():
            if job.simgr_id == simgr_id:
                return job
        return None

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

    def _instantiate_simprocedure(
        self,
        spec: Any,
        *,
        args: Optional[Iterable[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> Tuple[angr.SimProcedure, str]:
        args_list = list(args or [])
        kwargs_dict = dict(kwargs or {})

        if isinstance(spec, str):
            sim_cls = self._resolve_simprocedure(spec)
            instance = sim_cls(*args_list, **kwargs_dict)
            return instance, f"simprocedure:{spec}"

        if isinstance(spec, type) and issubclass(spec, angr.SimProcedure):
            instance = spec(*args_list, **kwargs_dict)
            return instance, f"simprocedure:{spec.__name__}"

        if isinstance(spec, angr.SimProcedure):
            return spec, f"simprocedure:{spec.display_name or type(spec).__name__}"

        raise TypeError(f"unsupported simprocedure specification: {spec!r}")

    def _load_technique(self, name: str, project: angr.Project):
        name = name.lower()
        if name in self._technique_cache:
            factory = self._technique_cache[name]
            return factory()

        if name == "veritesting":
            try:
                from angr.exploration_techniques.veritesting import Veritesting
            except ImportError as exc:  # pylint:disable=broad-except
                raise ImportError("veritesting technique unavailable") from exc

            self._technique_cache[name] = Veritesting
            return Veritesting()

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

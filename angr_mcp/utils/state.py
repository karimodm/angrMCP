"""Helpers for consistent state mutations across handlers and tests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

import claripy

# Key used to persist symbolic handles inside angr state.globals.
SYMBOL_STORE_KEY = "_mcp_symbolic_handles"


def _ensure_symbol_store(state: Any) -> Dict[str, claripy.ast.Base]:
    store = state.globals.get(SYMBOL_STORE_KEY)
    if store is None:
        store = {}
        state.globals[SYMBOL_STORE_KEY] = store
    return store


@dataclass
class StackMutationResult:
    """Summary describing a single stack mutation."""

    op: str
    stack_pointer: Optional[int] = None
    handle: Optional[str] = None
    bits: Optional[int] = None
    value: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"op": self.op}
        if self.stack_pointer is not None:
            data["stack_pointer"] = self.stack_pointer
        if self.handle is not None:
            data["handle"] = self.handle
        if self.bits is not None:
            data["bits"] = self.bits
        if self.value is not None:
            data["value"] = self.value
        return data


@dataclass
class StateMutationResult:
    """Aggregate summary for state mutations."""

    registers: List[Dict[str, Any]] = field(default_factory=list)
    stack: List[StackMutationResult] = field(default_factory=list)
    options_added: List[str] = field(default_factory=list)
    options_removed: List[str] = field(default_factory=list)
    memory: List[Dict[str, Any]] = field(default_factory=list)

    def add_register(self, entry: Dict[str, Any]) -> None:
        self.registers.append(entry)

    def add_stack_entry(self, entry: StackMutationResult) -> None:
        self.stack.append(entry)

    def add_memory_entry(self, entry: Dict[str, Any]) -> None:
        self.memory.append(entry)

    def add_options(self, added: Iterable[str] = (), removed: Iterable[str] = ()) -> None:
        self.options_added.extend(list(added))
        self.options_removed.extend(list(removed))

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        if self.registers:
            data["registers"] = list(self.registers)
        if self.stack:
            data["stack"] = [entry.as_dict() for entry in self.stack]
        if self.memory:
            data["memory"] = list(self.memory)
        if self.options_added or self.options_removed:
            data["options"] = {
                "added": list(self.options_added),
                "removed": list(self.options_removed),
            }
        return data


def new_symbolic_bitvector(
    state: Any,
    label: str,
    bits: int,
    *,
    handle_prefix: str = "sym",
) -> tuple[claripy.ast.BV, Dict[str, Any]]:
    """Create a symbolic bitvector and register it under a unique handle."""

    if bits <= 0 or bits % 8 != 0:
        raise ValueError("symbolic bitvector size must be positive and byte aligned")

    symbol = claripy.BVS(label, bits)
    handle = f"{handle_prefix}_{uuid.uuid4().hex}"
    store = _ensure_symbol_store(state)
    store[handle] = symbol

    metadata = {
        "handle": handle,
        "label": label,
        "bits": bits,
    }
    return symbol, metadata


def mutate_registers(
    state: Any,
    specs: Iterable[Dict[str, Any]],
    *,
    result: Optional[StateMutationResult] = None,
) -> StateMutationResult:
    """Apply register mutations to a state and record the resulting metadata."""

    result = result or StateMutationResult()
    arch_bits = state.arch.bits
    arch_bytes = state.arch.bytes

    for spec in specs:
        reg_name = spec["name"]
        entry: Dict[str, Any] = {"register": reg_name}

        if "copy_from" in spec:
            source = spec["copy_from"]
            setattr(state.regs, reg_name, getattr(state.regs, source))
            entry["copied_from"] = source
        elif "value" in spec:
            value = int(spec["value"])
            size_bits = int(spec.get("bits", arch_bits))
            bv = claripy.BVV(value, size_bits)
            setattr(state.regs, reg_name, bv)
            entry["value"] = value
            entry["bits"] = size_bits
        elif "symbolic" in spec:
            sym_spec = dict(spec["symbolic"])
            label = sym_spec.get("label", reg_name)
            bits = int(sym_spec.get("bits", arch_bits))
            symbol, metadata = new_symbolic_bitvector(state, label, bits)
            setattr(state.regs, reg_name, symbol)
            entry.update(metadata)
        else:
            raise ValueError(f"unsupported register mutation: {spec!r}")

        try:
            concrete = int(state.solver.eval(getattr(state.regs, reg_name)))
            entry["concrete"] = concrete
        except Exception:  # pylint:disable=broad-except
            entry["concrete"] = None

        entry.setdefault("bits", arch_bytes * 8)
        result.add_register(entry)

    return result


def mutate_stack(
    state: Any,
    operations: Iterable[Dict[str, Any]],
    *,
    result: Optional[StateMutationResult] = None,
) -> StateMutationResult:
    """Apply stack operations (adjust/push) to a state, returning metadata."""

    result = result or StateMutationResult()
    arch_bits = state.arch.bits

    for op in operations:
        action = op.get("op")
        if action == "adjust":
            delta = int(op.get("delta", 0))
            state.regs.sp = state.regs.sp + delta
            try:
                sp_val = int(state.solver.eval(state.regs.sp))
            except Exception:  # pylint:disable=broad-except
                sp_val = None
            result.add_stack_entry(StackMutationResult(op=action, stack_pointer=sp_val, value=delta))
            continue

        if action == "push":
            source = op.get("source", {})
            width_bits = int(source.get("bits", arch_bits))

            if "value" in source:
                value = int(source["value"])
                bv = claripy.BVV(value, width_bits)
                state.stack_push(bv)
                sp_val = int(state.solver.eval(state.regs.sp))
                result.add_stack_entry(
                    StackMutationResult(
                        op=action,
                        stack_pointer=sp_val,
                        value=value,
                        bits=width_bits,
                    )
                )
            elif "symbolic" in source:
                sym_spec = dict(source["symbolic"])
                label = sym_spec.get("label", "stack_symbol")
                bits = int(sym_spec.get("bits", width_bits))
                symbol, metadata = new_symbolic_bitvector(state, label, bits)
                state.stack_push(symbol)
                sp_val = int(state.solver.eval(state.regs.sp))
                result.add_stack_entry(
                    StackMutationResult(
                        op=action,
                        stack_pointer=sp_val,
                        handle=metadata["handle"],
                        bits=bits,
                    )
                )
            else:
                raise ValueError(f"unsupported stack push source: {source!r}")
            continue

        raise ValueError(f"unsupported stack operation: {action!r}")

    return result

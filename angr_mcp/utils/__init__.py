"""Utility helpers for higher-level MCP workflows."""

from .binary import (
    extract_uppercase_tokens,
    find_call_to_symbol,
    find_literal_addresses,
    find_string_reference_addresses,
    read_c_string,
    read_section_bytes,
)
from .exploration import StateBudgetExceeded, StateBudgetLimiter
from .state import (
    SYMBOL_STORE_KEY,
    StackMutationResult,
    StateMutationResult,
    mutate_registers,
    mutate_stack,
    new_symbolic_bitvector,
)

__all__ = [
    "extract_uppercase_tokens",
    "find_call_to_symbol",
    "find_literal_addresses",
    "find_string_reference_addresses",
    "read_c_string",
    "read_section_bytes",
    "StateBudgetExceeded",
    "StateBudgetLimiter",
    "mutate_registers",
    "mutate_stack",
    "new_symbolic_bitvector",
    "StackMutationResult",
    "StateMutationResult",
    "SYMBOL_STORE_KEY",
]

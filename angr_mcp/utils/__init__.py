"""Utility helpers for higher-level MCP workflows."""

from .binary import (
    extract_uppercase_tokens,
    find_literal_addresses,
    find_string_reference_addresses,
    read_section_bytes,
)
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
    "find_literal_addresses",
    "find_string_reference_addresses",
    "read_section_bytes",
    "mutate_registers",
    "mutate_stack",
    "new_symbolic_bitvector",
    "StackMutationResult",
    "StateMutationResult",
    "SYMBOL_STORE_KEY",
]

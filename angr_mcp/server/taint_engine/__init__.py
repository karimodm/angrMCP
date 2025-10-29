"""Wrapper exports for the angr taint engine."""

from . import defines
from .taint_tracking import (
    TaintTracker,
    add_taint_glob_dep,
    apply_taint,
    is_or_points_to_tainted_data,
    is_tainted,
    new_tainted_page,
    new_tainted_value,
    remove_taint,
)

__all__ = [
    "TaintTracker",
    "add_taint_glob_dep",
    "apply_taint",
    "is_tainted",
    "is_or_points_to_tainted_data",
    "new_tainted_page",
    "new_tainted_value",
    "remove_taint",
    "defines",
]

"""Binary analysis helpers shared across MCP workflows and tests."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, List, Optional, Sequence, Tuple

import angr

try:
    from capstone import CS_OP_IMM
except Exception:  # pylint:disable=broad-except
    CS_OP_IMM = 1  # Fall back to default value used by Capstone


SectionBytes = Tuple[int, bytes]


def read_section_bytes(project: angr.Project, section_name: str) -> SectionBytes:
    """Return the start address and bytes for a named section."""

    main_obj = project.loader.main_object
    section = None
    for candidate in getattr(main_obj, "sections", []):
        if getattr(candidate, "name", None) == section_name:
            section = candidate
            break

    if section is None:
        raise ValueError(f"section {section_name!r} not present in binary")

    base_addr = int(getattr(section, "vaddr", None) or getattr(section, "min_addr", 0))
    size = int(getattr(section, "memsize", None) or getattr(section, "filesize", 0))
    if size <= 0:
        raise ValueError(f"section {section_name!r} has no data to read")

    memory = project.loader.memory
    raw = memory.load(base_addr, size)
    if isinstance(raw, bytes):
        data = raw
    elif isinstance(raw, bytearray):
        data = bytes(raw)
    else:
        data = bytes(raw)  # cle may return an array-like object
    return base_addr, data


def extract_uppercase_tokens(
    project: angr.Project,
    *,
    min_length: int = 4,
    max_length: int = 64,
    exact_length: Optional[int] = None,
    section: str = ".rodata",
) -> List[Tuple[str, int]]:
    """Scan a read-only data section for uppercase ASCII tokens."""

    base, data = read_section_bytes(project, section)
    tokens: List[Tuple[str, int]] = []

    if exact_length is not None:
        pattern = re.compile(rb"[A-Z]{%d}" % exact_length)
    else:
        pattern = re.compile(rb"[A-Z]{%d,%d}" % (min_length, max_length))

    for match in pattern.finditer(data):
        token = match.group()
        if exact_length is not None and len(token) != exact_length:
            continue
        if len(token) < min_length or len(token) > max_length:
            continue
        tokens.append((token.decode("ascii"), base + match.start()))

    return tokens


def find_literal_addresses(
    project: angr.Project,
    literal: Sequence[int] | bytes | str,
    *,
    sections: Iterable[str] = (".rodata", ".data", ".data.rel.ro"),
) -> List[int]:
    """Locate literal occurrences in the given sections."""

    if isinstance(literal, str):
        needle = literal.encode("utf-8")
    elif isinstance(literal, bytes):
        needle = literal
    else:
        needle = bytes(literal)

    addresses: List[int] = []
    for section in sections:
        try:
            base, data = read_section_bytes(project, section)
        except ValueError:
            continue

        start = 0
        while True:
            idx = data.find(needle, start)
            if idx == -1:
                break
            addresses.append(base + idx)
            start = idx + 1

    return sorted(set(addresses))


def find_string_reference_addresses(
    project: angr.Project,
    literal: str | bytes,
    *,
    cfg: Optional[angr.analyses.analysis.Analysis] = None,
) -> List[int]:
    """Return code addresses referencing the provided literal via immediates."""

    literal_addresses = find_literal_addresses(project, literal)
    if not literal_addresses:
        return []

    analysis = cfg or _build_cfg(project)
    matches: List[int] = []

    for node in analysis.graph.nodes():
        addr = getattr(node, "addr", None)
        size = getattr(node, "size", None)
        if addr is None:
            continue

        block = project.factory.block(addr, size=size)
        capstone_block = getattr(block, "capstone", None)
        if capstone_block is None:
            continue

        for insn in capstone_block.insns:
            operands = getattr(insn, "operands", [])
            for op in operands:
                if getattr(op, "type", None) != CS_OP_IMM:
                    continue
                if int(getattr(op, "imm", 0)) in literal_addresses:
                    matches.append(insn.address)
                    break

    return sorted(set(matches))


@lru_cache(maxsize=16)
def _build_cfg(project: angr.Project) -> angr.analyses.analysis.Analysis:
    """Construct and memoise a fast CFG for literal search helpers."""
    return project.analyses.CFGFast()

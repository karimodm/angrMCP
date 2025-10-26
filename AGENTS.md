# Agent Operations Guide

This document records the workflow followed so far, key decisions, and rules
for future human or agent contributors working on the angr MCP server project.

## Environment & Tooling

- **Python**: 3.13 (system interpreter). A dedicated virtual environment is
  created via `uv venv .venv`. Keep `UV_CACHE_DIR=.uv-cache` to store build
  artifacts locally.
- **Dependencies**: install `claripy` and `angr` from PyPI inside the virtual
  environment (`uv pip install --python .venv/bin/python claripy angr`).
- **Testing**: run `.venv/bin/python -m unittest discover tests` to cover both
  the synthetic sample binary suite and the angr CTF Phase 1 regressions.
- **Binary samples**: Phase 1 tests rely on bundled 32-bit angr CTF binaries.
  Native replay assertions will skip automatically if `/lib/ld-linux.so.2`
  (or equivalent) is unavailable. The legacy sample binary still compiles on
  the fly and therefore continues to require a working C compiler (`cc` or
  `gcc`).

## Repository Layout Snapshot

- `angr_mcp/` – MCP server implementation and runtime registry.
- `resources/` – Bundled reference material and companion codebases:
  - `resources/angr` – Upstream angr source tree (currently unused for installs;
    PyPI packages are consumed instead).
  - `resources/awesome-angr` – Community exploration techniques dynamically
    imported by the server when requested.
  - `resources/angr_ctf` – Capture-the-flag training levels and build scripts
    for learning angr-based symbolic exploitation (MetaCTF workshop content).
  - `resources/dAngr` – dAngr examples and docs for additional exploration
    strategies.
  - `resources/GhidraMCP` – Shared assets for coordinating workflows with the
    Ghidra MCP server.
- `angr_mcp/utils/` – Shared binary-inspection and state-mutation helpers used
  by handlers and tests.
- `tests/test_mcp_server.py` – Integration tests; doubles as executable examples
  for the handler workflow.
- `tests/test_phase1_ctf.py` – Automates angr CTF levels 00–04 through MCP
  handlers, asserting predicate metadata, register/stack tooling, and native
  replay.
- `tests/test_deep_call_partition.py` – Builds a deeply nested binary and
  exercises call-chain recovery, state-budget limits, and chunked symbolic
  execution to reach a buried function.
- `pyproject.toml` – Minimal configuration for `uv` environment management.

## Implemented Workflow (Session Summary)

1. Explored bundled angr documentation and `resources/awesome-angr` techniques to scope key
   capabilities for MCP exposure.
2. Implemented the MCP server core:
   - Registry tracking projects, states, simulation managers, hooks, monitors.
   - Handlers covering project load, state creation, instrumentation, symbolic
     execution, monitoring, inspection, constraint solving, CFG, and slicing.
   - Dynamic loading of exploration techniques with resilient error handling.
3. Added error-tolerant execution (capturing exceptions and returning them in
   handler responses) and stash-safe state collection.
4. Implemented structured alerting for unconstrained instruction pointers and
   suspicious memory writes; alerts accumulate per state and surface in run
   results and inspections.
5. Introduced job persistence: `run_symbolic_search` now issues job handles,
   jobs can be listed/resumed/deleted, and persisted snapshots live under
   `.mcp_jobs/`.
6. Authored JSON Schemas for every handler request/response in `schemas/` to
   aid downstream validation.
7. Wrote integration tests compiling a sample binary that requires discovering
   the string “AB” to reach a `win` function; tests cover hooking, exploration,
   constraint solving, monitoring, alerts, job persistence, CFG, and slicing.
8. Provisioned a `uv`-managed virtual environment and documented setup in the
   README.
9. Implemented predicate descriptors (`address`, `stdout_contains`,
   `stdout_not_contains`) with recorded match metadata and stream capture in
   `run_symbolic_search`.
10. Added structured state-mutation helpers (register injection, stack
    adjustments, solver-option presets) plus the public `mutate_state` handler
    and symbolic handle tracking for constraint queries.
11. Created binary-analysis utilities (`angr_mcp/utils`) powering `.rodata`
    scans and literal cross-referencing used by Phase 1 automation.
12. Authored Phase 1 angr CTF regression tests validating levels 00–04 via the
    MCP tooling and confirming native execution of recovered inputs.
13. Added `analyze_call_chain`, caching CFG results to surface caller→callee
    paths so assistants can plan deep explorations without recomputing graph
    analyses.
14. Introduced a `state_budget` guard in `run_symbolic_search`; the handler now
    reports per-stash state pressure and interrupts runs when limits are
    exceeded so clients can shrink their search windows.
15. Landed the deep-call regression (`tests/test_deep_call_partition.py`) that
    compiles a wide branch tree and demonstrates chunked exploration via the
    new call-chain handler and state-budget feedback.

## Collaboration Rules

- **Documentation**: Update `README.md` and `AGENTS.md` whenever workflows or
  capabilities change. These are the authoritative status records.
- **Testing**: Run the unittest suite after meaningful code changes; document
  any failures or intentionally skipped cases.
- **Edits**: Prefer `apply_patch` for manual modifications. Do not run
  destructive git commands (e.g., `git reset --hard`) unless explicitly
  requested by the maintainer.
- **Hooks & Techniques**: When adding new exploration techniques or hooks,
  ensure file paths are accurate and handle missing files gracefully, as the
  current implementation does.
- **Error Handling**: If a handler catches an exception, report it in the
  response rather than exiting early; maintain existing patterns.
- **New Features**: Before adding functionality, outline the plan (use
  `update_plan`) and ensure tests and documentation reflect the change.

## Open Opportunities

- Expand monitoring hooks to automatically flag patterns like unconstrained
  stack pivots or self-modifying code.
- Support long-running background analyses with resumable job IDs executed in
  the background and polled via metadata.
- Automate JSON Schema generation from source annotations and enforce
  validation in CI once `jsonschema` is bundled.
- Enhance tests with multiple architectures and binaries once additional
  dependencies are in place.

Keep this guide synchronized with actual project state after each session so
future agents can resume work without rediscovering context.

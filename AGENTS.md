# Agent Operations Guide

This document records the workflow followed so far, key decisions, and rules
for future human or agent contributors working on the angr MCP server project.

## Environment & Tooling

- **Python**: 3.13 (system interpreter). A dedicated virtual environment is
  created via `uv venv .venv`. Keep `UV_CACHE_DIR=.uv-cache` to store build
  artifacts locally.
- **Dependencies**: install `claripy` and `angr` from PyPI inside the virtual
  environment (`uv pip install --python .venv/bin/python claripy angr`).
- **Testing**: run `.venv/bin/python -m unittest tests.test_mcp_server`.
- **Binary samples**: tests compile a tiny C program on the fly; a working C
  compiler (`cc` or `gcc`) must be available.

## Repository Layout Snapshot

- `angr_mcp/` – MCP server implementation and runtime registry.
- `awesome-angr/` – Community exploration techniques dynamically imported by
  the server when requested.
- `angr/` – Upstream angr source tree (currently unused for installs; PyPI
  packages are consumed instead).
- `tests/test_mcp_server.py` – Integration tests; doubles as executable
  examples for the handler workflow.
- `pyproject.toml` – Minimal configuration for `uv` environment management.

## Implemented Workflow (Session Summary)

1. Explored bundled angr documentation and awesome-angr resources to scope key
   capabilities for MCP exposure.
2. Implemented the MCP server core:
   - Registry tracking projects, states, simulation managers, hooks, monitors.
   - Handlers covering project load, state creation, instrumentation, symbolic
     execution, monitoring, inspection, constraint solving, CFG, and slicing.
   - Dynamic loading of exploration techniques with resilient error handling.
3. Added error-tolerant execution (capturing exceptions and returning them in
   handler responses) and stash-safe state collection.
4. Wrote integration tests compiling a sample binary that requires discovering
   the string “AB” to reach a `win` function; tests cover hooking, exploration,
   constraint solving, monitoring, CFG, and slicing.
5. Provisioned a `uv`-managed virtual environment and documented setup in the
   README.

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
  instruction pointers or suspect stack writes.
- Provide structured schemas for handler inputs/outputs to aid client
  integration.
- Support long-running background analyses with resumable job IDs.
- Enhance tests with multiple architectures and binaries once additional
  dependencies are in place.

Keep this guide synchronized with actual project state after each session so
future agents can resume work without rediscovering context.


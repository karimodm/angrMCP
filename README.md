# angr-mcp MCP Server

This project implements a Model Context Protocol (MCP) server that exposes
core angr binary-analysis capabilities—loading binaries, constructing symbolic
states, steering execution, and harvesting exploit artifacts—through a set of
tool handlers. The initial focus is rapid vulnerability exploration: analysts
can load a target, make its inputs symbolic, drive execution toward interesting
addresses, and extract concrete witness inputs once a path of interest is
found.

## Current Components

- `angr_mcp/registry.py` – In-memory registry tracking angr projects, states,
  simulation managers, hooks, cached analyses, and event logs.
- `angr_mcp/server.py` – The MCP server entry point. It implements handlers for
  project loading, symbolic-state creation, environment instrumentation
  (hooks and SimProcedures), symbolic execution, breakpoint-style monitoring,
  state inspection, constraint solving, CFG recovery, and backward slicing. It
  also integrates community exploration techniques shipped in
  `awesome-angr/ExplorationTechniques`.
- `tests/test_mcp_server.py` – Integration tests that compile a small C binary
  and exercise the server end-to-end (load project, set symbolic stdin, run a
  targeted search, solve constraints, capture monitored events, and perform
  CFG/slice queries).
- `pyproject.toml` – Minimal configuration enabling `uv` to manage a local
  virtual environment.

## Environment Setup

1. Create and activate the virtual environment with `uv`:

   ```bash
   UV_CACHE_DIR=.uv-cache uv venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies into the environment (angr and claripy are pulled from
   PyPI):

   ```bash
   UV_CACHE_DIR=.uv-cache uv pip install --python .venv/bin/python claripy angr
   ```

3. Run the integration tests:

   ```bash
   .venv/bin/python -m unittest tests.test_mcp_server
   ```

## Usage Overview

Instantiate `AngrMCPServer` and call the handlers programmatically or via your
MCP transport:

1. `load_project` – load the binary and receive a `project_id`.
2. `setup_symbolic_context` – create entry/call/blank/full-init states with
   optional symbolic stdin/memory/registers (state IDs are tracked in the
   registry).
3. `instrument_environment` – install SimProcedures or custom hooks on
   addresses/symbols before execution.
4. `run_symbolic_search` – step or explore states, optionally attaching
   exploration techniques for coverage, loop exhaustion, etc. The handler
   returns new state IDs per stash and records execution errors without
   raising.
5. `monitor_for_vulns` – register inspection breakpoints (e.g., `mem_write`)
   so exploit-relevant actions are recorded.
6. `inspect_state` – fetch registers, memory, constraint sets, and recorded
   events for any stored state.
7. `solve_constraints` – query Claripy for concrete inputs/ranges from the
   current constraints.
8. `analyze_control_flow` and `trace_dataflow` – generate CFGs and backward
   slices to guide further exploration.

## Current Status (October 25, 2025)

- Core MCP plumbing is in place with registry-backed state tracking and
  resilient execution (errors are captured and returned to clients).
- Basic exploration techniques from the `awesome-angr` bundle are dynamically
  loadable.
- Symbolic stdin setup now initializes the default `SimPacketsStream` content
  in-place to avoid compat issues with angr’s POSIX plugin.
- Integration tests validate the exploit-oriented workflow end to end.

## Planned Next Steps

- Expand monitoring primitives to automatically flag conditions like
  unconstrained instruction pointers or suspicious memory writes and return
  structured alerts.
- Support persisted job handles so long-running analyses can continue across
  MCP sessions.
- Surface richer metadata (e.g., recorded hooks, cached analyses) through
  dedicated query endpoints to assist front-ends.
- Document the tool schemas formally (JSON schema) for downstream MCP clients.

## Contributing Notes for Agents and Humans

- Use `uv` for package management; keep the `.venv` environment in sync with
  `README` instructions.
- Keep documentation (this file and `AGENTS.md`) updated with each change so
  future sessions understand the current context, constraints, and open items.
- Prefer `apply_patch` for manual edits. Avoid destructive git commands unless
  explicitly approved.


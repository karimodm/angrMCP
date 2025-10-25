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
  simulation managers, hooks, cached analyses, alert logs, and persisted job
  metadata.
- `angr_mcp/server.py` – The MCP server entry point. It implements handlers for
  project loading, symbolic-state creation, environment instrumentation
  (hooks and SimProcedures), symbolic execution, breakpoint-style monitoring,
  state inspection, structured alert reporting, job persistence/management,
  constraint solving, CFG recovery, and backward slicing. It also integrates
  community exploration techniques shipped in
  `awesome-angr/ExplorationTechniques`.
- `angr_mcp/utils/` – Binary-inspection and state-mutation helpers shared by
  the MCP handlers and tests (section scanners, literal cross-referencing,
  register/stack mutation primitives, and symbolic-handle registration).
- `tests/test_mcp_server.py` – Integration tests that compile a small C binary
  and exercise the server end-to-end (load project, set symbolic stdin, run a
  targeted search, solve constraints, capture monitored events, and perform
  CFG/slice queries).
- `tests/test_phase1_ctf.py` – Phase 1 regression suite recreating angr CTF
  levels 00–04 exclusively through MCP handlers, asserting predicate metadata,
  register/stack mutation APIs, and native replay of recovered inputs.
- `pyproject.toml` – Minimal configuration enabling `uv` to manage a local
  virtual environment.
- `schemas/` – JSON Schema Draft 2020-12 definitions for every MCP handler
  request/response pair plus shared structures (alerts, jobs, UUIDs).

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
   .venv/bin/python -m unittest discover tests
   ```

   The Phase 1 tests exercise 32-bit angr CTF binaries. If your host lacks
   32-bit runtime libraries (`/lib/ld-linux.so.2`), the suite will skip the
   native replay assertions automatically.

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
   returns new state IDs per stash, emits structured alert records, and
   registers/updates a job handle that can be resumed later.
5. `monitor_for_vulns` – register inspection breakpoints (e.g., `mem_write`)
   so exploit-relevant actions are recorded (alerts accumulate alongside raw
   event logs).
6. `inspect_state` – fetch registers, memory, constraint sets, recorded
   events, and generated alerts for any stored state.
7. `solve_constraints` – query Claripy for concrete inputs/ranges from the
   current constraints.
8. `list_jobs`, `resume_job`, and `delete_job` – manage persisted simulation
   jobs (list metadata, hydrate back into memory, or remove from registry/disk).
9. `analyze_control_flow` and `trace_dataflow` – generate CFGs and backward
   slices to guide further exploration.

## Current Status (October 25, 2025)

- Core MCP plumbing is in place with registry-backed state tracking and
  resilient execution (errors are captured and returned to clients).
- Structured alerting now highlights unconstrained instruction-pointer states
  and suspicious memory writes, returning normalized JSON objects alongside run
  results and state inspection payloads.
- `setup_symbolic_context` and the new `mutate_state` handler support option
  presets, register copying/injection, stack adjustments, and symbolic handle
  tracking for later constraint solving.
- Predicate descriptors (`address`, `stdout_contains`, `stdout_not_contains`)
  now drive `run_symbolic_search`, and predicate matches are recorded in the
  run payload alongside base64-encoded stdin/stdout streams.
- Helper utilities in `angr_mcp/utils/` expose section scanners and literal
  cross-references used to automate angr CTF level analysis.
- Jobs created via `run_symbolic_search` can be resumed, enumerated, and
  persisted to `.mcp_jobs/<job_id>.json`; persisted jobs can be rehydrated
  across processes through `resume_job`.
- JSON Schemas in `schemas/` describe every handler request/response, enabling
  downstream clients (e.g., GhidraMCP) to validate payloads.
- Basic exploration techniques from the `awesome-angr` bundle remain
  dynamically loadable.
- Symbolic stdin setup initializes the default `SimPacketsStream` content
  in-place to avoid compat issues with angr’s POSIX plugin.
- Integration tests validate the exploit-oriented workflow end to end (requires
  installing `claripy` and `angr` via `uv pip`). Supplementary Phase 1 CTF
  tests assert deterministic solutions for levels 00–04 in
  `tests/test_phase1_ctf.py`.

## Phase 1 angr_ctf Coverage Highlights

- Level 00/01: `.rodata` token extraction and literal cross-referencing feed
  predicate descriptors that prove the concrete solution and ensure avoid sites
  remain untouched.
- Level 02: Pure stdout-based predicates demonstrate predicate logging,
  metadata persistence, and streamed stdout capture for repro.
- Level 03: Blank-state creation, symbolic register injection, and solver
  handle queries recover integer tuples that replay natively.
- Level 04: Stack alignment helpers and symbolic push operations mirror the
  native stack frame without triggering alert detectors, validating stack
  integrity through the handler pipeline.

## Planned Next Steps

- Extend alert coverage to include additional exploit heuristics (e.g.,
  unconstrained stack pivots, self-modifying code) and configurable thresholds.
- Add background job execution and progress polling so long-running searches
  can continue asynchronously while clients poll via job metadata.
- Generate JSON Schemas directly from type annotations to avoid drift and
  integrate schema validation into the test suite when `jsonschema` is
  available.
- Surface richer metadata (e.g., hook registry, cached analyses) through
  dedicated query endpoints to assist front-ends.

## Contributing Notes for Agents and Humans

- Use `uv` for package management; keep the `.venv` environment in sync with
  `README` instructions.
- Keep documentation (this file and `AGENTS.md`) updated with each change so
  future sessions understand the current context, constraints, and open items.
- Prefer `apply_patch` for manual edits. Avoid destructive git commands unless
  explicitly approved.

# Phase 1 – Baseline Symbolic Execution Coverage (Levels 00–04)

## Phase Objective
- Automate angr CTF levels `00_angr_find` through `04_angr_symbolic_stack` via MCP handlers.
- Produce deterministic concrete inputs for every binary and capture proof artefacts (stdout, solver models, alerts).
- Leave behind tests, utilities, and documentation so subsequent phases build on a stable baseline.

## Context Snapshot (October 25, 2025)
- Core MCP server, registry, job persistence, alerting, and schemas are in place; current integration test targets a synthetic binary only.
- Exploration techniques load dynamically but Phase 1 relies on vanilla symbolic execution.
- Collaboration rules require README/AGENTS updates whenever workflows change and Unittests live in `tests/test_mcp_server.py` today.
- Resources under `resources/angr_ctf` provide source for the five target binaries; compilation occurs on demand during tests.

## Deliverables
- Enhanced MCP functionality supporting predicate-based exploration, blank state creation, and structured register/stack injection.
- Helper utilities under `angr_mcp/utils/` consolidating binary-analysis routines used by multiple levels.
- Comprehensive integration tests covering all five binaries plus focused unit coverage for predicate parsing and state mutation helpers.
- Documentation updates: new Phase 1 section in `README.md`, operational handoff notes in `AGENTS.md`, and this plan kept current.
- Captured artefacts (solver results, stdout snippets, alert summaries) persisted in test fixtures for debugging.

## Workstream Overview
- **Binary Intelligence:** discover target/avoid addresses, stdout literals, and post-scanf resume points automatically.
- **Search Enhancements:** accept both address descriptors and semantically rich predicates; record which predicate fired.
- **State Construction:** support entry and blank states, register assignments, stack manipulation, and solver option control.
- **Persistence & Telemetry:** persist predicate descriptors and symbolic metadata in `.mcp_jobs/`; extend alerting to cover predicate aborts.
- **Testing & Tooling:** implement deterministic fixtures, helper assertions, and native binary replays for validation.

## Level-Specific Plans

### Level 00 – `angr_find`
- **Mechanic:** single success site printing `"Good Job."`; password is 8 uppercase bytes stored in `.rodata`.
- **Tasks:**
  - Implement `.rodata` scanner (`extract_upper_token`) returning candidate string and its address for assertions.
  - Allow `load_project` to accept solver option presets so entry states match canonical solutions (`SYMBOL_FILL_*`).
  - Extend `run_symbolic_search` to accept a `find` descriptor referencing the discovered success address or stdout predicate.
- **Validation:**
  - Test asserts stdin equals extracted token and stdout contains success message.
  - Record job metadata proving the `find` predicate triggered exactly once.

### Level 01 – `angr_avoid`
- **Mechanic:** identical cipher; must reach success while avoiding failure print.
- **Tasks:**
  - Build CFG-based literal locator returning addresses for both success (`"Good Job."`) and failure (`"Try again."`) strings.
  - Update search handler to accept multiple `find`/`avoid` descriptors and annotate the execution trace with visited sites.
  - Add inspection helper verifying the avoid address is absent from the found state history.
- **Validation:**
  - Test ensures solver path never touches avoid site and recovered token still matches `.rodata` constant.
  - Persist trace summary for regression debugging.

### Level 02 – `angr_find_condition`
- **Mechanic:** nested conditionals make static addresses brittle; rely on stdout predicates.
- **Tasks:**
  - Introduce predicate descriptor schema supporting `stdout_contains`, `stdout_not_contains`, and `address` types.
  - Translate descriptors to callables inside the simulation manager wrapper; include logging/alerting when predicates fire.
  - Ensure job persistence records predicate configuration for resumable runs.
- **Validation:**
  - Test runs search with stdout-only predicates and asserts produced stdin matches `.rodata` helper output.
  - Confirm alerts remain empty unless abort predicate fires (negative test).

### Level 03 – `angr_symbolic_registers`
- **Mechanic:** resume execution after `scanf`, inject symbolic registers (`eax`, `ebx`, `edx`).
- **Tasks:**
  - Extend state creation handler with `blank_state` support at caller-provided addresses plus solver options.
  - Provide register injection API returning symbolic handles (name, bit width, AST) for downstream evaluation.
  - Implement helper identifying instruction immediately after `__isoc99_scanf` call.
- **Validation:**
  - Test asserts concrete solutions satisfy the binary when replayed natively and that symbolic metadata is exposed.
  - Capture register assignments in persisted job snapshots.

### Level 04 – `angr_symbolic_stack`
- **Mechanic:** manipulate stack to mirror native execution; inject two symbolic values while maintaining saved `ebp`.
- **Tasks:**
  - Add stack mutation helper accepting value descriptors (symbolic or concrete) and handling alignment/frame pointer restoration.
  - Implement analyzer deriving offsets for saved `ebp` and input buffers to guard against corruption.
  - Extend inspection handler to verify final `esp`/`ebp` relationship and optionally dump memory slices for diagnostics.
- **Validation:**
  - Test asserts recovered integers replay successfully and stack invariants hold (no unexpected alerts).
  - Ensure monitoring hooks flag stack pivot attempts; success path should show clean alert log.

## Shared Engineering Tasks
- **Schema Updates:** expand `schemas/` to capture predicate descriptors, register/stack mutation payloads, and response metadata.
- **Utilities:** consolidate repeated binary inspection logic inside a new module imported by handlers and tests.
- **Documentation:** add walkthrough covering environment setup, command examples (`uv pip install`, unittest invocation), and troubleshooting for 32-bit toolchains.
- **CI Considerations:** enable optional jsonschema validation once dependencies are bundled; gate Phase 1 tests behind feature flag until ready.
- **Logging & Alerts:** provide structured logs indicating predicate matches, state creations, and any exceptional termination reasons.

## Testing Strategy
- Create `tests/test_phase1_ctf.py` (or extend existing suite) with per-level methods leveraging shared fixtures.
- Fixture responsibilities:
  - Compile binaries from `resources/angr_ctf` into temporary directory using detected C compiler.
  - Manage MCP project lifecycle (create, reuse project id, teardown) per test to reduce overhead.
  - Cache discovered metadata (addresses, tokens) to avoid repeated analysis work.
- Assertions per test:
  - Concrete stdin/stdout validation, including re-running native binaries via `subprocess.run`.
  - Inspection of solver models, register/stack values, and alert logs.
  - Persistence checks ensuring saved jobs reload and resume successfully.

## Milestone Timeline (target start October 27, 2025)
- **Week 1:** Utilities + predicate schema groundwork; implement Level 00 and Level 01 automation with tests and documentation updates.
- **Week 2:** Predicate execution engine and Level 02 coverage; add logging and alert integration.
- **Week 3:** Register injection APIs, Level 03 tests, persisted metadata enhancements.
- **Week 4:** Stack manipulation support, Level 04 validation, CI wiring, final documentation polish.
- **Week 5 (buffer):** Harden edge cases, triage test flakes, prepare for Phase 2 handoff.

## Exit Criteria
- All Phase 1 tests pass on fresh checkout using documented `uv` environment and system compiler.
- Handlers expose predicate descriptors, blank state creation, register/stack mutation, and return structured metadata consumed by tests.
- Documentation accurately reflects required setup, execution steps, and troubleshooting for the five binaries.
- Alert log remains empty on happy paths; any observed alerts are documented, categorized, and addressed before sign-off.

## Risks & Mitigations
- **Environment drift:** 32-bit libc dependencies may be missing; document package requirements and guard tests with skip messages when unavailable.
- **Predicate misuse:** Strict schema validation and logging around predicate execution will aid debugging and prevent silent failures.
- **Stack modeling errors:** Provide inspection tools (memory dump, esp/ebp snapshot) to quickly diagnose mismatched layouts.
- **Solver nondeterminism:** Seed claripy and capture concrete models in tests to detect regressions early.

## Follow-On Opportunities
- Generalize predicate descriptors for other I/O channels and memory conditions to support later CTF phases.
- Extend monitoring hooks to recognize stack pivots or self-modifying code, aligning with project collaboration rules.
- Automate jsonschema validation in CI once dependency footprint is finalized.
- Begin outlining Phase 2 requirements (multi-function binaries, path explosion mitigation) leveraging utilities created here.

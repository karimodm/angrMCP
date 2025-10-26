# Phase 2 – Intermediate Symbolic Techniques (Levels 05–12)

## Scope
- Covers angr CTF levels `05_angr_symbolic_memory` through `12_angr_veritesting`.
- Focus areas: global/dynamic memory injection, symbolic filesystem, manual constraint solving, custom hooks/SimProcedures, and exploration techniques (veritesting).
- Deliverables: comprehensive tests (and supporting MCP features) that replicate the canonical solutions for each level and assert solver outputs against the ground truth binaries in `resources/angr_ctf/dist`.

## Audit Summary

### Level 05 – `angr_symbolic_memory`
- **Mechanic:** Jump into the program post-`scanf("%8s %8s %8s %8s")`, replace four global buffers with symbolic strings, and solve for the 32-byte secret split into four 8-byte chunks.
- **Binary observations:** Global array `user_input[33]` in `.bss`; random padding arrays before/after create large offsets but the symbol name is preserved (`nm` exposes `user_input`).
- **Reference solution tactics:** `blank_state` at the instruction after `scanf`, store four 8-byte BVS values into successive offsets of `user_input`, run stdout predicate, then evaluate each BVS to ASCII.
- **Automation implications:** We can leverage the existing `symbolic_memory` parameter on `setup_symbolic_context` but need it to accept an `offset` so a single allocation can be partitioned into chunks; alternatively, seed one 32-byte symbol and slice it. Require helper to locate the post-`scanf` address automatically (e.g., by scanning for the call to `__isoc99_scanf` within `main`).
- **Data extraction needs:** Determine the random 32-byte uppercase `USERDEF` token by reading `.rodata` to compare against the solver output.

### Level 06 – `angr_symbolic_dynamic_memory`
- **Mechanic:** Intercept heap allocations so the buffers filled by `scanf("%8s %8s")` become symbolic despite angr’s limited automatic malloc modelling; force both buffer pointers to reference concrete heap regions we control.
- **Binary observations:** Global pointers `buffer0`…`buffer3` stored in `.bss`; runtime writes set them to malloc’d chunks before reading user input.
- **Reference solution tactics:** Start after the two `malloc` calls and `scanf`, replace the two global pointers with fake heap addresses pointing into unconstrained memory, and manually store two 8-byte BVS strings at those fake addresses; stdout predicate for success.
- **Automation implications:** MCP needs an ergonomic way to overwrite global data with concrete addresses and to store symbolic strings at those addresses before execution. Option ideas: extend `setup_symbolic_context` with a `prelude` block describing memory writes (address, value, endness). Tests also need a helper to allocate disjoint fake heap regions (e.g., from angr’s abstract memory) to avoid collisions.
- **Data extraction needs:** Identify where to resume execution (right after second `scanf`). Compute pointer symbol addresses via `project.loader.find_symbol("buffer0")` etc.

### Level 07 – `angr_symbolic_file`
- **Mechanic:** Replace the file read by `fread` with a symbolic file in the simulated filesystem, then solve for the 8-byte expected password string.
- **Binary observations:** File name literal `USERDEF1.txt` (random uppercase) embedded in `.rodata`; program opens, reads, and deletes the file; uses `fread(buffer, 1, 64, fp)`.
- **Reference solution tactics:** Create blank state after `scanf`, construct a `SimFile` with 8-byte BVS content, insert it into the state’s filesystem (`state.fs.insert`), run stdout predicate, evaluate string.
- **Automation implications:** MCP needs a handler to seed symbolic files. Proposal: extend `setup_symbolic_context` with a `files` parameter accepting entries like `{"path": "FOOBAR.txt", "size": 8, "symbolic": True}` returning the created BVS handle. Also ensure tests can record the inserted symbol for later evaluation. Additional helper should read `.rodata` to recover the expected file path and reference string.
- **Data extraction needs:** Parse file name literal and success token from `.rodata`; ensure tests clean up any real files created if the binary under test is spawned for verification.

### Level 08 – `angr_constraints`
- **Mechanic:** Stop execution just before `check_equals_<token>` is invoked, inject a constraint equating its argument to the known target string, then solve backwards for the required input.
- **Binary observations:** Function `check_equals_<token>` exported with a symbol; password literal stored in `.rodata`; success path prints “Good Job.” but reaching it naively explodes due to recursion.
- **Reference solution tactics:** Explore until the call to `check_equals_*`, load the argument buffer from memory, add equality constraint against the target string, and solve for the four 8-byte input chunks.
- **Automation implications:** Need to reliably find the address just prior to the function call (e.g., final instruction before `call`). Plan to statically read the symbol for `check_equals` and use relocation info/CFG to find call sites. Also ensure MCP exposes an API to add constraints to a recorded state (currently we can use `registry.get_state` and call `state.add_constraints`, but tests should prefer a `server.add_constraints` wrapper).
- **Data extraction needs:** Obtain the target string via `.rodata` parse; track which BVS instances map to each 8-byte chunk so assertion is straightforward.

### Level 09 – `angr_hooks`
- **Mechanic:** Replace a particularly expensive call to `check_equals_*` with a custom hook that performs the comparison instantly in Python, allowing the rest of the execution to proceed symbolically.
- **Binary observations:** A single call site needs patching; the callee symbol is present; success path still prints “Good Job.”.
- **Reference solution tactics:** Hook the call site (pre-call) to intercept parameters, compare symbolic buffer against known string, assign result into `eax` using `claripy.If`, and skip original instructions by specifying `length`.
- **Automation implications:** MCP’s `instrument_environment` already supports `python_callable` hooks, but we must compute the call-site address and instruction length automatically. Plan to create helper that scans `main` for call to `check_equals_*` and returns the preceding instruction address and size (via `block.capstone.insns`). Tests should assert the hook was invoked (e.g., using a side-channel flag) and that the solver recovers the correct stdin string.
- **Data extraction needs:** Retrieve target string from `.rodata`; gather hook metadata for documentation.

### Level 10 – `angr_simprocedures`
- **Mechanic:** Replace every call to `check_equals_*` with a custom SimProcedure rather than per-call hooks (function is called repeatedly).
- **Binary observations:** Symbol `check_equals_<token>` present; otherwise similar to level 09.
- **Reference solution tactics:** Define a `SimProcedure` subclass implementing `run(self, to_check, length)` and hook it via `project.hook_symbol`.
- **Automation implications:** Extend `instrument_environment` to accept an actual Python SimProcedure class (not just a string pointing into `angr.SIM_PROCEDURES`) and instantiate it. Provide builtin helper to reference randomly-generated token. Ensure tests can confirm the SimProcedure was registered (e.g., by checking hook metadata).
- **Data extraction needs:** Identify target symbol and string, same as level 09.

### Level 11 – `angr_sim_scanf`
- **Mechanic:** Replace `__isoc99_scanf` with a SimProcedure that writes symbolic integers into supplied buffers, because angr struggles with multi-argument scanf in this binary.
- **Binary observations:** Input format `"%u %u"`; program reads two integers into global buffers and later compares them to encrypted constants.
- **Reference solution tactics:** Hook `__isoc99_scanf` with custom SimProcedure, allocate two 32-bit BVS values, store them into provided memory pointers with correct endianness, stash BVS handles in `state.globals` for later retrieval, run stdout predicate, evaluate both integers to decimal.
- **Automation implications:** Similar to level 10—need SimProcedure injection via Python class. Additionally, tests need to query stored BVS handles via new server helper (e.g., `inspect_state(..., include_globals=True)` or explicit state return). Consider augmenting `inspect_state` or adding a dedicated handler for retrieving captured globals.
- **Data extraction needs:** Determine target comparison values (via `.rodata`) so we can assert correctness.

### Level 12 – `angr_veritesting`
- **Mechanic:** Enable veritesting to collapse the massive branch explosion and then proceed like level 02 (stdout predicate).
- **Binary observations:** Similar structure to earlier “find” levels but constructed to defeat naive DFS/BFS; enabling veritesting is the intended fix.
- **Reference solution tactics:** `project.factory.simgr(initial_state, veritesting=True)`, use stdout predicate for success.
- **Automation implications:** Extend `run_symbolic_search` to accept a `techniques` list that can include built-in angr techniques like `veritesting` (not just plugins from `awesome-angr`). Implementation idea: recognize `"veritesting"` and instantiate `angr.exploration_techniques.veritesting.Veritesting()`. Tests should assert that solving without the technique either times out or leaves `found` empty, while enabling veritesting succeeds.
- **Data extraction needs:** Reuse stdout predicate; compare recovered password to `.rodata` string.

## Required MCP Enhancements (Phase 2 Deliverables)
- **Generalized state prelude:** Expand state setup APIs to support scripted memory/register writes with concrete or symbolic values (covering dynamic memory pointer rewriting, fake heap allocation, etc.).
- **Symbolic file seeding:** Introduce a handler (e.g., `seed_filesystem`) or extend `setup_symbolic_context` to create concrete/symbolic files; return handles to underlying BVS objects for later evaluation.
- **SimProcedure injection:** Allow `instrument_environment` to accept Python classes or callables that inherit `angr.SimProcedure`, in addition to angr’s built-in registry names. Include hook metadata in responses for traceability.
- **Constraint API:** Provide a server method to append constraints to a saved state (`add_constraints(project_id, state_id, expressions)`) instead of accessing registry internals directly.
- **Captured globals inspection:** Extend `inspect_state` to optionally dump `state.globals` (or provide a targeted API) so tests can fetch BVS handles stored by SimProcedures like the custom scanf.
- **Technique registry:** Recognize built-in angr exploration techniques (starting with `veritesting`) in `run_symbolic_search`.

## Harness Design
- **Binary discovery:** Reuse the Phase 1 fixture but add helpers for symbol lookup (global variables, functions), Capstone disassembly for instruction sizing, and `.rodata` extraction for arbitrary-length strings (16, 32 bytes).
- **State builders:** Provide convenience wrappers for common setups:
  - `setup_blank_after_scanf(symbol_name, nth_call)` to position execution after relevant library calls.
  - `seed_global_buffer(symbol, size, chunk=8)` to populate `.bss` ranges with symbolic data.
  - `prepare_fake_heap(pointer_symbol, base_addr, size)` to rewrite global pointers and map symbolic storage.
  - `install_simfile(path, size)` returning both the file object and backing BVS.
- **Hook utilities:** Build a helper that, given a function symbol and call index, returns the call-site address and size for hooking; optionally verify the hook executed by incrementing a counter stored in `state.globals`.
- **Solver validation:** After recovering passwords or integers, validate by executing the binary (or, when applying constraints without finished path execution, re-running from entry with the solved input to ensure “Good Job.” is printed).
- **Regression capture:** Record outputs (strings, integers) in structured fixtures (e.g., JSON alongside tests) so we can assert deterministic solutions even if the binaries are regenerated later.

## Per-Level Test Outline
- **test_level_05_symbolic_globals:** Blank state post-`scanf`, seed `user_input` with symbolic bytes, run stdout predicate, assert 32-byte solution matches `.rodata`.
- **test_level_06_symbolic_dynamic_memory:** Rewrite pointer targets, seed fake heap with two BVS strings, run predicate, assert both chunks match expected tokens.
- **test_level_07_symbolic_file:** Insert symbolic file for discovered filename, explore to success, solve for 8-byte password, ensure file hook executed.
- **test_level_08_manual_constraint:** Explore to call-site, add equality constraint, solve for four substrings, and verify by running binary with reconstructed input.
- **test_level_09_hook_check_equals:** Install Python hook, run entry state, confirm hook invoked (counter) and solution matches expected string.
- **test_level_10_simprocedure:** Register custom SimProcedure class, solve, and assert no manual hook instrumentation was required (e.g., ensure call-site address stayed untouched).
- **test_level_11_simulated_scanf:** Replace libc scanf with SimProcedure, retrieve stored BVS via globals inspection, solve for integers, and verify with native execution.
- **test_level_12_veritesting:** Demonstrate failure without technique, success with technique; assert recovered input string.

## Risks & Open Questions
- **Custom hook safety:** Allowing arbitrary Python callables/SimProcedures increases the chance of accidental state pollution; consider sandboxing or providing vetted utility classes per test.
- **File-system side effects:** When verifying solutions by executing binaries, ensure temporary directories are used so the binaries’ real file operations (unlink, fopen) do not affect the repository.
- **Constraint synchronization:** After adding constraints via new API, ensure registry and persisted job metadata stay consistent (e.g., updating monitors, alerts, job snapshots).
- **Instruction-length detection:** Capstone disassembly must remain architecture-aware; implement caching to avoid repeated decoding for the same addresses.
- **Veritesting determinism:** Evaluate whether enabling veritesting changes stash ordering enough to complicate assertions; we may need to normalize outputs (e.g., sort stash IDs) in run results.

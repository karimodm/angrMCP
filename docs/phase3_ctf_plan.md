# Phase 3 – Advanced Analyses & Exploit Scenarios (Levels 13–17, xx)

## Scope
- Targets the remaining angr CTF content: `13_angr_static_binary`, `14_angr_shared_library`, `15_angr_arbitrary_read`, `16_angr_arbitrary_write`, `17_angr_arbitrary_jump`, and the bonus `xx_angr_segfault`.
- These exercises require exercising the MCP server across static binaries, shared objects, intentional vulnerability exploitation, and unconstrained-state handling.
- Objective: design MCP enhancements and tests that solve each level autonomously, validating both functional correctness (recovering the expected secrets) and instrumentation coverage (hooks, alerts, stash management).

## Audit Summary

### Level 13 – `angr_static_binary`
- **Mechanic:** Solve the original “find” problem against a statically-linked binary by manually hooking standard C library functions (printf/scanf/puts/__libc_start_main) to their SimProcedure equivalents.
- **Binary observations:** 32-bit ELF compiled with `-static`; glibc routines are fully inlined. Symbols for `printf`, `scanf`, etc., still exist but point inside the binary.
- **Reference solution tactics:** Create an entry state, replace the four heavy libc routines with angr SimProcedures, run stdout predicate to find “Good Job.”.
- **Automation implications:** MCP must support bulk hooking of built-in SimProcedures by address, possibly via a helper that maps requested symbol names to `angr.SIM_PROCEDURES['libc'][…]`. Need a way to bypass `__libc_start_main` quickly (hook to glibc SimProcedure) and start directly at `main` (consider adding `kind="entry"` vs `kind="blank"` choice). Tests should assert that hooks are active (e.g., inspect `project.hooked_by`).
- **Data extraction needs:** Determine the correct entry point (`main` symbol) and the random `USERDEF` string for assertion.

### Level 14 – `angr_shared_library`
- **Mechanic:** Load the shared object, construct a call state to `validate`, seed the string argument with symbolic bytes, and demand the function return true (non-zero) to reveal the password.
- **Binary observations:** Shared object built with PIC; must be loaded at a specified base (e.g., `0x4000000`). Exported symbol `validate`; expected password literal is 8 uppercase bytes in `.rodata`.
- **Reference solution tactics:** Use `Angr.Project(path, load_options={'main_opts': {'base_addr': base}})`, call state at `base + validate_offset` with pointer to synthetic memory (`0x3000000`), store 8-byte BVS at that memory, explore until right-before-return, add constraint `eax != 0`, solve BVS to ASCII.
- **Automation implications:** MCP should expose loader options when creating projects (already supported) and provide a streamlined way to create call states with concrete pointer arguments plus symbolic backing memory. Consider extending `setup_symbolic_context(kind="call")` to accept a `memory_inits` list containing `(address, size, symbolic)` descriptors so the BVS handle is returned alongside the new state. Also ensure tests can set register constraints (`eax != 0`) through the new constraint API.
- **Data extraction needs:** Identify validate’s offset via `project.loader.find_symbol("validate")`; parse `.rodata` password for assertion; compute the return-site address (e.g., last block before function epilogue) for the `find` descriptor.

### Level 15 – `angr_arbitrary_read`
- **Mechanic:** Detect an exploitable call to `puts`, constrain its argument pointer to the address of the “Good Job.” string, and solve for input (key + string) that achieves this controlled read.
- **Binary observations:** Uses `scanf("%u %20s")`; stores pointer to string in `struct overflow_me.to_print`; random switch statement chooses when to call `puts(locals.to_print)`; `good_job` is a global symbol in `.data/.rodata`.
- **Reference solution tactics:** Hook `__isoc99_scanf` to create symbolic key and string (with printable constraints). On reaching `puts`, inspect stack to read argument pointer; if symbolic, test constraint `ptr == good_job_addr`; if satisfiable, add constraint, report success. Query stored BVS for final solution.
- **Automation implications:** Build on Phase 2 SimProcedure infrastructure for custom scanf. Need helper to inspect the stack frame generically (read `[esp+4]` for parameter). Introduce a high-level API to evaluate whether ASTs are symbolic and to test satisfiability with extra constraints (wrapper around `state.solver.satisfiable(extra_constraints=...)`). Tests should validate the hook path and ensure the final input reproduces “Good Job.” when fed to the binary.
- **Data extraction needs:** Lookup symbol `good_job` via loader; capture both components of the solution (numeric key, uppercase string).

### Level 16 – `angr_arbitrary_write`
- **Mechanic:** Similar overflow theme but targeting writes: intercept `strncpy` to ensure both destination pointer (locals.to_copy_to) and source contents derive from user input and can be forced to overwrite `password_buffer` with the target secret `USERDEF`.
- **Binary observations:** Struct `overflow_me` holds `buffer` and `to_copy_to`; `password_buffer` in `.bss`; switch statement determines whether `strncpy(locals.to_copy_to, ...)` is executed with a controllable pointer. `USERDEF` (8 characters) sits in `.rodata`.
- **Reference solution tactics:** Hook `__isoc99_scanf` to produce symbolic key/string (with ASCII constraints). When the program reaches `strncpy`, read `dest`, `src`, and `len` from stack, ensure both `dest` and `src_contents` are symbolic; test whether constraints `dest == &password_buffer` and `src_contents == USERDEF` are satisfiable, add them if so, and mark state as success. After solving, emit numeric key and string.
- **Automation implications:** Need ability to slice BVS values (e.g., `src_contents[-1:-64]`) via helper utilities, plus support for multiple simultaneous constraints. Consider augmenting the new constraint API to accept high-level descriptors (memory equality, symbolic checks). Tests should also verify that adding only one of the constraints fails, demonstrating the exploit requirement.
- **Data extraction needs:** Retrieve addresses of `password_buffer` and the target string; capture final solution values for regression files.

### Level 17 – `angr_arbitrary_jump`
- **Mechanic:** Manage unconstrained states to craft a payload that overwrites the return address and jumps to the “print_good” function.
- **Binary observations:** Reads 100-byte string; overflow leads to user-controlled return address; `print_good` (or similar) symbol available; program designed to produce unconstrained instruction pointer.
- **Reference solution tactics:** Create entry state with 100-byte symbolic stdin; initialize sim manager with `save_unconstrained=True` and custom stash layout; iteratively step and move states from `unconstrained` to `found`; add constraint `ip == print_good_addr`; constrain stdin to printable uppercase; evaluate to ASCII string.
- **Automation implications:** Extend `run_symbolic_search` to (a) expose arbitrary stashes (`unconstrained`, `found`, etc.) in `RunResult.stashes`, and (b) optionally enable `save_unconstrained`. Provide new handler to move states between stashes (`move_state(project_id, simgr_id, source, dest)`) or to promote unconstrained states to found automatically when returned. Also supply options to set per-byte constraints on symbolic stdin (e.g., via new helper `constrain_stdin_range(state_id, low, high)`). Tests must assert that the server’s alert system flags the unconstrained IP (existing monitoring) and that the final payload triggers “Good Job.” when replayed.
- **Data extraction needs:** Acquire address of the target function (likely `print_good` symbol); record the solved 100-byte payload for regression.

### Bonus – `xx_angr_segfault`
- **Mechanic:** Variant of the arbitrary read challenge with deliberately fragile code paths that segfault unless the exploit is crafted correctly; includes additional randomization in the switch statement and stack layout.
- **Binary observations:** Similar structure to level 15 but with additional fields in `struct overflow_me`; still relies on controlling a pointer used by `puts`.
- **Reference solution tactics:** Combine approaches from levels 15 and 16: custom scanf SimProcedure, pointer/stack inspection at `puts`, satisfiability checks for pointing to “Good Job.”, uppercase constraints for input.
- **Automation implications:** Reuse infrastructure built for 15/16 but ensure the test exercises error handling—for example, verify that the MCP hook tolerates intermediate segfaults (the underlying simulation may produce errored states). Extend run results to surface errored state metadata so tests can assert they were safely ignored.
- **Data extraction needs:** Same as 15—addresses of target strings and final input components.

## Required MCP Enhancements (Phase 3 Deliverables)
- **SimProcedure hook utilities:** Provide helper functions to bind multiple built-in SimProcedures by symbol (for static binaries) and to uninstall or override them cleanly across tests.
- **Call-state provisioning:** Enhance `setup_symbolic_context(kind="call")` with structured argument descriptors (`{"type": "ptr", "address": 0x...}`, `{"type": "bvs", "size": 8}`) that return references to created BVS objects.
- **Advanced constraint management:** Implement high-level wrappers for common expressions (equality to concrete bytes, pointer equality, per-byte range constraints) and expose them via an administrative handler so tests can request complex constraints without direct `registry` access.
- **Stash & job control:** Extend `RunResult` to include every stash present in the simulation manager (`unconstrained`, `pruned`, `stashed`, etc.) and add endpoints to (a) move states between stashes, (b) enable `save_unconstrained`/custom stash initializers, and (c) request targeted stepping loops (e.g., `step_until_unconstrained` with limit).
- **Alert integration:** Tie unconstrained-state findings to the existing alerting system (should emit `unconstrained_ip` alerts) and surface them through the run results consumed by tests.
- **Error reporting:** Include errored states with exception metadata so we can assert that segfault-inducing paths were encountered and handled.

## Harness Design
- **Static/shared loading helpers:** Extend the Phase 2 fixture with utilities to (a) load binaries with custom `base_addr` (shared libs), (b) copy companion `.so` files into the temp directory, and (c) confirm loader metadata (arch, entry address) before executing analyses.
- **Hook orchestration:** Provide helper `install_libc_shims(symbols)` returning hook IDs so tests can clean up. For custom hooks, track invocation counts via shared structures stored in `state.globals`.
- **Exploit detectors:** Implement reusable checker functions (`check_pointer_equals`, `check_strncpy_control`) that return predicate callables for hook use; tests only need to supply target addresses/strings.
- **Stash supervisor:** Build a controller around `run_symbolic_search` that repeatedly steps the sim manager while retrieving stash snapshots, promoting unconstrained states as needed, and applying follow-up constraints (e.g., ip equality). Encapsulate this logic so tests remain declarative.
- **Replay verification:** For each recovered payload, execute the binary (or driver executable for level 14) with the computed input to confirm “Good Job.” appears and no crashes occur; capture stdout/stderr for debugging.
- **Regression artifacts:** Store results (e.g., JSON mapping of level → recovered input) for future comparisons and to aid deterministic testing when binaries are regenerated.

## Per-Level Test Outline
- **test_level_13_static_binary:** Install libc SimProcedures via helper, run stdout predicate, confirm `found` stash contains solution, and assert derived password matches `.rodata`. Optionally verify speed-up compared to unhooked run (timeout guard).
- **test_level_14_shared_library:** Load SO with base address, create call state with pointer argument, seed symbolic buffer, explore to pre-return site, constrain `eax != 0`, solve for 8-byte string, and replay using the provided executable to validate.
- **test_level_15_arbitrary_read:** Install custom scanf SimProcedure, hook `puts` with predicate, constrain pointer to `good_job`, solve for key+string, replay binary, and assert no failure output.
- **test_level_16_arbitrary_write:** Similar to above but monitor `strncpy`; add dual constraints for destination and contents, solve, replay, and check that `password_buffer` is overwritten (optionally inspect memory via `inspect_state`).
- **test_level_17_arbitrary_jump:** Enable `save_unconstrained`, step until unconstrained state discovered, promote to found, add `ip == target` and printable ASCII constraints, solve for 100-byte payload, and replay to confirm success.
- **test_xx_angr_segfault:** Mirror level 15 test but assert that any errored states returned by the run are logged and ignored; final solution must still print “Good Job.”.

## Risks & Open Questions
- **Static binary environment:** Running static binaries for verification may require additional loader permissions; ensure tests gracefully skip when execution is not allowed.
- **Performance & determinism:** Static/shared analyses plus exploitation hooks can be slow; consider caching computed addresses and seeds, and set explicit timeouts per test.
- **Stash mutation safety:** Exposing stash move operations must guard against invalid transitions (e.g., moving nonexistent state IDs); design API with validation and deterministic behavior.
- **Constraint explosion:** Adding multiple equality constraints in levels 15/16 can balloon the solver load; monitor performance and consider heuristic pruning (e.g., early satisfiable checks) in helper functions.
- **Shared-library driver:** The archive contains both the `.so` and a driver executable. Decide whether tests operate directly on the `.so` or through the driver; if the latter, ensure hooking/SimProcedure logic stays compatible.

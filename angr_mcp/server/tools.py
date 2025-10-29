"""FastMCP tool registrations and thin wrappers around :mod:`angr_mcp.server.core`."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence

from mcp.server.fastmcp import FastMCP

from .core import AngrMCPServer

_NOISY_LOGGERS = (
    "angr",
    "angr.analyses",
    "angr.exploration_techniques",
    "angr.project",
    "cle",
    "claripy",
)

for _logger_name in _NOISY_LOGGERS:
    logging.getLogger(_logger_name).setLevel(logging.WARNING)


mcp = FastMCP("angr-mcp", log_level="WARNING")
SERVER = AngrMCPServer()


@mcp.tool()
def load_project(
    binary_path: str,
    *,
    auto_load_libs: bool = True,
    load_options: Optional[Dict[str, Any]] = None,
    exclude_sim_procedures_list: Optional[Iterable[str]] = None,
    exclude_sim_procedures_func: Optional[str] = None,
    use_sim_procedures: bool = True,
) -> Dict[str, Any]:
    """Load a program into angr and register it with the MCP registry.

    Use this to initialise only the binary you intend to explore symbolically.
    When paired with lightweight load options (e.g., ``auto_load_libs=False``),
    it provides the minimal foundation for later, budgeted reachability runs.

    Args:
        binary_path: Path to the binary to analyse. Relative paths are resolved from the
            current working directory.
        auto_load_libs: When true, angr attempts to load dependent shared libraries.
        load_options: Additional keyword arguments forwarded to ``angr.Project``.
        exclude_sim_procedures_list: Iterable of simprocedure names (e.g. ``libc.printf``)
            to disable when creating the project.
        exclude_sim_procedures_func: Dotted path to a callable that decides whether a
            simprocedure should be excluded.
        use_sim_procedures: Set to ``False`` to create the project without simprocedures.

    Returns:
        Dictionary containing a ``project_id`` plus loader ``metadata`` that summarises
        the program's architecture and loaded objects.
    """

    return SERVER.load_project(
        binary_path,
        auto_load_libs=auto_load_libs,
        load_options=load_options,
        exclude_sim_procedures_list=exclude_sim_procedures_list,
        exclude_sim_procedures_func=exclude_sim_procedures_func,
        use_sim_procedures=use_sim_procedures,
    )


@mcp.tool()
def setup_symbolic_context(
    project_id: str,
    *,
    kind: str = "entry",
    addr: Optional[int] = None,
    args: Optional[List[Any]] = None,
    argv: Optional[List[Any]] = None,
    env: Optional[Dict[str, Any]] = None,
    stdin_symbolic: Optional[int] = None,
    symbolic_memory: Optional[List[Dict[str, Any]]] = None,
    symbolic_registers: Optional[List[Dict[str, Any]]] = None,
    stack_mutations: Optional[List[Dict[str, Any]]] = None,
    filesystem: Optional[List[Dict[str, Any]]] = None,
    add_options: Optional[Iterable[Any]] = None,
    remove_options: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    """Create and register a symbolic execution state for the given project.

    Build narrow states that reflect the exact execution slice you care about:
    pick the closest factory (`"entry"`, `"blank"`, etc.), introduce only the
    necessary symbolic data, and keep everything else concrete so subsequent
    searches stay tractable.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        kind: Requested factory entry point (``"entry"``, ``"full_init"`` or ``"blank"``).
        addr: Explicit program counter when ``kind`` is ``"blank"``.
        args: Positional arguments for ``blank_state`` factories.
        argv: Command-line arguments used by ``entry_state``/``full_init_state``.
        env: Mapping of environment variables to seed into the process.
        stdin_symbolic: Number of symbolic bytes to create on standard input.
        symbolic_memory: List of memory descriptors. Each descriptor must provide
            ``address`` and ``size`` plus either a concrete ``bytes_b64`` payload or a
            ``symbolic`` specification with ``label`` and optional ``bits``.
        symbolic_registers: Register mutation descriptors with ``name`` and either a
            concrete ``value`` or ``symbolic`` specification.
        stack_mutations: Stack slot adjustments expressed as dictionaries accepted by
            :func:`mutate_state` (offset, size, value/symbolic).
        filesystem: Virtual file descriptors to pre-populate. Provide ``path`` plus
            either concrete ``content`` (via ``bytes_b64`` or ``string``) or a
            ``symbolic`` specification, along with optional ``perm`` and ``size``.
        add_options: Additional angr state options to enable.
        remove_options: angr state options to disable before returning the state.

    Returns:
        Dictionary with the new ``state_id`` and register snapshots. When symbolic data
        was created, a ``symbolic`` block summarises the generated handles.
    """

    return SERVER.setup_symbolic_context(
        project_id,
        kind=kind,
        addr=addr,
        args=args,
        argv=argv,
        env=env,
        stdin_symbolic=stdin_symbolic,
        symbolic_memory=symbolic_memory,
        symbolic_registers=symbolic_registers,
        stack_mutations=stack_mutations,
        filesystem=filesystem,
        add_options=add_options,
        remove_options=remove_options,
    )


@mcp.tool()
def instrument_environment(
    project_id: str,
    hooks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Install simprocedures or Python callables at specific addresses or symbols.

    Hook only the routines that impact your chosen path (e.g., stubbing I/O)
    so you can focus the symbolic executor on the reachability question at hand.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        hooks: Sequence of hook definitions. Each entry accepts ``address`` or ``symbol``
            plus one of:
                - ``simprocedure``: ``"library.Procedure"`` name or class reference.
                - ``python_callable``: Callable object to invoke when the hook triggers.
            Optional keys include ``hook_id`` (stable identifier), ``length`` for
            callsite trampolines, and ``simprocedure_args``/``simprocedure_kwargs``.

    Returns:
        Mapping of applied ``hook_id`` values to their address/symbol metadata.
    """

    return SERVER.instrument_environment(project_id, hooks)


@mcp.tool()
def mutate_state(
    project_id: str,
    state_id: str,
    *,
    registers: Optional[List[Dict[str, Any]]] = None,
    stack: Optional[List[Dict[str, Any]]] = None,
    memory: Optional[List[Dict[str, Any]]] = None,
    add_options: Optional[Iterable[Any]] = None,
    remove_options: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    """Apply register, stack, memory, or option mutations to a recorded state.

    Use this after initial setup to incrementally steer a state—forcing concrete
    preconditions, introducing fresh symbols, or toggling options before you
    resume a budgeted exploration.

    Args:
        project_id: Project identifier returned by :func:`load_project`.
        state_id: State identifier created by :func:`setup_symbolic_context` or
            :func:`run_symbolic_search`.
        registers: Register mutation descriptors such as ``{"name": "rax", "value": 0}``
            or ``{"name": "rdi", "symbolic": {"label": "arg0", "bits": 64}}``.
        stack: Stack slot specifications with ``offset`` relative to SP, ``size``, and
            either a concrete ``value`` or ``symbolic`` metadata.
        memory: Memory write descriptors with ``address`` and ``size`` plus ``value``
            (integer) or ``symbolic`` specification analogous to register mutations.
        add_options: Extra angr state options to enable after mutations.
        remove_options: angr state options to disable after mutations.

    Returns:
        Dictionary summarising applied mutations. Symbolic writes include generated
        handles under the ``symbolic`` key.
    """

    return SERVER.mutate_state(
        project_id,
        state_id,
        registers=registers,
        stack=stack,
        memory=memory,
        add_options=add_options,
        remove_options=remove_options,
    )


@mcp.tool()
def add_constraints(
    project_id: str,
    state_id: str,
    constraints: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Add solver constraints to a state.

    Tighten the search space between exploration bursts by pinning values or
    relating symbolic bytes discovered earlier to new requirements.

    Args:
        project_id: Project identifier returned by :func:`load_project`.
        state_id: State identifier to mutate.
        constraints: Sequence of constraint descriptors. Supported ``kind`` values are
            ``"expression"`` (supply ``expression`` AST), ``"symbol"`` (reference a
            stored handle), ``"memory"`` (requires ``address`` and ``size``), and
            ``"register"`` (requires ``name``). Non-expression constraints must also
            provide an ``equals`` value, which can be an integer, bytes (raw/``bytes_b64``),
            string, or symbolic handle descriptor.

    Returns:
        Dictionary reporting how many constraints were applied and the descriptors that
        were accepted.
    """

    return SERVER.add_constraints(project_id, state_id, constraints)


@mcp.tool()
def run_symbolic_search(
    project_id: str,
    *,
    state_id: Optional[str] = None,
    simgr_id: Optional[str] = None,
    job_id: Optional[str] = None,
    mode: str = "explore",
    find: Optional[List[int]] = None,
    avoid: Optional[List[int]] = None,
    step_count: int = 1,
    techniques: Optional[List[str]] = None,
    state_budget: Optional[int] = None,
    budget_stashes: Optional[Sequence[str]] = None,
    persist_job: bool = False,
    job_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Advance symbolic execution from a state or simulation manager.

    Use this when you need block-by-block reachability instead of whole-function
    views. Symbolic execution will traverse concrete basic blocks, revealing the
    precise branch predicates and successor states that static decompilation
    glosses over. Tip: treat the run as a bounded, repeatable step—always set
    ``state_budget`` (and optionally ``budget_stashes``) so the solver cannot
    explode on large programs, and consider ``persist_job=True`` to resume the
    run in short, controlled bursts (e.g. 100–200 total states at a time).

    Args:
        project_id: Identifier returned by :func:`load_project`.
        state_id: Resume from a specific state registered in the project.
        simgr_id: Resume from an existing simulation manager.
        job_id: Reuse metadata from a persisted job (also rehydrates disk snapshots).
        mode: Symbolic execution strategy. ``"explore"`` respects ``find``/``avoid``
            predicates; ``"step"`` performs raw stepping.
        find: Predicate descriptors for success states. Provide either integer addresses
            or structured predicates matching those accepted during schema-based usage.
        avoid: Predicate descriptors for states to discard.
        step_count: Number of steps to perform when ``mode`` is ``"step"``.
        techniques: Exploration techniques to enable (e.g. ``"veritesting"``).
        state_budget: Maximum total states allowed before raising ``StateBudgetExceeded``.
        budget_stashes: Specific stashes to include when enforcing ``state_budget``.
        persist_job: When true, snapshot the run to ``.mcp_jobs`` for future resumption.
        job_metadata: Arbitrary metadata to attach to the recorded job entry.

    Returns:
        Dictionary containing a ``run`` payload with stash membership, predicate matches,
        alert summaries, and job identifiers for subsequent calls.
    """

    return SERVER.run_symbolic_search(
        project_id,
        state_id=state_id,
        simgr_id=simgr_id,
        job_id=job_id,
        mode=mode,
        find=find,
        avoid=avoid,
        step_count=step_count,
        techniques=techniques,
        state_budget=state_budget,
        budget_stashes=budget_stashes,
        persist_job=persist_job,
        job_metadata=job_metadata,
    )


@mcp.tool()
def run_taint_analysis(
    project_id: str,
    *,
    state_id: str,
    tracker_options: Optional[Dict[str, Any]] = None,
    sources: Optional[Sequence[Dict[str, Any]]] = None,
    sinks: Optional[Sequence[Dict[str, Any]]] = None,
    use_dfs: bool = True,
    techniques: Optional[Sequence[str]] = None,
    stop_on_first_hit: bool = False,
    max_sink_hits: Optional[int] = None,
    state_budget: Optional[int] = None,
    budget_stashes: Optional[Sequence[str]] = None,
    max_steps: Optional[int] = None,
) -> Dict[str, Any]:
    """Track how tainted data flows through the program.

    Use this when you need to prove that attacker-controlled bytes reach a
    sensitive sink (format string, indirect jump, pointer dereference, etc.).
    Mark one or more *sources* that should be tainted (memory, registers, or
    pointers that get re-tainted on writes), then describe *sinks* by giving
    the block address and what must be tainted at that moment. The server runs
    a taint-aware symbolic execution, logs every sink hit (with the state ID
    you can inspect later), and returns a summary of the propagation.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        state_id: Base state identifier created via :func:`setup_symbolic_context`.
        tracker_options: Keyword arguments forwarded to :class:`TaintTracker`.
        sources: List of taint source descriptors. Supported kinds:
            ``"memory"`` (requires ``address`` and optional ``size``/``monitor_writes``)
            or ``"register"`` (requires ``name`` and optional ``bits``).
        sinks: List of sink descriptors. Each entry requires ``address`` and optional
            ``checks`` describing what should be tainted (``register``, ``memory``,
            or ``pointer`` dereferences). ``mode`` controls whether *any* or *all*
            checks must be tainted.
        use_dfs: Enable the bundled DFS exploration technique for tighter search.
        techniques: Additional exploration techniques (by name) to stack with taint tracking.
        stop_on_first_hit: Stop execution after the first sink triggers.
        max_sink_hits: Hard cap on recorded sink hits; execution stops at the limit.
        state_budget: Optional state budget enforced via :class:`StateBudgetLimiter`.
        budget_stashes: Stashes counted toward ``state_budget``.
        max_steps: Maximum number of simulation steps before stopping.

    Returns:
        A payload containing the symbolic run metadata plus a ``taint`` block with
        configured sources/sinks and every recorded sink hit (each tied to a new state_id).
    """

    return SERVER.run_taint_analysis(
        project_id,
        state_id=state_id,
        tracker_options=tracker_options,
        sources=sources,
        sinks=sinks,
        use_dfs=use_dfs,
        techniques=techniques,
        stop_on_first_hit=stop_on_first_hit,
        max_sink_hits=max_sink_hits,
        state_budget=state_budget,
        budget_stashes=budget_stashes,
        max_steps=max_steps,
    )


@mcp.tool()
def monitor_for_vulns(
    project_id: str,
    state_id: str,
    events: List[str],
) -> Dict[str, Any]:
    """Register angr inspector callbacks that report high-risk runtime events.

    Attach monitors to the specific state you plan to explore so each bounded
    search run yields exploit-relevant telemetry without re-running analyses.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        state_id: State identifier to monitor.
        events: List of angr breakpoint names (e.g. ``"mem_write"``) to observe.

    Returns:
        Dictionary echoing the events that are now monitored for the given state.
    """

    return SERVER.monitor_for_vulns(project_id, state_id, events)


@mcp.tool()
def list_jobs(project_id: str) -> Dict[str, Any]:
    """List symbolic execution jobs recorded for the given project.

    Budgeted searches produce many short runs; use this to enumerate saved
    snapshots that you can resume or prune later.

    Args:
        project_id: Identifier returned by :func:`load_project`.

    Returns:
        Dictionary containing ``jobs`` with their metadata and tracked state IDs.
    """

    return SERVER.list_jobs(project_id)


@mcp.tool()
def resume_job(project_id: str, job_id: str) -> Dict[str, Any]:
    """Reload a previously recorded symbolic execution job.

    Rehydrate a persisted search chunk (created via ``persist_job=True``) so
    you can keep exploring a path without restarting from the binary entry.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        job_id: Job identifier returned by :func:`run_symbolic_search` or :func:`list_jobs`.

    Returns:
        Dictionary with the ``job`` metadata and a ``simgr_id`` ready for resuming
        execution.
    """

    return SERVER.resume_job(project_id, job_id)


@mcp.tool()
def delete_job(
    project_id: str,
    job_id: str,
    *,
    remove_disk: bool = False,
) -> Dict[str, Any]:
    """Delete a recorded job and optionally remove its persisted snapshot.

    Clean up exploration branches you no longer need once you have extracted
    the relevant path or inputs.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        job_id: Identifier of the job to delete.
        remove_disk: When true, delete the associated ``.mcp_jobs`` snapshot if present.

    Returns:
        Dictionary with the ``deleted`` job identifier.
    """

    return SERVER.delete_job(project_id, job_id, remove_disk=remove_disk)


@mcp.tool()
def inspect_state(
    project_id: str,
    state_id: str,
    *,
    registers: Optional[List[str]] = None,
    memory: Optional[List[Dict[str, int]]] = None,
    include_constraints: bool = False,
    include_events: bool = False,
    include_alerts: bool = False,
    include_globals: bool = False,
    globals_keys: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Summarise a recorded state, including registers, memory, constraints, and alerts.

    Call this between exploration bursts to checkpoint progress, extract alert
    logs, or pull register/memory snapshots before adding fresh constraints.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        state_id: State identifier to inspect.
        registers: List of register names to read concretely.
        memory: List of dictionaries with ``address`` and ``size`` describing memory reads.
        include_constraints: Include stringified solver constraints in the response.
        include_events: Include monitor events captured via :func:`monitor_for_vulns`.
        include_alerts: Include structured alerts such as unconstrained instruction pointer
            detections.
        include_globals: Include the ``state.globals`` mapping. Use ``globals_keys`` to
            narrow the response.
        globals_keys: Optional subset of keys from ``state.globals`` to include.

    Returns:
        Dictionary with the requested sections (``registers``, ``memory``, ``constraints``,
        ``events``, ``alerts``, ``globals``).
    """

    return SERVER.inspect_state(
        project_id,
        state_id,
        registers=registers,
        memory=memory,
        include_constraints=include_constraints,
        include_events=include_events,
        include_alerts=include_alerts,
        include_globals=include_globals,
        globals_keys=globals_keys,
    )


@mcp.tool()
def solve_constraints(
    project_id: str,
    state_id: str,
    queries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Evaluate symbolic expressions for the given state.

    Use solver queries to extract concrete witnesses (inputs, register values)
    once a bounded run reaches the desired state, then feed them back into
    native repro or further constraint tightening.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        state_id: State identifier containing the solver context.
        queries: Sequence of solver queries. Supported ``kind`` values are ``"memory"``,
            ``"register"``, and ``"symbol"``. Provide ``address``/``size`` for memory,
            ``name`` for register, or ``handle`` for symbolic handles. Optional keys
            include ``minmax`` (bool) and ``format``/``include_bytes`` to request
            base64-encoded bytes.

    Returns:
        Dictionary containing concrete values (integers) and optional byte payloads for
        each query.
    """

    return SERVER.solve_constraints(project_id, state_id, queries)


@mcp.tool()
def analyze_call_chain(
    project_id: str,
    *,
    source: Optional[Dict[str, Any]] = None,
    target: Optional[Dict[str, Any]] = None,
    max_paths: int = 10,
    max_depth: Optional[int] = None,
) -> Dict[str, Any]:
    """Return call-graph paths between two locations, caching underlying CFG results.

    Static tools surface entire functions; this call narrows the search to the
    chain of basic blocks that actually connect your source and target. Use it
    to carve the CFG into bite-sized segments before launching symbolic runs on
    those blocks.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        source: Location descriptor with ``address`` or ``symbol`` to start from. If not
            provided, the project's entry point is used.
        target: Location descriptor with ``address`` or ``symbol``. Defaults to the main
            function when omitted.
        max_paths: Maximum number of simple paths to enumerate.
        max_depth: Optional depth limit for path enumeration.

    Returns:
        Dictionary summarising discovered paths, adjacency information, and statistics
        about the cached CFG.
    """

    return SERVER.analyze_call_chain(
        project_id,
        source=source,
        target=target,
        max_paths=max_paths,
        max_depth=max_depth,
    )


@mcp.tool()
def trace_dataflow(
    project_id: str,
    *,
    target_addr: int,
    target_stmt: int = -1,
    use_ddg: bool = False,
    use_cdg: bool = False,
) -> Dict[str, Any]:
    """Compute a backward slice rooted at the given address and statement index.

    Combine this block-scoped slice with ``analyze_call_chain`` to highlight the
    exact predecessors and data dependencies that feed your target. It turns
    broad, function-level dumps into concrete constraints you can check with
    short symbolic runs.

    Args:
        project_id: Identifier returned by :func:`load_project`.
        target_addr: Program counter to slice from.
        target_stmt: Specific VEX statement index within the basic block (``-1`` selects
            every statement).
        use_ddg: Include the data dependence graph in the slice.
        use_cdg: Include the control dependence graph in the slice.

    Returns:
        Dictionary containing nodes that participate in the slice (CFG, CDG/DDG) and any
        chosen statements or exits when available.
    """

    return SERVER.trace_dataflow(
        project_id,
        target_addr=target_addr,
        target_stmt=target_stmt,
        use_ddg=use_ddg,
        use_cdg=use_cdg,
    )


__all__ = [
    "mcp",
    "SERVER",
    "load_project",
    "setup_symbolic_context",
    "instrument_environment",
    "mutate_state",
    "add_constraints",
    "run_symbolic_search",
    "monitor_for_vulns",
    "list_jobs",
    "resume_job",
    "delete_job",
    "inspect_state",
    "solve_constraints",
    "analyze_call_chain",
    "trace_dataflow",
]

import r2pipe
import networkx as nx
from pathlib import Path

BIN = "/tmp/vuln/vuln_server"
TARGET = "0x11a9"   # can be address: "0x401020" or function name

# BIN = "/tmp/vuln/vuln_file"
# TARGET = "0x00403993"   # can be address: "0x401020" or function name

r2 = r2pipe.open(BIN)
r2.cmd("e scr.color=false")  # keep decompiler output plain
r2.cmd("aaa")


def resolve_target(t):
    if t.startswith("0x"):
        return int(t, 16)
    funcs = r2.cmdj("aflj") or []
    for f in funcs:
        if f["name"] == t:
            return f["offset"]
    raise ValueError("Target not found: " + t)


def get_function_info(addr):
    info = r2.cmdj(f"afij @ {addr}") or []
    return info[0] if info else None


def get_function_start(addr):
    fi = get_function_info(addr)
    return fi["offset"] if fi else None


def get_function_name(addr):
    fi = get_function_info(addr)
    return fi["name"] if fi else None


target_entry = resolve_target(TARGET)

G = nx.DiGraph()
visited = set()
target_node = hex(target_entry)


def walk(target_func_start):
    fi = get_function_info(target_func_start)
    if not fi:
        return

    # use function start address as the canonical node id
    target_addr = fi["offset"]

    if target_addr in visited:
        return
    visited.add(target_addr)

    # ensure the callee node exists even if no callers are discovered
    G.add_node(hex(target_addr))

    # only "CALL" xrefs to the function entry
    xrefs = [
        x for x in (r2.cmdj(f"axtj @ {target_func_start}") or [])
        if x.get("type") == "CALL"
    ]

    for x in xrefs:
        callsite = x["from"]
        caller_info = get_function_info(callsite)
        if not caller_info:
            continue

        caller_start = caller_info["offset"]

        # store nodes as hex addresses to satisfy visualization requirement
        caller_node = hex(caller_start)
        callee_node = hex(target_addr)

        # function-level edge caller -> callee
        G.add_edge(caller_node, callee_node)

        # recurse on caller
        walk(caller_start)


walk(target_entry)

print("Functions:", len(G.nodes))
print("Edges:", len(G.edges))
nx.drawing.nx_pydot.write_dot(G, "func_calls_to_TARGET.dot")


# ---- decompilation utilities ----

def decompile_function(addr):
    """
    Decompile the function at the given address using r2ghidra-dec (pdg).
    Returns the plain-text decompiled code.
    """
    r2.cmd(f"s {addr}")
    return r2.cmd("pdg")


def write_path_decomp(path_nodes, path_idx, output_dir):
    """
    Decompile every function along a single caller->...->target path and
    write them (in call order) to a dedicated file.
    """
    parts = []
    for node in path_nodes:
        addr_int = int(node, 16)
        name = get_function_name(addr_int) or node
        code = decompile_function(node)
        header = f"// {name} @ {node}\n"
        parts.append(header + code.strip() + "\n\n")

    outfile = output_dir / f"path_{path_idx}_to_{target_node}.c"
    outfile.write_text("".join(parts))
    print(f"[+] Wrote {outfile}")


# ---- enumerate paths and emit decompilations ----

def emit_path_decompilations():
    output_dir = Path("path_decompilations")
    output_dir.mkdir(exist_ok=True)

    # roots = callers that are not themselves called (graph sources)
    roots = [n for n in G.nodes if G.in_degree(n) == 0]
    if not roots:
        roots = [target_node]  # degenerate case: only the target

    if target_node not in G:
        print("Target node missing from graph; nothing to decompile.")
        return

    path_count = 0
    for root in roots:
        for path in nx.all_simple_paths(G, source=root, target=target_node):
            path_count += 1
            write_path_decomp(path, path_count, output_dir)

    print(f"Total unique paths decompiled: {path_count}")


emit_path_decompilations()

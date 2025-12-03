import r2pipe
import networkx as nx

# BIN = "/tmp/vuln/vuln_server"
# TARGET = "0x11a9"   # can be address: "0x401020" or function name

BIN = "/tmp/vuln/vuln_file"
TARGET = "0x00403993"   # can be address: "0x401020" or function name

r2 = r2pipe.open(BIN)
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

import r2pipe
import networkx as nx

BIN = "/tmp/vuln/vuln_server"
TARGET = "0x11a9"   # can be address: "0x401020" or function name

r2 = r2pipe.open(BIN)
r2.cmd("aaa")   # full analysis

# resolve symbol name to address
def resolve_target(t):
    if t.startswith("0x"):
        return int(t, 16)
    funcs = r2.cmdj("aflj")
    for f in funcs:
        if f["name"] == t:
            return f["offset"]
    raise ValueError("Target not found")

target_addr = resolve_target(TARGET)

# Recursively collect XREFs-to graph
G = nx.DiGraph()
visited = set()

def walk(addr):
    if addr in visited:
        return
    visited.add(addr)

    xrefs = r2.cmdj(f"axtj @ {addr}") or []
    for x in xrefs:
        src = hex(x["from"])
        G.add_edge(src, hex(addr))
        walk(src)

walk(target_addr)

print("Nodes:", len(G.nodes))
print("Edges:", len(G.edges))

# Optional: export DOT for visualization
nx.drawing.nx_pydot.write_dot(G, "xref_to.dot")


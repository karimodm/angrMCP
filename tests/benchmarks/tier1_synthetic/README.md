# Tier 1: Synthetic Smoke Test

## Description
This is a simple "smoke test" to verify that the Angr/Ghidra MCP workflow is functioning correctly.

**Target**: `vuln_server`
**Vulnerability**: Stack-based buffer overflow via `read()` into a fixed-size buffer.

## Goal
The LLM should:
1.  Identify the `read` call as a potential sink using Ghidra MCP.
2.  Use Angr MCP to prove that user input from `stdin` can overflow the buffer.
3.  (Optional) Generate an input that crashes the program or overwrites the return address.

## Build & Run
```bash
docker build -t tier1-vuln .
docker run -it tier1-vuln
```

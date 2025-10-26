from __future__ import annotations

import base64
import errno
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
from typing import Iterable, List, Tuple

import angr
import claripy

from angr_mcp import AngrMCPServer
from angr_mcp.registry import registry
from angr_mcp.utils import (
    SYMBOL_STORE_KEY,
    extract_uppercase_tokens,
    find_call_to_symbol,
    new_symbolic_bitvector,
    read_section_bytes,
)


def _decode_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def _skip_if_native_unavailable(exc: OSError) -> None:
    if exc.errno in {errno.ENOENT, errno.ELIBBAD, errno.ENOEXEC}:
        raise unittest.SkipTest(f"native execution unavailable: {exc}") from exc
    raise


class PhaseTwoCTFTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solutions_root = pathlib.Path("resources/angr_ctf/solutions")
        if not cls.solutions_root.exists():
            raise unittest.SkipTest("angr_ctf solutions directory not available")

        cls.binary_map = {
            "05_angr_symbolic_memory": cls.solutions_root / "05_angr_symbolic_memory" / "05_angr_symbolic_memory",
            "06_angr_symbolic_dynamic_memory": cls.solutions_root
            / "06_angr_symbolic_dynamic_memory"
            / "06_angr_symbolic_dynamic_memory",
            "07_angr_symbolic_file": cls.solutions_root / "07_angr_symbolic_file" / "07_angr_symbolic_file",
            "08_angr_constraints": cls.solutions_root / "08_angr_constraints" / "08_angr_constraints",
            "09_angr_hooks": cls.solutions_root / "09_angr_hooks" / "09_angr_hooks",
            "10_angr_simprocedures": cls.solutions_root / "10_angr_simprocedures" / "10_angr_simprocedures",
            "11_angr_sim_scanf": cls.solutions_root / "11_angr_sim_scanf" / "11_angr_sim_scanf",
            "12_angr_veritesting": cls.solutions_root / "12_angr_veritesting" / "12_angr_veritesting",
        }

        missing = [lvl for lvl, path in cls.binary_map.items() if not path.exists()]
        if missing:
            raise unittest.SkipTest(f"missing prebuilt binaries: {', '.join(missing)}")

    def setUp(self) -> None:
        registry.reset()
        self.server = AngrMCPServer()

    def tearDown(self) -> None:
        registry.reset()
        job_dir = pathlib.Path(".mcp_jobs")
        if job_dir.exists():
            for entry in job_dir.iterdir():
                entry.unlink()
            job_dir.rmdir()

    # ------------------------------------------------------------------
    def _load_level(self, level: str, *, auto_load_libs: bool = False) -> Tuple[str, angr.Project]:
        binary_path = self.binary_map[level]
        load_result = self.server.load_project(str(binary_path), auto_load_libs=auto_load_libs)
        project_id = load_result["project_id"]
        project = registry.get_project(project_id).project
        return project_id, project

    def _assert_runs_natively(
        self,
        level: str,
        stdin_payload: bytes,
        expected_substring: bytes,
        *,
        files: Iterable[Tuple[str, bytes]] | None = None,
    ) -> None:
        binary_path = self.binary_map[level]
        if files:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = pathlib.Path(tmpdir)
                tmp_binary = tmp_path / binary_path.name
                tmp_binary.write_bytes(binary_path.read_bytes())
                for relpath, content in files:
                    file_path = tmp_path / relpath
                    file_path.write_bytes(content)
                try:
                    proc = subprocess.run(
                        [str(tmp_binary)],
                        input=stdin_payload,
                        capture_output=True,
                        check=True,
                        cwd=tmp_path,
                    )
                except FileNotFoundError as exc:
                    raise unittest.SkipTest(f"native binary missing: {exc}") from exc
                except OSError as exc:
                    _skip_if_native_unavailable(exc)
                except subprocess.CalledProcessError as exc:
                    self.fail(f"native execution failed: {exc.stderr.decode(errors='ignore')}")
                else:
                    self.assertIn(
                        expected_substring,
                        proc.stdout,
                        "native execution stdout mismatch",
                    )
                return

        try:
            proc = subprocess.run(
                [str(binary_path)],
                input=stdin_payload,
                capture_output=True,
                check=True,
            )
        except FileNotFoundError as exc:
            raise unittest.SkipTest(f"native binary missing: {exc}") from exc
        except OSError as exc:  # missing interpreter / incompatible arch
            _skip_if_native_unavailable(exc)
        except subprocess.CalledProcessError as exc:
            self.fail(f"native execution failed: {exc.stderr.decode(errors='ignore')}")
        else:
            self.assertIn(
                expected_substring,
                proc.stdout,
                "native execution stdout mismatch",
            )

    @staticmethod
    def _address_after_call(
        project: angr.Project,
        caller_symbol: str,
        callee_symbol: str,
        *,
        occurrence: int = 0,
    ) -> int:
        addr, size = find_call_to_symbol(project, caller_symbol, callee_symbol, occurrence=occurrence)
        return addr + size

    # ------------------------------------------------------------------
    def test_level05_symbolic_memory(self) -> None:
        project_id, project = self._load_level("05_angr_symbolic_memory")

        after_scanf = self._address_after_call(project, "main", "__isoc99_scanf")
        symbol = project.loader.find_symbol("user_input")
        self.assertIsNotNone(symbol, "expected user_input symbol")
        base_addr = symbol.rebased_addr

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="blank",
            addr=after_scanf,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
            symbolic_memory=[
                {"address": base_addr + (index * 8), "size": 8, "label": f"chunk_{index}"}
                for index in range(4)
            ],
        )
        state_id = setup["state_id"]
        mem_handles = [entry["handle"] for entry in setup.get("symbolic", {}).get("memory", [])]
        self.assertEqual(len(mem_handles), 4, "expected four symbolic memory handles")

        self.server.instrument_environment(
            project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids, "expected a found state")
        found_state_id = found_ids[0]

        solution_chunks: List[str] = []
        query_payload = [
            {"kind": "symbol", "handle": handle, "format": "bytes"}
            for handle in mem_handles
        ]
        solved = self.server.solve_constraints(project_id, found_state_id, query_payload)
        for item in solved["results"]:
            self.assertIn("bytes_b64", item)
            chunk = _decode_b64(item["bytes_b64"]).decode("ascii")
            solution_chunks.append(chunk.strip("\x00"))

        joined_solution = " ".join(solution_chunks)

        for chunk in solution_chunks:
            self.assertEqual(len(chunk), 8)
            self.assertTrue(chunk.isupper())

        stdout_blob = run["run"]["streams"][found_state_id]["stdout"]
        self.assertIn(b"Good Job.", _decode_b64(stdout_blob))

        self._assert_runs_natively(
            "05_angr_symbolic_memory",
            joined_solution.encode("ascii") + b"\n",
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level06_symbolic_dynamic_memory(self) -> None:
        project_id, project = self._load_level("06_angr_symbolic_dynamic_memory")

        after_second_scanf = self._address_after_call(
            project,
            "main",
            "__isoc99_scanf",
            occurrence=0,
        )

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="blank",
            addr=after_second_scanf,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

        buffer_symbols = [
            project.loader.find_symbol(name) for name in ("buffer0", "buffer1")
        ]
        for idx, symbol in enumerate(buffer_symbols):
            self.assertIsNotNone(symbol, f"expected buffer{idx} symbol")

        fake_heap_base = 0x40444440
        heap_addresses = [fake_heap_base, fake_heap_base + 0x10]
        pointer_specs = []
        symbolic_specs = []
        for index, symbol in enumerate(buffer_symbols):
            ptr_addr = symbol.rebased_addr
            fake_addr = heap_addresses[index]
            pointer_specs.append({"address": ptr_addr, "size": 4, "value": fake_addr})
            symbolic_specs.append(
                {"address": fake_addr, "size": 8, "symbolic": {"label": f"chunk_{index}"}}
            )

        mutation = self.server.mutate_state(
            project_id,
            state_id,
            memory=pointer_specs + symbolic_specs,
        )
        memory_symbols = mutation.get("symbolic", {}).get("memory", [])
        self.assertEqual(len(memory_symbols), 2, "expected two symbolic heap handles")
        handles = [entry["handle"] for entry in memory_symbols]

        strncmp_addr, strncmp_size = find_call_to_symbol(project, "main", "strncmp")
        post_strncmp_addr = strncmp_addr + strncmp_size

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "address", "address": post_strncmp_addr}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids, "expected to reach strncmp call")
        found_state_id = found_ids[0]

        expected_tokens = [token for token, _ in extract_uppercase_tokens(project, exact_length=8)]
        self.assertEqual(len(expected_tokens), 2, "expected two comparison tokens")

        constraint_specs = [
            {
                "kind": "memory",
                "address": heap_addresses[index],
                "size": 8,
                "equals": {"string": expected_tokens[index]},
            }
            for index in range(2)
        ]
        self.server.add_constraints(project_id, found_state_id, constraint_specs)

        solved_inputs = self.server.solve_constraints(
            project_id,
            found_state_id,
            [
                {"kind": "symbol", "handle": handle, "format": "bytes"}
                for handle in handles
            ],
        )
        solver_chunks = [
            _decode_b64(item["bytes_b64"]).decode("ascii").rstrip("\x00")
            for item in solved_inputs["results"]
        ]

        def _invert_token(token: str, base: int) -> str:
            return "".join(
                chr(((ord(ch) - ord("A") - 13 * (base + idx)) % 26) + ord("A"))
                for idx, ch in enumerate(token)
            )

        solution_chunks = [_invert_token(expected_tokens[0], 0), _invert_token(expected_tokens[1], 32)]
        self.assertEqual(len(solution_chunks), 2)
        self.assertEqual(solver_chunks[0], solution_chunks[0])

        success_run = self.server.run_symbolic_search(
            project_id,
            state_id=found_state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
            avoid=[{"kind": "stdout_contains", "text": "Try again."}],
        )
        success_ids = success_run["run"]["found"]
        self.assertTrue(success_ids, "expected constrained state to reach success")
        success_state_id = success_ids[0]
        stdout_blob = success_run["run"]["streams"][success_state_id]["stdout"]
        self.assertIn(b"Good Job.", _decode_b64(stdout_blob))

        native_input = " ".join(solution_chunks).encode("ascii") + b"\n"
        self._assert_runs_natively(
            "06_angr_symbolic_dynamic_memory",
            native_input,
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level07_symbolic_file(self) -> None:
        project_id, project = self._load_level("07_angr_symbolic_file")

        _, rodata = read_section_bytes(project, ".rodata")
        match = re.search(rb"[A-Z]{8}\.txt", rodata)
        self.assertIsNotNone(match, "expected filename literal in .rodata")
        after_fread = self._address_after_call(project, "main", "fread")
        buffer_symbol = project.loader.find_symbol("buffer")
        self.assertIsNotNone(buffer_symbol, "expected global buffer symbol")
        buffer_addr = buffer_symbol.rebased_addr

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="blank",
            addr=after_fread,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
            symbolic_memory=[{"address": buffer_addr, "size": 8, "label": "file_buffer"}],
        )
        state_id = setup["state_id"]
        memory_symbols = setup.get("symbolic", {}).get("memory", [])
        self.assertEqual(len(memory_symbols), 1, "expected a single buffer handle")
        buffer_handle = memory_symbols[0]["handle"]

        # Ensure the ninth byte stays null-terminated for strncmp.
        self.server.mutate_state(
            project_id,
            state_id,
            memory=[{"address": buffer_addr + 8, "size": 1, "value": 0}],
        )

        self.server.instrument_environment(
            project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        expected_tokens = [token for token, _ in extract_uppercase_tokens(project, exact_length=8)]
        self.assertTrue(expected_tokens, "expected transformed token in .rodata")

        self.server.add_constraints(
            project_id,
            state_id,
            [
                {
                    "kind": "memory",
                    "address": buffer_addr,
                    "size": 8,
                    "equals": {"string": expected_tokens[1]},
                }
            ],
        )

        solved = self.server.solve_constraints(
            project_id,
            state_id,
            [{"kind": "symbol", "handle": buffer_handle, "format": "bytes"}],
        )
        transformed = _decode_b64(solved["results"][0]["bytes_b64"])[:8].decode("ascii")
        self.assertEqual(transformed, expected_tokens[1])

        def _invert_token(token: str, lam: int) -> str:
            return "".join(
                chr(((ord(ch) - ord("A") - lam * idx) % 26) + ord("A"))
                for idx, ch in enumerate(token)
            )

        solution = _invert_token(transformed, 17)
        self.assertEqual(len(solution), 8)

        self._assert_runs_natively(
            "07_angr_symbolic_file",
            solution.encode("ascii") + b"\n",
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level08_manual_constraints(self) -> None:
        project_id, project = self._load_level("08_angr_constraints")

        after_scanf = self._address_after_call(project, "main", "__isoc99_scanf")
        buffer_symbol = project.loader.find_symbol("buffer")
        self.assertIsNotNone(buffer_symbol, "expected buffer symbol")
        buffer_addr = buffer_symbol.rebased_addr

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="blank",
            addr=after_scanf,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
            symbolic_memory=[{"address": buffer_addr, "size": 16, "label": "encrypted_buffer"}],
        )
        state_id = setup["state_id"]
        memory_symbols = setup.get("symbolic", {}).get("memory", [])
        self.assertEqual(len(memory_symbols), 1, "expected single buffer handle")
        buffer_handle = memory_symbols[0]["handle"]

        self.server.instrument_environment(
            project_id,
            hooks=[
                {"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"},
                {"symbol": "exit", "simprocedure": "stubs.ReturnUnconstrained"},
            ],
        )

        check_symbol = None
        for sym in project.loader.main_object.symbols:
            if sym.name.startswith("check_equals_"):
                check_symbol = sym
                break
        self.assertIsNotNone(check_symbol, "expected check_equals symbol")
        check_addr, _ = find_call_to_symbol(project, "main", check_symbol.name)

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "address", "address": check_addr}],
            techniques=["veritesting"],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids, "expected to hit check_equals call")
        found_state_id = found_ids[0]

        target_literal = check_symbol.name.replace("check_equals_", "")
        constraint_result = self.server.add_constraints(
            project_id,
            found_state_id,
            [
                {
                    "kind": "symbol",
                    "handle": buffer_handle,
                    "equals": {"string": target_literal},
                }
            ],
        )
        self.assertEqual(constraint_result["count"], 1)

        solved = self.server.solve_constraints(
            project_id,
            found_state_id,
            [{"kind": "symbol", "handle": buffer_handle, "format": "bytes"}],
        )
        candidate_bytes = _decode_b64(solved["results"][0]["bytes_b64"])
        candidate = candidate_bytes.decode("ascii")
        self.assertEqual(len(candidate), 16)

        self._assert_runs_natively(
            "08_angr_constraints",
            candidate.encode("ascii") + b"\n",
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level09_hook_check_equals(self) -> None:
        project_id, project = self._load_level("09_angr_hooks")

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="entry",
            stdin_symbolic=32,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

        check_symbol = None
        for sym in project.loader.main_object.symbols:
            if sym.name.startswith("check_equals_"):
                check_symbol = sym
                break
        self.assertIsNotNone(check_symbol, "expected check_equals symbol")
        check_addr, call_size = find_call_to_symbol(project, "main", check_symbol.name)
        buffer_symbol = project.loader.find_symbol("buffer")
        self.assertIsNotNone(buffer_symbol, "expected buffer symbol")
        buffer_addr = buffer_symbol.rebased_addr
        expected_bytes = check_symbol.name.replace("check_equals_", "").encode("ascii")

        def _hook(state: angr.SimState) -> None:
            current = state.memory.load(buffer_addr, len(expected_bytes))
            state.globals["check_equals_calls"] = state.globals.get("check_equals_calls", 0) + 1
            comparison = claripy.If(
                current == claripy.BVV(expected_bytes),
                claripy.BVV(1, state.arch.bits),
                claripy.BVV(0, state.arch.bits),
            )
            state.regs.eax = comparison

        self.server.instrument_environment(
            project_id,
            hooks=[
                {"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"},
                {"address": check_addr, "python_callable": _hook, "length": call_size},
            ],
        )

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids, "expected a found state")
        found_state_id = found_ids[0]

        globals_payload = self.server.inspect_state(
            project_id,
            found_state_id,
            include_globals=True,
            globals_keys=["check_equals_calls", SYMBOL_STORE_KEY],
        )
        calls = globals_payload.get("globals", {}).get("check_equals_calls", 0)
        self.assertEqual(calls, 1, "expected hook to execute exactly once")

        state = registry.get_state(project_id, found_state_id)
        stdin_bytes = state.posix.dumps(0).split(b"\n", 1)[0]
        solution_str = stdin_bytes.decode("ascii")
        self.assertIn(solution_str, [token for token, _ in extract_uppercase_tokens(project, exact_length=len(solution_str))])

        self._assert_runs_natively(
            "09_angr_hooks",
            solution_str.encode("ascii") + b"\n",
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level10_simprocedure_hook(self) -> None:
        project_id, project = self._load_level("10_angr_simprocedures")

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="entry",
            stdin_symbolic=32,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

        check_symbol = None
        for sym in project.loader.main_object.symbols:
            if sym.name.startswith("check_equals_"):
                check_symbol = sym
                break
        self.assertIsNotNone(check_symbol, "expected check_equals symbol")
        expected_bytes = check_symbol.name.replace("check_equals_", "").encode("ascii")

        class ReplacementCheckEquals(angr.SimProcedure):
            def run(self, to_check, length):  # type: ignore[override]
                data = self.state.memory.load(to_check, length)
                self.state.globals["simproc_calls"] = self.state.globals.get("simproc_calls", 0) + 1
                return claripy.If(
                    data == claripy.BVV(expected_bytes),
                    claripy.BVV(1, self.state.arch.bits),
                    claripy.BVV(0, self.state.arch.bits),
                )

        instrument = self.server.instrument_environment(
            project_id,
            hooks=[
                {"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"},
                {"symbol": check_symbol.name, "simprocedure": ReplacementCheckEquals},
            ],
        )
        hook_entries = instrument["hooks"]
        self.assertTrue(any(entry["symbol"] == check_symbol.name for entry in hook_entries.values()))

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids, "expected a found state")
        found_state_id = found_ids[0]

        globals_payload = self.server.inspect_state(
            project_id,
            found_state_id,
            include_globals=True,
            globals_keys=["simproc_calls"],
        )
        calls = globals_payload.get("globals", {}).get("simproc_calls", 0)
        self.assertGreaterEqual(calls, 1, "expected SimProcedure to run")

        state = registry.get_state(project_id, found_state_id)
        stdin_bytes = state.posix.dumps(0).split(b"\n", 1)[0]
        solution = stdin_bytes.decode("ascii")

        self._assert_runs_natively(
            "10_angr_simprocedures",
            solution.encode("ascii") + b"\n",
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level11_simulated_scanf(self) -> None:
        project_id, project = self._load_level("11_angr_sim_scanf")

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="entry",
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

        class ReplacementScanf(angr.SimProcedure):
            def run(self, fmt, dest0, dest1):  # type: ignore[override]
                value0, meta0 = new_symbolic_bitvector(
                    self.state,
                    "scanf0",
                    32,
                    handle_prefix="scanf",
                )
                value1, meta1 = new_symbolic_bitvector(
                    self.state,
                    "scanf1",
                    32,
                    handle_prefix="scanf",
                )
                self.state.memory.store(dest0, value0, endness=self.state.arch.memory_endness)
                self.state.memory.store(dest1, value1, endness=self.state.arch.memory_endness)
                handles = self.state.globals.setdefault("scanf_handles", [])
                handles.extend([meta0["handle"], meta1["handle"]])
                return claripy.BVV(2, self.state.arch.bits)

        self.server.instrument_environment(
            project_id,
            hooks=[
                {"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"},
                {"symbol": "__isoc99_scanf", "simprocedure": ReplacementScanf},
            ],
        )

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids, "expected a found state")
        found_state_id = found_ids[0]

        globals_payload = self.server.inspect_state(
            project_id,
            found_state_id,
            include_globals=True,
            globals_keys=["scanf_handles", SYMBOL_STORE_KEY],
        )
        handle_list = globals_payload.get("globals", {}).get("scanf_handles")
        self.assertIsInstance(handle_list, list)
        handles = [handle for handle in handle_list if isinstance(handle, str)]
        self.assertEqual(len(handles), 2, "expected two scanf handles")

        solved = self.server.solve_constraints(
            project_id,
            found_state_id,
            [{"kind": "symbol", "handle": handle} for handle in handles],
        )
        values = [item["value"] for item in solved["results"]]
        stdin_payload = f"{values[0]} {values[1]}\n".encode("ascii")

        self._assert_runs_natively(
            "11_angr_sim_scanf",
            stdin_payload,
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level12_veritesting(self) -> None:
        project_id, project = self._load_level("12_angr_veritesting")

        def _make_state() -> Tuple[str, List[str]]:
            setup = self.server.setup_symbolic_context(
                project_id,
                kind="entry",
                stdin_symbolic=32,
                add_options=[
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                ],
            )
            state_id_local = setup["state_id"]
            return state_id_local, [entry["handle"] for entry in setup.get("symbolic", {}).get("stdin", [])]

        state_id_plain, _ = _make_state()
        self.server.instrument_environment(
            project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        run_plain = self.server.run_symbolic_search(
            project_id,
            state_id=state_id_plain,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
            avoid=[{"kind": "stdout_contains", "text": "Try again."}],
        )
        self.assertFalse(run_plain["run"]["found"], "expected no solution without veritesting")

        state_id_veri, _ = _make_state()
        run_veri = self.server.run_symbolic_search(
            project_id,
            state_id=state_id_veri,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
            avoid=[{"kind": "stdout_contains", "text": "Try again."}],
            techniques=["veritesting"],
        )
        found_ids = run_veri["run"]["found"]
        self.assertTrue(found_ids, "expected veritesting-assisted run to succeed")
        found_state_id = found_ids[0]

        state = registry.get_state(project_id, found_state_id)
        stdin_value = state.posix.dumps(0).split(b"\n", 1)[0]
        self.assertTrue(stdin_value, "expected stdin solution")

        expected_tokens = [token for token, _ in extract_uppercase_tokens(project, min_length=4)]
        solution_text = stdin_value.decode("ascii")
        if expected_tokens:
            self.assertTrue(
                any(solution_text.startswith(token) for token in expected_tokens),
                "solution should align with literals",
            )

        self._assert_runs_natively(
            "12_angr_veritesting",
            solution_text.encode("ascii") + b"\n",
            b"Good Job.",
        )

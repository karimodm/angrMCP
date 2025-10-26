from __future__ import annotations

import base64
import errno
import os
import pathlib
import subprocess
import unittest
from typing import Iterable, List

import angr

from angr_mcp.server import AngrMCPServer
from angr_mcp.registry import registry
from angr_mcp.utils import (
    extract_uppercase_tokens,
    find_string_reference_addresses,
)


def _decode_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def _skip_if_native_unavailable(exc: OSError) -> None:
    if exc.errno in {errno.ENOENT, errno.ELIBBAD, errno.ENOEXEC}:
        raise unittest.SkipTest(f"native execution unavailable: {exc}") from exc
    raise


class PhaseOneCTFTests(unittest.TestCase):
    _solution_cache: dict[str, dict[str, object]] = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls.solutions_root = pathlib.Path("resources/angr_ctf/solutions")
        if not cls.solutions_root.exists():
            raise unittest.SkipTest("angr_ctf solutions directory not available")

        cls.binary_map = {
            "00_angr_find": cls.solutions_root / "00_angr_find" / "00_angr_find",
            "01_angr_avoid": cls.solutions_root / "01_angr_avoid" / "01_angr_avoid",
            "02_angr_find_condition": cls.solutions_root / "02_angr_find_condition" / "02_angr_find_condition",
            "03_angr_symbolic_registers": cls.solutions_root
            / "03_angr_symbolic_registers"
            / "03_angr_symbolic_registers",
            "04_angr_symbolic_stack": cls.solutions_root / "04_angr_symbolic_stack" / "04_angr_symbolic_stack",
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
    def _load_level(self, level: str, *, auto_load_libs: bool = False) -> tuple[str, angr.Project]:
        binary_path = self.binary_map[level]
        load_result = self.server.load_project(str(binary_path), auto_load_libs=auto_load_libs)
        project_id = load_result["project_id"]
        project = registry.get_project(project_id).project
        return project_id, project

    def _assert_runs_natively(self, level: str, stdin_payload: bytes, expected_substring: bytes) -> None:
        binary_path = self.binary_map[level]
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

    # ------------------------------------------------------------------
    def test_level00_find_with_stdout_predicate(self) -> None:
        project_id, project = self._load_level("00_angr_find")
        tokens = extract_uppercase_tokens(project, exact_length=8)
        self.assertTrue(tokens, "expected uppercase token in .rodata")
        self.assertEqual(len(tokens), 1, "expected a single candidate token")
        expected_token = tokens[0][0].encode("ascii")

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="entry",
            stdin_symbolic=8,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

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

        stdout_blob = run["run"]["streams"][found_state_id]["stdout"]
        stdout_bytes = _decode_b64(stdout_blob)
        self.assertIn(b"Good Job.", stdout_bytes)

        predicate_matches = run["run"]["predicate_matches"]
        self.assertTrue(
            any(match["role"] == "find" and match["kind"] == "stdout_contains" for match in predicate_matches),
            "expected stdout predicate match to be recorded",
        )

        state = registry.get_state(project_id, found_state_id)
        stdin_bytes = state.posix.dumps(0).rstrip(b"\x00")
        self.assertEqual(len(stdin_bytes), len(expected_token))

        self._assert_runs_natively("00_angr_find", stdin_bytes + b"\n", b"Good Job.")

    # ------------------------------------------------------------------
    def test_level01_find_and_avoid_descriptors(self) -> None:
        project_id, project = self._load_level("01_angr_avoid")

        success_refs = find_string_reference_addresses(project, "Good Job.")
        avoid_refs = find_string_reference_addresses(project, "Try again.")
        self.assertTrue(success_refs, "expected code references to success literal")
        self.assertTrue(avoid_refs, "expected code references to avoid literal")

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="entry",
            stdin_symbolic=8,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

        self.server.instrument_environment(
            project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[
                {"kind": "address", "address": success_refs[0]},
                {"kind": "stdout_contains", "text": "Good Job."},
            ],
            avoid=[
                {"kind": "address", "address": avoid_refs[0]},
                {"kind": "stdout_not_contains", "text": "Try again."},
            ],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids)
        found_state_id = found_ids[0]

        predicate_matches = run["run"]["predicate_matches"]
        self.assertTrue(
            any(match["role"] == "find" and match["kind"].startswith("stdout") for match in predicate_matches),
            "expected stdout-based find predicate to be recorded",
        )
        self.assertTrue(
            any(match["role"] == "avoid" for match in predicate_matches),
            "expected avoid predicates to trigger",
        )

        stdout_blob = run["run"]["streams"][found_state_id]["stdout"]
        self.assertIn(b"Good Job.", _decode_b64(stdout_blob))

        state = registry.get_state(project_id, found_state_id)
        stdin_bytes = state.posix.dumps(0).rstrip(b"\x00")
        self.assertEqual(len(stdin_bytes), 8)

        self._assert_runs_natively("01_angr_avoid", stdin_bytes + b"\n", b"Good Job.")

    # ------------------------------------------------------------------
    def test_level02_stdout_only_predicates(self) -> None:
        result = self._solve_level02()
        self.assertIn(b"Good Job.", result["stdout"])
        self.assertEqual(len(result["stdin"]), 8)
        self.assertTrue(result["found_ids"])
        self.assertIn(result["found_ids"][0], result["stashes"]["found"])
        self.assertTrue(
            all(match["kind"].startswith("stdout") for match in result["predicate_matches"]),
            "expected stdout-only predicate matches",
        )

    def test_level02_native_replay(self) -> None:
        result = self._solve_level02()
        self._assert_runs_natively(
            "02_angr_find_condition",
            result["stdin"] + b"\n",
            b"Good Job.",
        )

    # ------------------------------------------------------------------
    def test_level03_symbolic_register_recovery(self) -> None:
        project_id, project = self._load_level("03_angr_symbolic_registers")

        resume_addr = self._post_call_address(project, "__isoc99_scanf")
        if resume_addr is None or resume_addr < 0x80488C7:
            resume_addr = 0x80488C7

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="blank",
            addr=resume_addr,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
            symbolic_registers=[
                {"name": "eax", "symbolic": {"label": "password0", "bits": 32}},
                {"name": "ebx", "symbolic": {"label": "password1", "bits": 32}},
                {"name": "edx", "symbolic": {"label": "password2", "bits": 32}},
            ],
        )
        state_id = setup["state_id"]
        register_symbols = setup.get("symbolic", {}).get("registers", [])
        handles = [entry["handle"] for entry in register_symbols]
        self.assertEqual(len(handles), 3)

        base_state = registry.get_state(project_id, state_id)
        sp_val = base_state.solver.eval(base_state.regs.sp)
        self.server.mutate_state(
            project_id,
            state_id,
            registers=[{"name": "ebp", "value": sp_val + 36}],
        )

        self.server.instrument_environment(
            project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
            avoid=[{"kind": "stdout_contains", "text": "Try again."}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids)
        found_state_id = found_ids[0]

        solutions = self._solve_symbolic_handles(project_id, found_state_id, handles)
        self.assertEqual(len(solutions), 3)

        payload = "{} {} {}\n".format(*[format(value, "x") for value in solutions]).encode("ascii")
        self._assert_runs_natively("03_angr_symbolic_registers", payload, b"Good Job.")

    # ------------------------------------------------------------------
    def test_level04_symbolic_stack_setup(self) -> None:
        project_id, project = self._load_level("04_angr_symbolic_stack")

        resume_addr = self._post_call_address(project, "__isoc99_scanf")
        if resume_addr is None or resume_addr < 0x80486AE:
            resume_addr = 0x80486AE

        setup = self.server.setup_symbolic_context(
            project_id,
            kind="blank",
            addr=resume_addr,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

        # Align EBP with the current stack pointer, then emulate the stack layout.
        self.server.mutate_state(
            project_id,
            state_id,
            registers=[{"name": "ebp", "copy_from": "sp"}],
        )
        stack_mutation = self.server.mutate_state(
            project_id,
            state_id,
            stack=[
                {"op": "adjust", "delta": -8},
                {"op": "push", "source": {"symbolic": {"label": "password0", "bits": 32}}},
                {"op": "push", "source": {"symbolic": {"label": "password1", "bits": 32}}},
            ],
        )
        stack_symbols = stack_mutation.get("symbolic", {}).get("stack", [])
        handles = [entry["handle"] for entry in stack_symbols]
        self.assertEqual(len(handles), 2)

        base_state = registry.get_state(project_id, state_id)
        sp_val = base_state.solver.eval(base_state.regs.sp)
        # Align EBP before pushing stack values.
        self.server.mutate_state(
            project_id,
            state_id,
            registers=[{"name": "ebp", "value": sp_val + 16}],
        )

        self.server.instrument_environment(
            project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
            avoid=[{"kind": "stdout_contains", "text": "Try again."}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids)
        found_state_id = found_ids[0]

        solutions = self._solve_symbolic_handles(project_id, found_state_id, handles)
        payload = "{} {}\n".format(*solutions).encode("ascii")

        alerts = run["run"]["alerts"]
        self.assertFalse(alerts, "expected no alerts on clean stack manipulation path")

        self._assert_runs_natively("04_angr_symbolic_stack", payload, b"Good Job.")

    # ------------------------------------------------------------------
    def _solve_symbolic_handles(self, project_id: str, state_id: str, handles: Iterable[str]) -> List[int]:
        queries = [{"kind": "symbol", "handle": handle} for handle in handles]
        result = self.server.solve_constraints(project_id, state_id, queries)
        return [entry["value"] for entry in result["results"]]

    def _post_call_address(self, project: angr.Project, symbol_name: str) -> int | None:
        cfg = project.analyses.CFGFast()
        target = project.loader.find_symbol(symbol_name)
        plt_addr = project.loader.main_object.plt.get(symbol_name, None)
        candidate_targets: List[int] = []
        if plt_addr:
            candidate_targets.append(int(plt_addr))
        if target is not None and getattr(target, "rebased_addr", 0):
            candidate_targets.append(int(target.rebased_addr))
        if not candidate_targets:
            return None

        matches: List[int] = []

        for function in cfg.kb.functions.values():
            for block in function.blocks:
                for insn in block.capstone.insns:
                    if insn.insn_name() != "call":
                        continue
                    operands = getattr(insn, "operands", [])
                    if not operands:
                        continue
                    operand = operands[-1]
                    if not hasattr(operand, "imm"):
                        continue
                    if int(getattr(operand, "imm", 0)) not in candidate_targets:
                        continue

                    successor = insn.address + insn.size
                    best_match = successor
                    for follow_block in function.blocks:
                        capstone_block = getattr(follow_block, "capstone", None)
                        if capstone_block is None:
                            continue
                        for next_insn in capstone_block.insns:
                            if next_insn.address < successor:
                                continue
                            if next_insn.insn_name() == "mov" and "ebp -" in next_insn.op_str:
                                best_match = next_insn.address
                                break
                        else:
                            continue
                        break
                    matches.append(best_match)

        if matches:
            return max(matches)
        return None

    def _solve_level02(self) -> dict[str, object]:
        cache_key = "level02"
        if cache_key in self._solution_cache:
            return self._solution_cache[cache_key]

        project_id, _ = self._load_level("02_angr_find_condition")
        setup = self.server.setup_symbolic_context(
            project_id,
            kind="entry",
            stdin_symbolic=8,
            add_options=[
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            ],
        )
        state_id = setup["state_id"]

        self.server.instrument_environment(
            project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        run = self.server.run_symbolic_search(
            project_id,
            state_id=state_id,
            mode="explore",
            find=[{"kind": "stdout_contains", "text": "Good Job."}],
            avoid=[{"kind": "stdout_contains", "text": "Try again."}],
        )
        found_ids = run["run"]["found"]
        self.assertTrue(found_ids, "expected level02 search to locate a solution state")
        found_state_id = found_ids[0]

        stdout_data = _decode_b64(run["run"]["streams"][found_state_id]["stdout"])
        state = registry.get_state(project_id, found_state_id)
        stdin_bytes = state.posix.dumps(0).rstrip(b"\x00")

        payload = {
            "stdin": stdin_bytes,
            "stdout": stdout_data,
            "predicate_matches": run["run"]["predicate_matches"],
            "stashes": run["run"]["stashes"],
            "found_ids": found_ids,
        }
        self._solution_cache[cache_key] = payload
        return payload


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

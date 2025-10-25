from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from angr_mcp import AngrMCPServer
from angr_mcp.registry import registry


class TestAngrMCPServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("C compiler required for integration tests")

        cls.compiler = compiler
        cls.build_dir = tempfile.mkdtemp(prefix="mcp_bin_")
        cls.binary_path = cls._build_sample_binary(cls.build_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "build_dir") and os.path.isdir(cls.build_dir):
            shutil.rmtree(cls.build_dir)

    @classmethod
    def _build_sample_binary(cls, build_dir: str) -> str:
        source = textwrap.dedent(
            """
            #include <unistd.h>
            #include <stdint.h>

            char flag_buf[4];

            void win(void) {
                write(1, "win\\n", 4);
            }

            int main(void) {
                read(0, flag_buf, sizeof(flag_buf));
                if (flag_buf[0] == 'A' && flag_buf[1] == 'B') {
                    win();
                }
                return 0;
            }
            """
        )

        src_path = os.path.join(build_dir, "sample.c")
        with open(src_path, "w", encoding="utf-8") as fp:
            fp.write(source)

        binary_path = os.path.join(build_dir, "sample")
        flag_variants = [
            ["-O0", "-fno-stack-protector", "-no-pie"],
            ["-O0", "-fno-stack-protector", "-fno-pie"],
            ["-O0", "-fno-stack-protector"],
        ]
        for flags in flag_variants:
            try:
                subprocess.check_call([cls.compiler, *flags, "-o", binary_path, src_path])
                return binary_path
            except subprocess.CalledProcessError:
                continue

        raise unittest.SkipTest("unable to compile sample binary")

    def setUp(self) -> None:
        registry.reset()
        self.server = AngrMCPServer()
        load_result = self.server.load_project(self.binary_path, auto_load_libs=False)
        self.project_id = load_result["project_id"]
        self.project_metadata = load_result["metadata"]

    def tearDown(self) -> None:
        registry.reset()

    # ------------------------------------------------------------------
    def test_load_and_setup(self) -> None:
        self.assertIn("entry", self.project_metadata)
        setup = self.server.setup_symbolic_context(self.project_id, kind="entry", stdin_symbolic=4)
        self.assertIn("state_id", setup)

    # ------------------------------------------------------------------
    def test_symbolic_search_and_constraints(self) -> None:
        project = registry.get_project(self.project_id).project
        win_symbol = project.loader.find_symbol("win")
        self.assertIsNotNone(win_symbol)
        win_addr = win_symbol.rebased_addr

        setup = self.server.setup_symbolic_context(self.project_id, kind="entry", stdin_symbolic=4)
        state_id = setup["state_id"]

        self.server.instrument_environment(
            self.project_id,
            hooks=[{"symbol": "write", "simprocedure": "stubs.ReturnUnconstrained"}],
        )

        run_info = self.server.run_symbolic_search(
            self.project_id,
            state_id=state_id,
            mode="explore",
            find=[win_addr],
        )
        found_ids = run_info["run"]["found"]
        self.assertTrue(found_ids)

        found_state = registry.get_state(self.project_id, found_ids[0])
        stdin_bytes = found_state.posix.dumps(0)
        self.assertTrue(stdin_bytes.startswith(b"AB"))

        flag_addr = project.loader.find_symbol("flag_buf").rebased_addr
        constraint_result = self.server.solve_constraints(
            self.project_id,
            found_ids[0],
            queries=[
                {"kind": "memory", "address": flag_addr, "size": 1},
                {"kind": "memory", "address": flag_addr + 1, "size": 1},
            ],
        )
        values = [item["value"] for item in constraint_result["results"]]
        self.assertEqual(values, [ord("A"), ord("B")])

    # ------------------------------------------------------------------
    def test_monitor_and_inspect(self) -> None:
        state_id = self.server.setup_symbolic_context(self.project_id, kind="entry", stdin_symbolic=4)["state_id"]
        self.server.monitor_for_vulns(self.project_id, state_id, ["mem_write"])
        self.server.run_symbolic_search(self.project_id, state_id=state_id, mode="step", step_count=5)
        inspected = self.server.inspect_state(self.project_id, state_id, include_events=True)
        self.assertIn("events", inspected)
        self.assertTrue(inspected["events"], "Expected mem_write events to be recorded")

    # ------------------------------------------------------------------
    def test_cfg_and_slice(self) -> None:
        project = registry.get_project(self.project_id).project
        cfg_info = self.server.analyze_control_flow(self.project_id, force_fast=True)
        self.assertGreater(cfg_info["node_count"], 0)

        win_addr = project.loader.find_symbol("win").rebased_addr
        slice_info = self.server.trace_dataflow(self.project_id, target_addr=win_addr)
        self.assertIn("runs_in_slice", slice_info)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from angr_mcp.registry import registry
from angr_mcp.server import AngrMCPServer


class TestTaintAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("C compiler required for taint analysis tests")

        cls.compiler = compiler
        cls.build_dir = tempfile.mkdtemp(prefix="mcp_taint_")
        cls.binary_path = cls._build_sample_binary(cls.build_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "build_dir") and os.path.isdir(cls.build_dir):
            shutil.rmtree(cls.build_dir)

    @classmethod
    def _build_sample_binary(cls, build_dir: str) -> str:
        source = textwrap.dedent(
            """
            #include <stdio.h>

            char user_buf[16] = { '%', 's', '\\0' };

            int main(void) {
                printf(user_buf);
                return 0;
            }
            """
        )

        src_path = os.path.join(build_dir, "taint_sample.c")
        with open(src_path, "w", encoding="utf-8") as fp:
            fp.write(source)

        binary_path = os.path.join(build_dir, "taint_sample")
        compile_flags = ["-O0", "-fno-stack-protector", "-no-pie"]
        subprocess.check_call([cls.compiler, *compile_flags, "-o", binary_path, src_path])
        return binary_path

    def setUp(self) -> None:
        registry.reset()
        self.server = AngrMCPServer()
        load_result = self.server.load_project(self.binary_path, auto_load_libs=False)
        self.project_id = load_result["project_id"]
        self.project = registry.get_project(self.project_id).project

    def tearDown(self) -> None:
        registry.reset()

    def test_format_string_sink_becomes_tainted(self) -> None:
        if self.project.arch.name not in {"AMD64", "X86_64"}:
            raise unittest.SkipTest(f"Unsupported arch for taint test: {self.project.arch.name}")

        main_symbol = self.project.loader.find_symbol("main")
        printf_symbol = self.project.loader.find_symbol("printf")
        user_buf_symbol = self.project.loader.find_symbol("user_buf")
        if main_symbol is None or printf_symbol is None or user_buf_symbol is None:
            raise unittest.SkipTest("required symbols not found in sample binary")

        setup = self.server.setup_symbolic_context(
            self.project_id,
            kind="call",
            addr=main_symbol.rebased_addr,
            stdin_symbolic=16,
        )
        state_id = setup["state_id"]

        printf_stub = self.project.loader.main_object.plt.get("printf")
        if printf_stub is None:
            raise unittest.SkipTest("printf PLT stub not found")
        printf_call_addr = printf_stub

        result = self.server.run_taint_analysis(
            self.project_id,
            state_id=state_id,
            sources=[
                {
                    "kind": "memory",
                    "address": user_buf_symbol.rebased_addr,
                    "size": 8,
                    "label": "user_buf",
                }
            ],
            sinks=[
                {
                    "address": printf_call_addr,
                    "description": "printf format string",
                    "checks": [
                        {"kind": "pointer", "register": "rdi", "size": 2},
                    ],
                }
            ],
            stop_on_first_hit=True,
            max_steps=200,
        )

        taint_summary = result["taint"]
        self.assertTrue(taint_summary["hits"], "Expected at least one taint sink hit")

        first_hit = taint_summary["hits"][0]
        self.assertTrue(first_hit["checks"][0]["tainted"], "printf argument should be tainted")
        hit_state_id = first_hit["state_id"]
        self.assertIsNotNone(hit_state_id)
        registry.get_state(self.project_id, hit_state_id)  # should not raise

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from angr_mcp.server import AngrMCPServer


class TestAnalyzeTaintComplex(unittest.TestCase):
    """Test the analyze_taint tool with complex scenarios."""

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("C compiler required for taint analysis tests")

        cls.compiler = compiler
        cls.build_dir = tempfile.mkdtemp(prefix="mcp_analyze_taint_complex_")
        cls.binary_path = cls._build_complex_binary(cls.build_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "build_dir") and os.path.isdir(cls.build_dir):
            shutil.rmtree(cls.build_dir)

    @classmethod
    def _build_complex_binary(cls, build_dir: str) -> str:
        source = textwrap.dedent(
            """
            #include <stdio.h>
            #include <string.h>
            #include <stdlib.h>

            char sink_buf[64];
            
            void sink(char *data) {
                strncpy(sink_buf, data, 63);
            }

            void test_loop_propagation(char *input) {
                char buf[32];
                for (int i = 0; i \u003c 10 && input[i]; i++) {
                    buf[i] = input[i];
                }
                sink(buf);
            }

            void test_conditional(char *input, int flag) {
                char *data;
                if (flag) {
                    data = input;
                } else {
                    data = "safe";
                }
                sink(data);
            }

            int main(int argc, char **argv) {
                return 0;
            }
            """
        )

        src_path = os.path.join(build_dir, "complex_taint.c")
        with open(src_path, "w", encoding="utf-8") as fp:
            fp.write(source)

        binary_path = os.path.join(build_dir, "complex_taint")
        compile_flags = ["-O0", "-fno-stack-protector", "-no-pie"]
        subprocess.check_call([cls.compiler, *compile_flags, "-o", binary_path, src_path])
        return binary_path

    def setUp(self) -> None:
        self.server = AngrMCPServer()

    def test_loop_propagation(self):
        """Test that taint propagates through a loop."""
        # First load project to get symbol address
        load_result = self.server.load_project(self.binary_path, auto_load_libs=False)
        project_id = load_result["project_id"]
        from angr_mcp.registry import registry
        project = registry.get_project(project_id).project
        sink_addr = project.loader.find_symbol("sink").rebased_addr
        
        result = self.server.analyze_taint(
            self.binary_path,
            function_name="test_loop_propagation",
            args=[0x2000],  # Address of input buffer
            sources=[
                {
                    "kind": "memory",
                    "address": 0x2000,
                    "size": 16,
                    "label": "loop_input",
                }
            ],
            sinks=[
                {
                    "address": sink_addr,
                    "checks": [
                        {"kind": "pointer", "register": "rdi", "size": 1},
                    ],
                }
            ],
        )

        self.assertIn("taint", result)
        self.assertIn("hits", result["taint"])
        # Should find taint propagating through the loop
        self.assertTrue(
            result["taint"]["hits"],
            f"Loop propagation taint failed. Result: {result['taint']}"
        )

    def test_conditional_taint(self):
        """Test that taint propagates through conditional branches."""
        # First load project to get symbol address
        load_result = self.server.load_project(self.binary_path, auto_load_libs=False)
        project_id = load_result["project_id"]
        from angr_mcp.registry import registry
        project = registry.get_project(project_id).project
        sink_addr = project.loader.find_symbol("sink").rebased_addr
        
        result = self.server.analyze_taint(
            self.binary_path,
            function_name="test_conditional",
            args=[0x2000, 1],  # Address of input, flag=1 (tainted path)
            sources=[
                {
                    "kind": "memory",
                    "address":  0x2000,
                    "size": 16,
                    "label": "conditional_input",
                }
            ],
            sinks=[
                {
                    "address": sink_addr,
                    "checks": [
                        {"kind": "pointer", "register": "rdi", "size": 1},
                    ],
                }
            ],
        )

        self.assertIn("taint", result)
        self.assertIn("hits", result["taint"])
        # When flag=1, input reaches sink
        self.assertTrue(
            result["taint"]["hits"],
            f"Conditional taint failed. Result: {result['taint']}"
        )


if __name__ == "__main__":
    unittest.main()

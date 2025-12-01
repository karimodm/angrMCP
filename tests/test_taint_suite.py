
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from angr_mcp.registry import registry
from angr_mcp.server import AngrMCPServer


class TestTaintSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("C compiler required for taint analysis tests")

        cls.compiler = compiler
        cls.build_dir = tempfile.mkdtemp(prefix="mcp_taint_suite_")
        cls.binary_path = cls._build_test_binary(cls.build_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "build_dir") and os.path.isdir(cls.build_dir):
            shutil.rmtree(cls.build_dir)

    @classmethod
    def _build_test_binary(cls, build_dir: str) -> str:
        source = textwrap.dedent(
            """
            #include <stdio.h>
            #include <string.h>
            #include <stdlib.h>

            char sink_buf[64];
            
            void sink(char *data) {
                // This is our sink function
                // We will hook it or check for calls to it
                strncpy(sink_buf, data, 63);
            }

            void test_direct(char *input) {
                sink(input);
            }

            void test_propagation(char *input) {
                char *local = input;
                sink(local);
            }

            void test_arithmetic(char *input) {
                char *local = input + 1;
                sink(local);
            }

            void nested_call(char *data) {
                sink(data);
            }

            void test_call(char *input) {
                nested_call(input);
            }

            char* return_taint(char *input) {
                return input;
            }

            void test_return(char *input) {
                char *res = return_taint(input);
                sink(res);
            }

            void test_pointer(char **input_ptr) {
                char *data = *input_ptr;
                sink(data);
            }

            int main(int argc, char **argv) {
                // We won't actually run main, we'll call functions directly
                return 0;
            }
            """
        )

        src_path = os.path.join(build_dir, "taint_suite.c")
        with open(src_path, "w", encoding="utf-8") as fp:
            fp.write(source)

        binary_path = os.path.join(build_dir, "taint_suite")
        # -O0 to prevent optimizations that might confuse simple analysis
        compile_flags = ["-O0", "-fno-stack-protector", "-no-pie"]
        subprocess.check_call([cls.compiler, *compile_flags, "-o", binary_path, src_path])
        return binary_path

    def setUp(self) -> None:
        registry.reset()
        self.server = AngrMCPServer()
        load_result = self.server.load_project(self.binary_path, auto_load_libs=False)
        self.project_id = load_result["project_id"]
        self.project = registry.get_project(self.project_id).project
        self.sink_addr = self.project.loader.find_symbol("sink").rebased_addr

    def tearDown(self) -> None:
        registry.reset()

    def _run_test(self, function_name, setup_args, source_spec):
        func_symbol = self.project.loader.find_symbol(function_name)
        if func_symbol is None:
            self.fail(f"Function {function_name} not found")

        setup = self.server.setup_symbolic_context(
            self.project_id,
            kind="call",
            addr=func_symbol.rebased_addr,
            args=setup_args,
        )
        state_id = setup["state_id"]

        # Configure sink: call to 'sink' function
        # We check if the first argument (rdi) is tainted
        sink_spec = {
            "address": self.sink_addr,
            "description": "sink call",
            "checks": [
                {"kind": "pointer", "register": "rdi", "size": 1},
            ],
        }

        result = self.server.run_taint_analysis(
            self.project_id,
            state_id=state_id,
            sources=[source_spec],
            sinks=[sink_spec],
            stop_on_first_hit=True,
            max_steps=500,
        )
        return result["taint"]

    def test_direct_taint(self):
        # void test_direct(char *input)
        # input is at 0x1000
        input_addr = 0x1000
        
        # We need to setup memory for the string
        # But for direct taint, we can just say the pointer itself is tainted?
        # Or the memory it points to?
        # The sink checks 'pointer' taint (is_tainted(val) or is_tainted(mem[val]))
        # Let's taint the memory at 0x1000
        
        source = {
            "kind": "memory",
            "address": input_addr,
            "size": 8,
            "label": "input_data",
        }
        
        taint = self._run_test("test_direct", [input_addr], source)
        self.assertTrue(taint["hits"], "Direct taint failed")

    def test_propagation(self):
        # void test_propagation(char *input)
        input_addr = 0x1000
        source = {
            "kind": "memory",
            "address": input_addr,
            "size": 8,
            "label": "input_data",
        }
        taint = self._run_test("test_propagation", [input_addr], source)
        self.assertTrue(taint["hits"], "Propagation taint failed")

    def test_arithmetic(self):
        # void test_arithmetic(char *input)
        # input + 1 passed to sink
        input_addr = 0x1000
        source = {
            "kind": "memory",
            "address": input_addr,
            "size": 16, # Taint enough bytes
            "label": "input_data",
        }
        taint = self._run_test("test_arithmetic", [input_addr], source)
        self.assertTrue(taint["hits"], "Arithmetic taint failed")

    def test_call(self):
        # void test_call(char *input) -> nested_call -> sink
        input_addr = 0x1000
        source = {
            "kind": "memory",
            "address": input_addr,
            "size": 8,
            "label": "input_data",
        }
        # smart_call might fail here if arg detection fails, so we might need smart_call=False
        # But let's try True first to see if it works on this simple binary
        taint = self._run_test("test_call", [input_addr], source)
        self.assertTrue(taint["hits"], "Call taint failed")

    def test_return(self):
        # void test_return(char *input) -> return_taint -> sink
        input_addr = 0x1000
        source = {
            "kind": "memory",
            "address": input_addr,
            "size": 8,
            "label": "input_data",
        }
        taint = self._run_test("test_return", [input_addr], source)
        self.assertTrue(taint["hits"], "Return taint failed")

    def test_pointer(self):
        # void test_pointer(char **input_ptr)
        # *input_ptr is tainted
        ptr_addr = 0x2000
        data_addr = 0x1000
        
        # We need to set up memory: *ptr_addr = data_addr
        # And taint data_addr
        
        # We can't easily set up memory in _run_test helper without passing state
        # So we'll do it manually here or improve helper.
        # Let's do it manually for this test.
        
        func_symbol = self.project.loader.find_symbol("test_pointer")
        setup = self.server.setup_symbolic_context(
            self.project_id,
            kind="call",
            addr=func_symbol.rebased_addr,
            args=[ptr_addr],
        )
        state_id = setup["state_id"]
        state = registry.get_state(self.project_id, state_id)
        
        state.memory.store(ptr_addr, data_addr, endness=self.project.arch.memory_endness, size=8)
        
        source = {
            "kind": "memory",
            "address": data_addr,
            "size": 8,
            "label": "input_data",
        }
        
        sink_spec = {
            "address": self.sink_addr,
            "description": "sink call",
            "checks": [
                {"kind": "pointer", "register": "rdi", "size": 1},
            ],
        }

        result = self.server.run_taint_analysis(
            self.project_id,
            state_id=state_id,
            sources=[source],
            sinks=[sink_spec],
            stop_on_first_hit=True,
            max_steps=500,
        )
        print(f"DEBUG: test_pointer result: {result['taint']}")
        self.assertTrue(result["taint"]["hits"], f"Pointer taint failed. Hits: {result['taint']['hits']}")


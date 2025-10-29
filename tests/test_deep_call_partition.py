from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from typing import Any, Dict, Optional

from angr_mcp.server import AngrMCPServer
from angr_mcp.registry import registry


class TestDeepCallPartition(unittest.TestCase):
    KEY_SEQUENCE = "ANGRMCPSPLIT!"
    CHUNK_SIZE = 4

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("C compiler required for deep-call test")

        cls.compiler = compiler
        cls.build_dir = tempfile.mkdtemp(prefix="mcp_deep_")
        cls.binary_path = cls._build_deep_binary(cls.build_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "build_dir") and os.path.isdir(cls.build_dir):
            shutil.rmtree(cls.build_dir)

    @classmethod
    def _build_deep_binary(cls, build_dir: str) -> str:
        key = cls.KEY_SEQUENCE
        key_len = len(key)

        stage_defs = []
        checkpoint_defs = []
        target_mask = (1 << key_len) - 1
        for idx, ch in enumerate(key):
            if idx == key_len - 1:
                stage_defs.append(
                    textwrap.dedent(
                        f"""
                        static __attribute__((noinline)) void stage{idx}(char *buf) {{
                            confuse({idx}, buf[{idx}]);
                            unsigned short shifted = (unsigned short)(gate_value << 1);
                            if (buf[{idx}] == {repr(ch)}) {{
                                gate_value = shifted | 1u;
                            }} else {{
                                gate_value = shifted;
                            }}
                            if (gate_value == {target_mask}u) {{
                                deep_reward();
                            }} else {{
                                detour({idx} + KEY_LEN, buf[{idx}]);
                            }}
                        }}
                        """
                    )
                )
            else:
                checkpoint_defs.append(
                    textwrap.dedent(
                        f"""
                        static __attribute__((noinline)) void checkpoint{idx}(void) {{
                            volatile unsigned short echo = gate_value;
                            if ((echo & 1u) == 0u) {{
                                echo ^= {idx + 1}u;
                            }}
                        }}
                        """
                    )
                )
                stage_defs.append(
                    textwrap.dedent(
                        f"""
                        static __attribute__((noinline)) void stage{idx}(char *buf) {{
                            confuse({idx}, buf[{idx}]);
                            unsigned short shifted = (unsigned short)(gate_value << 1);
                            if (buf[{idx}] == {repr(ch)}) {{
                                gate_value = shifted | 1u;
                                detour({idx} + KEY_LEN, buf[{idx}]);
                                checkpoint{idx}();
                                stage{idx + 1}(buf);
                            }} else {{
                                gate_value = shifted;
                                detour({idx} + KEY_LEN * 2, buf[{idx}]);
                                stage{idx + 1}(buf);
                            }}
                        }}
                        """
                    )
                )

        stage_prototypes = "\n".join(f"static void stage{idx}(char *buf);" for idx in range(key_len))
        checkpoint_prototypes = "\n".join(f"static void checkpoint{idx}(void);" for idx in range(key_len - 1))
        prototypes = "\n".join(filter(None, [stage_prototypes, checkpoint_prototypes]))

        source = textwrap.dedent(
            f"""
            #include <unistd.h>

            #define KEY_LEN {len(key)}
            static char deep_buf[KEY_LEN];
            static unsigned short gate_value;

            __attribute__((noinline)) void deep_reward(void) {{
                write(1, "deep\\n", 5);
            }}

            __attribute__((noinline)) void confuse(int depth, char value) {{
                volatile int acc = depth * 3 + (value & 0x7);
                for (int i = 0; i < 3; i++) {{
                    acc ^= (value << ((depth + i) & 3));
                }}
                if ((value & depth) == 0x13) {{
                    acc += value;
                }}
            }}

            __attribute__((noinline)) void detour(int depth, char value) {{
                if (((value ^ depth) & 0x1f) == 0x1c) {{
                    confuse(depth + 7, value);
                }}
                confuse(depth + 11, value);
            }}

            {prototypes}

            {''.join(checkpoint_defs + stage_defs)}

            int main(void) {{
                read(0, deep_buf, KEY_LEN);
                gate_value = 0;
                stage0(deep_buf);
                return 0;
            }}
            """
        )

        src_path = os.path.join(build_dir, "deep.c")
        with open(src_path, "w", encoding="utf-8") as fp:
            fp.write(source)

        binary_path = os.path.join(build_dir, "deep_target")
        compile_variants = [
            ["-O0", "-fno-stack-protector", "-no-pie"],
            ["-O0", "-fno-stack-protector", "-fno-pie"],
            ["-O0", "-fno-stack-protector"],
            ["-O0"],
        ]
        for flags in compile_variants:
            try:
                subprocess.check_call([cls.compiler, *flags, "-o", binary_path, src_path])
                return binary_path
            except subprocess.CalledProcessError:
                continue

        raise unittest.SkipTest("unable to compile deep-call sample binary")

    def setUp(self) -> None:
        registry.reset()
        self.server = AngrMCPServer()
        load = self.server.load_project(self.binary_path, auto_load_libs=False)
        self.project_id = load["project_id"]
        self.project = registry.get_project(self.project_id).project
        self.buffer_addr = self.project.loader.find_symbol("deep_buf").rebased_addr
        self.reward_addr = self.project.loader.find_symbol("deep_reward").rebased_addr

    def tearDown(self) -> None:
        registry.reset()
        job_dir = pathlib.Path(".mcp_jobs")
        if job_dir.exists():
            shutil.rmtree(job_dir)

    # ------------------------------------------------------------------
    def test_partitioned_reach(self) -> None:
        chain = self.server.analyze_call_chain(
            self.project_id,
            source="main",
            target="deep_reward",
            max_paths=3,
        )
        self.assertTrue(chain["paths"], "Call chain should provide at least one path")
        primary_path = chain["paths"][0]["nodes"]
        path_names = [entry["name"] for entry in primary_path]
        expected_stages = [f"stage{i}" for i in range(len(self.KEY_SEQUENCE))]
        self.assertEqual(path_names[0], "main")
        self.assertEqual(path_names[-1], "deep_reward")
        cursor = 0
        for stage_name in expected_stages:
            try:
                cursor = path_names.index(stage_name, cursor)
            except ValueError as exc:
                self.fail(f"Stage {stage_name} missing from call chain: {exc}")
            cursor += 1

        entry = self.server.setup_symbolic_context(
            self.project_id,
            kind="entry",
            stdin_symbolic=len(self.KEY_SEQUENCE),
            remove_options=["LAZY_SOLVES"],
        )
        entry_state = entry["state_id"]

        overshoot = self.server.run_symbolic_search(
            self.project_id,
            state_id=entry_state,
            mode="step",
            step_count=len(self.KEY_SEQUENCE) * 10,
            state_budget=64,
        )
        overshoot_run = overshoot["run"]
        self.assertEqual(overshoot_run["state_pressure"]["status"], "exceeded")
        self.assertIn("StateBudgetExceeded", {err["type"] for err in overshoot_run["errors"]})

        fresh_entry = self.server.setup_symbolic_context(
            self.project_id,
            kind="entry",
            stdin_symbolic=len(self.KEY_SEQUENCE),
            remove_options=["LAZY_SOLVES"],
        )
        current_state = fresh_entry["state_id"]

        node_addresses = [entry["addr"] for entry in primary_path]
        self.assertTrue(all(addr.startswith("0x") for addr in node_addresses))
        total_stages = len(self.KEY_SEQUENCE)
        final_index = len(node_addresses) - 1

        bytes_goals = []
        cursor = self.CHUNK_SIZE
        while cursor < total_stages:
            bytes_goals.append(cursor)
            cursor += self.CHUNK_SIZE
        if not bytes_goals or bytes_goals[-1] != total_stages:
            bytes_goals.append(total_stages)

        step_budget = len(self.KEY_SEQUENCE) * 8
        job_ids = []

        def run_step(state_id: str, *, label: str) -> Dict[str, Any]:
            run = self.server.run_symbolic_search(
                self.project_id,
                state_id=state_id,
                mode="step",
                step_count=step_budget,
                state_budget=256,
                persist_job=True,
                job_metadata={"label": label, "step_budget": step_budget},
            )
            payload = run["run"]
            self.assertEqual(payload["state_pressure"]["status"], "ok")
            job_ids.append(payload["job_id"])
            resume = self.server.resume_job(self.project_id, payload["job_id"])
            self.assertEqual(resume["job"]["metadata"]["last_run"]["state_pressure"]["status"], "ok")
            return payload

        def select_state_by_prefix(payload: Dict[str, Any], prefix_len: int) -> Optional[str]:
            if prefix_len == 0:
                # No constraints required for an empty prefix.
                for ids in payload["stashes"].values():
                    if ids:
                        return ids[0]
                return None
            for state_ids in payload["stashes"].values():
                for state_id in state_ids:
                    state = registry.get_state(self.project_id, state_id)
                    matches = True
                    for offset in range(prefix_len):
                        value = state.solver.eval(state.memory.load(self.buffer_addr + offset, 1))
                        if value != ord(self.KEY_SEQUENCE[offset]):
                            matches = False
                            break
                    if matches:
                        return state_id
            return None

        def select_state_by_ip(payload: Dict[str, Any], target_addr: int) -> Optional[str]:
            for state_ids in payload["stashes"].values():
                for state_id in state_ids:
                    state = registry.get_state(self.project_id, state_id)
                    if state.solver.eval(state.regs.ip) == target_addr:
                        return state_id
            return None

        prev_prefix = 0
        for chunk_index, goal_bytes in enumerate(bytes_goals):
            target_prefix = min(goal_bytes, total_stages - 1)
            if target_prefix <= prev_prefix:
                continue
            payload = run_step(
                current_state,
                label=f"chunk_{chunk_index}_prefix_{target_prefix}",
            )
            candidate_state = select_state_by_prefix(payload, target_prefix)
            self.assertIsNotNone(
                candidate_state,
                f"Unable to isolate prefix length {target_prefix} during chunk {chunk_index}",
            )
            current_state = candidate_state
            prev_prefix = target_prefix

            queries = [
                {"kind": "memory", "address": self.buffer_addr + offset, "size": 1}
                for offset in range(target_prefix)
            ]
            if queries:
                solved = self.server.solve_constraints(self.project_id, current_state, queries)
                values = bytes(item["value"] for item in solved["results"])
                self.assertEqual(values, self.KEY_SEQUENCE[:target_prefix].encode("ascii"))

        self.assertEqual(prev_prefix, total_stages - 1)

        # Final chunk: satisfy the last byte and position the execution for the reward function.
        final_payload = run_step(current_state, label="final_deep_reward")
        final_state_id = select_state_by_prefix(final_payload, total_stages)
        self.assertIsNotNone(final_state_id, "Failed to recover complete input prefix")
        current_state = final_state_id

        final_queries = [
            {"kind": "memory", "address": self.buffer_addr + offset, "size": 1}
            for offset in range(len(self.KEY_SEQUENCE))
        ]
        final_solution = self.server.solve_constraints(self.project_id, current_state, final_queries)
        solved_bytes = bytes(item["value"] for item in final_solution["results"])
        self.assertEqual(solved_bytes, self.KEY_SEQUENCE.encode("ascii"))

        post_run = self.server.run_symbolic_search(
            self.project_id,
            state_id=current_state,
            mode="step",
            step_count=8,
        )
        post_payload = post_run["run"]
        dead_ids = post_payload["deadended"] or post_payload["found"]
        self.assertTrue(dead_ids, "Expected execution to terminate after reward call")
        final_dead = registry.get_state(self.project_id, dead_ids[0])
        self.assertIn(b"deep", final_dead.posix.dumps(1))

        jobs = self.server.list_jobs(self.project_id)["jobs"]
        self.assertTrue(jobs, "Persisted chunk jobs should be discoverable")

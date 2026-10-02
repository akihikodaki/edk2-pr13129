# SPDX-License-Identifier: 0BSD
"""Check page tables, monitor failures, and guest device discovery."""

import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, call, patch

from qmp import QMP, read_arm_registers, walk_arm_page_tables, walk_page_tables


class PageTableTests(unittest.TestCase):
    def test_4k_pat_selectors(self):
        memory = {0x1000: 0x2001, 0x2008: 0x3001, 0x3008: 0x4001}
        selectors = (
            (0x01, 0), (0x09, 1), (0x11, 2), (0x19, 3),
            (0x81, 4), (0x89, 5), (0x91, 6), (0x99, 7),
        )
        for flags, selector in selectors:
            with self.subTest(selector=selector):
                memory[0x4018] = 0x8000007000005000 | flags
                result = walk_page_tables(memory.__getitem__, 0x40203456,
                                          0x15a3, 0)
                self.assertEqual(result["physical"], 0x7000005456)
                self.assertEqual(result["pat_index"], selector)
                self.assertEqual(result["leaf_size"], 4096)
                self.assertEqual([step["address"] for step in result["walk"]],
                                 [0x1000, 0x2008, 0x3008, 0x4018])

    def test_2m_pat_does_not_change_physical_address(self):
        memory = {0x1000: 0x2001, 0x2008: 0x3001}
        for flags, selector in ((0x99, 3), (0x1099, 7)):
            with self.subTest(selector=selector):
                memory[0x3008] = 0x8000007000200000 | flags
                result = walk_page_tables(memory.__getitem__, 0x40234567,
                                          0x1000, 0)
                self.assertEqual(result["physical"], 0x7000234567)
                self.assertEqual(result["pat_index"], selector)
                self.assertEqual(result["leaf_size"], 2 * 1024 * 1024)
                self.assertEqual(len(result["walk"]), 3)

    def test_1g_pat_does_not_change_physical_address(self):
        memory = {0x1000: 0x2001}
        for flags, selector in ((0x91, 2), (0x1091, 6)):
            with self.subTest(selector=selector):
                memory[0x2008] = 0x8000007000000000 | flags
                result = walk_page_tables(memory.__getitem__, 0x456789ab,
                                          0x1000, 0)
                self.assertEqual(result["physical"], 0x70056789ab)
                self.assertEqual(result["pat_index"], selector)
                self.assertEqual(result["leaf_size"], 1024 * 1024 * 1024)
                self.assertEqual(len(result["walk"]), 2)

    def test_la57_uses_fifth_index(self):
        memory = {
            0x1008: 0x2001,
            0x2000: 0x3001,
            0x3008: 0x4001,
            0x4008: 0x5001,
            0x5018: 0x8000007000005099,
        }
        result = walk_page_tables(memory.__getitem__, 0x1000040203456,
                                  0x15a3, 1 << 12)
        self.assertEqual(result["physical"], 0x7000005456)
        self.assertEqual(result["pat_index"], 7)
        self.assertEqual(result["leaf_size"], 4096)
        self.assertEqual([step["shift"] for step in result["walk"]],
                         [48, 39, 30, 21, 12])

    def test_absent_entry_at_each_level(self):
        present = {
            0x1000: 0x2001, 0x2008: 0x3001,
            0x3008: 0x4001, 0x4018: 0x7000005001,
        }
        for address in present:
            with self.subTest(address=hex(address)):
                memory = dict(present)
                memory[address] &= ~1
                with self.assertRaisesRegex(ValueError, "absent"):
                    walk_page_tables(memory.__getitem__, 0x40203456,
                                     0x1000, 0)

    def test_large_page_at_invalid_level(self):
        for cr4 in (0, 1 << 12):
            with self.subTest(cr4=cr4):
                with self.assertRaisesRegex(ValueError, "invalid.*level"):
                    walk_page_tables({0x1000: 0x2081}.__getitem__, 0,
                                     0x1000, cr4)


class QMPTests(unittest.TestCase):
    def test_closed_or_invalid_response(self):
        for data, error in ((b"", ConnectionError),
                            (b"[]\n", RuntimeError),
                            (b"{}", RuntimeError)):
            with self.subTest(data=data):
                connection = QMP.__new__(QMP)
                connection.stream = io.BytesIO(data)
                with self.assertRaises(error):
                    connection.receive()


class GuestTests(unittest.TestCase):
    def test_virtio_gpu_render_node_discovery(self):
        spec = importlib.util.spec_from_file_location(
            "guest_info", Path(__file__).with_name("guest-info.py"))
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            drm = root / "drm"
            nodes = root / "dev" / "dri"
            other = drm / "renderD128" / "device"
            other.mkdir(parents=True)
            (other / "driver").symlink_to(root / "i915")
            with self.assertRaisesRegex(RuntimeError, "no virtio-gpu"):
                guest.find_render_node(drm, nodes)

            device = drm / "renderD139" / "device"
            device.mkdir(parents=True)
            (device / "driver").symlink_to(root / "virtio_gpu")
            self.assertEqual(guest.find_render_node(drm, nodes),
                             nodes / "renderD139")
            (device / "driver").unlink()
            (device / "vendor").write_text("0x1af4\n")
            (device / "device").write_text("0x1050\n")
            self.assertEqual(guest.find_render_node(drm, nodes),
                             nodes / "renderD139")
            (device / "device").write_text("0x1051\n")
            with self.assertRaisesRegex(RuntimeError, "no virtio-gpu"):
                guest.find_render_node(drm, nodes)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "run_probe", Path(__file__).with_name("run-probe.py"))
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)

    def test_native_command_and_arm_pat_rejection(self):
        def tool(name):
            return Path("/tools") / name

        for arch, machine, pat in (("aarch64", "virt", "default"),
                                   ("x86_64", "q35", "on")):
            with self.subTest(arch=arch), \
                    tempfile.TemporaryDirectory() as directory, \
                    patch.object(self.runner.platform, "machine",
                                 return_value=arch), \
                    patch.object(self.runner.sys, "argv", [
                        "run-probe.py", "--kernel", directory + "/kernel",
                        "--render-node", "/dev/dri/renderD128", "--dry-run",
                        "--pat", pat]), \
                    patch.object(self.runner, "read_file",
                                 side_effect=lambda p: p), \
                    patch.object(self.runner, "executable",
                                 side_effect=tool) as executable, \
                    patch.object(self.runner.os, "access", return_value=True), \
                    patch.object(self.runner.subprocess, "check_output",
                                 return_value="egl-headless\n"):
                config = self.runner.parse_args()
                self.assertEqual(config.qemu, f"qemu-system-{arch}")
                command = self.runner.build_command(config, Path(directory))
                qemu = Path(command[command.index("--qemu") + 1])
                self.assertEqual(qemu.resolve(), Path("/tools") / config.qemu)
                options = shlex.split(command[-1].removeprefix("--qemu-opts="))
                self.assertEqual(options[options.index("-machine") + 1],
                                 machine)
                if arch == "aarch64":
                    self.assertEqual(options[options.index("-gdb") + 1],
                                     f"unix:{directory}/gdb.sock,"
                                     "server=on,wait=off")
                    self.assertIn(call("gdb"), executable.call_args_list)
                    self.assertNotIn("--disable-kvm", command)
                    self.assertEqual(command[command.index("--append") + 1],
                                     "iomem=relaxed")
                    self.runner.sys.argv += ["--pat", "on"]
                    with patch.object(self.runner.sys, "stderr",
                                      io.StringIO()), \
                            self.assertRaises(SystemExit) as error:
                        self.runner.parse_args()
                    self.assertEqual(error.exception.code, 2)
                else:
                    self.assertNotIn("-gdb", options)
                    self.assertIn("--disable-kvm", command)
                    self.assertEqual(options[options.index("-accel") + 1],
                                     "kvm,honor-guest-pat=on")
                    self.assertEqual(command[command.index("--append") + 1],
                                     "iomem=relaxed pti=off")

    def test_decode_map_info(self):
        blob = "BLOB bo_handle=5 res_handle=3 size=65536\n"
        other = ("VIRGL_MAP_INFO resource=8 ret=0 "
                 "map_info=0x00000003 cache=0x3\n")
        failed = ("VIRGL_MAP_INFO resource=3 ret=-22 "
                  "map_info=0x00000000 cache=0x0\n")
        none = ("VIRGL_MAP_INFO resource=3 ret=0 "
                "map_info=0x00000000 cache=0x0\n")
        cases = []
        for value, name in ((0, "NONE"), (1, "CACHED"), (2, "UNCACHED"),
                            (3, "WC"), (0x12345671, "CACHED"),
                            (0xabcdef04, "RESERVED")):
            observation = (f"VIRGL_MAP_INFO resource=3 ret=0 "
                           f"map_info=0x{value:08x} cache=0x{value & 15:x}\n")
            macro = name if name == "RESERVED" else (
                "VIRTIO_GPU_MAP_CACHE_" + name)
            cases.append((other + observation + blob, (value, macro)))
        cases += [
            ("", None), (none, None), (blob, None), (other + blob, None),
            (failed + blob, None),
            (failed + blob + none, (0, "VIRTIO_GPU_MAP_CACHE_NONE")),
        ]
        for text, expected in cases:
            with self.subTest(text=text, expected=expected):
                if expected is None:
                    with self.assertRaises(RuntimeError):
                        self.runner.decode_map_info(text)
                else:
                    self.assertEqual(self.runner.decode_map_info(text), {
                        "resource_id": 3,
                        "map_info": expected[0],
                        "virtio_map_cache": expected[1],
                    })

    def test_capture_accepts_crlf_mtree(self):
        mtree = (
            "address-space: memory\r\n"
            "  0000007000000000-000000700fffffff "
            "(prio 1, i/o): virtio-gpu-hostmem\r\n"
            "    0000007000005000-0000007000014fff (prio 1, ram): mr\r\n"
        )
        responses = {
            "info registers": "CR0=80050033 CR3=15a3 CR4=0\r\n",
            "info mtree": mtree,
            "info ramblock": "mr: 65536 bytes\r\n",
            "xp /1gx 0x1000": "0000000000001000: 0x0000000000002001\r\n",
            "xp /1gx 0x2008": "0000000000002008: 0x0000000000003001\r\n",
            "xp /1gx 0x3008": "0000000000003008: 0x0000000000004001\r\n",
            "xp /1gx 0x4018": "0000000000004018: 0x8000007000005011\r\n",
        }
        monitor = Mock()
        monitor.call.return_value = {"enabled": True}
        monitor.hmp.side_effect = responses.__getitem__
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = self.runner.capture(monitor, 0x40203456, output)
            self.assertEqual(result["physical"], 0x7000005456)
            self.assertEqual(result["pat_index"], 2)
            self.assertEqual(json.loads((output / "pte.json").read_text()),
                             result)
            self.assertEqual((output / "mtree.txt").read_bytes().decode(),
                             mtree)
        self.assertEqual(monitor.call.call_args_list,
                         [call("query-kvm"), call("stop"), call("cont")])

    def test_cleanup_signals_group_after_leader_exits(self):
        process = Mock(pid=12345)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with patch.object(self.runner.os, "killpg") as killpg:
            self.runner.stop_process(process)
        self.assertTrue(any(
            args[0] == process.pid
            and args[1] in (signal.SIGTERM, signal.SIGKILL)
            for args, _kwargs in killpg.call_args_list
        ))


class ArmTests(unittest.TestCase):
    def test_page_and_block_mappings(self):
        mair = 0xff | (0x44 << 16)
        # Explicit addresses exercise all supported translation granules.
        cases = (
            (16, 0x40203456, 0x1000,
             {0x1000: 0x2003, 0x2008: 0x3003, 0x3008: 0x4003,
              0x4018: 0x700000500b}, 0x7000005456, 4096),
            (16, 0x40203456, 0x1000,
             {0x1000: 0x2003, 0x2008: 0x3003,
              0x3008: 0x7000200009}, 0x7000203456, 2 << 20),
            ((2 << 14) | 16, 0x40203456, 0x4000,
             {0x4000: 0x8003, 0x8000: 0xc003, 0xc100: 0x10003,
              0x10400: 0x700000400b}, 0x7000007456, 16384),
            ((2 << 14) | 16, 0x40203456, 0x4000,
             {0x4000: 0x8003, 0x8000: 0xc003,
              0xc100: 0x7002000009}, 0x7002203456, 32 << 20),
            ((1 << 14) | 16, 0x40203456, 0x10000,
             {0x10000: 0x20003, 0x20010: 0x30003,
              0x30100: 0x700001000b}, 0x7000013456, 65536),
            # A 4K 42-bit VA starts in an aligned 64-byte root table.
            (22, 0x80203456, 0x1040,
             {0x1040: 0x2003, 0x2010: 0x3003, 0x3008: 0x4003,
              0x4018: 0x700000500b}, 0x7000005456, 4096),
        )
        for tcr, va, ttbr, memory, pa, leaf_size in cases:
            with self.subTest(tcr=tcr, size=leaf_size):
                result = walk_arm_page_tables(
                    memory.__getitem__, va, ttbr | (0x1234 << 48) | 1,
                    tcr | (5 << 32), mair)
                self.assertEqual(result["physical"], pa)
                self.assertEqual(result["leaf_size"], leaf_size)
                self.assertEqual(result["attr_index"], 2)
                self.assertEqual(result["mair_attr"], 0x44)
                self.assertEqual(result["guest_memory_type"],
                                 "Normal non-cacheable")

    def test_mair2_leaf_rejected_but_table_pxn_allowed(self):
        cases = (
            (0x4018, {0x1000: 0x2003, 0x2008: 0x3003,
                      0x3008: 0x4003, 0x4018: 0x700000500b}),
            (0x3008, {0x1000: 0x2003, 0x2008: 0x3003,
                      0x3008: 0x7000200009}),
        )
        for leaf, memory in cases:
            with self.subTest(leaf=leaf):
                memory[leaf] |= 1 << 59
                with self.assertRaisesRegex(RuntimeError, "MAIR2"):
                    walk_arm_page_tables(memory.__getitem__, 0x40203456,
                                         0x1000, 16 | (5 << 32), 0x44ffff)
                memory[leaf] &= ~(1 << 59)
                result = walk_arm_page_tables(
                    memory.__getitem__, 0x40203456, 0x1000,
                    16 | (5 << 32), 0x44ffff)
                self.assertEqual(result["attr_index"], 2)
                self.assertEqual(result["mair_attr"], 0x44)
                self.assertEqual(result["guest_memory_type"],
                                 "Normal non-cacheable")
                memory[0x1000] |= 1 << 59  # PXNTable, not a MAIR2 selector.
                result = walk_arm_page_tables(
                    memory.__getitem__, 0x40203456, 0x1000,
                    16 | (5 << 32), 0x44ffff)
                self.assertEqual(result["mair_attr"], 0x44)

    def test_invalid_and_unsupported_translation(self):
        memory = {0x1000: 0x2003, 0x2000: 0x3003,
                  0x3000: 0x4003, 0x4000: 0x5003}
        for address in memory:
            absent = dict(memory)
            absent[address] = 0
            with self.subTest(absent=address):
                with self.assertRaisesRegex(ValueError, "absent"):
                    walk_arm_page_tables(absent.__getitem__, 0, 0x1000,
                                         16, 0xff)
        for tcr in (12, 16 | (6 << 32), 16 | (1 << 59), 16 | (3 << 14)):
            with self.subTest(tcr=tcr):
                with self.assertRaises(RuntimeError):
                    walk_arm_page_tables(memory.__getitem__, 0, 0x1000,
                                         tcr, 0xff)
        with self.assertRaisesRegex(ValueError, "invalid level"):
            walk_arm_page_tables({0x1000: 0x2001}.__getitem__, 0,
                                 0x1000, 16, 0xff)
        memory[0x4000] = 0x5001  # A level-3 leaf must be a page descriptor.
        with self.assertRaisesRegex(ValueError, "invalid level"):
            walk_arm_page_tables(memory.__getitem__, 0, 0x1000, 16, 0xff)

    def test_gdb_registers_and_failures(self):
        expected = {"SCTLR_EL1": 0x30500801, "TTBR0_EL1": 0x1000,
                    "TCR_EL1": 0x500000010, "MAIR_EL1": 0x44ff}
        dump = "\n".join(f"{name:15} 0x{value:x} {value}"
                         for name, value in expected.items())
        with patch("qmp.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, dump)
            self.assertEqual(read_arm_registers("/tmp/probe/gdb.sock"),
                             expected)
            self.assertEqual(run.call_args.args[0][-2:],
                             ["-ex", "disconnect"])
            self.assertEqual(run.call_args.kwargs["timeout"], 15)
            run.return_value = subprocess.CompletedProcess([], 0, "")
            with self.assertRaisesRegex(RuntimeError, "Missing SCTLR_EL1"):
                read_arm_registers("/tmp/probe/gdb.sock")
            run.return_value = subprocess.CompletedProcess([], 1, "failure")
            with self.assertRaisesRegex(RuntimeError, "failure"):
                read_arm_registers("/tmp/probe/gdb.sock")
        with self.assertRaisesRegex(RuntimeError, "absolute path"):
            read_arm_registers("/tmp/gdb.sock\nshell true")

    def test_capture_keeps_arm_snapshot_stopped_and_validates_mapping(self):
        spec = importlib.util.spec_from_file_location(
            "run_probe", Path(__file__).with_name("run-probe.py"))
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        memory = {0x4000: 0x8003, 0x8000: 0xc003, 0xc100: 0x10003,
                  0x10400: 0x700000400b}
        registers = "PC=0000000040001000 PSTATE=0000000060000000\r\n"
        mtree = ("  0000007000000000-000000700fffffff "
                 "(prio 1, i/o): virtio-gpu-hostmem\r\n")
        cases = (
            (1, False, mtree, None, ""),
            (0, False, mtree, ValueError, "MMU is not enabled"),
            (1 | (1 << 25), False, mtree, RuntimeError, "Big-endian"),
            (1, True, mtree, RuntimeError, "resumed"),
            (1, False, "", ValueError, "GPU hostmem BAR"),
        )
        for sctlr, running, region, error, message in cases:
            with self.subTest(sctlr=sctlr, running=running, region=region):
                system_registers = {
                    "SCTLR_EL1": sctlr, "TTBR0_EL1": 0x1234000000004001,
                    "TCR_EL1": (5 << 32) | (2 << 14) | 16,
                    "MAIR_EL1": 0xff | (0x44 << 16),
                }
                monitor = Mock()
                monitor.call.side_effect = lambda command: {
                    "query-kvm": {"enabled": True},
                    "query-status": {"running": running},
                    "stop": None, "cont": None,
                }[command]

                def hmp(command):
                    if command.startswith("xp /1gx "):
                        self.assertIn(call("query-status"),
                                      monitor.call.call_args_list)
                        self.assertNotIn(call("cont"),
                                         monitor.call.call_args_list)
                        address = int(command.split()[-1], 16)
                        return f"{address:016x}: 0x{memory[address]:016x}\r\n"
                    return {"info registers": registers, "info mtree": region,
                            "info ramblock": "mr: 65536 bytes\r\n"}[command]

                monitor.hmp.side_effect = hmp
                with tempfile.TemporaryDirectory() as directory, patch.object(
                        runner, "read_arm_registers",
                        return_value=system_registers) as read_registers:
                    output = Path(directory)
                    if error:
                        with self.assertRaisesRegex(error, message):
                            runner.capture(monitor, 0x40203456, output,
                                           "/tmp/probe/gdb.sock")
                        self.assertFalse((output / "pte.json").exists())
                    else:
                        result = runner.capture(monitor, 0x40203456, output,
                                                "/tmp/probe/gdb.sock")
                        self.assertEqual(result["physical"], 0x7000007456)
                        self.assertEqual(result["granule_size"], 16384)
                        self.assertEqual(result["system_registers"],
                                         system_registers)
                        self.assertEqual(json.loads(
                            (output / "pte.json").read_text()), result)
                        self.assertEqual((output / "registers.txt").read_bytes(),
                                         registers.encode())
                    read_registers.assert_called_once_with(
                        "/tmp/probe/gdb.sock")
                expected = [call("query-kvm"), call("stop")]
                if sctlr == 1:
                    expected.append(call("query-status"))
                self.assertEqual(monitor.call.call_args_list,
                                 expected + [call("cont")])


class GuestArmTests(unittest.TestCase):
    def test_arm_collection_skips_x86_msrs_and_trace(self):
        spec = importlib.util.spec_from_file_location(
            "guest_info", Path(__file__).with_name("guest-info.py"))
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        args = argparse.Namespace(node=Path("/dev/dri/renderD128"),
                                  probe=Path("/tmp/gpu-blob-probe"),
                                  hold=1, iterations=100)
        machine = os.uname_result(("Linux", "guest", "7.1", "test", "aarch64"))
        with patch.object(guest.os, "uname", return_value=machine), \
                patch.object(guest, "dump_msrs") as dump_msrs, \
                patch.object(guest, "load_module") as load_module, \
                patch.object(guest, "mount_optional"), \
                patch.object(guest.subprocess, "run",
                             return_value=Mock(returncode=0)) as run:
            self.assertEqual(guest.collect(args, None), 0)
            root = Mock()
            with guest.memtype_trace(root):
                pass
            self.assertEqual(root.mock_calls, [])
        dump_msrs.assert_not_called()
        load_module.assert_called_once_with("virtio_gpu", None)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0][0], str(args.probe))


if __name__ == "__main__":
    unittest.main()

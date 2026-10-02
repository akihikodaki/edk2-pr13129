# SPDX-License-Identifier: 0BSD
"""Check page tables, monitor failures, and guest device discovery."""

import importlib.util
import io
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, call, patch

from qmp import QMP, walk_page_tables


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


if __name__ == "__main__":
    unittest.main()

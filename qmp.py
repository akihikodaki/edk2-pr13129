# SPDX-License-Identifier: 0BSD
"""Read QEMU monitor state and walk x86 or AArch64 guest page tables."""

import json
import re
import socket
import subprocess
from typing import Any, Callable, Dict, Optional


class QMP:
    """A synchronous QMP connection with bounded reads."""

    def __init__(self, path: str, timeout: float = 5.0) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.stream = None
        try:
            self.sock.connect(path)
            self.stream = self.sock.makefile("rwb")
            if "QMP" not in self.receive():
                raise RuntimeError("QMP greeting is missing")
            self.call("qmp_capabilities")
        except BaseException:
            self.close()
            raise

    def receive(self) -> Dict[str, Any]:
        """Read one response, rejecting a closed or malformed connection."""
        assert self.stream is not None
        line = self.stream.readline(8 * 1024 * 1024)
        if not line:
            raise ConnectionError("QMP connection closed")
        if not line.endswith(b"\n"):
            raise RuntimeError("QMP response exceeds the size limit")
        reply = json.loads(line)
        if not isinstance(reply, dict):
            raise RuntimeError("QMP response is not an object")
        return reply

    def call(self, command: str,
             arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Execute one command, skipping asynchronous events."""
        assert self.stream is not None
        request = {"execute": command, "arguments": arguments or {}}
        self.stream.write(json.dumps(request).encode() + b"\n")
        self.stream.flush()
        while True:
            reply = self.receive()
            if "error" in reply:
                raise RuntimeError(f"QMP {command}: {reply['error']}")
            if "return" in reply:
                return reply["return"]

    def hmp(self, command: str) -> str:
        """Run an HMP command through QMP."""
        return self.call("human-monitor-command", {"command-line": command})

    def close(self) -> None:
        """Release the monitor connection."""
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            self.sock.close()

    def __enter__(self) -> "QMP":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


def walk_page_tables(read64: Callable[[int], int], va: int, cr3: int,
                     cr4: int) -> Dict[str, Any]:
    """Resolve a 4- or 5-level x86 mapping, preserving its PAT selector."""
    address_mask = 0x000FFFFFFFFFF000
    table = cr3 & address_mask
    shifts = ([48] if cr4 & (1 << 12) else []) + [39, 30, 21, 12]
    walk = []
    for shift in shifts:
        address = table + ((va >> shift) & 511) * 8
        entry = read64(address)
        walk.append({"shift": shift, "address": address, "entry": entry})
        if not entry & 1:
            raise ValueError(f"Page-table entry at 0x{address:x} is absent")
        large = shift in (21, 30) and bool(entry & 128)
        if shift == 12 or large:
            pat_bit = 12 if large else 7
            index = ((entry >> 3) & 3) | (((entry >> pat_bit) & 1) << 2)
            offset_mask = (1 << shift) - 1
            physical = ((entry & address_mask & ~offset_mask)
                        | (va & offset_mask))
            return {
                "physical": physical,
                "pat_index": index,
                "leaf_size": 1 << shift,
                "walk": walk,
            }
        if entry & 128:
            raise ValueError("Large page at an invalid page-table level")
        table = entry & address_mask
    raise ValueError("Page-table walk did not reach a leaf")


def read_arm_registers(gdb_socket: str) -> Dict[str, int]:
    """Read system registers absent from ARM HMP, leaving QEMU stopped."""
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", gdb_socket):
        raise RuntimeError("GDB socket must have a shell-safe absolute path")
    names = ("SCTLR_EL1", "TTBR0_EL1", "TCR_EL1", "MAIR_EL1")
    command = [
        "gdb", "--nx", "--quiet", "--batch",
        "-iex", "set auto-load off", "-ex", "set remotetimeout 5",
        "-ex", f"target remote {gdb_socket}",
        "-ex", "info registers " + " ".join(names),
        # detach would resume the guest before its tables are captured.
        "-ex", "disconnect",
    ]
    reply = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=15)
    if reply.returncode:
        raise RuntimeError(f"Cannot read ARM registers: {reply.stdout.strip()}")
    registers = {}
    for name in names:
        match = re.search(rf"^{name}\s+0x([0-9a-fA-F]+)\b", reply.stdout,
                          re.MULTILINE)
        if match is None:
            raise RuntimeError(f"Missing {name} in QEMU GDB register dump")
        registers[name] = int(match[1], 16)
    return registers


def walk_arm_page_tables(read64: Callable[[int], int], va: int,
                         ttbr0: int, tcr: int, mair: int) -> Dict[str, Any]:
    """Resolve an EL0 stage-1 mapping with a 4K, 16K, or 64K granule.

    Limited to the original <=48-bit descriptor format. This reports the
    guest MAIR attribute, not the combined KVM stage-1/stage-2 memory type.
    """
    granule_bits = {0: 12, 1: 16, 2: 14}.get((tcr >> 14) & 3)
    if granule_bits is None:
        raise RuntimeError("Reserved ARM TG0 translation granule")
    va_bits = 64 - (tcr & 63)
    ips = (tcr >> 32) & 7
    if not 25 <= va_bits <= 48 or ips > 5 or tcr & (1 << 59):
        raise RuntimeError("ARM walk requires 25-48 VA bits and <=48 PA bits")
    if tcr & (1 << 7):
        raise ValueError("TTBR0 page-table walks are disabled")
    if tcr & (1 << 37):
        va &= (1 << 56) - 1  # TBI0 permits a tag in the top byte.
    if not 0 <= va < 1 << va_bits:
        raise ValueError("Address is outside the ARM TTBR0 region")

    pa_bits = (32, 36, 40, 42, 44, 48)[ips]
    address_mask = (1 << 48) - 1
    stride = granule_bits - 3
    first_level = 4 - (va_bits - 4) // stride
    first_shift = granule_bits + stride * (3 - first_level)
    # The first table may occupy only part of a granule.
    alignment = max(4, va_bits - first_shift + 3)
    table = ttbr0 & address_mask & ~((1 << alignment) - 1)
    descriptor_mask = address_mask & ~((1 << granule_bits) - 1)
    walk = []
    for level in range(first_level, 4):
        if table >> pa_bits:
            raise ValueError("ARM page table exceeds the PA size")
        shift = granule_bits + stride * (3 - level)
        index_bits = va_bits - shift if level == first_level else stride
        address = table + ((va >> shift) & ((1 << index_bits) - 1)) * 8
        entry = read64(address)
        walk.append({"level": level, "shift": shift,
                     "address": address, "entry": entry})
        if not entry & 1:
            raise ValueError(f"Page-table entry at 0x{address:x} is absent")
        table = entry & descriptor_mask
        if table >> pa_bits:
            raise ValueError("ARM descriptor exceeds the PA size")
        if level < 3 and entry & 2:
            continue
        if not entry & 2 and not (level == 2 or
                                  (level == 1 and granule_bits == 12)):
            raise ValueError("ARM block descriptor at an invalid level")
        index = (entry >> 2) & 7
        attr = (mair >> (index * 8)) & 255
        memory_type = {
            0x00: "Device-nGnRnE", 0x04: "Device-nGnRE",
            0x08: "Device-nGRE", 0x0c: "Device-GRE",
            0x44: "Normal non-cacheable", 0xff: "Normal write-back",
            0xbb: "Normal write-through", 0xf0: "Normal tagged write-back",
        }.get(attr, f"MAIR attribute 0x{attr:02x}")
        offset_mask = (1 << shift) - 1
        return {
            "physical": (table & ~offset_mask) | (va & offset_mask),
            "attr_index": index, "mair_el1": mair, "mair_attr": attr,
            "guest_memory_type": memory_type, "leaf_size": 1 << shift,
            "granule_size": 1 << granule_bits, "walk": walk,
        }
    raise ValueError("ARM page-table walk did not reach a leaf")

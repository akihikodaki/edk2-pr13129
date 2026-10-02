# SPDX-License-Identifier: 0BSD
"""Read QEMU monitor state and walk x86 guest page tables."""

import json
import socket
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

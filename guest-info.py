#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Collect guest cache attributes and run the virtio-gpu blob probe."""

import argparse
import contextlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Iterator
from typing import Optional


def warn(message: str) -> None:
    print(f"WARNING: {message}", file=sys.stderr, flush=True)


def load_module(name: str, root: Optional[Path]) -> None:
    command = ["modprobe"]
    if root is not None:
        command.extend(["-d", str(root)])
    command.append(name)
    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        warn(f"modprobe {name}: {error}; checking available devices")


def read_msr(fd: int, number: int) -> int:
    raw = os.pread(fd, 8, number)
    if len(raw) != 8:
        raise RuntimeError(f"short read of MSR {number:#x}")
    value, = struct.unpack("<Q", raw)
    print(f"MSR {number:#x}={value:#018x}", flush=True)
    return value


def dump_msrs() -> None:
    fd = os.open("/dev/cpu/0/msr", os.O_RDONLY)
    try:
        capability = read_msr(fd, 0xfe)
        read_msr(fd, 0x277)
        read_msr(fd, 0x2ff)
        for number in range(0x200, 0x200 + 2 * (capability & 0xff)):
            read_msr(fd, number)
        if capability & (1 << 8):
            for number in [0x250, 0x258, 0x259, *range(0x268, 0x270)]:
                read_msr(fd, number)
    finally:
        os.close(fd)


def find_render_node(drm: Path = Path("/sys/class/drm"),
                     nodes: Path = Path("/dev/dri")) -> Path:
    for render in sorted(drm.glob("renderD*")):
        device = (render / "device").resolve()
        if (device / "driver").resolve().name == "virtio_gpu":
            return nodes / render.name
        for pci in (device, device.parent):
            try:
                vendor = int((pci / "vendor").read_text(), 16)
                product = int((pci / "device").read_text(), 16)
            except (OSError, ValueError):
                continue
            if (vendor, product) == (0x1af4, 0x1050):
                return nodes / render.name
    raise RuntimeError("no virtio-gpu render node found")


def mount_optional(filesystem: str, target: Path) -> None:
    if os.path.ismount(target):
        return
    try:
        target.mkdir(parents=True, exist_ok=True)
        subprocess.run(["mount", "-t", filesystem, filesystem, str(target)],
                       check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        warn(f"{filesystem} unavailable: {error}")


@contextlib.contextmanager
def memtype_trace(root: Path) -> Iterator[None]:
    name = f"memtype_probe_{os.getpid()}"
    events = root / "kprobe_events"
    enable = root / "events" / "kprobes" / name / "enable"
    registered = False
    tracing = None
    active = False
    try:
        try:
            tracing = (root / "tracing_on").read_text()
            with events.open("a") as stream:
                # The first three integer arguments use these x86-64 regs.
                stream.write(f"p:{name} memtype_reserve start=%di:x64 "
                             "end=%si:x64 requested=%dx:u32\n")
            registered = True
            enable.write_text("1")
            (root / "tracing_on").write_text("1")
            active = True
        except OSError as error:
            warn(f"memtype_reserve trace unavailable: {error}")
        yield
    finally:
        if registered:
            try:
                enable.write_text("0")
            except OSError as error:
                warn(f"cannot disable memtype trace: {error}")
        if tracing is not None:
            try:
                (root / "tracing_on").write_text(tracing)
            except OSError as error:
                warn(f"cannot restore tracing state: {error}")
        if active:
            try:
                lines = [line for line in
                         (root / "trace").read_text().splitlines()
                         if name in line]
                print("MEMTYPE_TRACE", flush=True)
                print("\n".join(lines), flush=True)
                if not lines:
                    warn("memtype_reserve trace recorded no matching calls")
            except OSError as error:
                warn(f"cannot read memtype trace: {error}")
        if registered:
            try:
                with events.open("a") as stream:
                    stream.write(f"-:{name}\n")
            except OSError as error:
                warn(f"cannot remove memtype trace: {error}")


def positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def collect(args: argparse.Namespace, module_root: Optional[Path]) -> int:
    print("GUEST", os.uname(), flush=True)
    print("EFI", Path("/sys/firmware/efi").is_dir(), flush=True)
    try:
        print(Path("/proc/mtrr").read_text(), flush=True)
    except OSError as error:
        warn(f"/proc/mtrr unavailable: {error}")
    if not Path("/dev/cpu/0/msr").exists():
        load_module("msr", module_root)
    dump_msrs()
    load_module("virtio_gpu", module_root)
    node = args.node or find_render_node()
    print("RENDER_NODE", node, flush=True)
    try:
        subprocess.run(["lspci", "-vv", "-d", "1af4:1050"], check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        warn(f"lspci unavailable: {error}")

    mount_optional("debugfs", Path("/sys/kernel/debug"))
    trace = Path("/sys/kernel/tracing")
    mount_optional("tracefs", trace)
    with memtype_trace(trace):
        result = subprocess.run(
            [str(args.probe.resolve()), "--node", str(node),
             "--hold", str(args.hold),
             "--iterations", str(args.iterations)], check=False)
    return result.returncode if result.returncode >= 0 else (
        128 - result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--hold", type=positive_integer, default=20)
    parser.add_argument("--iterations", type=positive_integer, default=100000)
    parser.add_argument("--modules", type=Path,
                        help="directory of modules for the running kernel")
    args = parser.parse_args()

    try:
        if args.modules is None:
            return collect(args, None)
        modules = args.modules.resolve(strict=True)
        if not modules.is_dir():
            raise RuntimeError(f"not a module directory: {modules}")
        with tempfile.TemporaryDirectory(prefix="probe-modules-") as path:
            root = Path(path)
            link = root / "lib" / "modules" / os.uname().release
            link.parent.mkdir(parents=True)
            link.symlink_to(modules, target_is_directory=True)
            return collect(args, root)
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Inspect virtio-gpu cache attributes using vng and prebuilt x86 binaries."""

import argparse
import base64
from datetime import datetime
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import Any, Dict, List

from qmp import QMP, walk_page_tables


SOURCE = Path(__file__).resolve().parent
PAT_TYPES = {0: "UC", 1: "WC", 4: "WT", 5: "WP", 6: "WB", 7: "UC-"}
MAP_CACHE_TYPES = {
    0: "VIRTIO_GPU_MAP_CACHE_NONE", 1: "VIRTIO_GPU_MAP_CACHE_CACHED",
    2: "VIRTIO_GPU_MAP_CACHE_UNCACHED", 3: "VIRTIO_GPU_MAP_CACHE_WC",
}
MAPPING = re.compile(r"MAPPED pid=\d+ va=(0x[0-9a-f]+) size=(\d+)")
HOSTMEM = re.compile(
    r"^\s*([0-9a-f]+)-([0-9a-f]+).*: virtio-gpu-hostmem\r?$", re.MULTILINE
)


def positive_integer(value: str) -> int:
    """Parse a positive integer without accepting shell syntax."""
    if not value.isdecimal() or int(value) == 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return int(value)


def memory_size(value: str) -> str:
    """Validate a QEMU memory size before passing it through vng."""
    if not re.fullmatch(r"[1-9][0-9]*[KMG]?", value):
        raise argparse.ArgumentTypeError("use a size such as 256M or 1G")
    return value


def executable(value: str) -> Path:
    """Resolve either a program on PATH or an explicit executable path."""
    found = shutil.which(value)
    if found is None:
        raise RuntimeError(f"Executable not found: {value}")
    return Path(found).resolve()


def read_file(value: Path) -> Path:
    """Require a readable regular file."""
    value = value.resolve()
    if not value.is_file() or not os.access(value, os.R_OK):
        raise RuntimeError(f"File is not readable: {value}")
    return value


def alias(runtime: Path, name: str, target: Path) -> Path:
    """Use short, shell-safe paths with vng's command-string interface."""
    link = runtime / name
    link.symlink_to(target.resolve())
    return link


def parse_args() -> argparse.Namespace:
    """All machine-specific inputs are explicit or discovered locally."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--vng", default="vng")
    firmware = parser.add_mutually_exclusive_group()
    firmware.add_argument("--bios", type=Path, help="SeaBIOS image")
    firmware.add_argument("--ovmf-code", type=Path, help="OVMF code image")
    parser.add_argument("--ovmf-vars", type=Path, help="OVMF VARS template")
    parser.add_argument("--modules", type=Path,
                        help="matching lib/modules/RELEASE directory")
    parser.add_argument("--render-node", type=Path,
                        help="host DRM render node (otherwise discovered)")
    parser.add_argument("--guest-node", help="override guest DRM discovery")
    parser.add_argument("--pat", choices=("default", "on", "off", "auto"),
                        default="default")
    parser.add_argument("--pci64", action="store_true",
                        help="force SeaBIOS PCI allocation above 4 GiB")
    parser.add_argument("--memory", type=memory_size, default="1G")
    parser.add_argument("--hostmem", type=memory_size, default="256M")
    parser.add_argument("--hold", type=positive_integer, default=20)
    parser.add_argument("--iterations", type=positive_integer, default=100000)
    parser.add_argument("--timeout", type=positive_integer, default=90,
                        help="seconds allowed to boot and capture a mapping")
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--output", type=Path,
                             help="new directory for results")
    destination.add_argument("--export", action="store_true",
                             help="export a base64 tar.gz on stdout")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if bool(args.ovmf_code) != bool(args.ovmf_vars):
        parser.error("--ovmf-code and --ovmf-vars must be supplied together")
    if args.pci64 and args.ovmf_code:
        parser.error("--pci64 is a SeaBIOS option")
    return args


def build_command(config: argparse.Namespace, runtime: Path) -> List[str]:
    """Construct a vng invocation without shell-sensitive host paths."""
    kernel = read_file(config.kernel)
    qemu = executable(config.qemu)
    vng = executable(config.vng)
    probe = read_file(SOURCE / "gpu-blob-probe")
    if not os.access(probe, os.X_OK):
        raise RuntimeError("Run make before starting the probe")
    if not config.dry_run and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("Read/write access to /dev/kvm is required")

    render_node = config.render_node
    if render_node is None:
        nodes = sorted(Path("/dev/dri").glob("renderD*"))
        render_node = next((p for p in nodes
                            if os.access(p, os.R_OK | os.W_OK)), None)
        if render_node is None:
            raise RuntimeError("No render node; specify --render-node")
    if not config.dry_run and not os.access(render_node, os.R_OK | os.W_OK):
        raise RuntimeError(f"Render node is not accessible: {render_node}")

    displays = subprocess.check_output(
        [str(qemu), "-display", "help"], text=True, timeout=10
    )
    if "egl-headless" in displays.split():
        display = "egl-headless"
    elif "dbus" in displays.split():
        display = "dbus,p2p=on,gl=on"
    else:
        raise RuntimeError("QEMU needs egl-headless or D-Bus OpenGL support")

    render = alias(runtime, "render", render_node)
    qemu_args = ["-machine", "q35", "-device",
                 f"virtio-gpu-gl-pci,hostmem={config.hostmem},blob=true",
                 "-display",
                 f"{display},rendernode={render}",
                 "-qmp", f"unix:{runtime}/qmp.sock,server=on,wait=off"]
    if config.bios:
        bios = alias(runtime, "bios.bin", read_file(config.bios))
        qemu_args += ["-bios", str(bios)]
    if config.ovmf_code:
        code = alias(runtime, "code.fd", read_file(config.ovmf_code))
        vars_file = runtime / "vars.fd"
        shutil.copyfile(read_file(config.ovmf_vars), vars_file)
        qemu_args += [
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
        ]
    if config.pci64:
        qemu_args += ["-fw_cfg", "name=opt/org.seabios/pci64,string=on"]

    guest = ["python3", "/tmp/probe-tools/guest-info.py",
             "--probe", "/tmp/probe-tools/gpu-blob-probe",
             "--hold", str(config.hold),
             "--iterations", str(config.iterations)]
    if config.guest_node:
        guest += ["--node", config.guest_node]
    command = [
        str(vng), "--run", str(alias(runtime, "vmlinuz", kernel)),
        "--qemu", str(alias(runtime, "qemu", qemu)),
        "--disable-microvm", "--force-9p", "--verbose", "--user", "root",
        "--name", "memtype-probe", "--cwd", "/tmp",
        "--cpus", "1", "--memory", config.memory,
        "--append", "iomem=relaxed pti=off",
        f"--rodir=/tmp/probe-tools={alias(runtime, 'tools', SOURCE)}",
    ]
    modules = config.modules
    if modules is None and (kernel.parent / "modules.dep").is_file():
        modules = kernel.parent
    if modules is not None:
        modules = modules.resolve()
        if not (modules / "modules.dep").is_file():
            raise RuntimeError(f"Not a module directory: {modules}")
        if not re.fullmatch(r"[A-Za-z0-9._+-]+", modules.name):
            raise RuntimeError("Module directory must be named for its release")
        # vng locates boot modules by walking the kernel path's parents.
        module_root = runtime / "lib" / "modules"
        module_root.mkdir(parents=True)
        module_link = alias(module_root, modules.name, modules)
        command += [f"--rodir=/tmp/probe-modules={module_link}"]
        guest += ["--modules", "/tmp/probe-modules"]
    if config.pat != "default":
        # Suppress vng's -machine accel=kvm:tcg, then select KVM explicitly.
        command += ["--disable-kvm"]
        qemu_args += ["-cpu", "host,topoext=on",
                      "-accel", f"kvm,honor-guest-pat={config.pat}"]
    command += ["--exec", shlex.join(guest),
                "--qemu-opts=" + shlex.join(qemu_args)]
    return command


def register(registers: str, name: str) -> int:
    """Extract one hexadecimal HMP register."""
    match = re.search(rf"\b{name}=([0-9a-fA-F]+)", registers)
    if match is None:
        raise RuntimeError(f"Missing {name} in QEMU register dump")
    return int(match[1], 16)


def decode_map_info(text: str) -> Dict[str, Any]:
    """Match the renderer's cache attribute to the guest probe's resource."""
    blob = re.search(r"BLOB bo_handle=\d+ res_handle=(\d+) size=\d+", text)
    if blob is None:
        raise RuntimeError("The guest did not report its blob resource")
    resource = int(blob[1])
    replies = re.findall(
        r"VIRGL_MAP_INFO resource=(\d+) ret=0 map_info=(0x[0-9a-fA-F]+)",
        text
    )
    for handle, value in replies:
        if int(handle) == resource:
            info = int(value, 16)
            return {"resource_id": resource, "map_info": info,
                    "virtio_map_cache": MAP_CACHE_TYPES.get(info & 0xf,
                                                           "RESERVED")}
    raise RuntimeError(
        f"No successful map-info capture for resource {resource}; "
        "QEMU must dynamically link virglrenderer"
    )


def capture(qmp: QMP, va: int, output: Path) -> Dict[str, Any]:
    """Capture a stable guest mapping while the vCPU is stopped."""
    if not qmp.call("query-kvm")["enabled"]:
        raise RuntimeError("The probe requires KVM, not TCG")
    qmp.call("stop")
    try:
        registers = qmp.hmp("info registers")
        if not register(registers, "CR0") & (1 << 31):
            raise ValueError("Guest paging is not enabled")

        def read64(address: int) -> int:
            text = qmp.hmp(f"xp /1gx 0x{address:x}")
            match = re.search(r":\s*0x([0-9a-fA-F]+)", text)
            if match is None:
                raise RuntimeError(f"Cannot read page table: {text.strip()}")
            return int(match[1], 16)

        cr3 = register(registers, "CR3")
        cr4 = register(registers, "CR4")
        result = walk_page_tables(read64, va, cr3, cr4)
        mtree = qmp.hmp("info mtree")
        if not any(int(lo, 16) <= result["physical"] <= int(hi, 16)
                   for lo, hi in HOSTMEM.findall(mtree)):
            # A timer interrupt may have scheduled a different process.
            raise ValueError("Current CR3 does not map the GPU hostmem BAR")
        result.update({"virtual": va, "cr3": cr3, "cr4": cr4})
        (output / "registers.txt").write_text(registers, encoding="utf-8")
        (output / "mtree.txt").write_text(mtree, encoding="utf-8")
        (output / "ramblock.txt").write_text(
            qmp.hmp("info ramblock"), encoding="utf-8"
        )
        (output / "pte.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        return result
    finally:
        qmp.call("cont")


def stop_process(process: subprocess.Popen) -> None:
    """Stop only the process group created for this invocation."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The vng leader may exit before QEMU or another descendant does.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def run(config: argparse.Namespace, runtime: Path,
        output: Path) -> Dict[str, Any]:
    """Run the guest and require both a successful probe and a PTE capture."""
    command = build_command(config, runtime)
    observer = read_file(SOURCE / "map-info-observer.so")
    environment = os.environ.copy()
    preload = str(alias(runtime, "map-info-observer.so", observer))
    if environment.get("LD_PRELOAD"):
        preload += " " + environment["LD_PRELOAD"]
    environment["LD_PRELOAD"] = preload
    (output / "command.json").write_text(
        json.dumps(command, indent=2) + "\n", encoding="utf-8"
    )
    metadata = {"options": vars(config), "host": platform.uname()._asdict(),
                "map_info_observer": str(observer),
                "qemu_version": subprocess.check_output(
                    [str(executable(config.qemu)), "--version"],
                    text=True, timeout=10)}
    (output / "metadata.json").write_text(
        json.dumps(metadata, indent=2, default=str) + "\n", encoding="utf-8"
    )
    if config.dry_run:
        return {"command": command}

    log_path = output / "guest.log"
    result = None
    qmp = None
    last_error = "The guest did not reach its mapping hold loop"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", start_new_session=True,
            env=environment
        )

        def drain() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                log.write(line)
                log.flush()

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + config.timeout
            while time.monotonic() < deadline:
                text = log_path.read_text(encoding="utf-8")
                mapping = MAPPING.search(text)
                if mapping and "HOLD " in text:
                    if qmp is None:
                        qmp = QMP(str(runtime / "qmp.sock"))
                    try:
                        result = capture(qmp, int(mapping[1], 16), output)
                        break
                    except ValueError as error:
                        last_error = str(error)
                if process.poll() is not None:
                    last_error = f"vng exited with status {process.returncode}"
                    break
                time.sleep(0.05)
            if result is None:
                raise RuntimeError(f"No valid PTE capture: {last_error}")
            status = process.wait(timeout=config.hold + 15)
            reader.join(timeout=5)
            if status:
                raise RuntimeError(f"vng exited with status {status}")
        finally:
            try:
                if qmp is not None:
                    try:
                        if process.poll() is None:
                            qmp.call("quit")
                    except (OSError, RuntimeError):
                        pass
                    finally:
                        qmp.close()
            finally:
                stop_process(process)
                reader.join(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()

    text = log_path.read_text(encoding="utf-8")
    result.update(decode_map_info(text))
    pat = re.search(r"MSR 0x277=(0x[0-9a-fA-F]+)", text)
    if pat is None:
        raise RuntimeError("The guest did not report IA32_PAT")
    pat_value = int(pat[1], 16)
    pat_entry = (pat_value >> (result["pat_index"] * 8)) & 255
    result["pat_msr"] = pat_value
    result["guest_pat_type"] = PAT_TYPES.get(pat_entry, "reserved")
    for marker, key in (("DEPENDENT_LOAD", "gpu_ns_per_load"),
                        ("RAM_CONTROL", "ram_ns_per_load")):
        match = re.search(rf"{marker} ns_per_load=([0-9.]+)", text)
        if match is None:
            raise RuntimeError(f"The guest did not report {marker}")
        result[key] = float(match[1])
    return result


def main() -> int:
    """Keep failures visible and preserve their logs."""
    config = parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        print("This probe requires a Linux x86_64 host", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="memtype-", dir="/tmp") as temp:
        runtime = Path(temp)
        if config.export:
            output = runtime / "results"
        elif config.output:
            output = config.output.resolve()
        else:
            name = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            output = Path("results") / name
        try:
            output.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            print(f"Cannot create results directory: {error}", file=sys.stderr)
            return 1
        status = 0
        try:
            summary = run(config, runtime, output)
        except (OSError, RuntimeError, ValueError,
                subprocess.SubprocessError) as error:
            summary = {"error": str(error)}
            status = 1
        except KeyboardInterrupt:
            summary = {"error": "Interrupted"}
            status = 130
        (output / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        if config.export:
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                for path in sorted(output.iterdir()):
                    tar.add(path, arcname=path.name)
            print("ARTIFACTS_BASE64:"
                  + base64.b64encode(archive.getvalue()).decode())
        else:
            print(json.dumps(summary, indent=2))
            print(f"Results: {output}")
        return status


if __name__ == "__main__":
    sys.exit(main())

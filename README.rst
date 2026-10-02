.. SPDX-License-Identifier: 0BSD

virtio-gpu memory type probe
==========================

Inspect a Linux guest's mapping of a virgl HOST3D buffer using vng and
prebuilt QEMU, firmware, and kernel binaries. This probe was developed to
investigate https://github.com/tianocore/edk2/pull/13129.

The guest creates a 64 KiB host-visible blob, records PAT and MTRR MSRs,
and measures dependent loads against an anonymous RAM control. The host
pauses the guest through QMP, walks its page tables, and verifies that the
mapping lands in virtio-gpu's host-memory BAR. Results include the raw
registers, page-table entries, memory map, logs, and timings.

``guest_pat_type`` describes the guest PTE's PAT selection. It is not a
direct observation of the effective CPU memory type: that also depends on
KVM's second-stage mapping and the host GPU driver. Use the raw evidence,
KVM configuration, and timings together; this probe does not read EPT/NPT.

Requirements
------------

* Linux x86_64 with access to KVM and a DRM render node.
* QEMU with virglrenderer, host-visible blobs, and either ``egl-headless``
  or the D-Bus OpenGL display backend. Explicit ``--pat`` settings require
  QEMU's ``honor-guest-pat`` accelerator property.
* vng (virtme-ng), Python 3.9 or later, a C11 compiler, make, pkg-config,
  and libdrm development headers. Python uses only the standard library.
* A prebuilt x86_64 Linux kernel suitable for vng, with virtio-gpu, 9p,
  and MSR support built in or provided by matching modules.
* SeaBIOS or a matching pair of OVMF CODE and VARS images. If omitted,
  QEMU's default BIOS is used.

The runner shares the host userspace with the guest through vng. No QEMU
source checkout, guest disk image, or kernel/firmware build is required.
Optional lspci, debugfs, and kprobe diagnostics warn if unavailable.

Build and check
---------------

::

    make
    make check

``CC``, ``CPPFLAGS``, ``CFLAGS``, ``LDFLAGS``, ``LDLIBS``, ``PKG_CONFIG``,
and ``PYTHON`` can be overridden. Checks run without KVM or a GPU: they
validate the dependent-load chain, guest device discovery, page-table
decoding, and QMP failure handling.

Run
---

For SeaBIOS, allocating the GPU BAR above 4 GiB::

    python3 run-probe.py --qemu /path/to/qemu-system-x86_64 \
        --kernel /path/to/lib/modules/RELEASE/vmlinuz \
        --modules /path/to/lib/modules/RELEASE \
        --bios /path/to/bios-256k.bin --pci64 --pat on \
        --output results/seabios-pci64

Omit ``--pci64`` to use SeaBIOS's normal PCI allocation. For OVMF::

    python3 run-probe.py --qemu /path/to/qemu-system-x86_64 \
        --kernel /path/to/lib/modules/RELEASE/vmlinuz \
        --modules /path/to/lib/modules/RELEASE \
        --ovmf-code /path/to/OVMF_CODE.fd \
        --ovmf-vars /path/to/OVMF_VARS.fd --pat on \
        --output results/ovmf

The VARS template is copied for each run. Module directories must be named
for their kernel release; the kernel's parent directory is used when it
contains ``modules.dep``. Host and guest render nodes are discovered;
``--render-node`` and ``--guest-node`` override the choices.

``--pat default`` leaves QEMU's policy unchanged. Compare ``--pat on`` and
``--pat off`` to test whether honoring guest PAT changes the observed
behavior. Both explicitly select KVM, and every live run verifies that
KVM is active. ``--memory`` and ``--hostmem`` control the guest RAM and GPU
BAR sizes. ``--hold`` keeps the mapping active for page-table capture.

Each run writes a new results directory (timestamped by default), even
on failure. ``summary.json`` contains the decoded guest PAT type, physical
address, page size, and timings, or an error. A successful exit requires
both a completed guest probe and a valid GPU page-table capture.

``--dry-run`` records the generated command without booting a VM.
``--export`` instead writes a gzip tar archive, base64-encoded after the
``ARTIFACTS_BASE64:`` prefix, to stdout. This supports execution in an
environment where only temporary storage is writable.

Development and license
-----------------------

Sources follow QEMU's C and Python style, using libc and the Python
standard library to remain standalone. QEMU's checkpatch reports three
intentional exceptions: the requested 0BSD license, libc ``strtoull``
instead of QEMU's helper, and the Linux/x86_64 platform guard.

All source files are licensed under the BSD Zero Clause License, SPDX
``0BSD``; see LICENSE. Captured logs, firmware, and compiled binaries are
not part of the repository. The one-line ``*`` ignore rule is intentional;
use ``git add -f`` when adding a new source file.

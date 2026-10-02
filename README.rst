.. SPDX-License-Identifier: 0BSD

virtio-gpu memory type probe
==========================

Inspect a Linux guest's mapping of a virgl HOST3D buffer using vng and
prebuilt QEMU, firmware, and kernel binaries. This probe was developed to
investigate https://github.com/tianocore/edk2/pull/13129.

The guest creates a 64 KiB host-visible blob and measures dependent loads
against an anonymous RAM control. On x86_64 it records PAT and MTRR MSRs;
on AArch64 the host records the guest's translation and MAIR registers.
The host pauses the guest through QMP, walks its page tables, and verifies
that the mapping lands in virtio-gpu's host-memory BAR. Results include
the raw registers, page-table entries, memory map, logs, and timings. A
small ``LD_PRELOAD`` observer captures virglrenderer's ``map_info`` output
for the probe's resource and decodes its ``VIRTIO_GPU_MAP_CACHE_*`` value.

``guest_pat_type`` describes the guest PTE's PAT selection. It is not a
direct observation of the effective CPU memory type: that also depends on
KVM's second-stage mapping and the host GPU driver. On AArch64,
``guest_memory_type`` describes the PTE's MAIR selection, with the same
limitation. Use the raw evidence, KVM configuration, and timings together;
this probe does not read second-stage page tables.
``virtio_map_cache`` is the device's requested cache attribute, before the
guest applies its mapping policy. For example, ``CACHED`` can still result
in a UC- guest PTE. The Linux ``memtype_reserve`` argument ``requested=0``
means WB; it uses a different enum from ``VIRTIO_GPU_MAP_CACHE_NONE``.

Requirements
------------

* Linux x86_64 or AArch64 with access to KVM and a DRM render node.
* QEMU dynamically linked to virglrenderer, with host-visible blobs and
  either ``egl-headless`` or the D-Bus OpenGL display backend. Explicit
  ``--pat`` settings require QEMU's ``honor-guest-pat`` accelerator property.
* vng (virtme-ng), Python 3.9 or later, a C11 compiler, make, pkg-config,
  and libdrm development headers. Python uses only the standard library.
* A prebuilt native Linux kernel suitable for vng, with virtio-gpu and 9p
  support built in or provided by matching modules. x86_64 also needs MSR
  support; AArch64 needs native GDB on the host to read system registers.
* SeaBIOS or a matching pair of OVMF CODE and VARS images. If omitted,
  QEMU's default BIOS is used on x86_64. AArch64 boots the kernel directly
  unless an AAVMF CODE/VARS pair is supplied through the OVMF options.

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
decoding, resource matching and cache-type decoding, and QMP failures.

Run
---

For AArch64, using QEMU's ``virt`` machine and a native kernel::

    python3 run-probe.py --kernel /path/to/arch/arm64/boot/Image \
        --output results/arm64

The default QEMU executable follows the host architecture. Use ``--qemu``
to select a particular build. AArch64 captures TTBR0_EL1, TCR_EL1,
SCTLR_EL1, and MAIR_EL1 through a local QEMU GDB socket. It supports 4,
16, and 64 KiB translation granules with up to 48-bit virtual and physical
addresses. Unsupported translation formats fail explicitly. ``--pat``,
``--pci64``, and the SeaBIOS ``--bios`` option apply only to x86_64.

On Asahi hosts whose KVM does not support cacheable PFNMAP mappings, use
``--software-renderer``. This sets ``LIBGL_ALWAYS_SOFTWARE=1`` and
``GBM_ALWAYS_SOFTWARE=1`` for the run, using Mesa software GL while keeping
KVM enabled. The native Asahi driver allocates cacheable backing for the
persistent readable buffer, which these hosts cannot register with KVM.
Software results measure the virgl software backing; they do not
characterize the native GPU driver.

For x86_64 SeaBIOS, allocating the GPU BAR above 4 GiB::

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
on failure. ``summary.json`` contains the decoded guest PAT or MAIR type,
physical address, page size, and timings, or an error. ``map_info``
preserves the raw renderer value; ``virtio_map_cache`` names its low four
cache bits. ``resource_id`` identifies the matching guest blob. A successful exit
requires a completed guest probe, valid GPU page-table capture, and a
successful map-info observation for that resource. A statically linked
renderer cannot be observed with ``LD_PRELOAD`` and produces an error.

``--dry-run`` records the generated command without booting a VM.
``--export`` instead writes a gzip tar archive, base64-encoded after the
``ARTIFACTS_BASE64:`` prefix, to stdout. This supports execution in an
environment where only temporary storage is writable.

Development and license
-----------------------

Sources follow QEMU's C and Python style, using libc and the Python
standard library to remain standalone. QEMU's checkpatch reports three
intentional exceptions: the requested 0BSD license, libc ``strtoull``
instead of QEMU's helper, and the Linux/architecture platform guard.

All source files are licensed under the BSD Zero Clause License, SPDX
``0BSD``; see LICENSE. Captured logs, firmware, and compiled binaries are
not part of the repository. The ignore file explicitly includes tracked
files; add an exception when adding a new source file.

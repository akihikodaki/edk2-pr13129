/* SPDX-License-Identifier: 0BSD */
/*
 * Standalone Linux virtio-gpu HOST3D blob mapping probe.
 * Uses the installed DRM UAPI and virgl wire-format constants, with no
 * dependency on QEMU or virglrenderer libraries.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <virtgpu_drm.h>

#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
#error "This probe requires Linux x86_64 or aarch64"
#endif

#define BLOB_SIZE 65536
#define CACHE_LINE_SIZE 64
#define CHAIN_LINES (BLOB_SIZE / CACHE_LINE_SIZE)
#define WORDS_PER_LINE (CACHE_LINE_SIZE / sizeof(uint32_t))
#define CHAIN_STEP 257
#define HOLD_BATCH 100000
#define NS_PER_SECOND UINT64_C(1000000000)
#define SENTINEL_FIRST UINT32_C(0x12345678)
#define SENTINEL_LAST UINT32_C(0x87654321)

/* Stable protocol values from virgl_protocol.h and virgl_hw.h. */
#define VIRGL_CCMD_PIPE_RESOURCE_CREATE 48
#define VIRGL_PIPE_RES_CREATE_SIZE 11
#define VIRGL_PIPE_BUFFER 0
#define VIRGL_FORMAT_R8_UNORM 64
#define VIRGL_BIND_VERTEX_BUFFER (1U << 4)
#define VIRGL_RESOURCE_FLAG_MAP_PERSISTENT (1U << 1)
#define VIRGL_RESOURCE_FLAG_MAP_COHERENT (1U << 2)

static void fail(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

static uint64_t parse_number(const char *text, uint64_t min, uint64_t max)
{
    char *end;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 10);
    if (text[0] < '0' || text[0] > '9' || *end || errno == ERANGE ||
        value < min || value > max) {
        fprintf(stderr, "Invalid integer: %s (range %" PRIu64 "..%" PRIu64
                ")\n", text, min, max);
        exit(EXIT_FAILURE);
    }
    return value;
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        fail("clock_gettime");
    }
    return (uint64_t)now.tv_sec * NS_PER_SECOND + now.tv_nsec;
}

static uint32_t *map_ram(void)
{
    void *mapping = mmap(NULL, BLOB_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mapping == MAP_FAILED) {
        fail("mmap RAM control");
    }
    return mapping;
}

static void check_sentinels(uint32_t *mapping)
{
    /* Force actual device-memory accesses instead of constant propagation. */
    volatile uint32_t *data = mapping;

    data[0] = SENTINEL_FIRST;
    data[BLOB_SIZE / sizeof(*data) - 1] = SENTINEL_LAST;
    atomic_thread_fence(memory_order_seq_cst);
    if (data[0] != SENTINEL_FIRST ||
        data[BLOB_SIZE / sizeof(*data) - 1] != SENTINEL_LAST) {
        fprintf(stderr, "FAIL: sentinel readback mismatch\n");
        exit(EXIT_FAILURE);
    }
}

static void init_chain(uint32_t *mapping)
{
    uint32_t i;

    /* An odd step visits every line in this power-of-two sized buffer. */
    for (i = 0; i < CHAIN_LINES; i++) {
        mapping[i * WORDS_PER_LINE] =
            ((i + CHAIN_STEP) & (CHAIN_LINES - 1)) * WORDS_PER_LINE;
    }
    atomic_thread_fence(memory_order_seq_cst);
}

static uint32_t chase_chain(const uint32_t *mapping, uint64_t iterations,
                           uint32_t index)
{
    /* Every benchmark iteration must perform its dependent memory load. */
    const volatile uint32_t *data = mapping;
    uint64_t i;

    for (i = 0; i < iterations; i++) {
        index = data[index];
    }
    return index;
}

static double measure_latency(const uint32_t *mapping, uint64_t iterations,
                              uint32_t *index)
{
    uint64_t begin = monotonic_ns();

    *index = chase_chain(mapping, iterations, 0);
    return (double)(monotonic_ns() - begin) / iterations;
}

static void self_test(void)
{
    uint32_t *mapping = map_ram();
    bool visited[CHAIN_LINES] = { false };
    uint32_t index = 0;
    uint32_t i;

    check_sentinels(mapping);
    init_chain(mapping);
    for (i = 0; i < CHAIN_LINES; i++) {
        if (index >= BLOB_SIZE / sizeof(*mapping) ||
            index % WORDS_PER_LINE || visited[index / WORDS_PER_LINE]) {
            fprintf(stderr, "SELF_TEST failed: malformed chain\n");
            exit(EXIT_FAILURE);
        }
        visited[index / WORDS_PER_LINE] = true;
        index = mapping[index];
    }
    if (index || chase_chain(mapping, CHAIN_LINES, 0) ||
        chase_chain(mapping, 1, 0) != CHAIN_STEP * WORDS_PER_LINE) {
        fprintf(stderr, "SELF_TEST failed: unexpected chain result\n");
        exit(EXIT_FAILURE);
    }
    if (munmap((void *)mapping, BLOB_SIZE) < 0) {
        fail("munmap self-test");
    }
    puts("SELF_TEST passed: anonymous RAM sentinels and dependent-load chain");
}

static void print_pat_reservations(void)
{
#ifdef __x86_64__
    FILE *pat = fopen("/sys/kernel/debug/x86/pat_memtype_list", "r");
    char line[256];

    if (!pat) {
        perror("read active pat_memtype_list (optional)");
        return;
    }
    puts("PAT_RESERVATIONS_WHILE_MAPPED");
    while (fgets(line, sizeof(line), pat)) {
        fputs(line, stdout);
    }
    if (ferror(pat)) {
        fprintf(stderr, "Could not read all active PAT reservations\n");
    }
    fclose(pat);
#endif
}

static void check_features(int fd)
{
    const uint32_t required[] = {
        VIRTGPU_PARAM_3D_FEATURES,
        VIRTGPU_PARAM_RESOURCE_BLOB,
        VIRTGPU_PARAM_HOST_VISIBLE,
        VIRTGPU_PARAM_CONTEXT_INIT,
        VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs,
    };
    size_t i;

    for (i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        uint64_t value = 0;
        struct drm_virtgpu_getparam get = {
            .param = required[i],
            .value = (uintptr_t)&value,
        };

        if (ioctl(fd, DRM_IOCTL_VIRTGPU_GETPARAM, &get) < 0) {
            fail("GETPARAM");
        }
        printf("PARAM %u = 0x%" PRIx64 "\n", required[i], value);
        if (!value ||
            (required[i] == VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs &&
             !(value & (UINT64_C(1) << VIRTGPU_DRM_CAPSET_VIRGL2)))) {
            fprintf(stderr, "Required virtio-gpu feature %u is absent\n",
                    required[i]);
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char **argv)
{
    const struct option options[] = {
        { "node", required_argument, NULL, 'n' },
        { "hold", required_argument, NULL, 't' },
        { "iterations", required_argument, NULL, 'i' },
        { "self-test", no_argument, NULL, 's' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    const char *node = "/dev/dri/renderD128";
    uint64_t iterations = 100000;
    uint64_t hold = 20;
    bool test_only = false;
    uint32_t caps[1024] = { 0 };
    struct drm_virtgpu_get_caps getcaps = {
        .cap_set_id = VIRTGPU_DRM_CAPSET_VIRGL2,
        .cap_set_ver = 2,
        .addr = (uintptr_t)caps,
        .size = sizeof(caps),
    };
    struct drm_virtgpu_context_set_param context_param = {
        .param = VIRTGPU_CONTEXT_PARAM_CAPSET_ID,
        .value = VIRTGPU_DRM_CAPSET_VIRGL2,
    };
    struct drm_virtgpu_context_init context = {
        .num_params = 1,
        .ctx_set_params = (uintptr_t)&context_param,
    };
    uint32_t command[] = {
        VIRGL_CCMD_PIPE_RESOURCE_CREATE | (VIRGL_PIPE_RES_CREATE_SIZE << 16),
        VIRGL_PIPE_BUFFER, VIRGL_FORMAT_R8_UNORM, VIRGL_BIND_VERTEX_BUFFER,
        BLOB_SIZE, 1, 1, 1, 0, 0,
        VIRGL_RESOURCE_FLAG_MAP_PERSISTENT | VIRGL_RESOURCE_FLAG_MAP_COHERENT,
        1,
    };
    struct drm_virtgpu_resource_create_blob blob = {
        .blob_mem = VIRTGPU_BLOB_MEM_HOST3D,
        .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
        .size = BLOB_SIZE,
        .cmd_size = sizeof(command),
        .cmd = (uintptr_t)command,
        .blob_id = 1,
    };
    struct drm_virtgpu_map map = { 0 };
    struct drm_gem_close close_blob = { 0 };
    uint32_t *mapping;
    uint32_t *control;
    uint32_t index;
    uint32_t control_index;
    uint64_t begin;
    double blob_ns;
    double control_ns;
    int option;
    int fd;

    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'n':
            node = optarg;
            break;
        case 't':
            hold = parse_number(optarg, 0, UINT32_MAX);
            break;
        case 'i':
            iterations = parse_number(optarg, 1, UINT64_MAX);
            break;
        case 's':
            test_only = true;
            break;
        case 'h':
            printf("Usage: %s [--node PATH] [--hold SECONDS]\n"
                   "       [--iterations COUNT] [--self-test]\n"
                   "Linux x86_64/aarch64; defaults: renderD128, 20 s, "
                   "100000 loads.\n",
                   argv[0]);
            return EXIT_SUCCESS;
        default:
            return EXIT_FAILURE;
        }
    }
    if (optind != argc || !node[0]) {
        fprintf(stderr, "Expected named options and a nonempty render node\n");
        return EXIT_FAILURE;
    }
    if (test_only) {
        self_test();
        return EXIT_SUCCESS;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    fd = open(node, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fail("open render node");
    }
    check_features(fd);
    /* Querying v2 caps initializes virgl's inferred GL buffer cache type. */
    if (ioctl(fd, DRM_IOCTL_VIRTGPU_GET_CAPS, &getcaps) < 0) {
        fail("GET_CAPS virgl2");
    }
    printf("CAPS virgl2 max_version=%u\n", caps[0]);
    if (caps[0] < getcaps.cap_set_ver) {
        fprintf(stderr, "Host did not return the requested virgl2 caps\n");
        return EXIT_FAILURE;
    }
    if (ioctl(fd, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &context) < 0) {
        fail("CONTEXT_INIT virgl2");
    }
    if (ioctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &blob) < 0) {
        fail("CREATE_BLOB");
    }
    printf("BLOB bo_handle=%u res_handle=%u size=%u\n",
           blob.bo_handle, blob.res_handle, BLOB_SIZE);
    map.handle = blob.bo_handle;
    if (ioctl(fd, DRM_IOCTL_VIRTGPU_MAP, &map) < 0) {
        fail("MAP ioctl");
    }
    printf("MAP offset=0x%" PRIx64 "\n", (uint64_t)map.offset);
    mapping = mmap(NULL, BLOB_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                   fd, map.offset);
    if (mapping == MAP_FAILED) {
        fail("mmap blob");
    }
    check_sentinels(mapping);
    printf("MAPPED pid=%d va=%p size=%u first=0x%x last=0x%x\n",
           getpid(), (void *)mapping, BLOB_SIZE, mapping[0],
           mapping[BLOB_SIZE / sizeof(*mapping) - 1]);
    print_pat_reservations();

    /* Timings support the raw PTE inspection; they do not decode a type. */
    init_chain(mapping);
    blob_ns = measure_latency(mapping, iterations, &index);
    printf("DEPENDENT_LOAD ns_per_load=%.2f iterations=%" PRIu64 " index=%u\n",
           blob_ns, iterations, index);
    control = map_ram();
    init_chain(control);
    control_ns = measure_latency(control, iterations, &control_index);
    printf("RAM_CONTROL ns_per_load=%.2f iterations=%" PRIu64
           " index=%u blob_over_ram=%.2f\n",
           control_ns, iterations, control_index, blob_ns / control_ns);
    if (munmap((void *)control, BLOB_SIZE) < 0) {
        fail("munmap RAM control");
    }

    printf("HOLD busy loop %" PRIu64 " seconds\n", hold);
    begin = monotonic_ns();
    while (monotonic_ns() - begin < hold * NS_PER_SECOND) {
        index = chase_chain(mapping, HOLD_BATCH, index);
    }
    printf("HOLD done index=%u\n", index);
    if (munmap((void *)mapping, BLOB_SIZE) < 0) {
        fail("munmap blob");
    }
    close_blob.handle = blob.bo_handle;
    if (ioctl(fd, DRM_IOCTL_GEM_CLOSE, &close_blob) < 0) {
        fail("GEM_CLOSE");
    }
    close(fd);
    return EXIT_SUCCESS;
}

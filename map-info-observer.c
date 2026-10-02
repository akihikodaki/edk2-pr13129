/* SPDX-License-Identifier: 0BSD */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int virgl_renderer_resource_get_map_info(uint32_t resource, uint32_t *info)
{
    int (*get_info)(uint32_t, uint32_t *);
    int ret;
    int saved_errno = errno;

    get_info = dlsym(RTLD_NEXT, "virgl_renderer_resource_get_map_info");
    if (!get_info) {
        fprintf(stderr, "get_map_info lookup failed: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    errno = saved_errno;
    ret = get_info(resource, info);
    saved_errno = errno;
    if (!ret) {
        fprintf(stderr, "VIRGL_MAP_INFO resource=%" PRIu32
                " ret=%d map_info=0x%08" PRIx32 " cache=0x%x\n",
                resource, ret, *info, *info & 0xf);
    } else {
        fprintf(stderr, "VIRGL_MAP_INFO resource=%" PRIu32 " ret=%d\n",
                resource, ret);
    }
    errno = saved_errno;
    return ret;
}

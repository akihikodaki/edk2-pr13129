# SPDX-License-Identifier: 0BSD

CC ?= cc
CFLAGS ?= -O2 -g
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
DRM_CFLAGS = $(shell $(PKG_CONFIG) --cflags libdrm)

.PHONY: all check clean

all: gpu-blob-probe

gpu-blob-probe: gpu-blob-probe.c
	$(PKG_CONFIG) --exists libdrm
	$(CC) $(CPPFLAGS) $(DRM_CFLAGS) $(CFLAGS) -std=c11 -Wall -Wextra \
		$(LDFLAGS) -o $@ $< $(LDLIBS)

check: gpu-blob-probe
	./gpu-blob-probe --self-test
	$(PYTHON) -m unittest discover -v

clean:
	$(RM) gpu-blob-probe

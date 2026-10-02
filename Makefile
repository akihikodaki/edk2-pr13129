# SPDX-License-Identifier: 0BSD

CC ?= cc
CFLAGS ?= -O2 -g
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
DRM_CFLAGS = $(shell $(PKG_CONFIG) --cflags libdrm)

.PHONY: all check clean

all: gpu-blob-probe map-info-observer.so

gpu-blob-probe: gpu-blob-probe.c
	$(PKG_CONFIG) --exists libdrm
	$(CC) $(CPPFLAGS) $(DRM_CFLAGS) $(CFLAGS) -std=c11 -Wall -Wextra \
		$(LDFLAGS) -o $@ $< $(LDLIBS)

map-info-observer.so: map-info-observer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 -Wall -Wextra -shared -fPIC \
		$(LDFLAGS) -o $@ $< $(LDLIBS) -ldl

check: all
	./gpu-blob-probe --self-test
	$(PYTHON) -m unittest discover -v

clean:
	$(RM) gpu-blob-probe map-info-observer.so

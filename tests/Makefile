# SPDX-License-Identifier: GPL-2.0-or-later
# C helpers of the guest scripts: make -C tests
CFLAGS ?= -O2 -Wall
HELPERS = killed_short_write killed_write_mmap aio_dio_partial

all: $(HELPERS)

clean:
	rm -f $(HELPERS)

.PHONY: all clean

# ctrl-exec - build the privileged executor (C). The rest of ctrl-exec is Perl
# and needs no build step; this Makefile exists only for src/ctrl-exec-exec.
#
# The executor is the small, root, no-network half of the privilege-separated
# agent. Phase 2b adds capability handling (-lcap) and the socket/exec paths.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  ?= -lcap

BIN = src/ctrl-exec-exec
SRC = src/ctrl-exec-exec.c

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(BIN)

.PHONY: all clean

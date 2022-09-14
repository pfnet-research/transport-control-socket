#!/bin/make

INTERFACE = ens224

.PHONY: clean
clean:

.PHONY: pipe
pipe:
	cat  /sys/kernel/debug/tracing/trace_pipe

.PHONY: all
all:
	echo "Make all\n"

.PHONY: build
build:
	clang -Iclang -I/lib/modules/`uname -r`/build/include/ -I/lib/modules/`uname -r`/build/usr/include/  -DDEBUG -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign\
    -Wno-compare-distinct-pointer-types -O2 -emit-llvm -c -g bpf.c -o -| llc -march=bpf\
    -filetype=obj -o bpf.o

.PHONY: run
run:
	python3 tc.py $(INTERFACE)

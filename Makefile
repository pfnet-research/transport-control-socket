#!/bin/make

INTERFACE = ens224

.PHONY: clean
clean:

.PHONY: pipe
pipe:
	cat  /sys/kernel/debug/tracing/trace_pipe

.PHONY: run
run:
	python3 tc.py $(INTERFACE)

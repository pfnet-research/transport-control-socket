TARGET = bpf.o
SOURCE = bpf.c

DEVICE ?= test0

CFLAGS = -target bpf -O3 -g

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	rm -rf $(TARGET)

$(TARGET): $(SOURCE)
	clang $(CFLAGS) -c $(SOURCE) -o $(TARGET)

.PHONY: install
install: $(TARGET)
	tc qdisc add dev $(DEVICE) clsact
	tc filter add dev $(DEVICE) ingress pref 100 bpf obj $(TARGET) section tc-ingress
	tc filter add dev $(DEVICE) egress pref 100 bpf obj $(TARGET) section tc-egress

.PHONY: uninstall
uninstall:
	tc filter del dev $(DEVICE) ingress
	tc qdisc del dev $(DEVICE) clsact

.PHONY: tc-status
tc-status:
	tc qdisc show dev $(DEVICE) clsact
	tc filter show dev $(DEVICE) ingress
	tc filter show dev $(DEVICE) egress

.PHONY: map-status
map-status:
	sudo bpftool map dump name set_intent
	sudo bpftool map dump name set_opt_exp
	sudo bpftool map dump name tsval_flow

.PHONY: trace
trace:
	cat /sys/kernel/debug/tracing/trace_pipe

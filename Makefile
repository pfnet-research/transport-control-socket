.PHONY: all
all: agent bpf cmd

.PHONY: agent
agent:
	make -C agent

.PHONY: bpf
bpf:
	make -C bpf

.PHONY: cmd
cmd:
	make -C cmd

.PHONY: clean
clean:
	make clean -C agent
	make clean -C bpf
	make clean -C cmd

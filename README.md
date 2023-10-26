# Network Kernel API with the Control Socket for Extending Transport Protocols
https://doi.org/10.1145/3630202.3630229

## Dependencies
- make
- clang
- gcc-multilib
- libbpf-dev
  
For viewing BPF maps
- linux-tools-generic
- bpftool

## Environment
- Ubuntu 23.04 (Linux 6.2.0-32-generic x86_64)
- Ubuntu 22.04.3 LTS (Linux 5.15.0-83-generic x86_64)

## Building
```bash
make -C agent
make -C bpf
make -C cmd
```

## Problems
#### Incorrectly calculated checksum for UDP packets with UDP options

Disable offloading
```bash
sudo ethtool --offload IFNAME rx off tx off
```
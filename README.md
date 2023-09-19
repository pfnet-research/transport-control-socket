# i22_daiya
Network Kernel API with the Control Socket for Extending Transport Protocols

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
```sh
make -C agent
make -C bpf
make -C cmd
```

## Problems
#### UDPオプションをつけたUDPパケットのchecksumが誤って計算される

オフロードを無効化する
```
sudo ethtool --offload IFNAME rx off tx off
```
#ifndef BPF_UDPBPF_H
#define BPF_UDPBPF_H

#include <stdint.h>

#define MAX_OPTION_SIZE 64

struct key {
    uint32_t local_address;
    uint16_t local_port;
} __attribute__((packed));

struct value{
    uint8_t option_len;
    uint8_t option_data[MAX_OPTION_SIZE];
} __attribute__((packed));


#endif //BPF_UDPBPF_H

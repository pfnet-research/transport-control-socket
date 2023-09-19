#ifndef BPF_UDPBPF_H
#define BPF_UDPBPF_H

#include <stdint.h>
#include "../agent/ctrl_sock.h"

#define MAX_OPTION_SIZE 64

struct map_intent_key {
    uint32_t local_address;
    uint16_t local_port;
} __attribute__((packed));

struct map_intent_value {
    uint8_t option_len;
    uint8_t option_data[MAX_OPTION_SIZE];
} __attribute__((packed));

struct map_set_opt_exp_value {
    uint16_t value;
    set_type_t set_type;
    flow_info_t flow;
} __attribute__((packed));

#endif // BPF_UDPBPF_H

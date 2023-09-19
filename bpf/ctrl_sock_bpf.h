#ifndef BPF_UDPBPF_H
#define BPF_UDPBPF_H

#include <stdint.h>
#include "../agent/ctrl_sock.h"

#define MAX_OPTION_SIZE 64

/** Structures of BPF maps **/

struct map_set_intent_key {
    uint32_t local_address;
    uint16_t local_port;
} __attribute__((packed));

struct map_set_intent_value {
    uint8_t option_len;
    uint8_t option_data[MAX_OPTION_SIZE];
} __attribute__((packed));

struct map_set_opt_exp_value {
    uint16_t value;
    set_type_t set_type;
    flow_info_t flow;
} __attribute__((packed));

struct map_rcvd_opt_exp_value {
    uint16_t value;
    address_info_t addr;;
} __attribute__((packed));

/** Structures for UDP Options **/

struct udp_option_head{
    uint8_t type;
    uint8_t length;
} __attribute__((packed));

struct udp_option_intent {
    struct udp_option_head type_len;
    uint16_t intent;
} __attribute__((packed));

struct udp_option_exp {
    struct udp_option_head type_len;
    uint16_t exp_val;
} __attribute__((packed));

struct udp_option_time {
    struct udp_option_head type_len;
    uint32_t tsval;
    uint32_t tsecr;
} __attribute__((packed));

#endif // BPF_UDPBPF_H

#ifndef UDPCTL_H
#define UDPCTL_H

#include <cstdint>

#define UDPCTL_VERSION 0x01

const uint8_t UDPCTL_MAGIC[16] = {
        0x33, 0x77, 0x33, 0x77,
        0x33, 0x77, 0x33, 0x77,
        0x33, 0x77, 0x33, 0x77,
        0x33, 0x77, 0x33, 0x78
};

enum udpctl_type{
    type_open = 1,
    type_register = 2,
    type_close = 3, // 未実装
    type_keepalive = 4, // 特に何もしない動作確認用
    type_request = 5,
    type_feedback = 6,
};

struct udpctl_open {
    uint8_t version;
    uint8_t magic[16];
} __attribute__((packed));

struct udpctl_register{
    uint32_t local_address;
    uint16_t local_port;
} __attribute__((packed));

struct udpctl_request {
    uint32_t level;
} __attribute__((packed));

struct udpctl_header{
    uint8_t type;
    uint8_t length;
} __attribute__((packed));

#endif //UDPCTL_H

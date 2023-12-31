#ifndef UDPCTL_H
#define UDPCTL_H

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#define CTRL_SOCKET_PATH "/tmp/udp-ctrl.sock"
#define MAX_CONNECTION 10
#define MAX_MESSAGE_SIZE 250 // Maximum size of one ctrl message

/*
 *  UDP Options
 */

#define UDP_OPTION_EOL 0    // End of Options List
#define UDP_OPTION_NOP 1    // No operation
#define UDP_OPTION_APC 2    // Alternate payload checksum
#define UDP_OPTION_FRAG 3   // Fragmentation
#define UDP_OPTION_MDS 4    // Maximum datagram size
#define UDP_OPTION_MRDS 5   // Maximum reassembled datagram size
#define UDP_OPTION_REQ 6    // Request
#define UDP_OPTION_RES 7    // Response
#define UDP_OPTION_TIME 8   // Timestamps
#define UDP_OPTION_AUTH 9   // RESERVED for Authentication (AUTH)
#define UDP_OPTION_EXP 127  // RFC 3692-style experiments
#define UDP_OPTION_UENC 192 // RESERVED for Encryption (UENC)
#define UDP_OPTION_UEXP 254 // RFC 3692-style experiments

/*
 *  Types for message
 */

// user_sock_t: ユーザー空間のソケットを一意に特定する
typedef struct {
    uint32_t pid;
    uint32_t sock_fd;
} user_sock_t;

// set_type_t: どのパケットについてオプションを付与するか指定する
typedef uint16_t set_type_t;
#define SET_TYPE_PERMANENT 0                     // 無制限に送られるパケットにオプションを付与する
#define SET_TYPE_COUNT(N) std::min(N + 1, 65534) // 次から送られるN個のパケットにオプションを付与する
#define SET_TYPE_NEXT SET_TYPE_COUNT(1)          // 次に送信するパケットにオプションを付与する
#define SET_TYPE_RESERVED 65535

// flow_info_t: どのフローに対して設定するかを指定する
typedef struct {
    uint32_t prefix;
    uint32_t netmask;
    uint16_t src_port;
    uint16_t dst_port;
} flow_info_t;

// address_info_t: どのアドレスからの通知するかを指定する
typedef struct {
    uint32_t address;
    uint16_t port;
} address_info_t;

#ifdef __cplusplus

/*
 *  Control  message types
 */

struct msg_header {
    uint8_t length; // Message size including header
    uint8_t type;
} __attribute__((packed));

// Control types 0-9 for open

#define TYPE_NO_OPERATION 0 // なにもしない

struct msg_no_op {
    msg_header hdr;
} __attribute__((packed));

#define TYPE_OPEN 1 // オープン

struct msg_open {
    msg_header hdr;
    user_sock_t user_sock;
} __attribute__((packed));

#define TYPE_REGISTER_PID 1 // PIDの登録

// Control types 10-49 for ctrl

#define TYPE_CTRL_TEST_CONNECTION 10 // コントロールソケットの接続確認

struct msg_ctrl_test_con {
    msg_header hdr;
    uint32_t test_num;
} __attribute__((packed));

#define TYPE_CTRL_SET_OPTION_TIMESTAMP 20 // 送信するUDPパケットにタイムスタンプを付与するための設定

struct msg_ctrl_set_opt_time {
    msg_header hdr;
    flow_info_t flow;
} __attribute__((packed));

#define TYPE_CTRL_SET_OPTION_EXPERIMENTAL 21 // 送信するUDPパケットに実験用オプションを付与するための設定

struct msg_ctrl_set_opt_exp {
    msg_header hdr;
    uint16_t value;
    set_type_t set_type;
    flow_info_t flow;
} __attribute__((packed));

#define TYPE_CTRL_SUBSCRIBE_OPTION_TIMESTAMP 30 // 受け取ったUDPパケットのタイムスタンプをアプリケーションで受け取るための設定

#define TYPE_CTRL_SUBSCRIBE_OPTION_EXPERIMENTAL 31 // 受け取ったUDPパケットのExpオプションをアプリケーションで受け取るための設定

struct msg_ctrl_sbsc_opt_exp {
    msg_header hdr;
    user_sock_t user_sock;
    flow_info_t flow;
} __attribute__((packed));

// Control types 50-89 for notify

#define TYPE_NOTIFY_TEST_CONNECTION_REPLY 50 // コントロールソケットの接続に対する応答

struct msg_ctrl_test_con_reply {
    msg_header hdr;
    uint32_t test_num;
} __attribute__((packed));

#define TYPE_NOTIFY_STATISTICS_JITTER_OPTION_TIMESTAMP 60 // 受け取ったUDPパケットのタイムスタンプの統計をアプリケーションで受け取る通知

#define TYPE_NOTIFY_PER_PACKET_OPTION_EXP 61 // 受け取ったUDPパケットのExpオプションをアプリケーションで受け取る通知

struct msg_notify_per_pkt_opt_exp {
    msg_header hdr;
    uint32_t exp_val;
} __attribute__((packed));

// Control types 90-99 for notify errors

#define TYPE_NOTIFY_INVALID_CTRL_TYPE 90       // コントロールソケットを介して無効なタイプのコントロールパケットが送られてきた場合の通知
#define TYPE_NOTIFY_UNIMPLEMENTED_CTRL_TYPE 91 // コントロールソケットを介して未実装なタイプのコントロールパケットが送られてきた場合の通知

#endif

#endif // UDPCTL_H

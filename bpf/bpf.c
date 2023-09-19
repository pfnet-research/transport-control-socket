/**
 * BPF program for PFN UDP research
 */
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <stdint.h>

#include <bpf/bpf_helpers.h>

#include "ctrl_sock_bpf.h"

#define IP_CHECK_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_LEN_OFF (ETH_HLEN + offsetof(struct iphdr, tot_len))

#define DEBUG

#ifdef DEBUG
#define printk(fmt)                                                                                                                                                                                    \
    ({                                                                                                                                                                                                 \
        char msg[] = fmt;                                                                                                                                                                              \
        bpf_trace_printk(msg, sizeof(msg));                                                                                                                                                            \
    })

#define printk2(fmt, ...)                                                                                                                                                                              \
    ({                                                                                                                                                                                                 \
        char msg[] = fmt;                                                                                                                                                                              \
        bpf_trace_printk(msg, sizeof(msg), __VA_ARGS__);                                                                                                                                               \
    })
#else
#define printk(fmt)
#define printk2(fmt, ...)
#endif

/*
#define PIN_NONE 0
#define PIN_OBJECT_NS 1
#define PIN_GLOBAL_NS 2
#define PIN_CUSTOM_NS 3

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

struct bpf_elf_map SEC("maps") map_set_intent = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct key),
        .size_value = sizeof(struct value),
        .max_elem = 0xffffff,
        .pinning = PIN_NONE,
};
*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0xffff);
    __type(key, struct map_set_intent_key);
    __type(value, struct map_set_intent_value);
} set_intent SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0xff);
    __type(key, int);
    __type(value, struct map_set_opt_exp_value);
} set_opt_exp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rcvd_opt_exp SEC(".maps");

/**
 * Ingressの処理ではSurplusエリアの、Optionを外す
 * @param skb
 * @return TC_ACTの値
 */
SEC("tc-ingress")
int tc_handle_ingress(struct __sk_buff *skb) {
    void *data_end;
    void *data;
    data_end = (uint8_t *)(long)skb->data_end;
    data = (uint8_t *)(long)skb->data;
    struct ethhdr *eth = data;
    uint64_t nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return TC_ACT_OK; // 長さがイーサネットフレーム以下なら終了
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK; // IPパケットでなかったら終了
    struct iphdr *ip = data + nh_off;
    uint64_t iph_off = sizeof(*ip);
    if ((void *)&ip[1] > data_end)
        return TC_ACT_OK; // 長さがIPパケット以下なら終了

    if (ip->ihl != 0x05)
        return TC_ACT_OK; // IPオプションがついてたら終了
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK; // UDPでなかったら終了

    struct udphdr *udp = data + nh_off + iph_off;
    if ((void *)&udp[1] > data_end) 
        return TC_ACT_OK; // 長さがUDPパケット以下なら終了

    printk2("[I] Received skb_len=%d, ip_len=%d, udp_len=%d", skb->len, ntohs(ip->tot_len), ntohs(udp->len));

    uint16_t ip_len = ntohs(ip->tot_len);

    if (ip_len - iph_off == ntohs(udp->len)) {
        printk("[I] No surplus area");
        return TC_ACT_OK;
    }

    printk("[I] Has surplus area!");

    uint8_t ip_tail_offset = ETH_HLEN + iph_off + ntohs(udp->len);
    uint8_t aligned_ip_tail_offset = ((ip_tail_offset + 1) & ~((uint32_t)1));
    int count = 0;
    //bpf_ringbuf_reserve(&map_rcvd_opt_exp, sizeof(uint16_t), 0);
    while (count++ < 10) {
        struct udp_option_head *opthd = data + aligned_ip_tail_offset;
        if (&opthd[1] > data_end) {
            break;
        }
        printk2("Len: %d", opthd->length);
        printk2("Type: %d", opthd->type);

        if (opthd->type == UDP_OPTION_EXP) {
            struct udp_option_exp *expsp = data + aligned_ip_tail_offset;
            if (&expsp[1] > data_end) {
                break;
            }

            printk("Exp opt received!");

            struct map_rcvd_opt_exp_value notify_value;
            notify_value.value = expsp->exp_val;
            notify_value.addr.address = htonl(ip->saddr);
            notify_value.addr.port = htons(udp->source);
            bpf_ringbuf_output(&rcvd_opt_exp, &notify_value, sizeof(struct map_rcvd_opt_exp_value), 0);
        }

        ip_tail_offset += opthd->length;
    }

    return TC_ACT_OK;
}

struct callback_ctx_ip {
    uint32_t ip_address;
    uint16_t port;
    int16_t ret_value;
};

static int callback_set_exp_opt_entry(struct bpf_map *map, int *key, struct map_set_opt_exp_value *val, struct callback_ctx_ip *param) {
    if ((val->flow.prefix & val->flow.netmask) == (param->ip_address & val->flow.netmask)) { // エントリのネットワークと合致するか
        if (val->set_type != SET_TYPE_PERMANENT) {
            val->set_type--;
            if (val->set_type == 0) {
                bpf_map_delete_elem(map, key);
                printk("[E] Exp opt longer available");
                return 1;
            }
        }

        printk2("[E] Match index_set_exp_opt_entry: %d", val->value);
        param->ret_value = val->value;
        return 1;
    }
    printk("[E] No match index_set_exp_opt_entry");
    return 0;
}

/**
 * Egressの処理ではSurplusエリアに、Optionをつける
 * @param skb
 * @return TC_ACTの値
 */
SEC("tc-egress")
int tc_handle_egress(struct __sk_buff *skb) {
    void *data_end;
    void *data;
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    uint64_t nh_off = sizeof(*eth);

    /**
     * Verifierを通すためのチェック
     */
    if (data + nh_off > data_end)
        return TC_ACT_OK; // 長さがイーサネットフレーム以下なら終了
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK; // IPパケットでなかったら終了
    struct iphdr *ip = data + nh_off;
    uint64_t iph_off = sizeof(*ip);
    if ((void *)&ip[1] > data_end)
        return TC_ACT_OK; // 長さがIPパケット以下なら終了

    uint32_t protocol = ip->protocol;
    if (ip->ihl != 0x05)
        return TC_ACT_OK; // IPオプションがついてたら終了
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK; // UDPでなかったら終了

    struct udphdr *udp = data + nh_off + iph_off;
    if ((void *)&udp[1] > data_end)
        return TC_ACT_OK; // 長さがUDPパケット以下なら終了
    printk2("[E] UDP source %d", htons(udp->source));

    uint16_t udp_src = htons(udp->source);

    /** Check set intent **/

    struct map_set_intent_key intent_key = {.local_address = htonl(udp_src), .local_port = htons(udp->dest)};
    void *intent_entry;
    int has_intent = 0;

    intent_entry = bpf_map_lookup_elem(&set_intent, &intent_key);
    if (intent_entry != NULL) {
        printk("[E] Intent Found!");
        has_intent = 1;
    } else {
        printk("[E] No intent found!");
    }

    /** Check set option exp **/
    struct map_set_opt_exp_value *set_exp_opt_entry;
    int has_set_exp_opt = 0;

    struct callback_ctx_ip param = {.ip_address = ip->daddr, .port = udp->dest, .ret_value = -1};

    bpf_for_each_map_elem(&set_opt_exp, callback_set_exp_opt_entry, &param, 0);

    if (param.ret_value != -1) {
        printk("[E] Opt exp found!");
        has_set_exp_opt = 1;
    } else {
        printk("[E] No opt exp found!");
    }

    if (!has_intent && !has_set_exp_opt) { // オプションをつけない場合、終了
        return TC_ACT_OK;
    }

    /** オプション長の計算 **/
    int opts_len = 0;

    if (has_intent == 1) {
        opts_len += sizeof(struct udp_option_intent);
    }

    if (has_set_exp_opt == 1) {
        opts_len += sizeof(struct udp_option_exp);
    }

    printk2("[E] Old skb len %d", skb->len);

    uint16_t old_ip_len = ntohs(ip->tot_len);
    uint16_t aligned_ip_len = ((old_ip_len + 1) & ~((uint32_t)1)); // 2バイトアライメント
    uint16_t extended_ip_len = aligned_ip_len + opts_len; // オプション長を追加

    long res = bpf_skb_change_tail(skb, skb->len + (extended_ip_len - old_ip_len), 0); // skbの拡張

    if (res != 0) {
        printk("[E] Failed to extend skb");
        return TC_ACT_OK; // skbの拡張に失敗したら終了
    }
    printk2("[E] New skb len %d", skb->len);

    /**
     * skbを拡張したら初めからチェックを全てやり直す
     */
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    if (data + nh_off > data_end)
        return TC_ACT_OK; // 長さがイーサネットフレーム以下なら終了
    ip = data + nh_off;
    if ((void *)&ip[1] > data_end)
        return TC_ACT_OK; // 長さがIPパケット以下なら終了

    printk2("[E] IP old len = %d", old_ip_len);
    printk2("[E] IP new len = %d", extended_ip_len);

    uint16_t extended_ip_len_nw = htons(extended_ip_len);
    bpf_l3_csum_replace(skb, IP_CHECK_OFF, htons(old_ip_len), extended_ip_len_nw, 2); // IPチェックサムの再計算

    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    if (data + nh_off > data_end)
        return TC_ACT_OK; // 長さがイーサネットフレーム以下なら終了
    ip = data + nh_off;
    if ((void *)&ip[1] > data_end)
        return TC_ACT_OK; // 長さがIPパケット以下なら終了

    bpf_skb_store_bytes(skb, IP_LEN_OFF, &extended_ip_len_nw, 2, 0); // IP全長を書き換え

    int current_offset = ETH_HLEN + aligned_ip_len;

    if (has_set_exp_opt) {
        struct udp_option_exp exp_opt;
        exp_opt.type_len.type = UDP_OPTION_EXP;
        exp_opt.type_len.length = sizeof(struct udp_option_exp);
        exp_opt.exp_val = param.ret_value;
        bpf_skb_store_bytes(skb, current_offset, &exp_opt, sizeof(struct udp_option_exp), 0); // surplusエリアに書き込み
        current_offset += sizeof(struct udp_option_exp);
        printk("[E] Written option exp");
    }


    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
/**
 * BPF program for PFN UDP research
 */
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_LEN_OFF (ETH_HLEN + offsetof(struct iphdr, tot_len))

#define printk(fmt)   \
  ({                  \
    char msg[] = fmt; \
    bpf_trace_printk(msg, sizeof(msg)); \
  })

#define printk2(fmt, ...) \
  ({                      \
    char msg[] = fmt;     \
    bpf_trace_printk(msg, sizeof(msg), __VA_ARGS__); \
  })

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} udp_port_data SEC(".maps");

/**
 * Ingressの処理ではSurplusエリアの、Optionを外す
 * @param skb
 * @return TC_ACTの値
 */
SEC("tc-ingress")
int tc_handle_ingress(struct __sk_buff *skb) {
    int* entry_data;
    int kkk = 100;
    int value = 10303;

    entry_data = bpf_map_lookup_elem(&udp_port_data, &kkk);
    if(entry_data != NULL) {
        printk("Ext!");
    }else{
        printk("Null!");
        long res = bpf_map_update_elem(&udp_port_data, &kkk, &value, BPF_ANY);
        printk2("RES: %ld", res);
    }

    void *data_end;
    void *data;
    data_end = (void *) (long) skb->data_end;
    data = (void *) (long) skb->data;
    struct ethhdr *eth = data;
    uint64_t nh_off = sizeof(*eth);

    if (data + nh_off > data_end) return TC_ACT_OK;// 長さがイーサネットフレーム以下なら終了
    if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_OK;  // IPパケットでなかったら終了
    struct iphdr *ip = data + nh_off;
    uint64_t iph_off = sizeof(*ip);
    if ((void *) &ip[1] > data_end) return TC_ACT_OK;  // 長さがIPパケット以下なら終了

    uint32_t protocol = ip->protocol;
    if (ip->ihl != 0x05) return TC_ACT_OK; // IPオプションがついてたら終了
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK; // UDPでなかったら終了

    struct udphdr *udp = data + nh_off + iph_off;
    if ((void *) &udp[1] > data_end) return TC_ACT_OK;  // 長さがUDPパケット以下なら終了
    printk2("[I] skb_len=%d, ip_len=%d, udp_len=%d", skb->len, ntohs(ip->tot_len), ntohs(udp->len));

    if (ntohs(ip->tot_len) - iph_off == ntohs(udp->len)) {
        printk("[I] No surplus area");
        return TC_ACT_OK;
    }

    printk("[I] Surplus area!");

    return TC_ACT_OK;
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
    data_end = (void *) (long) skb->data_end;
    data = (void *) (long) skb->data;
    struct ethhdr *eth = data;
    uint64_t nh_off = sizeof(*eth);

    if (data + nh_off > data_end) return TC_ACT_OK;// 長さがイーサネットフレーム以下なら終了
    if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_OK;  // IPパケットでなかったら終了
    struct iphdr *ip = data + nh_off;
    uint64_t iph_off = sizeof(*ip);
    if ((void *) &ip[1] > data_end) return TC_ACT_OK;  // 長さがIPパケット以下なら終了

    uint32_t protocol = ip->protocol;
    if (ip->ihl != 0x05) return TC_ACT_OK; // IPオプションがついてたら終了
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK; // UDPでなかったら終了

    struct udphdr *udp = data + nh_off + iph_off;
    if ((void *) &udp[1] > data_end) return TC_ACT_OK;  // 長さがUDPパケット以下なら終了
    printk2("[E] UDP source %d\n", htons(udp->source));

    printk2("[E] Old len %d\n", skb->len);

    long res = bpf_skb_change_tail(skb, skb->len + 64, 0); // skbの拡張
    if (res != 0) return TC_ACT_OK; //skbの拡張に失敗したら終了
    printk2("[E] New len %d\n", skb->len);

    /**
     * skbを拡張したら初めからチェックを全てやり直す
     */
    data_end = (void *) (long) skb->data_end;
    data = (void *) (long) skb->data;
    if (data + nh_off > data_end) return TC_ACT_OK;// 長さがイーサネットフレーム以下なら終了
    ip = data + nh_off;
    if ((void *) &ip[1] > data_end) return TC_ACT_OK;  // 長さがIPパケット以下なら終了

    uint16_t old_len = ntohs(ip->tot_len);
    uint16_t new_len = old_len + 64;

    printk2("[E] IP old len = %d\n", old_len);
    printk2("[E] IP new len = %d\n", new_len);

    uint16_t new_len_nw = htons(new_len);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, htons(old_len), new_len_nw, 2); // IPチェックサムの再計算

    data_end = (void *) (long) skb->data_end;
    data = (void *) (long) skb->data;
    if (data + nh_off > data_end) return TC_ACT_OK;// 長さがイーサネットフレーム以下なら終了
    ip = data + nh_off;
    if ((void *) &ip[1] > data_end) return TC_ACT_OK;  // 長さがIPパケット以下なら終了

    bpf_skb_store_bytes(skb, IP_LEN_OFF, &new_len_nw, 2, 0); // IP全長を書き換え

    uint8_t add_buf[100] = {0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x77, 0x77, 0x77, 0x77, 0x77,
                       0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                       0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                       0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                       0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                       0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                       0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                       0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77};

    uint8_t zeros[100] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    bpf_skb_store_bytes(skb, ETH_HLEN + old_len, add_buf, 10, 0); // surplusエリアに書き込み

    //u32 hash = bpf_get_hash_recalc(skb);



    return TC_ACT_OK;
}



char __license[] SEC("license") = "GPL";
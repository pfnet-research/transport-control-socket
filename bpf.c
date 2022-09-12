#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/swab.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/types.h>

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_LEN_OFF (ETH_HLEN + offsetof(struct iphdr, tot_len))

BPF_HASH(ingress_count, u32, u32);
BPF_HASH(egress_count, u32, u32);

int tc_handle_udp_ingress(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

int tc_handle_udp_egress(struct __sk_buff *skb) {
    void *data_end = (void *) (long) skb->data_end;
    void *data = (void *) (long) skb->data;
    struct ethhdr *eth = data;
    u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end) return TC_ACT_OK;// 長さがイーサネットフレーム以下なら終了
    if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_OK;  // IPパケットでなかったら終了
    struct iphdr *ip = data + nh_off;
    if ((void *) &ip[1] > data_end) return TC_ACT_OK;  // 長さがIPパケット以下なら終了

    u32 protocol = ip->protocol;
    if (ip->ihl != 0x05) return TC_ACT_OK; // IPオプションがついてたら終了
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK; // UDPでなかったら終了

    bpf_trace_printk("Old len %d\n", skb->len);
    long res = bpf_skb_change_tail(skb, skb->len + 64, 0); // skbの拡張
    if(res != 0) return TC_ACT_OK; //skbの拡張に失敗したら終了
    bpf_trace_printk("New len %d\n", skb->len);

    /**
     * skbを拡張したら初めからチェックを全てやり直す
     */
    data_end = (void *) (long) skb->data_end;
    data = (void *) (long) skb->data;
    if (data + nh_off > data_end) return TC_ACT_OK;// 長さがイーサネットフレーム以下なら終了
    ip = data + nh_off;
    if ((void *) &ip[1] > data_end) return TC_ACT_OK;  // 長さがIPパケット以下なら終了

    u16 old_len = ntohs(ip->tot_len);
    u16 new_len = old_len + 64;
    u16 new_len_nw = htons(new_len);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, htons(old_len), new_len_nw , 2); // IPチェックサムの再計算

    data_end = (void *) (long) skb->data_end;
    data = (void *) (long) skb->data;
    if (data + nh_off > data_end) return TC_ACT_OK;// 長さがイーサネットフレーム以下なら終了
    ip = data + nh_off;
    if ((void *) &ip[1] > data_end) return TC_ACT_OK;  // 長さがIPパケット以下なら終了

    bpf_skb_store_bytes(skb, IP_LEN_OFF, &new_len_nw, 2, 0); // IP全長を書き換え

    u8 add_buf[] = {0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
                    0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
                    0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
                    0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
                    0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
                    0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
                    0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
                    0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77};

    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + old_len, add_buf, 64, 0); // surplusエリアに書き込み

    u32 value = 0, *vp;
    vp = ingress_count.lookup_or_init(&protocol, &value);
    *vp += 1;

    return TC_ACT_OK;
}

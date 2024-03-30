#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/btf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nsh.h"

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7

#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_P_NSH	0x894F /* Network Service Header */
#define __section(x) __attribute__((section(x), used))

// struct nsh_md1_ctx {
// 	__be32 context[4];
// };

// struct nsh_md2_tlv {
// 	__be16 md_class;
// 	__u8 type;
// 	__u8 length;
// 	__u8 md_value[];
// };

// struct nshhdr {
// 	__be16 ver_flags_ttl_len;
// 	__u8 mdtype;
// 	__u8 np;
// 	__be32 path_hdr;
// 	union {
// 	    struct nsh_md1_ctx md1;
// 	    struct nsh_md2_tlv md2;
// 	};
// };

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};


SEC("nsh_decap")
int nsh_decap_fn(struct __sk_buff *skb)
{

    void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
    struct hdr_cursor nh = { .pos = data };

    if (nh.pos + sizeof(struct ethhdr) > data_end)
        return TC_ACT_SHOT;

    struct ethhdr *eth = nh.pos;
    if (eth->h_proto != bpf_htons(ETH_P_NSH))
        return TC_ACT_OK;

    nh.pos += sizeof(struct ethhdr);

    struct nshhdr *nshhdr = nh.pos;
    if (nh.pos + sizeof(struct nshhdr) > data_end)
        return TC_ACT_SHOT;

    __u16 roomlen = nsh_hdr_len(nshhdr);

    if(roomlen < sizeof(struct nshhdr))
		return TC_ACT_SHOT;

    if (nh.pos + roomlen > data_end)
        return TC_ACT_SHOT;

    // int roomlen = sizeof(struct nshhdr);
    int ret = bpf_skb_adjust_room(skb, -roomlen, BPF_ADJ_ROOM_MAC, 0);
    if (ret) {
        bpf_printk("error reducing skb adjust room.\n");
        return TC_ACT_SHOT;
    }

    // data_end = (void *)(unsigned long long)skb->data_end;
    // data = (void *)(unsigned long long)skb->data;
    // eth = data;

    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
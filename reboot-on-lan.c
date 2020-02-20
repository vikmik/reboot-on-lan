#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/reboot.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Victor Michel");
MODULE_DESCRIPTION("Reboots the machine when a Magic Packet is received on UDP port 9");

#define UDP_PORT 9
#define MAGIC_PACKET_BYTES 108 // 6 bytes (FFFFFFFFFFFF) + 16 * 6 bytes (16 * MAC address) + 6 bytes SecureOn password
static const char password[6] = "darnit"; // "SecureOn" password (like in wake on LAN). The bestest security ever.

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#define REGISTER_NF_HOOK(hook) nf_register_net_hook(&init_net, (hook));
#define UNREGISTER_NF_HOOK(hook) nf_unregister_net_hook(&init_net, (hook));
#else
#define REGISTER_NF_HOOK(hook) nf_unregister_hook((hook));
#define UNREGISTER_NF_HOOK(hook) nf_unregister_hook((hook));
#endif

static struct nf_hook_ops nf_prerouting_hook_v4;
static struct nf_hook_ops nf_prerouting_hook_v6;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static unsigned int prerouting_hook(void* priv, struct sk_buff *skb, const struct nf_hook_state *state)
#else
static unsigned int prerouting_hook(const struct nf_hook_ops* ops, struct sk_buff* skb, const struct nf_hook_state* state)
#endif
{
    if (unlikely(!skb))
        return NF_ACCEPT;

    const struct iphdr* ipv4_header = ip_hdr(skb);
    const struct ipv6hdr* ipv6_header = ipv6_hdr(skb);

    if (ipv4_header->version == 4) {
        if (ipv4_header->protocol != IPPROTO_UDP)
            return NF_ACCEPT;
    } else {
        if (ipv6_header->nexthdr != IPPROTO_UDP)
            return NF_ACCEPT;
    }

    const struct udphdr* udp_header = udp_hdr(skb);
    uint16_t dport = ntohs((uint16_t)udp_header->dest); 
    if (likely(dport != UDP_PORT))
        return NF_ACCEPT;

    // Maybe (?) not worth bothering about non-linear SKBs
    if (skb_is_nonlinear(skb))
        return NF_ACCEPT;

    uint16_t payload_length = ntohs((uint16_t)udp_header->len) - sizeof(struct udphdr);
    if (payload_length < MAGIC_PACKET_BYTES)
        return NF_ACCEPT;

    // Initialize magic packet with header and password
    char magic[MAGIC_PACKET_BYTES] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    memcpy(magic + (MAGIC_PACKET_BYTES - sizeof password), password, sizeof password);

    const struct netdev_hw_addr* dev_addr;
    for_each_dev_addr(skb->dev, dev_addr) {
        if (dev_addr->type != NETDEV_HW_ADDR_T_LAN)
            continue;

        // Construct Magic Packet sequence that matches the receiving interface (copy MAC address 16 times)
        for (int i = 1; i <= 16; ++i)
            memcpy(magic + 6 * i, dev_addr->addr, 6);

        if (!memcmp(magic, skb->data + (skb->len - payload_length), MAGIC_PACKET_BYTES)) {
            if (ipv4_header->version == 4)
                pr_info("Reboot requested by %pI4\n", &ipv4_header->saddr);
            else
                pr_info("Reboot requested by %pI6c\n", &ipv6_header->saddr);

            // orderly_reboot() is also a (less nuclear) option
            emergency_restart();
        }
    }

    return NF_ACCEPT;
}

static int __init reboot_on_lan_init(void)
{
    pr_info("reboot-on-lan enabled\n");

    nf_prerouting_hook_v4.priority = NF_IP_PRI_FIRST;
    nf_prerouting_hook_v4.pf = PF_INET;
    nf_prerouting_hook_v4.hooknum = NF_INET_PRE_ROUTING;
    nf_prerouting_hook_v4.hook = prerouting_hook;

    nf_prerouting_hook_v6.priority = NF_IP6_PRI_FIRST;
    nf_prerouting_hook_v6.pf = PF_INET6;
    nf_prerouting_hook_v6.hooknum = NF_INET_PRE_ROUTING;
    nf_prerouting_hook_v6.hook = prerouting_hook;

    int err = REGISTER_NF_HOOK(&nf_prerouting_hook_v4);
    if (err) {
        return err;
    }
    err = REGISTER_NF_HOOK(&nf_prerouting_hook_v6);
    if (err) {
        UNREGISTER_NF_HOOK(&nf_prerouting_hook_v4);
    }
    return err;
}

static void __exit reboot_on_lan_exit(void)
{
    UNREGISTER_NF_HOOK(&nf_prerouting_hook_v4);
    UNREGISTER_NF_HOOK(&nf_prerouting_hook_v6);

    pr_info("reboot-on-lan disabled\n");
}

module_init(reboot_on_lan_init);
module_exit(reboot_on_lan_exit);

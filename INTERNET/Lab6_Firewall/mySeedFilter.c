#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

static struct nf_hook_ops hook1, hook2, hook3, hook4;

/* Print packet info (hooked to LOCAL_OUT in this example) */
unsigned int printInfo(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    const char *hook;
    const char *protocol;

    switch (state->hook) {
    case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break;
    case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break;
    case NF_INET_FORWARD:      hook = "FORWARD";      break;
    case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break;
    case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break;
    default:                   hook = "IMPOSSIBLE";   break;
    }
    printk(KERN_INFO "*** %s\n", hook);

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    switch (iph->protocol) {
    case IPPROTO_UDP:  protocol = "UDP";   break;
    case IPPROTO_TCP:  protocol = "TCP";   break;
    case IPPROTO_ICMP: protocol = "ICMP";  break;
    default:           protocol = "OTHER"; break;
    }

    printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", &(iph->saddr), &(iph->daddr), protocol);

    return NF_ACCEPT;
}

/* Block outbound UDP to a specific IP:port (example: 8.8.8.8:53) */
unsigned int blockUDP(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    u16 port = 53;
    char ip[] = "8.8.8.8";
    u32 ip_addr;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

    if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (udph && iph->daddr == ip_addr && ntohs(udph->dest) == port) {
            printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

/* Block ICMP echo requests (ping) destined to the VM IP (10.9.0.1) */
unsigned int block_ping(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    char vm[] = "10.9.0.1";
    u32 vm_ip;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    in4_pton(vm, -1, (u8 *)&vm_ip, '\0', NULL);

    if (iph->protocol == IPPROTO_ICMP && iph->daddr == vm_ip) {
        icmph = icmp_hdr(skb);
        if (icmph && icmph->type == ICMP_ECHO) {
            printk(KERN_WARNING "*** Dropping ICMP echo to %pI4\n", &iph->daddr);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

/* Block TCP dest port 23 (telnet) destined to the VM IP (10.9.0.1) */
unsigned int block_telnet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    char vm[] = "10.9.0.1";
    u32 vm_ip;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    in4_pton(vm, -1, (u8 *)&vm_ip, '\0', NULL);

    if (iph->protocol == IPPROTO_TCP && iph->daddr == vm_ip) {
        tcph = tcp_hdr(skb);
        if (tcph && ntohs(tcph->dest) == 23) {
            printk(KERN_WARNING "*** Dropping TELNET to %pI4\n", &iph->daddr);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

int registerFilter(void)
{
    printk(KERN_INFO "Registering filters.\n");

    /* hook1: printInfo on LOCAL_OUT (example) */
    hook1.hook = printInfo;
    hook1.hooknum = NF_INET_LOCAL_OUT;
    hook1.pf = PF_INET;
    hook1.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook1);

    /* hook2: blockUDP on POST_ROUTING (example) */
    hook2.hook = blockUDP;
    hook2.hooknum = NF_INET_POST_ROUTING;
    hook2.pf = PF_INET;
    hook2.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook2);

    /* hook3: block_ping on LOCAL_IN */
    hook3.hook = block_ping;
    hook3.hooknum = NF_INET_LOCAL_IN;
    hook3.pf = PF_INET;
    hook3.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook3);

    /* hook4: block_telnet on LOCAL_IN (same hook point as block_ping) */
    hook4.hook = block_telnet;
    hook4.hooknum = NF_INET_LOCAL_IN;
    hook4.pf = PF_INET;
    hook4.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook4);

    return 0;
}

void removeFilter(void)
{
    printk(KERN_INFO "The filters are being removed.\n");
    nf_unregister_net_hook(&init_net, &hook1);
    nf_unregister_net_hook(&init_net, &hook2);
    nf_unregister_net_hook(&init_net, &hook3);
    nf_unregister_net_hook(&init_net, &hook4);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netfilter module: printInfo, blockUDP, block_ping, block_telnet");
// SPDX-License-Identifier: GPL-2.0-only
/* Unstable ipv4 fragmentation helpers for TC-BPF hook
 *
 * These are called from SCHED_CLS BPF programs. Note that it is allowed to
 * break compatibility for these functions since the interface they are exposed
 * through to BPF programs is explicitly unstable.
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/sock.h>

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in ip_fragment BTF");

/* bpf_ip_defrag - Defragment an ipv4 packet
 *
 * This helper takes an skb as input. If this skb successfully reassembles
 * the original packet, the skb is updated to contain the original packet.
 *
 * Otherwise (on error or incomplete reassembly), the ipv4 infra will take
 * ownership of the skb and either free or hold onto the skb for future
 * reassembly when more fragments are received.
 *
 * Parameters:
 * @ctx		- Pointer to program context (skb)
 * @netns	- Child network namespace id. If value is a negative signed
 *		  32-bit integer, the netns of the device in the skb is used.
 *
 * Return:
 * 0 on successfully reassembly. Negative value on error or incomplete
 * reassembly.
 *
 * ctx (ie. program context) is only valid in branches where 0 was returned.
 * On all other branches skb is no longer accessible nor valid.
 */
int bpf_ip_defrag(struct __sk_buff *ctx, u64 netns)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct net *caller_net, *net;
	struct iphdr iph;
	int netoff;

	if (unlikely(!((s32)netns < 0 || netns <= S32_MAX)))
		goto out;

	caller_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	if ((s32)netns < 0) {
		net = caller_net;
	} else {
		net = get_net_ns_by_id(caller_net, netns);
		if (unlikely(!net))
			goto out;
	}

	netoff = skb_network_offset(skb);
	if (skb->protocol != htons(ETH_P_IP))
		goto out;
	if (skb_copy_bits(skb, netoff, &iph, sizeof(iph)) < 0)
		goto out;
	if (iph.ihl < 5 || iph.version != 4)
		goto out;
	if (!ip_is_fragment(&iph))
		goto out;

	return ip_defrag(net, skb, IP_DEFRAG_BPF);
out:
	kfree_skb_reason(skb, SKB_DROP_REASON_FRAG_BPF_EINVAL);
	return -EINVAL;
}

__diag_pop()

BTF_SET8_START(ip_frag_kfunc_set)
BTF_ID_FLAGS(func, bpf_ip_defrag, KF_RET_CONSUME)
BTF_SET8_END(ip_frag_kfunc_set)

static const struct btf_kfunc_id_set ip_frag_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ip_frag_kfunc_set,
};

int register_ip_frag_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					 &ip_frag_bpf_kfunc_set);
}

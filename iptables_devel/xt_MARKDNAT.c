/*
 *	xt_MARKDNAT - Netfilter module to DNAT based on the MARK value
 *
 *	Jesus Llorente <jesus.llorente@aalto.fi>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

/* Implementation based on xt_mark - Netfilter module to match NFMARK value. */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat_core.h>


static unsigned int
markdnat_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_mark_tginfo2 *info = par->targinfo;
	struct nf_nat_range range;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	__u32 dstaddr;

	ct = nf_ct_get(skb, &ctinfo);
	NF_CT_ASSERT(ct != NULL &&
				 (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));
	/* Mangle skb->mark same as in xt_mark */
	dstaddr = (skb->mark & ~info->mask) ^ info->mark;
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags		    = NF_NAT_RANGE_MAP_IPS;
	range.min_addr.ip   = htonl(dstaddr);
	range.max_addr.ip   = htonl(dstaddr);
	range.min_proto.all = 0;
	range.max_proto.all = 0;
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}


static int markdnat_tg_check(const struct xt_tgchk_param *par)
{
	int ret;

	ret = nf_ct_l3proto_try_module_get(par->family);
	if (ret < 0)
		pr_info("cannot load conntrack support for proto=%u\n",
			par->family);
	return ret;
}

static void markdnat_tg_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_l3proto_module_put(par->family);
}

static struct xt_target markdnat_tg_reg __read_mostly = {
	.name			= "MARKDNAT",
	.revision		= 0,
	.family			= NFPROTO_IPV4,
	.checkentry		= markdnat_tg_check,
	.target			= markdnat_tg,
	.targetsize		= sizeof(struct xt_mark_tginfo2),
	.table			= "nat",
	.hooks			= (1 << NF_INET_PRE_ROUTING) |
                                  (1 << NF_INET_LOCAL_OUT),
	.destroy		= markdnat_tg_destroy,
	.me			= THIS_MODULE,
};

static int __init markdnat_tg_init(void)
{
	return xt_register_target(&markdnat_tg_reg);
}

static void __exit markdnat_tg_exit(void)
{
	xt_unregister_target(&markdnat_tg_reg);
}

module_init(markdnat_tg_init);
module_exit(markdnat_tg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jesus Llorente <jesus.llorente@aalto.fi>");
MODULE_DESCRIPTION("Xtables: packet mark operations");
MODULE_ALIAS("xt_MARKDNAT");
MODULE_ALIAS("ipt_MARKDNAT");

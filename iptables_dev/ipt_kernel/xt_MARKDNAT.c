/*
 *	xt_MARKDNAT - Netfilter module to DNAT based on the MARK value
 *
 *	Jesus Llorente Santos <jesus.llorente.santos@aalto.fi>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat_core.h>

/*
static void debug_nf_nat_range(const struct nf_nat_range *data){
	printk(KERN_WARNING "debug_nf_nat_range\n");
	printk(KERN_WARNING "flags     = %d\n", data->flags);
	printk(KERN_WARNING "min.ip    = %d\n", data->min_addr.ip);
	printk(KERN_WARNING "max.ip    = %d\n", data->max_addr.ip);
	printk(KERN_WARNING "min.proto = %d\n", data->min_proto.all);
	printk(KERN_WARNING "max.proto = %d\n", data->max_proto.all);
}
*/
static unsigned int
markdnat_tg_v2(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_mark_tginfo2 *info = par->targinfo;
	struct nf_nat_range range;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	__u32 ipaddr;

	ct = nf_ct_get(skb, &ctinfo);
	NF_CT_ASSERT(ct != NULL &&
				 (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));
	/* Mangle packet MARK according */
	ipaddr = (skb->mark & ~info->mask) ^ info->mark;
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags		    = NF_NAT_RANGE_MAP_IPS;
	range.min_addr.ip   = htonl(ipaddr);
	range.max_addr.ip   = htonl(ipaddr);
	range.min_proto.all = 0;
	range.max_proto.all = 0;
	/* debug_nf_nat_range(&range); */
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

static struct xt_target markdnat_tg_reg __read_mostly = {
	.name			= "MARKDNAT",
	.revision		= 0,
	.family			= NFPROTO_IPV4,
	.target			= markdnat_tg_v2,
	.targetsize		= sizeof(struct xt_mark_tginfo2),
	.table		    = "nat",
	.hooks			= (1 << NF_INET_PRE_ROUTING),
	.me				= THIS_MODULE,
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
MODULE_AUTHOR("Jesus Llorente Santos <jesus.llorente.santos@aalto.fi>");
MODULE_DESCRIPTION("Xtables: packet mark operations");
MODULE_ALIAS("ipt_MARKDNAT");
/*
 *	xt_MARKCLASSIFY - Netfilter module to CLASSIFY based on the MARK value
 *
 *	Jesus Llorente <jesus.llorente@aalto.fi>
 *	Mael Kimmerlin <mael.kimmerlin@aalto.fi>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

/* Implementation based on xt_mark and xt_CLASSIFY */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_arp.h>

static unsigned int
markclassify_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_mark_tginfo2 *info = par->targinfo;

	/* Mangle skb->mark same as in xt_mark */
	skb->mark = (skb->mark & ~info->mask) ^ info->mark;
	skb->priority = skb->mark;
	return XT_CONTINUE;
}

static struct xt_target markclassify_tg_reg[] __read_mostly = {
    {
        .name			= "MARKCLASSIFY",
        .revision		= 0,
        .family			= NFPROTO_UNSPEC,
        .target			= markclassify_tg,
        .targetsize		= sizeof(struct xt_mark_tginfo2),
        .hooks			= (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD) |
                          (1 << NF_INET_POST_ROUTING),
        .me				= THIS_MODULE,
    },
    {
		.name           = "MARKCLASSIFY",
		.revision       = 0,
		.family         = NFPROTO_ARP,
		.hooks          = (1 << NF_ARP_OUT) | (1 << NF_ARP_FORWARD),
		.target         = markclassify_tg,
		.targetsize     = sizeof(struct xt_mark_tginfo2),
		.me             = THIS_MODULE,
	},
};

static int __init markclassify_tg_init(void)
{
	return xt_register_targets(markclassify_tg_reg, ARRAY_SIZE(markclassify_tg_reg));
}

static void __exit markclassify_tg_exit(void)
{
	xt_unregister_targets(markclassify_tg_reg, ARRAY_SIZE(markclassify_tg_reg));
}

module_init(markclassify_tg_init);
module_exit(markclassify_tg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jesus Llorente <jesus.llorente@aalto.fi>");
MODULE_AUTHOR("Mael Kimmerlin <mael.kimmerlin@aalto.fi>");
MODULE_DESCRIPTION("Xtables: packet mark operations");
MODULE_ALIAS("xt_MARKCLASSIFY");
MODULE_ALIAS("ipt_MARKCLASSIFY");
MODULE_ALIAS("ipt6_MARKCLASSIFY");

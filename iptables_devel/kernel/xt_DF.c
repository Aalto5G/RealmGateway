/* DF modification module for IP tables
 * (C) 2016 by Mael Kimmerlin <mael.kimmerlin@aalto.fi>
 *          by Jesus Llorente <jesus.llorente@aalto.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include <linux/netfilter/x_tables.h>
#include "xt_DF.h"


MODULE_AUTHOR("Mael Kimmerlin <mael.kimmerlin@aalto.fi>");
MODULE_AUTHOR("Jesus Llorente <jesus.llorente@aalto.fi>");
MODULE_DESCRIPTION("Xtables: DF bit modification target");
MODULE_LICENSE("GPL");

static unsigned int
df_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct xt_DF_info *info = par->targinfo;
    __u16 _frag_off;
    __u16 _value;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	iph = ip_hdr(skb);
    _frag_off = iph->frag_off;
    /* Modify info->value (0,1) to network order */
    _value = htons((info->value & 0x1) << 14);
    
    if ((iph->frag_off & htons(0x4000)) != _value) {
        _frag_off = (iph->frag_off & htons(0xBFFF)) | _value;
        csum_replace2(&iph->check, iph->frag_off, _frag_off);
		iph->frag_off = _frag_off;
    }
	return XT_CONTINUE;
}

static int df_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target df_tg_reg __read_mostly = {
    .name       = "DF",
    .revision   = 0,
    .family     = NFPROTO_IPV4,
    .target     = df_tg,
    .targetsize = sizeof(struct xt_DF_info),
    .table      = "mangle",
    .checkentry = df_tg_check,
    .me         = THIS_MODULE,
};

static int __init df_tg_init(void)
{
	return xt_register_target(&df_tg_reg);
}

static void __exit df_tg_exit(void)
{
	xt_unregister_target(&df_tg_reg);
}

module_init(df_tg_init);
module_exit(df_tg_exit);
MODULE_ALIAS("xt_DF");
MODULE_ALIAS("ipt_DF");

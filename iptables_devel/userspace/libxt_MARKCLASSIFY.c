/* Copyright (C) 2016
 *     Jesus Llorente <jesus.llorente@aalto.fi>
 *     Mael Kimmerlin <mael.kimmerlin@aalto.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Implementation based on xt_mark and xt_CLASSIFY */
 
#include <stdbool.h>
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_MARK.h>

enum {
	O_SET_MARK = 0,
	O_AND_MARK,
	O_OR_MARK,
	O_XOR_MARK,
	O_SET_XMARK,
	F_SET_MARK  = 1 << O_SET_MARK,
	F_AND_MARK  = 1 << O_AND_MARK,
	F_OR_MARK   = 1 << O_OR_MARK,
	F_XOR_MARK  = 1 << O_XOR_MARK,
	F_SET_XMARK = 1 << O_SET_XMARK,
	F_ANY       = F_SET_MARK | F_AND_MARK | F_OR_MARK |
	              F_XOR_MARK | F_SET_XMARK,
};

static const struct xt_option_entry markclassify_tg_opts[] = {
	{.name = "set-xmark", .id = O_SET_XMARK, .type = XTTYPE_MARKMASK32,
	 .excl = F_ANY},
	{.name = "set-mark", .id = O_SET_MARK, .type = XTTYPE_MARKMASK32,
	 .excl = F_ANY},
	{.name = "and-mark", .id = O_AND_MARK, .type = XTTYPE_UINT32,
	 .excl = F_ANY},
	{.name = "or-mark", .id = O_OR_MARK, .type = XTTYPE_UINT32,
	 .excl = F_ANY},
	{.name = "xor-mark", .id = O_XOR_MARK, .type = XTTYPE_UINT32,
	 .excl = F_ANY},
	XTOPT_TABLEEND,
};

static void markclassify_tg_help(void)
{
	printf(
"MARKCLASSIFY target options:\n"
"  --set-xmark value[/mask]  Clear bits in mask and XOR value into nfmark\n"
"  --set-mark value[/mask]   Clear bits in mask and OR value into nfmark\n"
"  --and-mark bits           Binary AND the nfmark with bits\n"
"  --or-mark bits            Binary OR the nfmark with bits\n"
"  --xor-mark bits           Binary XOR the nfmark with bits\n"
"\n");
}


static void markclassify_tg_parse(struct xt_option_call *cb)
{
	struct xt_mark_tginfo2 *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_SET_XMARK:
		info->mark = cb->val.mark;
		info->mask = cb->val.mask;
		break;
	case O_SET_MARK:
		info->mark = cb->val.mark;
		info->mask = cb->val.mark | cb->val.mask;
		break;
	case O_AND_MARK:
		info->mark = 0;
		info->mask = ~cb->val.u32;
		break;
	case O_OR_MARK:
		info->mark = info->mask = cb->val.u32;
		break;
	case O_XOR_MARK:
		info->mark = cb->val.u32;
		info->mask = 0;
		break;
	}
}

static void markclassify_tg_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "MARK: One of the --set-xmark, "
		           "--{and,or,xor,set}-mark options is required");
}

static void markclassify_tg_print(const void *ip, const struct xt_entry_target *target,
                          int numeric)
{
	const struct xt_mark_tginfo2 *info = (const void *)target->data;

	if (info->mark == 0)
		printf(" MARK and 0x%x", (unsigned int)(uint32_t)~info->mask);
	else if (info->mark == info->mask)
		printf(" MARK or 0x%x", info->mark);
	else if (info->mask == 0)
		printf(" MARK xor 0x%x", info->mark);
	else if (info->mask == 0xffffffffU)
		printf(" MARK set 0x%x", info->mark);
	else
		printf(" MARK xset 0x%x/0x%x", info->mark, info->mask);
}

static void markclassify_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_mark_tginfo2 *info = (const void *)target->data;

	printf(" --set-xmark 0x%x/0x%x", info->mark, info->mask);
}

static struct xtables_target markclassify_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "MARKCLASSIFY",
	.revision      = 0,
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_mark_tginfo2)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_mark_tginfo2)),
	.help          = markclassify_tg_help,
	.print         = markclassify_tg_print,
	.save          = markclassify_tg_save,
	.x6_parse      = markclassify_tg_parse,
	.x6_fcheck     = markclassify_tg_check,
	.x6_options    = markclassify_tg_opts,
};

void _init(void)
{
	xtables_register_target(&markclassify_tg_reg);
}

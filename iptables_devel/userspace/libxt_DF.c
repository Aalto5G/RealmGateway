/* DF modification module for IP tables
 * (C) 2016 by Mael Kimmerlin <mael.kimmerlin@aalto.fi>
 *          by Jesus Llorente <jesus.llorente@aalto.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <xtables.h>
#include "xt_DF.h"

enum {
	O_TTL_SET = 1,
};

#define s struct xt_DF_info
static const struct xt_option_entry DF_tg_opts[] = {
	{.name = "set-df", .type = XTTYPE_UINT8, .id = O_TTL_SET,
	 .flags = XTOPT_MAND | XTOPT_PUT, XTOPT_POINTER(s, value)},
	XTOPT_TABLEEND,
};
#undef s

static void DF_tg_help(void)
{
	printf(
"DF target options\n"
"  --set-df value		Set DF to <value 0-1>\n"
    );
}

static void DF_tg_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
}

static void DF_tg_check(struct xt_fcheck_call *cb)
{
}

static void DF_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_DF_info *info = 
		(struct xt_DF_info *) target->data;

	printf(" --set-df %u", info->value);
}

static void DF_tg_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	const struct xt_DF_info *info = 
		(struct xt_DF_info *) target->data;

	printf(" --set-df %u", info->value);
}

static struct xtables_target df_tg_reg = {
	.name		    = "DF",
	.version	    = XTABLES_VERSION,
	.family		    = NFPROTO_IPV4,
	.size		    = XT_ALIGN(sizeof(struct xt_DF_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_DF_info)),
	.help		    = DF_tg_help,
	.print		    = DF_tg_print,
	.save		    = DF_tg_save,
	.x6_parse	    = DF_tg_parse,
	.x6_fcheck	    = DF_tg_check,
	.x6_options	    = DF_tg_opts,
};

void _init(void)
{
	xtables_register_target(&df_tg_reg);
}

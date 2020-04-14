/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef PREPOSTCONDS_UTILS_H
#define PREPOSTCONDS_UTILS_H

enum ppc_trigger_func_type {
	PPC_TRIGGER_FUNC_TYPE_BASIC,
	PPC_TRIGGER_FUNC_TYPE_RUN_IN_COMP_CLS_INIT,
};

enum ppc_trigger_type {
	PPC_TRIGGER_TYPE_PRE,
	PPC_TRIGGER_TYPE_POST,
};

typedef void (* ppc_trigger_basic_func)(void);
typedef void (* ppc_trigger_run_in_comp_cls_init_func)(bt_self_component *);

struct ppc_trigger {
	enum ppc_trigger_type type;
	enum ppc_trigger_func_type func_type;
	const char *name;
	const char *regex;
	union {
		ppc_trigger_basic_func basic;
		ppc_trigger_run_in_comp_cls_init_func run_in_comp_cls_init;
	} func;
};

#define PPC_TRIGGER_PRE_BASIC(_name, _regex, _func)			\
	{								\
		.type = PPC_TRIGGER_TYPE_PRE,				\
		.func_type = PPC_TRIGGER_FUNC_TYPE_BASIC,		\
		.name = _name,						\
		.regex = _regex,					\
		.func = {						\
			.basic = _func,					\
		}							\
	}

#define PPC_TRIGGER_POST_BASIC(_name, _regex, _func)			\
	{								\
		.type = PPC_TRIGGER_TYPE_POST,				\
		.func_type = PPC_TRIGGER_FUNC_TYPE_BASIC,		\
		.name = _name,						\
		.regex = _regex,					\
		.func = {						\
			.basic = _func,					\
		}							\
	}

#define PPC_TRIGGER_PRE_RUN_IN_COMP_CLS_INIT(_name, _regex, _func)	\
	{								\
		.type = PPC_TRIGGER_TYPE_PRE,				\
		.func_type = PPC_TRIGGER_FUNC_TYPE_RUN_IN_COMP_CLS_INIT, \
		.name = _name,						\
		.regex = _regex,					\
		.func = {						\
			.run_in_comp_cls_init = _func,			\
		}							\
	}

#define PPC_TRIGGER_POST_RUN_IN_COMP_CLS_INIT(_name, _regex, _func)	\
	{								\
		.type = PPC_TRIGGER_TYPE_POST,				\
		.func_type = PPC_TRIGGER_FUNC_TYPE_RUN_IN_COMP_CLS_INIT, \
		.name = _name,						\
		.regex = _regex,					\
		.func = {						\
			.run_in_comp_cls_init = _func,			\
		}							\
	}

void ppc_main(int argc, const char *argv[],
			const struct ppc_trigger triggers[],
			size_t trigger_count);

#endif /* PREPOSTCONDS_UTILS_H */

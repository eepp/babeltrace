/*
 * ctf-visitor-generate-io-struct.c
 *
 * Common Trace Format Metadata Visitor (generates CTF IR structures).
 *
 * Copyright 2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2015 - Philippe Proulx <philippe.proulx@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <glib.h>
#include <inttypes.h>
#include <errno.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/list.h>
#include <babeltrace/types.h>
#include <babeltrace/ctf/metadata.h>
#include <babeltrace/compat/uuid.h>
#include <babeltrace/endian.h>
#include <babeltrace/ctf/events-internal.h>
#include "ctf-scanner.h"
#include "ctf-parser.h"
#include "ctf-ast.h"

#include <babeltrace/ctf-ir/trace.h>
#include <babeltrace/ctf-ir/event-types.h>
#include <babeltrace/ctf-ir/clock.h>
#include <babeltrace/ctf-ir/clock-internal.h>

#define _BV(val)		(1 << (val))
#define _IS_SET(set, mask)	(*(set) & (mask))
#define _SET(set, mask)		(*(set) |= (mask))

enum {
	_CLOCK_NAME_SET =		_BV(0),
	_CLOCK_UUID_SET =		_BV(1),
	_CLOCK_FREQ_SET =		_BV(2),
	_CLOCK_PRECISION_SET =		_BV(3),
	_CLOCK_OFFSET_S_SET =		_BV(4),
	_CLOCK_OFFSET_SET =		_BV(5),
	_CLOCK_ABSOLUTE_SET =		_BV(6),
	_CLOCK_DESCRIPTION_SET =	_BV(7),
};

enum {
	_INTEGER_ALIGN_SET =		_BV(0),
	_INTEGER_SIZE_SET =		_BV(1),
	_INTEGER_BASE_SET =		_BV(2),
	_INTEGER_ENCODING_SET =		_BV(3),
	_INTEGER_BYTE_ORDER_SET =	_BV(4),
	_INTEGER_SIGNED_SET =		_BV(5),
	_INTEGER_MAP_SET =		_BV(6),
};

enum {
	_FLOAT_ALIGN_SET =		_BV(0),
	_FLOAT_MANT_DIG_SET =		_BV(1),
	_FLOAT_EXP_DIG_SET =		_BV(2),
	_FLOAT_BYTE_ORDER_SET =		_BV(3),
};

enum {
	_STRING_ENCODING_SET =		_BV(0),
};

#define _PREFIX_ALIAS	'a'
#define _PREFIX_ENUM	'e'
#define _PREFIX_STRUCT	's'
#define _PREFIX_VARIANT	'v'

#define fprintf_dbg(fd, fmt, args...)	fprintf(fd, "%s: " fmt, __func__, ## args)

#define _bt_list_first_entry(ptr, type, member)	\
	bt_list_entry((ptr)->next, type, member)

/*
 * Declaration scope of a visitor context. This represents a TSDL
 * lexical scope, so that aliases and named
 * structures/variants/enumerations may be registered and looked up
 * hierarchically.
 *
 * All the hash tables below hold weak references to field types.
 */
struct ctx_decl_scope {
	/*
	 * Alias name to field type.
	 *
	 * GQuark -> struct bt_ctf_field_type *
	 */
	GHashTable *decl_map;

	/* parent scope; NULL if this is the root declaration scope */
	struct ctx_decl_scope *parent_scope;
};

/*
 * Visitor context.
 */
struct ctx {
	/* trace being filled */
	struct bt_ctf_trace *trace;

	/* error stream */
	FILE *efd;

	/* current declaration scope */
	struct ctx_decl_scope *current_scope;
};

/**
 * Creates a new declaration scope.
 *
 * @param parent_scope	Parent scope (NULL if creating a root scope)
 * @returns		New declaration scope, or NULL on error
 */
static
struct ctx_decl_scope *ctx_decl_scope_create(struct ctx_decl_scope *parent_scope)
{
	struct ctx_decl_scope *scope;

	scope = g_new(struct ctx_decl_scope, 1);

	if (!scope) {
		return NULL;
	}

	scope->decl_map = g_hash_table_new(g_direct_hash, g_direct_equal);
	scope->parent_scope = parent_scope;

	return scope;
}

/**
 * Destroys a declaration scope.
 *
 * This function does not destroy the parent scope.
 *
 * @param scope	Scope to destroy
 */
static
void ctx_decl_scope_destroy(struct ctx_decl_scope *scope)
{
	if (!scope) {
		return;
	}

	g_hash_table_destroy(scope->decl_map);
	g_free(scope);
}

/**
 * Returns the GQuark of a prefixed alias.
 *
 * @param prefix	Prefix character
 * @param name		Name
 * @returns		Associated GQuark, or 0 on error
 */
GQuark get_prefixed_named_quark(char prefix, const char *name)
{
	assert(name);

	char *prname = g_new(char, strlen(name) + 3);

	if (!prname) {
		return 0;
	}

	sprintf(prname, "%c#%s", prefix, name);

	GQuark qname = g_quark_from_string(prname);

	g_free(prname);

	return qname;
}

/**
 * Looks up a prefixed type alias within a declaration scope.
 *
 * @param scope		Declaration scope
 * @param prefix	Prefix character
 * @param name		Alias name
 * @param level		Number of levels to dig (-1 means infinite)
 * @returns		Declaration, or NULL if not found
 */
struct bt_ctf_field_type *ctx_decl_scope_lookup_prefix_alias(
	struct ctx_decl_scope *scope, char prefix,
	const char *name, int levels)
{
	assert(scope);
	assert(name);

	GQuark qname = get_prefixed_named_quark(prefix, name);

	if (!qname) {
		goto error;
	}

	struct ctx_decl_scope *cur_scope = scope;
	struct bt_ctf_field_type *decl = NULL;
	int cur_levels = 0;

	if (levels < 0) {
		levels = INT_MAX;
	}

	while (cur_scope && cur_levels < levels) {
		decl = g_hash_table_lookup(scope->decl_map,
			(gconstpointer) (unsigned long) qname);

		if (decl) {
			break;
		}

		cur_scope = cur_scope->parent_scope;
		cur_levels++;
	}

	return decl;

error:
	return NULL;
}

/**
 * Looks up a type alias within a declaration scope.
 *
 * @param scope		Declaration scope
 * @param name		Alias name
 * @param level		Number of levels to dig (-1 means infinite)
 * @returns		Declaration, or NULL if not found
 */
struct bt_ctf_field_type *ctx_decl_scope_lookup_alias(
	struct ctx_decl_scope *scope, const char *name, int levels)
{
	return ctx_decl_scope_lookup_prefix_alias(scope, _PREFIX_ALIAS,
		name, levels);
}

/**
 * Looks up an enumeration within a declaration scope.
 *
 * @param scope		Declaration scope
 * @param name		Enumeration name
 * @param level		Number of levels to dig (-1 means infinite)
 * @returns		Declaration, or NULL if not found
 */
struct bt_ctf_field_type *ctx_decl_scope_lookup_enum(
	struct ctx_decl_scope *scope, const char *name, int levels)
{
	return ctx_decl_scope_lookup_prefix_alias(scope, _PREFIX_ENUM,
		name, levels);
}

/**
 * Looks up a structure within a declaration scope.
 *
 * @param scope		Declaration scope
 * @param name		Structure name
 * @param level		Number of levels to dig (-1 means infinite)
 * @returns		Declaration, or NULL if not found
 */
struct bt_ctf_field_type *ctx_decl_scope_lookup_struct(
	struct ctx_decl_scope *scope, const char *name, int levels)
{
	return ctx_decl_scope_lookup_prefix_alias(scope, _PREFIX_STRUCT,
		name, levels);
}

/**
 * Looks up a variant within a declaration scope.
 *
 * @param scope		Declaration scope
 * @param name		Variant name
 * @param level		Number of levels to dig (-1 means infinite)
 * @returns		Declaration, or NULL if not found
 */
struct bt_ctf_field_type *ctx_decl_scope_lookup_variant(
	struct ctx_decl_scope *scope, const char *name, int levels)
{
	return ctx_decl_scope_lookup_prefix_alias(scope, _PREFIX_VARIANT,
		name, levels);
}

/**
 * Registers a prefixed type alias within a declaration scope.
 *
 * Reference count is not incremented (weak ref).
 *
 * @param scope		Declaration scope
 * @param prefix	Prefix character
 * @param name		Alias name (non-NULL)
 * @param decl		Declaration to register
 * @returns		0 if registration went okay, negative value otherwise
 */
int ctx_decl_scope_register_prefix_alias(struct ctx_decl_scope *scope,
	char prefix, const char *name, struct bt_ctf_field_type *decl)
{
	int ret = 0;

	assert(scope);
	assert(name);
	assert(decl);

	GQuark qname = get_prefixed_named_quark(prefix, name);

	if (!qname) {
		ret = -ENOMEM;
		goto error;
	}

	/* make sure alias does not exist in local scope */
	if (ctx_decl_scope_lookup_prefix_alias(scope, prefix, name, 1)) {
		ret = -EEXIST;
		goto error;
	}

	g_hash_table_insert(scope->decl_map,
		(gpointer) (unsigned long) qname, decl);

	return 0;

error:
	return ret;
}

/**
 * Registers a type alias within a declaration scope.
 *
 * Reference count is not incremented (weak ref).
 *
 * @param scope	Declaration scope
 * @param name	Alias name (non-NULL)
 * @param decl	Declaration to register
 * @returns	0 if registration went okay, negative value otherwise
 */
int ctx_decl_scope_register_alias(struct ctx_decl_scope *scope,
	const char *name, struct bt_ctf_field_type *decl)
{
	return ctx_decl_scope_register_prefix_alias(scope, _PREFIX_ALIAS,
		name, decl);
}

/**
 * Registers an enumeration declaration within a declaration scope.
 *
 * Reference count is not incremented (weak ref).
 *
 * @param scope	Declaration scope
 * @param name	Enumeration name (non-NULL)
 * @param decl	Enumeration declaration to register
 * @returns	0 if registration went okay, negative value otherwise
 */
int ctx_decl_scope_register_enum(struct ctx_decl_scope *scope,
	const char *name, struct bt_ctf_field_type *decl)
{
	return ctx_decl_scope_register_prefix_alias(scope, _PREFIX_ENUM,
		name, decl);
}

/**
 * Registers a structure declaration within a declaration scope.
 *
 * Reference count is not incremented (weak ref).
 *
 * @param scope	Declaration scope
 * @param name	Structure name (non-NULL)
 * @param decl	Structure declaration to register
 * @returns	0 if registration went okay, negative value otherwise
 */
int ctx_decl_scope_register_struct(struct ctx_decl_scope *scope,
	const char *name, struct bt_ctf_field_type *decl)
{
	return ctx_decl_scope_register_prefix_alias(scope, _PREFIX_STRUCT,
		name, decl);
}

/**
 * Registers a variant declaration within a declaration scope.
 *
 * Reference count is not incremented (weak ref).
 *
 * @param scope	Declaration scope
 * @param name	Variant name (non-NULL)
 * @param decl	Variant declaration to register
 * @returns	0 if registration went okay, negative value otherwise
 */
int ctx_decl_scope_register_variant(struct ctx_decl_scope *scope,
	const char *name, struct bt_ctf_field_type *decl)
{
	return ctx_decl_scope_register_prefix_alias(scope, _PREFIX_VARIANT,
		name, decl);
}

/**
 * Creates a new visitor context.
 *
 * @param trace	Associated trace IR
 * @param efd	Error stream
 * @returns	New visitor context, or NULL on error
 */
static
struct ctx *ctx_create(struct bt_ctf_trace *trace, FILE *efd)
{
	struct ctx *ctx;

	ctx = g_new(struct ctx, 1);

	if (!ctx) {
		return NULL;
	}

	/* root declaration scope */
	struct ctx_decl_scope *scope = ctx_decl_scope_create(NULL);

	if (!scope) {
		g_free(ctx);
		return NULL;
	}

	ctx->trace = trace;
	ctx->efd = efd;
	ctx->current_scope = scope;

	return ctx;
}

/**
 * Destroys a visitor context.
 *
 * @param ctx	Visitor context to destroy
 */
static
void ctx_destroy(struct ctx *ctx)
{
	/*
	 * Destroy all scopes, from current one to the root scope.
	 */
	struct ctx_decl_scope *scope = ctx->current_scope;

	while (scope) {
		struct ctx_decl_scope *parent_scope = scope->parent_scope;
		ctx_decl_scope_destroy(scope);
		scope = parent_scope;
	}

	g_free(ctx);
}

/**
 * Pushes a new declaration scope on top of a visitor context's
 * declaration scope stack.
 *
 * @param ctx	Visitor context
 * @returns	0 on success, or a negative value on error
 */
static
int ctx_push_scope(struct ctx *ctx)
{
	struct ctx_decl_scope *new_scope =
		ctx_decl_scope_create(ctx->current_scope);

	if (!new_scope) {
		return -ENOMEM;
	}

	ctx->current_scope = new_scope;

	return 0;
}

/**
 * Pops a declaration scope from the top of a visitor context's
 * declaration scope stack.
 *
 * @param ctx	Visitor context
 * @returns	0 on success, or a negative value on error
 */
static
void ctx_pop_scope(struct ctx *ctx)
{
	if (!ctx->current_scope) {
		return;
	}

	struct ctx_decl_scope *parent_scope = ctx->current_scope->parent_scope;

	ctx_decl_scope_destroy(ctx->current_scope);
	ctx->current_scope = parent_scope;
}

#if 0
struct last_enum_value {
	union {
		int64_t s;
		uint64_t u;
	} u;
};
#endif

int opt_clock_force_correlate;

static
int is_unary_string(struct bt_list_head *head)
{
	struct ctf_node *node;

	bt_list_for_each_entry(node, head, siblings) {
		if (node->type != NODE_UNARY_EXPRESSION)
			return 0;
		if (node->u.unary_expression.type != UNARY_STRING)
			return 0;
	}
	return 1;
}

/**
 * Concatenates strings of a unary expression into a single one.
 *
 * @param head	Head of unary expression list
 * @returns	Concatenated string (to be freed using g_free()), or
 *		NULL on error
 */
static
char *concatenate_unary_strings(struct bt_list_head *head)
{
	struct ctf_node *node;
	GString *str;
	int i = 0;

	str = g_string_new("");
	bt_list_for_each_entry(node, head, siblings) {
		char *src_string;

		if (node->type != NODE_UNARY_EXPRESSION
				|| node->u.unary_expression.type != UNARY_STRING
				|| !((node->u.unary_expression.link != UNARY_LINK_UNKNOWN)
					^ (i == 0)))
			return NULL;
		switch (node->u.unary_expression.link) {
		case UNARY_DOTLINK:
			g_string_append(str, ".");
			break;
		case UNARY_ARROWLINK:
			g_string_append(str, "->");
			break;
		case UNARY_DOTDOTDOT:
			g_string_append(str, "...");
			break;
		default:
			break;
		}
		src_string = node->u.unary_expression.u.string;
		g_string_append(str, src_string);
		i++;
	}
	return g_string_free(str, FALSE);
}

static
const char *get_map_clock_name_value(struct bt_list_head *head)
{
	struct ctf_node *node;
	const char *name = NULL;
	int i = 0;

	bt_list_for_each_entry(node, head, siblings) {
		char *src_string;

		if (node->type != NODE_UNARY_EXPRESSION
			|| node->u.unary_expression.type != UNARY_STRING
			|| !((node->u.unary_expression.link != UNARY_LINK_UNKNOWN)
				^ (i == 0)))
			return NULL;

		/* needs to be chained with . */
		switch (node->u.unary_expression.link) {
		case UNARY_DOTLINK:
			break;

		case UNARY_ARROWLINK:
		case UNARY_DOTDOTDOT:
			return NULL;

		default:
			break;
		}

		src_string = node->u.unary_expression.u.string;

		switch (i) {
		case 0:	if (strcmp("clock", src_string) != 0) {
				return NULL;
			}
			break;

		case 1:	name = src_string;
			break;

		case 2:	if (strcmp("value", src_string) != 0) {
				return NULL;
			}
			break;
		default:
			return NULL;	/* extra identifier, unknown */
		}

		i++;
	}

	return name;
}

static
int is_unary_unsigned(struct bt_list_head *head)
{
	struct ctf_node *node;

	bt_list_for_each_entry(node, head, siblings) {
		if (node->type != NODE_UNARY_EXPRESSION)
			return 0;
		if (node->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT)
			return 0;
	}
	return 1;
}

static
int get_unary_unsigned(struct bt_list_head *head, uint64_t *value)
{
	struct ctf_node *node;
	int i = 0;

	bt_list_for_each_entry(node, head, siblings) {
		if (node->type != NODE_UNARY_EXPRESSION
				|| node->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT
				|| node->u.unary_expression.link != UNARY_LINK_UNKNOWN
				|| i != 0)
			return -EINVAL;
		*value = node->u.unary_expression.u.unsigned_constant;
		i++;
	}
	return 0;
}

static
int is_unary_signed(struct bt_list_head *head)
{
	struct ctf_node *node;

	bt_list_for_each_entry(node, head, siblings) {
		if (node->type != NODE_UNARY_EXPRESSION)
			return 0;
		if (node->u.unary_expression.type != UNARY_SIGNED_CONSTANT)
			return 0;
	}
	return 1;
}

static
int get_unary_signed(struct bt_list_head *head, int64_t *value)
{
	struct ctf_node *node;
	int i = 0;

	bt_list_for_each_entry(node, head, siblings) {
		if (node->type != NODE_UNARY_EXPRESSION
				|| node->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT
				|| (node->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT && node->u.unary_expression.type != UNARY_SIGNED_CONSTANT)
				|| node->u.unary_expression.link != UNARY_LINK_UNKNOWN
				|| i != 0)
			return -EINVAL;
		switch (node->u.unary_expression.type) {
		case UNARY_UNSIGNED_CONSTANT:
			*value = (int64_t) node->u.unary_expression.u.unsigned_constant;
			break;
		case UNARY_SIGNED_CONSTANT:
			*value = node->u.unary_expression.u.signed_constant;
			break;
		default:
			return -EINVAL;
		}
		i++;
	}
	return 0;
}

static
int get_unary_uuid(struct bt_list_head *head, unsigned char *uuid)
{
	struct ctf_node *node;
	int i = 0;
	int ret = -1;

	bt_list_for_each_entry(node, head, siblings) {
		const char *src_string;

		if (node->type != NODE_UNARY_EXPRESSION
				|| node->u.unary_expression.type != UNARY_STRING
				|| node->u.unary_expression.link != UNARY_LINK_UNKNOWN
				|| i != 0)
			return -EINVAL;
		src_string = node->u.unary_expression.u.string;
		ret = babeltrace_uuid_parse(src_string, uuid);
	}
	return ret;
}


static
enum bt_ctf_byte_order byte_order_from_unary_expr(FILE *efd,
		struct ctf_node *unary_expr)
{
	if (unary_expr->u.unary_expression.type != UNARY_STRING) {
		fprintf(efd, "[error] %s: \"byte_order\" attribute: expecting string\n", __func__);
		return BT_CTF_BYTE_ORDER_UNKNOWN;
	}

	if (!strcmp(unary_expr->u.unary_expression.u.string, "be") ||
			!strcmp(unary_expr->u.unary_expression.u.string, "network")) {
		return BT_CTF_BYTE_ORDER_BIG_ENDIAN;
	} else if (!strcmp(unary_expr->u.unary_expression.u.string, "le")) {
		return BT_CTF_BYTE_ORDER_LITTLE_ENDIAN;
	} else if (!strcmp(unary_expr->u.unary_expression.u.string, "native")) {
		return BT_CTF_BYTE_ORDER_NATIVE;
	} else {
		fprintf(efd, "[error] %s: unexpected string \"%s\" (should be \"be\", \"le\", \"network\", or \"native\")\n",
			__func__, unary_expr->u.unary_expression.u.string);
		return BT_CTF_BYTE_ORDER_UNKNOWN;
	}
}

static
enum bt_ctf_byte_order get_real_byte_order(struct ctx *ctx,
		struct ctf_node *unary_expr)
{
	enum bt_ctf_byte_order bo =
		byte_order_from_unary_expr(ctx->efd, unary_expr);

	if (bo == BT_CTF_BYTE_ORDER_NATIVE) {
		return bt_ctf_trace_get_byte_order(ctx->trace);
	} else {
		return bo;
	}
}

static
int is_align_valid(uint64_t align)
{
    return (align != 0) && !(align & (align - 1));
}

#if 0
static
int visit_type_specifier(FILE *fd, struct ctf_node *type_specifier, GString *str)
{
	if (type_specifier->type != NODE_TYPE_SPECIFIER)
		return -EINVAL;

	switch (type_specifier->u.type_specifier.type) {
	case TYPESPEC_VOID:
		g_string_append(str, "void");
		break;
	case TYPESPEC_CHAR:
		g_string_append(str, "char");
		break;
	case TYPESPEC_SHORT:
		g_string_append(str, "short");
		break;
	case TYPESPEC_INT:
		g_string_append(str, "int");
		break;
	case TYPESPEC_LONG:
		g_string_append(str, "long");
		break;
	case TYPESPEC_FLOAT:
		g_string_append(str, "float");
		break;
	case TYPESPEC_DOUBLE:
		g_string_append(str, "double");
		break;
	case TYPESPEC_SIGNED:
		g_string_append(str, "signed");
		break;
	case TYPESPEC_UNSIGNED:
		g_string_append(str, "unsigned");
		break;
	case TYPESPEC_BOOL:
		g_string_append(str, "bool");
		break;
	case TYPESPEC_COMPLEX:
		g_string_append(str, "_Complex");
		break;
	case TYPESPEC_IMAGINARY:
		g_string_append(str, "_Imaginary");
		break;
	case TYPESPEC_CONST:
		g_string_append(str, "const");
		break;
	case TYPESPEC_ID_TYPE:
		if (type_specifier->u.type_specifier.id_type)
			g_string_append(str, type_specifier->u.type_specifier.id_type);
		break;
	case TYPESPEC_STRUCT:
	{
		struct ctf_node *node = type_specifier->u.type_specifier.node;

		if (!node->u._struct.name) {
			fprintf(fd, "[error] %s: unexpected empty variant name\n", __func__);
			return -EINVAL;
		}
		g_string_append(str, "struct ");
		g_string_append(str, node->u._struct.name);
		break;
	}
	case TYPESPEC_VARIANT:
	{
		struct ctf_node *node = type_specifier->u.type_specifier.node;

		if (!node->u.variant.name) {
			fprintf(fd, "[error] %s: unexpected empty variant name\n", __func__);
			return -EINVAL;
		}
		g_string_append(str, "variant ");
		g_string_append(str, node->u.variant.name);
		break;
	}
	case TYPESPEC_ENUM:
	{
		struct ctf_node *node = type_specifier->u.type_specifier.node;

		if (!node->u._enum.enum_id) {
			fprintf(fd, "[error] %s: unexpected empty enum ID\n", __func__);
			return -EINVAL;
		}
		g_string_append(str, "enum ");
		g_string_append(str, node->u._enum.enum_id);
		break;
	}
	case TYPESPEC_FLOATING_POINT:
	case TYPESPEC_INTEGER:
	case TYPESPEC_STRING:
	default:
		fprintf(fd, "[error] %s: unknown specifier\n", __func__);
		return -EINVAL;
	}
	return 0;
}

static
int visit_type_specifier_list(FILE *fd, struct ctf_node *type_specifier_list, GString *str)
{
	struct ctf_node *iter;
	int alias_item_nr = 0;
	int ret;

	bt_list_for_each_entry(iter, &type_specifier_list->u.type_specifier_list.head, siblings) {
		if (alias_item_nr != 0)
			g_string_append(str, " ");
		alias_item_nr++;
		ret = visit_type_specifier(fd, iter, str);
		if (ret)
			return ret;
	}
	return 0;
}

static
GQuark create_typealias_identifier(FILE *fd, int depth,
	struct ctf_node *type_specifier_list,
	struct ctf_node *node_type_declarator)
{
	struct ctf_node *iter;
	GString *str;
	char *str_c;
	GQuark alias_q;
	int ret;

	str = g_string_new("");
	ret = visit_type_specifier_list(fd, type_specifier_list, str);
	if (ret) {
		g_string_free(str, TRUE);
		return 0;
	}
	bt_list_for_each_entry(iter, &node_type_declarator->u.type_declarator.pointers, siblings) {
		g_string_append(str, " *");
		if (iter->u.pointer.const_qualifier)
			g_string_append(str, " const");
	}
	str_c = g_string_free(str, FALSE);
	alias_q = g_quark_from_string(str_c);
	g_free(str_c);
	return alias_q;
}

static
struct bt_declaration *ctf_type_declarator_visit(FILE *fd, int depth,
	struct ctf_node *type_specifier_list,
	GQuark *field_name,
	struct ctf_node *node_type_declarator,
	struct declaration_scope *declaration_scope,
	struct bt_declaration *nested_declaration,
	struct ctf_trace *trace)
{
	/*
	 * Visit type declarator by first taking care of sequence/array
	 * (recursively). Then, when we get to the identifier, take care
	 * of pointers.
	 */

	if (node_type_declarator) {
		if (node_type_declarator->u.type_declarator.type == TYPEDEC_UNKNOWN) {
			return NULL;
		}

		/* TODO: gcc bitfields not supported yet. */
		if (node_type_declarator->u.type_declarator.bitfield_len != NULL) {
			fprintf(fd, "[error] %s: gcc bitfields are not supported yet.\n", __func__);
			return NULL;
		}
	}

	if (!nested_declaration) {
		if (node_type_declarator && !bt_list_empty(&node_type_declarator->u.type_declarator.pointers)) {
			GQuark alias_q;

			/*
			 * If we have a pointer declarator, it _has_ to be present in
			 * the typealiases (else fail).
			 */
			alias_q = create_typealias_identifier(fd, depth,
				type_specifier_list, node_type_declarator);
			nested_declaration = bt_lookup_declaration(alias_q, declaration_scope);
			if (!nested_declaration) {
				fprintf(fd, "[error] %s: cannot find typealias \"%s\".\n", __func__, g_quark_to_string(alias_q));
				return NULL;
			}
			if (nested_declaration->id == CTF_TYPE_INTEGER) {
				struct declaration_integer *integer_declaration =
					container_of(nested_declaration, struct declaration_integer, p);
				/* For base to 16 for pointers (expected pretty-print) */
				if (!integer_declaration->base) {
					/*
					 * We need to do a copy of the
					 * integer declaration to modify it. There could be other references to
					 * it.
					 */
					integer_declaration = bt_integer_declaration_new(integer_declaration->len,
						integer_declaration->byte_order, integer_declaration->signedness,
						integer_declaration->p.alignment, 16, integer_declaration->encoding,
						integer_declaration->clock);
					nested_declaration = &integer_declaration->p;
				}
			}
		} else {
			nested_declaration = ctf_type_specifier_list_visit(fd, depth,
				type_specifier_list, declaration_scope, trace);
		}
	}

	if (!node_type_declarator)
		return nested_declaration;

	if (node_type_declarator->u.type_declarator.type == TYPEDEC_ID) {
		if (node_type_declarator->u.type_declarator.u.id)
			*field_name = g_quark_from_string(node_type_declarator->u.type_declarator.u.id);
		else
			*field_name = 0;
		return nested_declaration;
	} else {
		struct bt_declaration *declaration;
		struct ctf_node *first;

		/* TYPEDEC_NESTED */

		if (!nested_declaration) {
			fprintf(fd, "[error] %s: nested type is unknown.\n", __func__);
			return NULL;
		}

		/* create array/sequence, pass nested_declaration as child. */
		if (bt_list_empty(&node_type_declarator->u.type_declarator.u.nested.length)) {
			fprintf(fd, "[error] %s: expecting length field reference or value.\n", __func__);
			return NULL;
		}
		first = _bt_list_first_entry(&node_type_declarator->u.type_declarator.u.nested.length,
				struct ctf_node, siblings);
		if (first->type != NODE_UNARY_EXPRESSION) {
			return NULL;
		}

		switch (first->u.unary_expression.type) {
		case UNARY_UNSIGNED_CONSTANT:
		{
			struct declaration_array *array_declaration;
			size_t len;

			len = first->u.unary_expression.u.unsigned_constant;
			array_declaration = bt_array_declaration_new(len, nested_declaration,
						declaration_scope);

			if (!array_declaration) {
				fprintf(fd, "[error] %s: cannot create array declaration.\n", __func__);
				return NULL;
			}
			bt_declaration_unref(nested_declaration);
			declaration = &array_declaration->p;
			break;
		}
		case UNARY_STRING:
		{
			/* Lookup unsigned integer definition, create sequence */
			char *length_name = concatenate_unary_strings(&node_type_declarator->u.type_declarator.u.nested.length);
			struct declaration_sequence *sequence_declaration;

			if (!length_name)
				return NULL;
			sequence_declaration = bt_sequence_declaration_new(length_name, nested_declaration, declaration_scope);
			if (!sequence_declaration) {
				fprintf(fd, "[error] %s: cannot create sequence declaration.\n", __func__);
				g_free(length_name);
				return NULL;
			}
			bt_declaration_unref(nested_declaration);
			declaration = &sequence_declaration->p;
			g_free(length_name);
			break;
		}
		default:
			return NULL;
		}

		/* Pass it as content of outer container */
		declaration = ctf_type_declarator_visit(fd, depth,
				type_specifier_list, field_name,
				node_type_declarator->u.type_declarator.u.nested.type_declarator,
				declaration_scope, declaration, trace);
		return declaration;
	}
}

static
int ctf_struct_type_declarators_visit(FILE *fd, int depth,
	struct declaration_struct *struct_declaration,
	struct ctf_node *type_specifier_list,
	struct bt_list_head *type_declarators,
	struct declaration_scope *declaration_scope,
	struct ctf_trace *trace)
{
	struct ctf_node *iter;
	GQuark field_name;

	bt_list_for_each_entry(iter, type_declarators, siblings) {
		struct bt_declaration *field_declaration;

		field_declaration = ctf_type_declarator_visit(fd, depth,
						type_specifier_list,
						&field_name, iter,
						struct_declaration->scope,
						NULL, trace);
		if (!field_declaration) {
			fprintf(fd, "[error] %s: unable to find struct field declaration type\n", __func__);
			return -EINVAL;
		}

		/* Check if field with same name already exists */
		if (bt_struct_declaration_lookup_field_index(struct_declaration, field_name) >= 0) {
			fprintf(fd, "[error] %s: duplicate field %s in struct\n", __func__, g_quark_to_string(field_name));
			return -EINVAL;
		}

		bt_struct_declaration_add_field(struct_declaration,
					     g_quark_to_string(field_name),
					     field_declaration);
		bt_declaration_unref(field_declaration);
	}
	return 0;
}

static
int ctf_variant_type_declarators_visit(FILE *fd, int depth,
	struct declaration_untagged_variant *untagged_variant_declaration,
	struct ctf_node *type_specifier_list,
	struct bt_list_head *type_declarators,
	struct declaration_scope *declaration_scope,
	struct ctf_trace *trace)
{
	struct ctf_node *iter;
	GQuark field_name;

	bt_list_for_each_entry(iter, type_declarators, siblings) {
		struct bt_declaration *field_declaration;

		field_declaration = ctf_type_declarator_visit(fd, depth,
						type_specifier_list,
						&field_name, iter,
						untagged_variant_declaration->scope,
						NULL, trace);
		if (!field_declaration) {
			fprintf(fd, "[error] %s: unable to find variant field declaration type\n", __func__);
			return -EINVAL;
		}

		if (bt_untagged_variant_declaration_get_field_from_tag(untagged_variant_declaration, field_name) != NULL) {
			fprintf(fd, "[error] %s: duplicate field %s in variant\n", __func__, g_quark_to_string(field_name));
			return -EINVAL;
		}

		bt_untagged_variant_declaration_add_field(untagged_variant_declaration,
					      g_quark_to_string(field_name),
					      field_declaration);
		bt_declaration_unref(field_declaration);
	}
	return 0;
}
#endif

static
int visit_typedef(struct ctx *ctx, struct ctf_node *type_specifier_list,
		struct bt_list_head *type_declarators)
{
#if 0
	struct ctf_node *iter;
	GQuark identifier;

	bt_list_for_each_entry(iter, type_declarators, siblings) {
		struct bt_declaration *type_declaration;
		int ret;

		type_declaration = ctf_type_declarator_visit(fd, depth,
					type_specifier_list,
					&identifier, iter,
					scope, NULL, trace);
		if (!type_declaration) {
			fprintf(fd, "[error] %s: problem creating type declaration\n", __func__);
			return -EINVAL;
		}
		/*
		 * Don't allow typedef and typealias of untagged
		 * variants.
		 */
		if (type_declaration->id == CTF_TYPE_UNTAGGED_VARIANT) {
			fprintf(fd, "[error] %s: typedef of untagged variant is not permitted.\n", __func__);
			bt_declaration_unref(type_declaration);
			return -EPERM;
		}
		ret = bt_register_declaration(identifier, type_declaration, scope);
		if (ret) {
			type_declaration->declaration_free(type_declaration);
			return ret;
		}
		bt_declaration_unref(type_declaration);
	}
#endif

	return 0;
}

static
int visit_typealias(struct ctx *ctx, struct ctf_node *target,
		struct ctf_node *alias)
{
#if 0
	struct bt_declaration *type_declaration;
	struct ctf_node *node;
	GQuark dummy_id;
	GQuark alias_q;
	int err;

	/* See ctf_visitor_type_declarator() in the semantic validator. */

	/*
	 * Create target type declaration.
	 */

	if (bt_list_empty(&target->u.typealias_target.type_declarators))
		node = NULL;
	else
		node = _bt_list_first_entry(&target->u.typealias_target.type_declarators,
				struct ctf_node, siblings);
	type_declaration = ctf_type_declarator_visit(fd, depth,
		target->u.typealias_target.type_specifier_list,
		&dummy_id, node,
		scope, NULL, trace);
	if (!type_declaration) {
		fprintf(fd, "[error] %s: problem creating type declaration\n", __func__);
		err = -EINVAL;
		goto error;
	}
	/*
	 * Don't allow typedef and typealias of untagged
	 * variants.
	 */
	if (type_declaration->id == CTF_TYPE_UNTAGGED_VARIANT) {
		fprintf(fd, "[error] %s: typedef of untagged variant is not permitted.\n", __func__);
		bt_declaration_unref(type_declaration);
		return -EPERM;
	}
	/*
	 * The semantic validator does not check whether the target is
	 * abstract or not (if it has an identifier). Check it here.
	 */
	if (dummy_id != 0) {
		fprintf(fd, "[error] %s: expecting empty identifier\n", __func__);
		err = -EINVAL;
		goto error;
	}
	/*
	 * Create alias identifier.
	 */

	node = _bt_list_first_entry(&alias->u.typealias_alias.type_declarators,
				struct ctf_node, siblings);
	alias_q = create_typealias_identifier(fd, depth,
			alias->u.typealias_alias.type_specifier_list, node);
	err = bt_register_declaration(alias_q, type_declaration, scope);
	if (err)
		goto error;
	bt_declaration_unref(type_declaration);
	return 0;

error:
	if (type_declaration) {
		type_declaration->declaration_free(type_declaration);
	}
	return err;
#endif
	return 0;
}

#if 0
static
int ctf_struct_declaration_list_visit(FILE *fd, int depth,
	struct ctf_node *iter, struct declaration_struct *struct_declaration,
	struct ctf_trace *trace)
{
	int ret;

	switch (iter->type) {
	case NODE_TYPEDEF:
		/* For each declarator, declare type and add type to struct bt_declaration scope */
		ret = ctf_typedef_visit(fd, depth,
			struct_declaration->scope,
			iter->u._typedef.type_specifier_list,
			&iter->u._typedef.type_declarators, trace);
		if (ret)
			return ret;
		break;
	case NODE_TYPEALIAS:
		/* Declare type with declarator and add type to struct bt_declaration scope */
		ret = ctf_typealias_visit(fd, depth,
			struct_declaration->scope,
			iter->u.typealias.target,
			iter->u.typealias.alias, trace);
		if (ret)
			return ret;
		break;
	case NODE_STRUCT_OR_VARIANT_DECLARATION:
		/* Add field to structure declaration */
		ret = ctf_struct_type_declarators_visit(fd, depth,
				struct_declaration,
				iter->u.struct_or_variant_declaration.type_specifier_list,
				&iter->u.struct_or_variant_declaration.type_declarators,
				struct_declaration->scope, trace);
		if (ret)
			return ret;
		break;
	default:
		fprintf(fd, "[error] %s: unexpected node type %d\n", __func__, (int) iter->type);
		return -EINVAL;
	}
	return 0;
}

static
int ctf_variant_declaration_list_visit(FILE *fd, int depth,
	struct ctf_node *iter,
	struct declaration_untagged_variant *untagged_variant_declaration,
	struct ctf_trace *trace)
{
	int ret;

	switch (iter->type) {
	case NODE_TYPEDEF:
		/* For each declarator, declare type and add type to variant declaration scope */
		ret = ctf_typedef_visit(fd, depth,
			untagged_variant_declaration->scope,
			iter->u._typedef.type_specifier_list,
			&iter->u._typedef.type_declarators, trace);
		if (ret)
			return ret;
		break;
	case NODE_TYPEALIAS:
		/* Declare type with declarator and add type to variant declaration scope */
		ret = ctf_typealias_visit(fd, depth,
			untagged_variant_declaration->scope,
			iter->u.typealias.target,
			iter->u.typealias.alias, trace);
		if (ret)
			return ret;
		break;
	case NODE_STRUCT_OR_VARIANT_DECLARATION:
		/* Add field to structure declaration */
		ret = ctf_variant_type_declarators_visit(fd, depth,
				untagged_variant_declaration,
				iter->u.struct_or_variant_declaration.type_specifier_list,
				&iter->u.struct_or_variant_declaration.type_declarators,
				untagged_variant_declaration->scope, trace);
		if (ret)
			return ret;
		break;
	default:
		fprintf(fd, "[error] %s: unexpected node type %d\n", __func__, (int) iter->type);
		return -EINVAL;
	}
	return 0;
}
#endif

static
int visit_struct(struct ctx *ctx, const char *name,
	struct bt_list_head *decl_list, int has_body,
	struct bt_list_head *min_align,
	struct bt_ctf_field_type **struct_decl)
{
	int ret = 0;

	*struct_decl = NULL;

	/* for named struct (without body), lookup in declaration scope */
	if (!has_body) {
		if (!name) {
			ret = -EPERM;
			goto error;
		}

		*struct_decl = ctx_decl_scope_lookup_struct(ctx->current_scope,
			name, -1);

		if (!*struct_decl) {
			fprintf(ctx->efd, "[error] %s: cannot find \"struct %s\"\n",
				__func__, name);
			ret = -EINVAL;
			goto error;
		}

		bt_ctf_field_type_get(*struct_decl);
	} else {
		if (name) {
			if (ctx_decl_scope_lookup_struct(ctx->current_scope, name, 1)) {
				fprintf(ctx->efd, "[error] %s: \"struct %s\" already declared in local scope\n",
					__func__, name);
				ret = -EINVAL;
				goto error;
			}
		}

		uint64_t min_align_value = 0;

		if (!bt_list_empty(min_align)) {
			int ret;

			ret = get_unary_unsigned(min_align, &min_align_value);

			if (ret) {
				fprintf(ctx->efd, "[error] %s: unexpected unary expression for structure declaration's \"align\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}
		}

		*struct_decl = bt_ctf_field_type_structure_create();

		if (!*struct_decl) {
			fprintf(ctx->efd, "[error] %s: cannot create structure declaration\n",
				__func__);
			ret = -ENOMEM;
			goto error;
		}

		struct ctf_node *iter;

		bt_list_for_each_entry(iter, decl_list, siblings) {
			int ret = 0;

			/*
			ret = ctf_struct_declaration_list_visit(fd, depth + 1, iter,
				struct_declaration, trace);
			*/

			if (ret) {
				goto error;
			}
		}

		if (name) {
			int ret = ctx_decl_scope_register_struct(ctx->current_scope,
				name, *struct_decl);

			if (ret) {
				goto error;
			}
		}
	}

	return 0;

error:
	if (*struct_decl) {
		bt_ctf_field_type_put(*struct_decl);
	}

	return ret;
}

#if 0
static
struct bt_declaration *ctf_declaration_variant_visit(FILE *fd,
	int depth, const char *name, const char *choice,
	struct bt_list_head *declaration_list,
	int has_body, struct declaration_scope *declaration_scope,
	struct ctf_trace *trace)
{
	struct declaration_untagged_variant *untagged_variant_declaration;
	struct declaration_variant *variant_declaration;
	struct ctf_node *iter;

	/*
	 * For named variant (without body), lookup in
	 * declaration scope. Don't take reference on variant
	 * declaration: ref is only taken upon definition.
	 */
	if (!has_body) {
		if (!name)
			return NULL;
		untagged_variant_declaration =
			bt_lookup_variant_declaration(g_quark_from_string(name),
						   declaration_scope);
		bt_declaration_ref(&untagged_variant_declaration->p);
	} else {
		/* For unnamed variant, create type */
		/* For named variant (with body), create type and add to declaration scope */
		if (name) {
			if (bt_lookup_variant_declaration(g_quark_from_string(name),
						       declaration_scope)) {
				fprintf(fd, "[error] %s: variant %s already declared in scope\n", __func__, name);
				return NULL;
			}
		}
		untagged_variant_declaration = bt_untagged_bt_variant_declaration_new(declaration_scope);
		bt_list_for_each_entry(iter, declaration_list, siblings) {
			int ret;

			ret = ctf_variant_declaration_list_visit(fd, depth + 1, iter,
				untagged_variant_declaration, trace);
			if (ret)
				goto error;
		}
		if (name) {
			int ret;

			ret = bt_register_variant_declaration(g_quark_from_string(name),
					untagged_variant_declaration,
					declaration_scope);
			if (ret)
				return NULL;
		}
	}
	/*
	 * if tagged, create tagged variant and return. else return
	 * untagged variant.
	 */
	if (!choice) {
		return &untagged_variant_declaration->p;
	} else {
		variant_declaration = bt_variant_declaration_new(untagged_variant_declaration, choice);
		if (!variant_declaration)
			goto error;
		bt_declaration_unref(&untagged_variant_declaration->p);
		return &variant_declaration->p;
	}
error:
	untagged_variant_declaration->p.declaration_free(&untagged_variant_declaration->p);
	return NULL;
}

static
int ctf_enumerator_list_visit(FILE *fd, int depth,
		struct ctf_node *enumerator,
		struct declaration_enum *enum_declaration,
		struct last_enum_value *last)
{
	GQuark q;
	struct ctf_node *iter;

	q = g_quark_from_string(enumerator->u.enumerator.id);
	if (enum_declaration->integer_declaration->signedness) {
		int64_t start = 0, end = 0;
		int nr_vals = 0;

		bt_list_for_each_entry(iter, &enumerator->u.enumerator.values, siblings) {
			int64_t *target;

			if (iter->type != NODE_UNARY_EXPRESSION)
				return -EINVAL;
			if (nr_vals == 0)
				target = &start;
			else
				target = &end;

			switch (iter->u.unary_expression.type) {
			case UNARY_SIGNED_CONSTANT:
				*target = iter->u.unary_expression.u.signed_constant;
				break;
			case UNARY_UNSIGNED_CONSTANT:
				*target = iter->u.unary_expression.u.unsigned_constant;
				break;
			default:
				fprintf(fd, "[error] %s: invalid enumerator\n", __func__);
				return -EINVAL;
			}
			if (nr_vals > 1) {
				fprintf(fd, "[error] %s: invalid enumerator\n", __func__);
				return -EINVAL;
			}
			nr_vals++;
		}
		if (nr_vals == 0)
			start = last->u.s;
		if (nr_vals <= 1)
			end = start;
		last->u.s = end + 1;
		bt_enum_signed_insert(enum_declaration, start, end, q);
	} else {
		uint64_t start = 0, end = 0;
		int nr_vals = 0;

		bt_list_for_each_entry(iter, &enumerator->u.enumerator.values, siblings) {
			uint64_t *target;

			if (iter->type != NODE_UNARY_EXPRESSION)
				return -EINVAL;
			if (nr_vals == 0)
				target = &start;
			else
				target = &end;

			switch (iter->u.unary_expression.type) {
			case UNARY_UNSIGNED_CONSTANT:
				*target = iter->u.unary_expression.u.unsigned_constant;
				break;
			case UNARY_SIGNED_CONSTANT:
				/*
				 * We don't accept signed constants for enums with unsigned
				 * container type.
				 */
				fprintf(fd, "[error] %s: invalid enumerator (signed constant encountered, but enum container type is unsigned)\n", __func__);
				return -EINVAL;
			default:
				fprintf(fd, "[error] %s: invalid enumerator\n", __func__);
				return -EINVAL;
			}
			if (nr_vals > 1) {
				fprintf(fd, "[error] %s: invalid enumerator\n", __func__);
				return -EINVAL;
			}
			nr_vals++;
		}
		if (nr_vals == 0)
			start = last->u.u;
		if (nr_vals <= 1)
			end = start;
		last->u.u = end + 1;
		bt_enum_unsigned_insert(enum_declaration, start, end, q);
	}
	return 0;
}

static
struct bt_declaration *ctf_declaration_enum_visit(FILE *fd, int depth,
			const char *name,
			struct ctf_node *container_type,
			struct bt_list_head *enumerator_list,
			int has_body,
			struct declaration_scope *declaration_scope,
			struct ctf_trace *trace)
{
	struct bt_declaration *declaration;
	struct declaration_enum *enum_declaration;
	struct declaration_integer *integer_declaration;
	struct last_enum_value last_value;
	struct ctf_node *iter;
	GQuark dummy_id;

	/*
	 * For named enum (without body), lookup in
	 * declaration scope. Don't take reference on enum
	 * declaration: ref is only taken upon definition.
	 */
	if (!has_body) {
		if (!name)
			return NULL;
		enum_declaration =
			bt_lookup_enum_declaration(g_quark_from_string(name),
						declaration_scope);
		bt_declaration_ref(&enum_declaration->p);
		return &enum_declaration->p;
	} else {
		/* For unnamed enum, create type */
		/* For named enum (with body), create type and add to declaration scope */
		if (name) {
			if (bt_lookup_enum_declaration(g_quark_from_string(name),
						    declaration_scope)) {
				fprintf(fd, "[error] %s: enum %s already declared in scope\n", __func__, name);
				return NULL;
			}
		}
		if (!container_type) {
			declaration = bt_lookup_declaration(g_quark_from_static_string("int"),
							 declaration_scope);
			if (!declaration) {
				fprintf(fd, "[error] %s: \"int\" type declaration missing for enumeration\n", __func__);
				return NULL;
			}
		} else {
			declaration = ctf_type_declarator_visit(fd, depth,
						container_type,
						&dummy_id, NULL,
						declaration_scope,
						NULL, trace);
		}
		if (!declaration) {
			fprintf(fd, "[error] %s: unable to create container type for enumeration\n", __func__);
			return NULL;
		}
		if (declaration->id != CTF_TYPE_INTEGER) {
			fprintf(fd, "[error] %s: container type for enumeration is not integer\n", __func__);
			return NULL;
		}
		integer_declaration = container_of(declaration, struct declaration_integer, p);
		enum_declaration = bt_enum_declaration_new(integer_declaration);
		bt_declaration_unref(&integer_declaration->p);	/* leave ref to enum */
		if (enum_declaration->integer_declaration->signedness) {
			last_value.u.s = 0;
		} else {
			last_value.u.u = 0;
		}
		bt_list_for_each_entry(iter, enumerator_list, siblings) {
			int ret;

			ret = ctf_enumerator_list_visit(fd, depth + 1, iter, enum_declaration,
					&last_value);
			if (ret)
				goto error;
		}
		if (name) {
			int ret;

			ret = bt_register_enum_declaration(g_quark_from_string(name),
					enum_declaration,
					declaration_scope);
			if (ret)
				return NULL;
			bt_declaration_unref(&enum_declaration->p);
		}
		return &enum_declaration->p;
	}
error:
	enum_declaration->p.declaration_free(&enum_declaration->p);
	return NULL;
}

static
struct bt_declaration *ctf_declaration_type_specifier_visit(FILE *fd, int depth,
		struct ctf_node *type_specifier_list,
		struct declaration_scope *declaration_scope)
{
	GString *str;
	struct bt_declaration *declaration;
	char *str_c;
	int ret;
	GQuark id_q;

	str = g_string_new("");
	ret = visit_type_specifier_list(fd, type_specifier_list, str);
	if (ret) {
		(void) g_string_free(str, TRUE);
		return NULL;
	}
	str_c = g_string_free(str, FALSE);
	id_q = g_quark_from_string(str_c);
	g_free(str_c);
	declaration = bt_lookup_declaration(id_q, declaration_scope);
	if (!declaration)
		return NULL;
	bt_declaration_ref(declaration);
	return declaration;
}
#endif

/*
 * Returns 0/1 boolean, or < 0 on error.
 */
static
int get_boolean(FILE *efd, struct ctf_node *unary_expr)
{
	if (unary_expr->type != NODE_UNARY_EXPRESSION) {
		fprintf(efd, "[error] %s: expecting unary expression\n",
			__func__);
		return -EINVAL;
	}

	switch (unary_expr->u.unary_expression.type) {
	case UNARY_UNSIGNED_CONSTANT:
		if (unary_expr->u.unary_expression.u.unsigned_constant == 0) {
			return 0;
		} else {
			return 1;
		}

	case UNARY_SIGNED_CONSTANT:
		if (unary_expr->u.unary_expression.u.signed_constant == 0) {
			return 0;
		} else {
			return 1;
		}

	case UNARY_STRING:
		if (!strcmp(unary_expr->u.unary_expression.u.string, "true")) {
			return 1;
		} else if (!strcmp(unary_expr->u.unary_expression.u.string, "TRUE")) {
			return 1;
		} else if (!strcmp(unary_expr->u.unary_expression.u.string, "false")) {
			return 0;
		} else if (!strcmp(unary_expr->u.unary_expression.u.string, "FALSE")) {
			return 0;
		} else {
			fprintf(efd, "[error] %s: unexpected string \"%s\"\n",
				__func__, unary_expr->u.unary_expression.u.string);
			return -EINVAL;
		}

	default:
		fprintf(efd, "[error] %s: unexpected unary expression type\n",
			__func__);
		return -EINVAL;
	}
}

#if 0
static
int get_trace_byte_order(FILE *fd, int depth, struct ctf_node *unary_expression)
{
	int byte_order;

	if (unary_expression->u.unary_expression.type != UNARY_STRING) {
		fprintf(fd, "[error] %s: byte_order: expecting string\n",
			__func__);
		return -EINVAL;
	}
	if (!strcmp(unary_expression->u.unary_expression.u.string, "be"))
		byte_order = BIG_ENDIAN;
	else if (!strcmp(unary_expression->u.unary_expression.u.string, "le"))
		byte_order = LITTLE_ENDIAN;
	else {
		fprintf(fd, "[error] %s: unexpected string \"%s\". Should be \"be\" or \"le\".\n",
			__func__, unary_expression->u.unary_expression.u.string);
		return -EINVAL;
	}
	return byte_order;
}

static
int get_byte_order(FILE *fd, int depth, struct ctf_node *unary_expression,
		struct ctf_trace *trace)
{
	int byte_order;

	if (unary_expression->u.unary_expression.type != UNARY_STRING) {
		fprintf(fd, "[error] %s: byte_order: expecting string\n",
			__func__);
		return -EINVAL;
	}
	if (!strcmp(unary_expression->u.unary_expression.u.string, "native"))
		byte_order = trace->byte_order;
	else if (!strcmp(unary_expression->u.unary_expression.u.string, "network"))
		byte_order = BIG_ENDIAN;
	else if (!strcmp(unary_expression->u.unary_expression.u.string, "be"))
		byte_order = BIG_ENDIAN;
	else if (!strcmp(unary_expression->u.unary_expression.u.string, "le"))
		byte_order = LITTLE_ENDIAN;
	else {
		fprintf(fd, "[error] %s: unexpected string \"%s\". Should be \"native\", \"network\", \"be\" or \"le\".\n",
			__func__, unary_expression->u.unary_expression.u.string);
		return -EINVAL;
	}
	return byte_order;
}
#endif

static
int visit_integer_decl(struct ctx *ctx,
	struct bt_list_head *expressions,
	struct bt_ctf_field_type **integer_decl)
{
	struct ctf_node *expression;
	uint64_t alignment, size;
	enum bt_ctf_byte_order byte_order = bt_ctf_trace_get_byte_order(ctx->trace);
	int signedness = 0;
	enum bt_ctf_integer_base base = BT_CTF_INTEGER_BASE_DECIMAL;
	enum ctf_string_encoding encoding = CTF_STRING_NONE;
	struct bt_ctf_clock *mapped_clock = NULL;
	int set = 0;
	int ret = 0;

	*integer_decl = NULL;

	bt_list_for_each_entry(expression, expressions, siblings) {
		struct ctf_node *left, *right;

		left = _bt_list_first_entry(&expression->u.ctf_expression.left, struct ctf_node, siblings);
		right = _bt_list_first_entry(&expression->u.ctf_expression.right, struct ctf_node, siblings);

		if (left->u.unary_expression.type != UNARY_STRING) {
			ret = -EINVAL;
			goto error;
		}

		if (!strcmp(left->u.unary_expression.u.string, "signed")) {
			if (_IS_SET(&set, _INTEGER_SIGNED_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"signed\" in integer declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			signedness = get_boolean(ctx->efd, right);

			if (signedness < 0) {
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _INTEGER_SIGNED_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "byte_order")) {
			if (_IS_SET(&set, _INTEGER_BYTE_ORDER_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"byte_order\" in integer declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			byte_order = get_real_byte_order(ctx, right);

			if (byte_order == BT_CTF_BYTE_ORDER_UNKNOWN) {
				fprintf(ctx->efd, "[error] %s: invalid \"byte_order\" attribute in integer declaration\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _INTEGER_BYTE_ORDER_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "size")) {
			if (_IS_SET(&set, _INTEGER_SIZE_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"size\" in integer declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT) {
				fprintf(ctx->efd, "[error] %s: invalid \"size\" attribute in integer declaration: expecting unsigned constant\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			size = right->u.unary_expression.u.unsigned_constant;

			if (size == 0) {
				fprintf(ctx->efd, "[error] %s: invalid \"size\" attribute in integer declaration: expecting positive constant\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _INTEGER_SIZE_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "align")) {
			if (_IS_SET(&set, _INTEGER_ALIGN_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"align\" in integer declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT) {
				fprintf(ctx->efd, "[error] %s: invalid \"align\" attribute in integer declaration: expecting unsigned constant\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			alignment = right->u.unary_expression.u.unsigned_constant;

			if (!is_align_valid(alignment)) {
				fprintf(ctx->efd, "[error] %s: invalid \"align\" attribute in integer declaration: expecting power of two\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _INTEGER_ALIGN_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "base")) {
			if (_IS_SET(&set, _INTEGER_BASE_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"base\" in integer declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			switch (right->u.unary_expression.type) {
			case UNARY_UNSIGNED_CONSTANT:
				switch (right->u.unary_expression.u.unsigned_constant) {
				case 2:
					base = BT_CTF_INTEGER_BASE_BINARY;
					break;

				case 8:
					base = BT_CTF_INTEGER_BASE_OCTAL;
					break;

				case 10:
					base = BT_CTF_INTEGER_BASE_DECIMAL;
					break;

				case 16:
					base = BT_CTF_INTEGER_BASE_HEXADECIMAL;
					break;

				default:
					fprintf(ctx->efd, "[error] %s: invalid \"base\" attribute in integer declaration: %" PRIu64 "\n",
						__func__, right->u.unary_expression.u.unsigned_constant);
					ret = -EINVAL;
					goto error;
				}
				break;

			case UNARY_STRING:
			{
				char *s_right = concatenate_unary_strings(&expression->u.ctf_expression.right);

				if (!s_right) {
					fprintf(ctx->efd, "[error] %s: unexpected unary expression for integer declaration's \"base\" attribute\n",
						__func__);
					ret = -EINVAL;
					goto error;
				}

				if (!strcmp(s_right, "decimal") ||
						!strcmp(s_right, "dec") ||
						!strcmp(s_right, "d") ||
						!strcmp(s_right, "i") ||
						!strcmp(s_right, "u")) {
					base = BT_CTF_INTEGER_BASE_DECIMAL;
				} else if (!strcmp(s_right, "hexadecimal") ||
						!strcmp(s_right, "hex") ||
						!strcmp(s_right, "x") ||
						!strcmp(s_right, "X") ||
						!strcmp(s_right, "p")) {
					base = BT_CTF_INTEGER_BASE_HEXADECIMAL;
				} else if (!strcmp(s_right, "octal") ||
						!strcmp(s_right, "oct") ||
						!strcmp(s_right, "o")) {
					base = BT_CTF_INTEGER_BASE_OCTAL;
				} else if (!strcmp(s_right, "binary") ||
						!strcmp(s_right, "b")) {
					base = BT_CTF_INTEGER_BASE_BINARY;
				} else {
					fprintf(ctx->efd, "[error] %s: unexpected unary expression for integer declaration's \"base\" attribute: \"%s\"\n",
						__func__, s_right);
					g_free(s_right);
					ret = -EINVAL;
					goto error;
				}

				g_free(s_right);
				break;
			}

			default:
				fprintf(ctx->efd, "[error] %s: invalid \"base\" attribute in integer declaration: expecting unsigned constant or unary string\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _INTEGER_BASE_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "encoding")) {
			if (_IS_SET(&set, _INTEGER_ENCODING_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"encoding\" in integer declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_STRING) {
				fprintf(ctx->efd, "[error] %s: invalid \"encoding\" attribute in integer declaration: expecting unary string\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			char *s_right = concatenate_unary_strings(&expression->u.ctf_expression.right);

			if (!s_right) {
				fprintf(ctx->efd, "[error] %s: unexpected unary expression for integer declaration's \"encoding\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			if (!strcmp(s_right, "UTF8") ||
					!strcmp(s_right, "utf8") ||
					!strcmp(s_right, "utf-8") ||
					!strcmp(s_right, "UTF-8")) {
				encoding = CTF_STRING_UTF8;
			} else if (!strcmp(s_right, "ASCII") ||
					!strcmp(s_right, "ascii")) {
				encoding = CTF_STRING_ASCII;
			} else if (!strcmp(s_right, "none")) {
				encoding = CTF_STRING_NONE;
			} else {
				fprintf(ctx->efd, "[error] %s: invalid \"encoding\" attribute in integer declaration: unknown encoding \"%s\"\n",
					__func__, s_right);
				g_free(s_right);
				ret = -EINVAL;
				goto error;
			}

			g_free(s_right);
			_SET(&set, _INTEGER_ENCODING_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "map")) {
			if (_IS_SET(&set, _INTEGER_MAP_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"map\" in integer declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_STRING) {
				fprintf(ctx->efd, "[error] %s: invalid \"map\" attribute in integer declaration: expecting unary string\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			const char *clock_name =
				get_map_clock_name_value(&expression->u.ctf_expression.right);

			if (!clock_name) {
				char *s_right = concatenate_unary_strings(&expression->u.ctf_expression.right);

				if (!s_right) {
					fprintf(ctx->efd, "[error] %s: unexpected unary expression for integer declaration's \"map\" attribute\n",
						__func__);
					ret = -EINVAL;
					goto error;
				}

				fprintf(ctx->efd, "[error] %s: invalid \"map\" attribute in integer declaration: unknown clock: \"%s\"\n",
					__func__, s_right);
				_SET(&set, _INTEGER_MAP_SET);
				g_free(s_right);
				continue;
			}

			mapped_clock = bt_ctf_trace_get_clock_by_name(ctx->trace,
				clock_name);

			if (!mapped_clock) {
				fprintf(ctx->efd, "[error] %s: invalid \"map\" attribute in integer declaration: cannot find clock \"%s\"\n",
					__func__, clock_name);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _INTEGER_MAP_SET);
		} else {
			fprintf(ctx->efd, "[warning] %s: unknown attribute \"%s\" in integer declaration\n",
				__func__,
				left->u.unary_expression.u.string);
		}
	}

	if (!_IS_SET(&set, _INTEGER_SIZE_SET)) {
		fprintf(ctx->efd, "[error] %s: missing \"size\" attribute in integer declaration\n",
			__func__);
		ret = -EPERM;
		goto error;
	}

	if (!_IS_SET(&set, _INTEGER_ALIGN_SET)) {
		if (size % CHAR_BIT) {
			/* bit-packed alignment */
			alignment = 1;
		} else {
			/* byte-packed alignment */
			alignment = CHAR_BIT;
		}
	}

	*integer_decl = bt_ctf_field_type_integer_create((unsigned int) size);

	if (!*integer_decl) {
		fprintf(ctx->efd, "[error] %s: cannot create integer declaration\n",
			__func__);
		ret = -ENOMEM;
		goto error;
	}

	ret = bt_ctf_field_type_integer_set_signed(*integer_decl, signedness);
	ret &= bt_ctf_field_type_integer_set_base(*integer_decl, base);
	ret &= bt_ctf_field_type_integer_set_encoding(*integer_decl, encoding);
	ret &= bt_ctf_field_type_set_alignment(*integer_decl,
		(unsigned int) alignment);
	ret &= bt_ctf_field_type_set_byte_order(*integer_decl, byte_order);

	if (mapped_clock) {
		ret &= bt_ctf_field_type_integer_set_mapped_clock(*integer_decl,
			mapped_clock);
		bt_ctf_clock_put(mapped_clock);
		mapped_clock = NULL;
	}

	if (ret) {
		fprintf(ctx->efd, "[error] %s: cannot configure integer declaration\n",
			__func__);
		ret = -EINVAL;
		goto error;
	}

	return 0;

error:
	if (mapped_clock) {
		bt_ctf_clock_put(mapped_clock);
	}

	if (*integer_decl) {
		bt_ctf_field_type_put(*integer_decl);
	}

	return ret;
}

static
int visit_floating_point_decl(struct ctx *ctx,
	struct bt_list_head *expressions,
	struct bt_ctf_field_type **float_decl)
{
	struct ctf_node *expression;
	uint64_t alignment = 1, exp_dig, mant_dig;
	enum bt_ctf_byte_order byte_order = bt_ctf_trace_get_byte_order(ctx->trace);
	int set = 0;
	int ret = 0;

	*float_decl = NULL;

	bt_list_for_each_entry(expression, expressions, siblings) {
		struct ctf_node *left, *right;

		left = _bt_list_first_entry(&expression->u.ctf_expression.left, struct ctf_node, siblings);
		right = _bt_list_first_entry(&expression->u.ctf_expression.right, struct ctf_node, siblings);

		if (left->u.unary_expression.type != UNARY_STRING) {
			ret = -EINVAL;
			goto error;
		}

		if (!strcmp(left->u.unary_expression.u.string, "byte_order")) {
			if (_IS_SET(&set, _FLOAT_BYTE_ORDER_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"byte_order\" in floating point number declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			byte_order = get_real_byte_order(ctx, right);

			if (byte_order == BT_CTF_BYTE_ORDER_UNKNOWN) {
				fprintf(ctx->efd, "[error] %s: invalid \"byte_order\" attribute in floating point number declaration\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _FLOAT_BYTE_ORDER_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "exp_dig")) {
			if (_IS_SET(&set, _FLOAT_EXP_DIG_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"exp_dig\" in floating point number declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT) {
				fprintf(ctx->efd, "[error] %s: invalid \"exp_dig\" attribute in floating point number declaration: expecting unsigned constant\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			exp_dig = right->u.unary_expression.u.unsigned_constant;

			if (!is_align_valid(alignment)) {
				fprintf(ctx->efd, "[error] %s: invalid \"exp_dig\" attribute in floating point number declaration: expecting power of two\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _FLOAT_EXP_DIG_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "mant_dig")) {
			if (_IS_SET(&set, _FLOAT_MANT_DIG_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"mant_dig\" in floating point number declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT) {
				fprintf(ctx->efd, "[error] %s: invalid \"mant_dig\" attribute in floating point number declaration: expecting unsigned constant\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			mant_dig = right->u.unary_expression.u.unsigned_constant;

			if (!is_align_valid(alignment)) {
				fprintf(ctx->efd, "[error] %s: invalid \"mant_dig\" attribute in floating point number declaration: expecting power of two\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _FLOAT_MANT_DIG_SET);
		} else if (!strcmp(left->u.unary_expression.u.string, "align")) {
			if (_IS_SET(&set, _FLOAT_ALIGN_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"align\" in floating point number declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_UNSIGNED_CONSTANT) {
				fprintf(ctx->efd, "[error] %s: invalid \"align\" attribute in floating point number declaration: expecting unsigned constant\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			alignment = right->u.unary_expression.u.unsigned_constant;

			if (!is_align_valid(alignment)) {
				fprintf(ctx->efd, "[error] %s: invalid \"align\" attribute in floating point number declaration: expecting power of two\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			_SET(&set, _FLOAT_ALIGN_SET);
		} else {
			fprintf(ctx->efd, "[warning] %s: unknown attribute \"%s\" in floating point number declaration\n",
				__func__,
				left->u.unary_expression.u.string);
		}
	}

	if (!_IS_SET(&set, _FLOAT_MANT_DIG_SET)) {
		fprintf(ctx->efd, "[error] %s: missing \"mant_dig\" attribute in floating point number declaration\n",
			__func__);
		ret = -EPERM;
		goto error;
	}

	if (!_IS_SET(&set, _FLOAT_EXP_DIG_SET)) {
		fprintf(ctx->efd, "[error] %s: missing \"exp_dig\" attribute in floating point number declaration\n",
			__func__);
		ret = -EPERM;
		goto error;
	}

	if (!_IS_SET(&set, _INTEGER_ALIGN_SET)) {
		if ((mant_dig + exp_dig) % CHAR_BIT) {
			/* bit-packed alignment */
			alignment = 1;
		} else {
			/* byte-packed alignment */
			alignment = CHAR_BIT;
		}
	}

	*float_decl = bt_ctf_field_type_floating_point_create();

	if (!*float_decl) {
		fprintf(ctx->efd, "[error] %s: cannot create floating point number declaration\n",
			__func__);
		ret = -ENOMEM;
		goto error;
	}

	ret = bt_ctf_field_type_floating_point_set_exponent_digits(*float_decl,
		exp_dig);
	ret &= bt_ctf_field_type_floating_point_set_mantissa_digits(*float_decl,
		mant_dig);
	ret &= bt_ctf_field_type_set_byte_order(*float_decl, byte_order);
	ret &= bt_ctf_field_type_set_alignment(*float_decl, alignment);

	if (ret) {
		fprintf(ctx->efd, "[error] %s: cannot configure floating point number declaration\n",
			__func__);
		ret = -EINVAL;
		goto error;
	}

	return 0;

error:
	if (*float_decl) {
		bt_ctf_field_type_put(*float_decl);
	}

	return ret;
}

static
int visit_string_decl(struct ctx *ctx,
	struct bt_list_head *expressions,
	struct bt_ctf_field_type **string_decl)
{
	struct ctf_node *expression;
	enum ctf_string_encoding encoding = CTF_STRING_UTF8;
	int set = 0;
	int ret = 0;

	*string_decl = NULL;

	bt_list_for_each_entry(expression, expressions, siblings) {
		struct ctf_node *left, *right;

		left = _bt_list_first_entry(&expression->u.ctf_expression.left, struct ctf_node, siblings);
		right = _bt_list_first_entry(&expression->u.ctf_expression.right, struct ctf_node, siblings);

		if (left->u.unary_expression.type != UNARY_STRING) {
			ret = -EINVAL;
			goto error;
		}

		if (!strcmp(left->u.unary_expression.u.string, "encoding")) {
			if (_IS_SET(&set, _STRING_ENCODING_SET)) {
				fprintf(ctx->efd, "[error] %s: duplicate attribute \"encoding\" in string declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			if (right->u.unary_expression.type != UNARY_STRING) {
				fprintf(ctx->efd, "[error] %s: invalid \"encoding\" attribute in string declaration: expecting unary string\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			char *s_right = concatenate_unary_strings(&expression->u.ctf_expression.right);

			if (!s_right) {
				fprintf(ctx->efd, "[error] %s: unexpected unary expression for string declaration's \"encoding\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			if (!strcmp(s_right, "UTF8") ||
					!strcmp(s_right, "utf8") ||
					!strcmp(s_right, "utf-8") ||
					!strcmp(s_right, "UTF-8")) {
				encoding = CTF_STRING_UTF8;
			} else if (!strcmp(s_right, "ASCII") ||
					!strcmp(s_right, "ascii")) {
				encoding = CTF_STRING_ASCII;
			} else if (!strcmp(s_right, "none")) {
				encoding = CTF_STRING_NONE;
			} else {
				fprintf(ctx->efd, "[error] %s: invalid \"encoding\" attribute in string declaration: unknown encoding \"%s\"\n",
					__func__, s_right);
				g_free(s_right);
				ret = -EINVAL;
				goto error;
			}

			g_free(s_right);
			_SET(&set, _STRING_ENCODING_SET);
		} else {
			fprintf(ctx->efd, "[warning] %s: unknown attribute \"%s\" in string declaration\n",
				__func__,
				left->u.unary_expression.u.string);
		}
	}

	*string_decl = bt_ctf_field_type_floating_point_create();

	if (!*string_decl) {
		fprintf(ctx->efd, "[error] %s: cannot create string declaration\n",
			__func__);
		ret = -ENOMEM;
		goto error;
	}

	ret = bt_ctf_field_type_string_set_encoding(*string_decl, encoding);

	if (ret) {
		fprintf(ctx->efd, "[error] %s: cannot configure string declaration\n",
			__func__);
		ret = -EINVAL;
		goto error;
	}

	return 0;

error:
	if (*string_decl) {
		bt_ctf_field_type_put(*string_decl);
	}

	return ret;
}

static
int visit_type_specifier_list(struct ctx *ctx,
		struct ctf_node *ts_list,
		struct bt_ctf_field_type **decl)
{
	int ret = 0;
	struct ctf_node *first, *node;

	*decl = NULL;

	if (ts_list->type != NODE_TYPE_SPECIFIER_LIST) {
		ret = -EINVAL;
		goto error;
	}

	first = _bt_list_first_entry(&ts_list->u.type_specifier_list.head,
		struct ctf_node, siblings);

	if (first->type != NODE_TYPE_SPECIFIER) {
		ret = -EINVAL;
		goto error;
	}

	node = first->u.type_specifier.node;

	switch (first->u.type_specifier.type) {
	case TYPESPEC_INTEGER:
		return visit_integer_decl(ctx, &node->u.integer.expressions,
			decl);
	case TYPESPEC_FLOATING_POINT:
		return visit_floating_point_decl(ctx,
			&node->u.floating_point.expressions, decl);
	case TYPESPEC_STRING:
		return visit_string_decl(ctx,
			&node->u.string.expressions, decl);

#if 0
	case TYPESPEC_STRUCT:
		return ctf_declaration_struct_visit(fd, depth,
			node->u._struct.name,
			&node->u._struct.declaration_list,
			node->u._struct.has_body,
			&node->u._struct.min_align,
			declaration_scope,
			trace);
	case TYPESPEC_VARIANT:
		return ctf_declaration_variant_visit(fd, depth,
			node->u.variant.name,
			node->u.variant.choice,
			&node->u.variant.declaration_list,
			node->u.variant.has_body,
			declaration_scope,
			trace);
	case TYPESPEC_ENUM:
		return ctf_declaration_enum_visit(fd, depth,
			node->u._enum.enum_id,
			node->u._enum.container_type,
			&node->u._enum.enumerator_list,
			node->u._enum.has_body,
			declaration_scope,
			trace);
#endif

	case TYPESPEC_VOID:
	case TYPESPEC_CHAR:
	case TYPESPEC_SHORT:
	case TYPESPEC_INT:
	case TYPESPEC_LONG:
	case TYPESPEC_FLOAT:
	case TYPESPEC_DOUBLE:
	case TYPESPEC_SIGNED:
	case TYPESPEC_UNSIGNED:
	case TYPESPEC_BOOL:
	case TYPESPEC_COMPLEX:
	case TYPESPEC_IMAGINARY:
	case TYPESPEC_CONST:
	case TYPESPEC_ID_TYPE:
#if 0
		return ctf_declaration_type_specifier_visit(fd, depth,
			ts_list, declaration_scope);
#endif
	default:
		fprintf(ctx->efd, "[error] %s: unexpected node type: %d\n",
			__func__, (int) first->u.type_specifier.type);
		ret = -EINVAL;
		goto error;
	}

	return 0;

error:
	if (*decl) {
		bt_ctf_field_type_put(*decl);
	}

	return ret;
}

#if 0
static
int ctf_event_declaration_visit(FILE *fd, int depth, struct ctf_node *node, struct ctf_event_declaration *event, struct ctf_trace *trace)
{
	int ret = 0;

	switch (node->type) {
	case NODE_TYPEDEF:
		ret = ctf_typedef_visit(fd, depth + 1,
					event->declaration_scope,
					node->u._typedef.type_specifier_list,
					&node->u._typedef.type_declarators,
					trace);
		if (ret)
			return ret;
		break;
	case NODE_TYPEALIAS:
		ret = ctf_typealias_visit(fd, depth + 1,
				event->declaration_scope,
				node->u.typealias.target, node->u.typealias.alias,
				trace);
		if (ret)
			return ret;
		break;
	case NODE_CTF_EXPRESSION:
	{
		char *left;

		left = concatenate_unary_strings(&node->u.ctf_expression.left);
		if (!left)
			return -EINVAL;
		if (!strcmp(left, "name")) {
			char *right;

			if (CTF_EVENT_FIELD_IS_SET(event, name)) {
				fprintf(fd, "[error] %s: name already declared in event declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[error] %s: unexpected unary expression for event name\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			event->name = g_quark_from_string(right);
			g_free(right);
			CTF_EVENT_SET_FIELD(event, name);
		} else if (!strcmp(left, "id")) {
			if (CTF_EVENT_FIELD_IS_SET(event, id)) {
				fprintf(fd, "[error] %s: id already declared in event declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &event->id);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for event id\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			CTF_EVENT_SET_FIELD(event, id);
		} else if (!strcmp(left, "stream_id")) {
			if (CTF_EVENT_FIELD_IS_SET(event, stream_id)) {
				fprintf(fd, "[error] %s: stream_id already declared in event declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &event->stream_id);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for event stream_id\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			event->stream = trace_stream_lookup(trace, event->stream_id);
			if (!event->stream) {
				fprintf(fd, "[error] %s: stream id %" PRIu64 " cannot be found\n", __func__, event->stream_id);
				ret = -EINVAL;
				goto error;
			}
			CTF_EVENT_SET_FIELD(event, stream_id);
		} else if (!strcmp(left, "context")) {
			struct bt_declaration *declaration;

			if (event->context_decl) {
				fprintf(fd, "[error] %s: context already declared in event declaration\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			declaration = ctf_type_specifier_list_visit(fd, depth,
					_bt_list_first_entry(&node->u.ctf_expression.right,
						struct ctf_node, siblings),
					event->declaration_scope, trace);
			if (!declaration) {
				ret = -EPERM;
				goto error;
			}
			if (declaration->id != CTF_TYPE_STRUCT) {
				ret = -EPERM;
				goto error;
			}
			event->context_decl = container_of(declaration, struct declaration_struct, p);
		} else if (!strcmp(left, "fields")) {
			struct bt_declaration *declaration;

			if (event->fields_decl) {
				fprintf(fd, "[error] %s: fields already declared in event declaration\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			declaration = ctf_type_specifier_list_visit(fd, depth,
					_bt_list_first_entry(&node->u.ctf_expression.right,
						struct ctf_node, siblings),
					event->declaration_scope, trace);
			if (!declaration) {
				ret = -EPERM;
				goto error;
			}
			if (declaration->id != CTF_TYPE_STRUCT) {
				ret = -EPERM;
				goto error;
			}
			event->fields_decl = container_of(declaration, struct declaration_struct, p);
		} else if (!strcmp(left, "loglevel")) {
			int64_t loglevel = -1;

			if (CTF_EVENT_FIELD_IS_SET(event, loglevel)) {
				fprintf(fd, "[error] %s: loglevel already declared in event declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_signed(&node->u.ctf_expression.right, &loglevel);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for event loglevel\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			event->loglevel = (int) loglevel;
			CTF_EVENT_SET_FIELD(event, loglevel);
		} else if (!strcmp(left, "model.emf.uri")) {
			char *right;

			if (CTF_EVENT_FIELD_IS_SET(event, model_emf_uri)) {
				fprintf(fd, "[error] %s: model.emf.uri already declared in event declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[error] %s: unexpected unary expression for event model.emf.uri\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			event->model_emf_uri = g_quark_from_string(right);
			g_free(right);
			CTF_EVENT_SET_FIELD(event, model_emf_uri);
		} else {
			fprintf(fd, "[warning] %s: attribute \"%s\" is unknown in event declaration.\n", __func__, left);
			/* Fall-through after warning */
		}
error:
		g_free(left);
		break;
	}
	default:
		return -EPERM;
	/* TODO: declaration specifier should be added. */
	}

	return ret;
}

static
int ctf_event_visit(FILE *fd, int depth, struct ctf_node *node,
		    struct declaration_scope *parent_declaration_scope, struct ctf_trace *trace)
{
	int ret = 0;
	struct ctf_node *iter;
	struct ctf_event_declaration *event;
	struct bt_ctf_event_decl *event_decl;

	if (node->visited)
		return 0;
	node->visited = 1;

	event_decl = g_new0(struct bt_ctf_event_decl, 1);
	event = &event_decl->parent;
	event->declaration_scope = bt_new_declaration_scope(parent_declaration_scope);
	event->loglevel = -1;
	bt_list_for_each_entry(iter, &node->u.event.declaration_list, siblings) {
		ret = ctf_event_declaration_visit(fd, depth + 1, iter, event, trace);
		if (ret)
			goto error;
	}
	if (!CTF_EVENT_FIELD_IS_SET(event, name)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing name field in event declaration\n", __func__);
		goto error;
	}
	if (!CTF_EVENT_FIELD_IS_SET(event, stream_id)) {
		/* Allow missing stream_id if there is only a single stream */
		switch (trace->streams->len) {
		case 0:	/* Create stream if there was none. */
			ret = ctf_stream_visit(fd, depth, NULL, trace->root_declaration_scope, trace);
			if (ret)
				goto error;
			/* Fall-through */
		case 1:
			event->stream_id = 0;
			event->stream = trace_stream_lookup(trace, event->stream_id);
			break;
		default:
			ret = -EPERM;
			fprintf(fd, "[error] %s: missing stream_id field in event declaration\n", __func__);
			goto error;
		}
	}
	/* Allow only one event without id per stream */
	if (!CTF_EVENT_FIELD_IS_SET(event, id)
	    && event->stream->events_by_id->len != 0) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing id field in event declaration\n", __func__);
		goto error;
	}
	/* Disallow re-using the same event ID in the same stream */
	if (stream_event_lookup(event->stream, event->id)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: event ID %" PRIu64 " used more than once in stream %" PRIu64 "\n",
			__func__, event->id, event->stream_id);
		goto error;
	}
	if (event->stream->events_by_id->len <= event->id)
		g_ptr_array_set_size(event->stream->events_by_id, event->id + 1);
	g_ptr_array_index(event->stream->events_by_id, event->id) = event;
	g_hash_table_insert(event->stream->event_quark_to_id,
			    (gpointer) (unsigned long) event->name,
			    &event->id);
	g_ptr_array_add(trace->event_declarations, event_decl);
	return 0;

error:
	if (event->fields_decl)
		bt_declaration_unref(&event->fields_decl->p);
	if (event->context_decl)
		bt_declaration_unref(&event->context_decl->p);
	bt_free_declaration_scope(event->declaration_scope);
	g_free(event_decl);
	return ret;
}


static
int ctf_stream_declaration_visit(FILE *fd, int depth, struct ctf_node *node, struct ctf_stream_declaration *stream, struct ctf_trace *trace)
{
	int ret = 0;

	switch (node->type) {
	case NODE_TYPEDEF:
		ret = ctf_typedef_visit(fd, depth + 1,
					stream->declaration_scope,
					node->u._typedef.type_specifier_list,
					&node->u._typedef.type_declarators,
					trace);
		if (ret)
			return ret;
		break;
	case NODE_TYPEALIAS:
		ret = ctf_typealias_visit(fd, depth + 1,
				stream->declaration_scope,
				node->u.typealias.target, node->u.typealias.alias,
				trace);
		if (ret)
			return ret;
		break;
	case NODE_CTF_EXPRESSION:
	{
		char *left;

		left = concatenate_unary_strings(&node->u.ctf_expression.left);
		if (!left)
			return -EINVAL;
		if (!strcmp(left, "id")) {
			if (CTF_STREAM_FIELD_IS_SET(stream, stream_id)) {
				fprintf(fd, "[error] %s: id already declared in stream declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &stream->stream_id);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for stream id\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			CTF_STREAM_SET_FIELD(stream, stream_id);
		} else if (!strcmp(left, "event.header")) {
			struct bt_declaration *declaration;

			if (stream->event_header_decl) {
				fprintf(fd, "[error] %s: event.header already declared in stream declaration\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			declaration = ctf_type_specifier_list_visit(fd, depth,
					_bt_list_first_entry(&node->u.ctf_expression.right,
						struct ctf_node, siblings),
					stream->declaration_scope, trace);
			if (!declaration) {
				ret = -EPERM;
				goto error;
			}
			if (declaration->id != CTF_TYPE_STRUCT) {
				ret = -EPERM;
				goto error;
			}
			stream->event_header_decl = container_of(declaration, struct declaration_struct, p);
		} else if (!strcmp(left, "event.context")) {
			struct bt_declaration *declaration;

			if (stream->event_context_decl) {
				fprintf(fd, "[error] %s: event.context already declared in stream declaration\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			declaration = ctf_type_specifier_list_visit(fd, depth,
					_bt_list_first_entry(&node->u.ctf_expression.right,
						struct ctf_node, siblings),
					stream->declaration_scope, trace);
			if (!declaration) {
				ret = -EPERM;
				goto error;
			}
			if (declaration->id != CTF_TYPE_STRUCT) {
				ret = -EPERM;
				goto error;
			}
			stream->event_context_decl = container_of(declaration, struct declaration_struct, p);
		} else if (!strcmp(left, "packet.context")) {
			struct bt_declaration *declaration;

			if (stream->packet_context_decl) {
				fprintf(fd, "[error] %s: packet.context already declared in stream declaration\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			declaration = ctf_type_specifier_list_visit(fd, depth,
					_bt_list_first_entry(&node->u.ctf_expression.right,
						struct ctf_node, siblings),
					stream->declaration_scope, trace);
			if (!declaration) {
				ret = -EPERM;
				goto error;
			}
			if (declaration->id != CTF_TYPE_STRUCT) {
				ret = -EPERM;
				goto error;
			}
			stream->packet_context_decl = container_of(declaration, struct declaration_struct, p);
		} else {
			fprintf(fd, "[warning] %s: attribute \"%s\" is unknown in stream declaration.\n", __func__, left);
			/* Fall-through after warning */
		}

error:
		g_free(left);
		break;
	}
	default:
		return -EPERM;
	/* TODO: declaration specifier should be added. */
	}

	return ret;
}

static
int ctf_stream_visit(FILE *fd, int depth, struct ctf_node *node,
		     struct declaration_scope *parent_declaration_scope, struct ctf_trace *trace)
{
	int ret = 0;
	struct ctf_node *iter;
	struct ctf_stream_declaration *stream;

	if (node) {
		if (node->visited)
			return 0;
		node->visited = 1;
	}

	stream = g_new0(struct ctf_stream_declaration, 1);
	stream->declaration_scope = bt_new_declaration_scope(parent_declaration_scope);
	stream->events_by_id = g_ptr_array_new();
	stream->event_quark_to_id = g_hash_table_new(g_direct_hash, g_direct_equal);
	stream->streams = g_ptr_array_new();
	if (node) {
		bt_list_for_each_entry(iter, &node->u.stream.declaration_list, siblings) {
			ret = ctf_stream_declaration_visit(fd, depth + 1, iter, stream, trace);
			if (ret)
				goto error;
		}
	}
	if (CTF_STREAM_FIELD_IS_SET(stream, stream_id)) {
		/* check that packet header has stream_id field. */
		if (!trace->packet_header_decl
		    || bt_struct_declaration_lookup_field_index(trace->packet_header_decl, g_quark_from_static_string("stream_id")) < 0) {
			ret = -EPERM;
			fprintf(fd, "[error] %s: missing stream_id field in packet header declaration, but stream_id attribute is declared for stream.\n", __func__);
			goto error;
		}
	} else {
		/* Allow only one id-less stream */
		if (trace->streams->len != 0) {
			ret = -EPERM;
			fprintf(fd, "[error] %s: missing id field in stream declaration\n", __func__);
			goto error;
		}
		stream->stream_id = 0;
	}
	if (trace->streams->len <= stream->stream_id)
		g_ptr_array_set_size(trace->streams, stream->stream_id + 1);
	g_ptr_array_index(trace->streams, stream->stream_id) = stream;
	stream->trace = trace;

	return 0;

error:
	if (stream->event_header_decl)
		bt_declaration_unref(&stream->event_header_decl->p);
	if (stream->event_context_decl)
		bt_declaration_unref(&stream->event_context_decl->p);
	if (stream->packet_context_decl)
		bt_declaration_unref(&stream->packet_context_decl->p);
	g_ptr_array_free(stream->streams, TRUE);
	g_ptr_array_free(stream->events_by_id, TRUE);
	g_hash_table_destroy(stream->event_quark_to_id);
	bt_free_declaration_scope(stream->declaration_scope);
	g_free(stream);
	return ret;
}

static
int ctf_trace_declaration_visit(FILE *fd, int depth, struct ctf_node *node, struct ctf_trace *trace)
{
	int ret = 0;

	switch (node->type) {
	case NODE_TYPEDEF:
		ret = ctf_typedef_visit(fd, depth + 1,
					trace->declaration_scope,
					node->u._typedef.type_specifier_list,
					&node->u._typedef.type_declarators,
					trace);
		if (ret)
			return ret;
		break;
	case NODE_TYPEALIAS:
		ret = ctf_typealias_visit(fd, depth + 1,
				trace->declaration_scope,
				node->u.typealias.target, node->u.typealias.alias,
				trace);
		if (ret)
			return ret;
		break;
	case NODE_CTF_EXPRESSION:
	{
		char *left;

		left = concatenate_unary_strings(&node->u.ctf_expression.left);
		if (!left)
			return -EINVAL;
		if (!strcmp(left, "major")) {
			if (CTF_TRACE_FIELD_IS_SET(trace, major)) {
				fprintf(fd, "[error] %s: major already declared in trace declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &trace->major);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for trace major number\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			CTF_TRACE_SET_FIELD(trace, major);
		} else if (!strcmp(left, "minor")) {
			if (CTF_TRACE_FIELD_IS_SET(trace, minor)) {
				fprintf(fd, "[error] %s: minor already declared in trace declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &trace->minor);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for trace minor number\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			CTF_TRACE_SET_FIELD(trace, minor);
		} else if (!strcmp(left, "uuid")) {
			unsigned char uuid[BABELTRACE_UUID_LEN];

			ret = get_unary_uuid(&node->u.ctf_expression.right, uuid);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for trace uuid\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			if (CTF_TRACE_FIELD_IS_SET(trace, uuid)
				&& babeltrace_uuid_compare(uuid, trace->uuid)) {
				fprintf(fd, "[error] %s: uuid mismatch\n", __func__);
				ret = -EPERM;
				goto error;
			} else {
				memcpy(trace->uuid, uuid, sizeof(uuid));
			}
			CTF_TRACE_SET_FIELD(trace, uuid);
		} else if (!strcmp(left, "byte_order")) {
			struct ctf_node *right;
			int byte_order;

			right = _bt_list_first_entry(&node->u.ctf_expression.right, struct ctf_node, siblings);
			byte_order = get_trace_byte_order(fd, depth, right);
			if (byte_order < 0) {
				ret = -EINVAL;
				goto error;
			}

			if (CTF_TRACE_FIELD_IS_SET(trace, byte_order)
				&& byte_order != trace->byte_order) {
				fprintf(fd, "[error] %s: endianness mismatch\n", __func__);
				ret = -EPERM;
				goto error;
			} else {
				if (byte_order != trace->byte_order) {
					trace->byte_order = byte_order;
					/*
					 * We need to restart
					 * construction of the
					 * intermediate representation.
					 */
					trace->field_mask = 0;
					CTF_TRACE_SET_FIELD(trace, byte_order);
					ret = -EINTR;
					goto error;
				}
			}
			CTF_TRACE_SET_FIELD(trace, byte_order);
		} else if (!strcmp(left, "packet.header")) {
			struct bt_declaration *declaration;

			if (trace->packet_header_decl) {
				fprintf(fd, "[error] %s: packet.header already declared in trace declaration\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			declaration = ctf_type_specifier_list_visit(fd, depth,
					_bt_list_first_entry(&node->u.ctf_expression.right,
						struct ctf_node, siblings),
					trace->declaration_scope, trace);
			if (!declaration) {
				ret = -EPERM;
				goto error;
			}
			if (declaration->id != CTF_TYPE_STRUCT) {
				ret = -EPERM;
				goto error;
			}
			trace->packet_header_decl = container_of(declaration, struct declaration_struct, p);
		} else {
			fprintf(fd, "[warning] %s: attribute \"%s\" is unknown in trace declaration.\n", __func__, left);
		}

error:
		g_free(left);
		break;
	}
	default:
		return -EPERM;
	/* TODO: declaration specifier should be added. */
	}

	return ret;
}

static
int ctf_trace_visit(FILE *fd, int depth, struct ctf_node *node, struct ctf_trace *trace)
{
	int ret = 0;
	struct ctf_node *iter;

	if (!trace->restart_root_decl && node->visited)
		return 0;
	node->visited = 1;

	if (trace->declaration_scope)
		return -EEXIST;

	trace->declaration_scope = bt_new_declaration_scope(trace->root_declaration_scope);
	trace->streams = g_ptr_array_new();
	trace->event_declarations = g_ptr_array_new();
	bt_list_for_each_entry(iter, &node->u.trace.declaration_list, siblings) {
		ret = ctf_trace_declaration_visit(fd, depth + 1, iter, trace);
		if (ret)
			goto error;
	}
	if (!CTF_TRACE_FIELD_IS_SET(trace, major)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing major field in trace declaration\n", __func__);
		goto error;
	}
	if (!CTF_TRACE_FIELD_IS_SET(trace, minor)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing minor field in trace declaration\n", __func__);
		goto error;
	}
	if (!CTF_TRACE_FIELD_IS_SET(trace, byte_order)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing byte_order field in trace declaration\n", __func__);
		goto error;
	}

	if (!CTF_TRACE_FIELD_IS_SET(trace, byte_order)) {
		/* check that the packet header contains a "magic" field */
		if (!trace->packet_header_decl
		    || bt_struct_declaration_lookup_field_index(trace->packet_header_decl, g_quark_from_static_string("magic")) < 0) {
			ret = -EPERM;
			fprintf(fd, "[error] %s: missing both byte_order and packet header magic number in trace declaration\n", __func__);
			goto error;
		}
	}
	return 0;

error:
	if (trace->packet_header_decl) {
		bt_declaration_unref(&trace->packet_header_decl->p);
		trace->packet_header_decl = NULL;
	}
	g_ptr_array_free(trace->streams, TRUE);
	g_ptr_array_free(trace->event_declarations, TRUE);
	bt_free_declaration_scope(trace->declaration_scope);
	trace->declaration_scope = NULL;
	return ret;
}


static
int ctf_callsite_declaration_visit(FILE *fd, int depth, struct ctf_node *node,
		struct ctf_callsite *callsite, struct ctf_trace *trace)
{
	int ret = 0;

	switch (node->type) {
	case NODE_CTF_EXPRESSION:
	{
		char *left;

		left = concatenate_unary_strings(&node->u.ctf_expression.left);
		if (!left)
			return -EINVAL;
		if (!strcmp(left, "name")) {
			char *right;

			if (CTF_CALLSITE_FIELD_IS_SET(callsite, name)) {
				fprintf(fd, "[error] %s: name already declared in callsite declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[error] %s: unexpected unary expression for callsite name\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			callsite->name = g_quark_from_string(right);
			g_free(right);
			CTF_CALLSITE_SET_FIELD(callsite, name);
		} else if (!strcmp(left, "func")) {
			char *right;

			if (CTF_CALLSITE_FIELD_IS_SET(callsite, func)) {
				fprintf(fd, "[error] %s: func already declared in callsite declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[error] %s: unexpected unary expression for callsite func\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			callsite->func = right;
			CTF_CALLSITE_SET_FIELD(callsite, func);
		} else if (!strcmp(left, "file")) {
			char *right;

			if (CTF_CALLSITE_FIELD_IS_SET(callsite, file)) {
				fprintf(fd, "[error] %s: file already declared in callsite declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[error] %s: unexpected unary expression for callsite file\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			callsite->file = right;
			CTF_CALLSITE_SET_FIELD(callsite, file);
		} else if (!strcmp(left, "line")) {
			if (CTF_CALLSITE_FIELD_IS_SET(callsite, line)) {
				fprintf(fd, "[error] %s: line already declared in callsite declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &callsite->line);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for callsite line\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			CTF_CALLSITE_SET_FIELD(callsite, line);
		} else if (!strcmp(left, "ip")) {
			if (CTF_CALLSITE_FIELD_IS_SET(callsite, ip)) {
				fprintf(fd, "[error] %s: ip already declared in callsite declaration\n", __func__);
				ret = -EPERM;
				goto error;
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &callsite->ip);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for callsite ip\n", __func__);
				ret = -EINVAL;
				goto error;
			}
			CTF_CALLSITE_SET_FIELD(callsite, ip);
		} else {
			fprintf(fd, "[warning] %s: attribute \"%s\" is unknown in callsite declaration.\n", __func__, left);
		}

error:
		g_free(left);
		break;
	}
	default:
		return -EPERM;
	/* TODO: declaration specifier should be added. */
	}

	return ret;
}

static
int ctf_callsite_visit(FILE *fd, int depth, struct ctf_node *node, struct ctf_trace *trace)
{
	int ret = 0;
	struct ctf_node *iter;
	struct ctf_callsite *callsite;
	struct ctf_callsite_dups *cs_dups;

	if (node->visited)
		return 0;
	node->visited = 1;

	callsite = g_new0(struct ctf_callsite, 1);
	bt_list_for_each_entry(iter, &node->u.callsite.declaration_list, siblings) {
		ret = ctf_callsite_declaration_visit(fd, depth + 1, iter, callsite, trace);
		if (ret)
			goto error;
	}
	if (!CTF_CALLSITE_FIELD_IS_SET(callsite, name)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing name field in callsite declaration\n", __func__);
		goto error;
	}
	if (!CTF_CALLSITE_FIELD_IS_SET(callsite, func)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing func field in callsite declaration\n", __func__);
		goto error;
	}
	if (!CTF_CALLSITE_FIELD_IS_SET(callsite, file)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing file field in callsite declaration\n", __func__);
		goto error;
	}
	if (!CTF_CALLSITE_FIELD_IS_SET(callsite, line)) {
		ret = -EPERM;
		fprintf(fd, "[error] %s: missing line field in callsite declaration\n", __func__);
		goto error;
	}

	cs_dups = g_hash_table_lookup(trace->callsites,
		(gpointer) (unsigned long) callsite->name);
	if (!cs_dups) {
		cs_dups = g_new0(struct ctf_callsite_dups, 1);
		BT_INIT_LIST_HEAD(&cs_dups->head);
		g_hash_table_insert(trace->callsites,
			(gpointer) (unsigned long) callsite->name, cs_dups);
	}
	bt_list_add_tail(&callsite->node, &cs_dups->head);
	return 0;

error:
	g_free(callsite->func);
	g_free(callsite->file);
	g_free(callsite);
	return ret;
}

static
void callsite_free(gpointer data)
{
	struct ctf_callsite_dups *cs_dups = data;
	struct ctf_callsite *callsite, *cs_n;

	bt_list_for_each_entry_safe(callsite, cs_n, &cs_dups->head, node) {
		g_free(callsite->func);
		g_free(callsite->file);
		g_free(callsite);
	}
	g_free(cs_dups);
}

static
int ctf_env_declaration_visit(FILE *fd, int depth, struct ctf_node *node,
		struct ctf_trace *trace)
{
	int ret = 0;
	struct ctf_tracer_env *env = &trace->env;

	switch (node->type) {
	case NODE_CTF_EXPRESSION:
	{
		char *left;

		left = concatenate_unary_strings(&node->u.ctf_expression.left);
		if (!left)
			return -EINVAL;
		if (!strcmp(left, "vpid")) {
			uint64_t v;

			if (env->vpid != -1) {
				fprintf(fd, "[error] %s: vpid already declared in env declaration\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			ret = get_unary_unsigned(&node->u.ctf_expression.right, &v);
			if (ret) {
				fprintf(fd, "[error] %s: unexpected unary expression for env vpid\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			env->vpid = (int) v;
			printf_verbose("env.vpid = %d\n", env->vpid);
		} else if (!strcmp(left, "procname")) {
			char *right;

			if (env->procname[0]) {
				fprintf(fd, "[warning] %s: duplicated env procname\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[warning] %s: unexpected unary expression for env procname\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			strncpy(env->procname, right, TRACER_ENV_LEN);
			env->procname[TRACER_ENV_LEN - 1] = '\0';
			printf_verbose("env.procname = \"%s\"\n", env->procname);
			g_free(right);
		} else if (!strcmp(left, "hostname")) {
			char *right;

			if (env->hostname[0]) {
				fprintf(fd, "[warning] %s: duplicated env hostname\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[warning] %s: unexpected unary expression for env hostname\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			strncpy(env->hostname, right, TRACER_ENV_LEN);
			env->hostname[TRACER_ENV_LEN - 1] = '\0';
			printf_verbose("env.hostname = \"%s\"\n", env->hostname);
			g_free(right);
		} else if (!strcmp(left, "domain")) {
			char *right;

			if (env->domain[0]) {
				fprintf(fd, "[warning] %s: duplicated env domain\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[warning] %s: unexpected unary expression for env domain\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			strncpy(env->domain, right, TRACER_ENV_LEN);
			env->domain[TRACER_ENV_LEN - 1] = '\0';
			printf_verbose("env.domain = \"%s\"\n", env->domain);
			g_free(right);
		} else if (!strcmp(left, "sysname")) {
			char *right;

			if (env->sysname[0]) {
				fprintf(fd, "[warning] %s: duplicated env sysname\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[warning] %s: unexpected unary expression for env sysname\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			strncpy(env->sysname, right, TRACER_ENV_LEN);
			env->sysname[TRACER_ENV_LEN - 1] = '\0';
			printf_verbose("env.sysname = \"%s\"\n", env->sysname);
			g_free(right);
		} else if (!strcmp(left, "kernel_release")) {
			char *right;

			if (env->release[0]) {
				fprintf(fd, "[warning] %s: duplicated env release\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[warning] %s: unexpected unary expression for env release\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			strncpy(env->release, right, TRACER_ENV_LEN);
			env->release[TRACER_ENV_LEN - 1] = '\0';
			printf_verbose("env.release = \"%s\"\n", env->release);
			g_free(right);
		} else if (!strcmp(left, "kernel_version")) {
			char *right;

			if (env->version[0]) {
				fprintf(fd, "[warning] %s: duplicated env version\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			right = concatenate_unary_strings(&node->u.ctf_expression.right);
			if (!right) {
				fprintf(fd, "[warning] %s: unexpected unary expression for env version\n", __func__);
				goto error;	/* ret is 0, so not an actual error, just warn. */
			}
			strncpy(env->version, right, TRACER_ENV_LEN);
			env->version[TRACER_ENV_LEN - 1] = '\0';
			printf_verbose("env.version = \"%s\"\n", env->version);
			g_free(right);
		} else {
			if (is_unary_string(&node->u.ctf_expression.right)) {
				char *right;

				right = concatenate_unary_strings(&node->u.ctf_expression.right);
				if (!right) {
					fprintf(fd, "[warning] %s: unexpected unary expression for env\n", __func__);
					ret = -EINVAL;
					goto error;
				}
				printf_verbose("env.%s = \"%s\"\n", left, right);
				g_free(right);
			} else if (is_unary_unsigned(&node->u.ctf_expression.right)) {
				uint64_t v;
				int ret;

				ret = get_unary_unsigned(&node->u.ctf_expression.right, &v);
				if (ret)
					goto error;
				printf_verbose("env.%s = %" PRIu64 "\n", left, v);
			} else if (is_unary_signed(&node->u.ctf_expression.right)) {
				int64_t v;
				int ret;

				ret = get_unary_signed(&node->u.ctf_expression.right, &v);
				if (ret)
					goto error;
				printf_verbose("env.%s = %" PRId64 "\n", left, v);
			} else {
				printf_verbose("%s: attribute \"%s\" has unknown type.\n", __func__, left);
			}
		}

error:
		g_free(left);
		break;
	}
	default:
		return -EPERM;
	}

	return ret;
}

static
int ctf_env_visit(FILE *fd, int depth, struct ctf_node *node, struct ctf_trace *trace)
{
	int ret = 0;
	struct ctf_node *iter;

	if (node->visited)
		return 0;
	node->visited = 1;

	trace->env.vpid = -1;
	trace->env.procname[0] = '\0';
	trace->env.hostname[0] = '\0';
	trace->env.domain[0] = '\0';
	trace->env.sysname[0] = '\0';
	trace->env.release[0] = '\0';
	trace->env.version[0] = '\0';
	bt_list_for_each_entry(iter, &node->u.env.declaration_list, siblings) {
		ret = ctf_env_declaration_visit(fd, depth + 1, iter, trace);
		if (ret)
			goto error;
	}
error:
	return 0;
}
#endif

static
int set_trace_byte_order(struct ctx *ctx, struct ctf_node *trace_node)
{
	struct ctf_node *node;
	int got_byte_order = 0;
	int ret = 0;

	bt_list_for_each_entry(node, &trace_node->u.trace.declaration_list, siblings) {
		if (node->type == NODE_CTF_EXPRESSION) {
			char *left = concatenate_unary_strings(&node->u.ctf_expression.left);
			struct ctf_node *right_node;

			if (!left) {
				return -EINVAL;
			}

			if (!strcmp(left, "byte_order")) {
				if (got_byte_order) {
					fprintf(ctx->efd, "[error] %s: duplicate \"byte_order\" attribute in trace declaration\n",
						__func__);
					ret = -EPERM;
					goto error;
				}

				got_byte_order = 1;

				enum bt_ctf_byte_order bo;

				right_node = _bt_list_first_entry(&node->u.ctf_expression.right, struct ctf_node, siblings);
				bo = byte_order_from_unary_expr(ctx->efd, right_node);

				if (bo == BT_CTF_BYTE_ORDER_UNKNOWN) {
					fprintf(ctx->efd, "[error] %s: unknown \"byte_order\" attribute in trace declaration\n",
						__func__);
					ret = -EINVAL;
					goto error;
				} else if (bo == BT_CTF_BYTE_ORDER_NATIVE) {
					fprintf(ctx->efd, "[error] %s: \"byte_order\" attribute cannot be set to \"native\" in trace declaration\n",
						__func__);
					ret = -EPERM;
					goto error;
				}

				ret = bt_ctf_trace_set_byte_order(ctx->trace, bo);

				if (ret) {
					fprintf(ctx->efd, "[error] %s: cannot set trace's byte order (%d)\n",
						__func__, ret);
					goto error;
				}
			}

error:
			g_free(left);

			if (ret) {
				return ret;
			}
		}
	}

	if (!got_byte_order) {
		fprintf(ctx->efd, "[error] %s: missing \"byte_order\" attribute in trace declaration\n",
			__func__);
		return -EINVAL;
	}

	return ret;
}

static
int visit_clock_attr(FILE *efd, struct ctf_node *entry_node,
		struct bt_ctf_clock *clock, int* set)
{
	int ret = 0;

	switch (entry_node->type) {
	case NODE_CTF_EXPRESSION:
	{
		char *left;

		left = concatenate_unary_strings(&entry_node->u.ctf_expression.left);

		if (!left) {
			return -EINVAL;
		}

		if (!strcmp(left, "name")) {
			char *right;

			if (_IS_SET(set, _CLOCK_NAME_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"name\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			right = concatenate_unary_strings(&entry_node->u.ctf_expression.right);

			if (!right) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"name\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			ret = bt_ctf_clock_set_name(clock, right);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's name\n",
					__func__);
				g_free(right);
				goto error;
			}

			g_free(right);

			_SET(set, _CLOCK_NAME_SET);
		} else if (!strcmp(left, "uuid")) {
			char *right;

			if (_IS_SET(set, _CLOCK_UUID_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"uuid\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			right = concatenate_unary_strings(&entry_node->u.ctf_expression.right);

			if (!right) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"uuid\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			unsigned char uuid[BABELTRACE_UUID_LEN];

			ret = babeltrace_uuid_parse(right, uuid);

			if (ret) {
				fprintf(efd, "[error] %s: invalid clock UUID\n",
					__func__);
				g_free(right);
				goto error;
			}

			ret = bt_ctf_clock_set_uuid(clock, uuid);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's UUID\n",
					__func__);
				g_free(right);
				goto error;
			}

			g_free(right);

			_SET(set, _CLOCK_UUID_SET);
		} else if (!strcmp(left, "description")) {
			char *right;

			if (_IS_SET(set, _CLOCK_DESCRIPTION_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"description\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			right = concatenate_unary_strings(&entry_node->u.ctf_expression.right);

			if (!right) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"description\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			ret = bt_ctf_clock_set_description(clock, right);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's description\n",
					__func__);
				g_free(right);
				goto error;
			}

			g_free(right);

			_SET(set, _CLOCK_DESCRIPTION_SET);
		} else if (!strcmp(left, "freq")) {
			if (_IS_SET(set, _CLOCK_FREQ_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"freq\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			uint64_t freq;

			ret = get_unary_unsigned(&entry_node->u.ctf_expression.right, &freq);

			if (ret) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"freq\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			ret = bt_ctf_clock_set_frequency(clock, freq);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's frequency\n",
					__func__);
				goto error;
			}

			_SET(set, _CLOCK_FREQ_SET);
		} else if (!strcmp(left, "precision")) {
			if (_IS_SET(set, _CLOCK_PRECISION_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"precision\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			uint64_t precision;

			ret = get_unary_unsigned(&entry_node->u.ctf_expression.right, &precision);

			if (ret) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"precision\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			ret = bt_ctf_clock_set_precision(clock, precision);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's precision\n",
					__func__);
				goto error;
			}

			_SET(set, _CLOCK_PRECISION_SET);
		} else if (!strcmp(left, "offset_s")) {
			if (_IS_SET(set, _CLOCK_OFFSET_S_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"offset_s\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			uint64_t offset_s;

			ret = get_unary_unsigned(&entry_node->u.ctf_expression.right, &offset_s);

			if (ret) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"offset_s\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			ret = bt_ctf_clock_set_offset_s(clock, offset_s);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's offset in seconds\n",
					__func__);
				goto error;
			}

			_SET(set, _CLOCK_OFFSET_S_SET);
		} else if (!strcmp(left, "offset")) {
			if (_IS_SET(set, _CLOCK_OFFSET_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"offset\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			uint64_t offset;

			ret = get_unary_unsigned(&entry_node->u.ctf_expression.right, &offset);

			if (ret) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"offset\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			ret = bt_ctf_clock_set_offset(clock, offset);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's offset in cycles\n",
					__func__);
				goto error;
			}

			_SET(set, _CLOCK_OFFSET_SET);
		} else if (!strcmp(left, "absolute")) {
			if (_IS_SET(set, _CLOCK_ABSOLUTE_SET)) {
				fprintf(efd, "[error] %s: duplicate attribute \"absolute\" in clock declaration\n",
					__func__);
				ret = -EPERM;
				goto error;
			}

			struct ctf_node *right;

			right = _bt_list_first_entry(&entry_node->u.ctf_expression.right, struct ctf_node, siblings);
			ret = get_boolean(efd, right);

			if (ret < 0) {
				fprintf(efd, "[error] %s: unexpected unary expression for clock's \"absolute\" attribute\n",
					__func__);
				ret = -EINVAL;
				goto error;
			}

			ret = bt_ctf_clock_set_is_absolute(clock, ret);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set clock's absolute option\n",
					__func__);
				goto error;
			}

			_SET(set, _CLOCK_ABSOLUTE_SET);
		} else {
			fprintf(efd, "[warning] %s: unknown attribute \"%s\" in clock declaration\n", __func__, left);
		}

error:
		g_free(left);
		break;
	}

	default:
		return -EPERM;
	}

	return ret;
}

static
int visit_clock(struct ctx *ctx, struct ctf_node *clock_node)
{
	int ret = 0;
	struct ctf_node *entry_node;

	if (clock_node->visited) {
		return 0;
	}

	clock_node->visited = 1;

	struct bt_ctf_clock *clock = _bt_ctf_clock_create();

	if (!clock) {
		fprintf(ctx->efd, "[error] %s: cannot create clock\n", __func__);
		ret = -ENOMEM;
		goto error;
	}

	int set = 0;

	bt_list_for_each_entry(entry_node, &clock_node->u.clock.declaration_list, siblings) {
		ret = visit_clock_attr(ctx->efd, entry_node, clock, &set);

		if (ret) {
			goto error;
		}
	}

#if 0
	if (opt_clock_force_correlate) {
		/*
		 * User requested to forcibly correlate the clock
		 * sources, even if we have no correlation
		 * information.
		 */
		if (!clock->absolute) {
			fprintf(fd, "[warning] Forcibly correlating trace clock sources (--clock-force-correlate).\n");
		}
		clock->absolute = 1;
	}
#endif

	if (!_IS_SET(&set, _CLOCK_NAME_SET)) {
		ret = -EPERM;
		fprintf(ctx->efd, "[error] %s: missing \"name\" attribute in clock declaration\n", __func__);
		goto error;
	}

	if (bt_ctf_trace_get_clock_count(ctx->trace) != 0) {
		fprintf(ctx->efd, "[error] Only CTF traces with a single clock declaration are supported by this Babeltrace version\n");
		ret = -EINVAL;
		goto error;
	}

	ret = bt_ctf_trace_add_clock(ctx->trace, clock);

	if (ret) {
		fprintf(ctx->efd, "[error] %s: cannot add clock to trace\n",
			__func__);
		goto error;
	}

error:
	if (clock) {
		bt_ctf_clock_put(clock);
	}

	return ret;
}

static
int visit_root_decl(struct ctx *ctx, struct ctf_node *root_decl_node)
{
	int ret = 0;

	if (root_decl_node->visited) {
		return 0;
	}

	root_decl_node->visited = 1;

#if 0
	if (!trace->restart_root_decl && node->visited)
		return 0;
	node->visited = 1;
#endif

	switch (root_decl_node->type) {
	case NODE_TYPEDEF:
		ret = visit_typedef(ctx, root_decl_node->u._typedef.type_specifier_list,
			&root_decl_node->u._typedef.type_declarators);

		if (ret) {
			return ret;
		}

		break;

	case NODE_TYPEALIAS:
		ret = visit_typealias(ctx, root_decl_node->u.typealias.target,
			root_decl_node->u.typealias.alias);

		if (ret) {
			return ret;
		}

		break;

	case NODE_TYPE_SPECIFIER_LIST:
	{
#if 0
		struct bt_declaration *declaration;

		/*
		 * Just add the type specifier to the root scope
		 * declaration scope. Release local reference.
		 */
		declaration = ctf_type_specifier_list_visit(fd, depth + 1,
			node, trace->root_declaration_scope, trace);
		if (!declaration)
			return -ENOMEM;
		bt_declaration_unref(declaration);
#endif
		break;
	}

	default:
		return -EPERM;
	}

	return ret;
}

int ctf_visitor_generate_ir(FILE *efd, struct ctf_node *node,
		struct bt_ctf_trace *trace)
{
	int ret = 0;

	printf_verbose("CTF visitor: AST -> IR...\n");

	struct ctx *ctx = ctx_create(trace, efd);

	if (!ctx) {
		fprintf(efd, "[error] %s: cannot create visitor context\n",
			__func__);
		return -ENOMEM;
	}

	switch (node->type) {
	case NODE_ROOT:
	{
		struct ctf_node *iter;

		/*
		 * Find trace declaration's byte order first (for early
		 * type aliases).
		 */
		int got_trace_decl = 0;

		bt_list_for_each_entry(iter, &node->u.root.trace, siblings) {
			if (got_trace_decl) {
				fprintf(efd, "[error] %s: duplicate trace declaration\n",
					__func__);
			}

			ret = set_trace_byte_order(ctx, iter);

			if (ret) {
				fprintf(efd, "[error] %s: cannot set trace's byte order (%d)\n",
					__func__, ret);
				goto error;
			}
		}

		/* visit clocks first since any early integer can be mapped to one */
		bt_list_for_each_entry(iter, &node->u.root.clock, siblings) {
			ret = visit_clock(ctx, iter);

			if (ret) {
				fprintf(efd, "[error] %s: error while visiting clock declaration (%d)\n",
					__func__, ret);
				goto error;
			}
		}

		/*
		 * Visit root declarations next, as they can be used by any
		 * following entity.
		 */
		bt_list_for_each_entry(iter, &node->u.root.declaration_list,
				siblings) {
			ret = visit_root_decl(ctx, iter);

			if (ret) {
				fprintf(efd, "[error] %s: error while visiting root declaration (%d)\n",
					__func__, ret);
				goto error;
			}
		}

#if 0
		bt_list_for_each_entry(iter, &node->u.root.declaration_list,
					siblings) {
			ret = ctf_root_declaration_visit(fd, depth + 1, iter, trace);
			if (ret) {
				fprintf(fd, "[error] %s: root declaration error\n", __func__);
				goto error;
			}
		}
		bt_list_for_each_entry(iter, &node->u.root.trace, siblings) {
			ret = ctf_trace_visit(fd, depth + 1, iter, trace);
			if (ret == -EINTR) {
				trace->restart_root_decl = 1;
				bt_free_declaration_scope(trace->root_declaration_scope);
				/*
				 * Need to restart creation of type
				 * definitions, aliases and
				 * trace header declarations.
				 */
				goto retry;
			}
			if (ret) {
				fprintf(fd, "[error] %s: trace declaration error\n", __func__);
				goto error;
			}
		}
		trace->restart_root_decl = 0;
		bt_list_for_each_entry(iter, &node->u.root.callsite, siblings) {
			ret = ctf_callsite_visit(fd, depth + 1, iter,
					      trace);
			if (ret) {
				fprintf(fd, "[error] %s: callsite declaration error\n", __func__);
				goto error;
			}
		}
		if (!trace->streams) {
			fprintf(fd, "[error] %s: missing trace declaration\n", __func__);
			ret = -EINVAL;
			goto error;
		}
		bt_list_for_each_entry(iter, &node->u.root.env, siblings) {
			ret = ctf_env_visit(fd, depth + 1, iter, trace);
			if (ret) {
				fprintf(fd, "[error] %s: env declaration error\n", __func__);
				goto error;
			}
		}
		bt_list_for_each_entry(iter, &node->u.root.stream, siblings) {
			ret = ctf_stream_visit(fd, depth + 1, iter,
		    			       trace->root_declaration_scope, trace);
			if (ret) {
				fprintf(fd, "[error] %s: stream declaration error\n", __func__);
				goto error;
			}
		}
		bt_list_for_each_entry(iter, &node->u.root.event, siblings) {
			ret = ctf_event_visit(fd, depth + 1, iter,
		    			      trace->root_declaration_scope, trace);
			if (ret) {
				fprintf(fd, "[error] %s: event declaration error\n", __func__);
				goto error;
			}
		}
#endif
		break;
	}

	case NODE_UNKNOWN:
	default:
		fprintf(efd, "[error] %s: unknown node type %d\n", __func__,
			(int) node->type);
		ret = -EINVAL;
		goto error;
	}

	ctx_destroy(ctx);
	printf_verbose("done!\n");
	return ret;

error:
	ctx_destroy(ctx);
	return ret;
}

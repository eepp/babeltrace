/*
 * durin.c
 *
 * Babeltrace - DWARF Information Reader
 *
 * Copyright 2015 Antoine Busque <abusque@efficios.com>
 *
 * Author: Antoine Busque <abusque@efficios.com>
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

#include <glib.h>
#include <babeltrace/ctf-text/durin.h>

/*
 * XXX: libdwarf often hides pointers behind typedefs, which can lead
 * to misleading code. For instance, `Dwarf_Debug` is in fact a
 * pointer to an opaque struct. Therefore, passing its 'value' to
 * functions such as `dwarf_next_cu_header` will modify its members,
 * and therefore the behaviour of other functions using the same
 * `Dwarf_Debug`. Use extra caution.
 */

/**
 * Advance `dwarf_info`'s internal state to point to the next compile
 * unit (CU) header.
 *
 * @param dwarf_info	Dwarf_Debug instance
 * @param cu_offset	Out parameter, offset in bytes to the new CU
 * @returns		0 on success, -1 on failure.
 */
static
int durin_cu_next_header(Dwarf_Debug *dwarf_info, Dwarf_Unsigned *cu_offset)
{
	int ret;
	Dwarf_Unsigned _cu_offset;

	if (!dwarf_info || !cu_offset) {
		goto error;
	}

	ret = dwarf_next_cu_header(*dwarf_info, NULL, NULL, NULL, NULL,
				&_cu_offset, NULL);
	if (ret != DW_DLV_OK) {
		goto error;
	}
	*cu_offset = _cu_offset;

	return 0;

error:
	return -1;
}

/**
 * Reset the internal CU offset state of `dwarf_info`, allowing to
 * read from the first CU again.
 *
 * libdwarf keeps the value of the last read CU header's offset stored
 * internally within the opaque Dwarf_Debug structure, from which it
 * then computes the offset of the next header and fetches
 * it. Therefore, the only apparent way to reset this offset is to
 * iterate over all CUs until they wrap over, short of instantiating a
 * new Dwarf_Debug structure. This function hides this manipulation.
 *
 * @param dwarf_info	Dwarf_Debug instance
 * @returns		0 on success, -1 on failure.
 */
static
int durin_cu_reset_internal_state(Dwarf_Debug *dwarf_info)
{
	int ret;
	Dwarf_Unsigned cu_offset;

	if (!dwarf_info) {
		goto error;
	}

	do {
		ret = dwarf_next_cu_header(*dwarf_info, NULL, NULL, NULL, NULL,
					&cu_offset, NULL);
	} while (ret == DW_DLV_OK);

	if (ret == DW_DLV_ERROR) {
		goto error;
	}

	return 0;

error:
	return -1;
}

struct durin_cu *durin_cu_create(Dwarf_Debug *dwarf_info)
{
	int ret;
	struct durin_cu *cu;

	if (!dwarf_info) {
		goto error;
	}

	ret = durin_cu_reset_internal_state(dwarf_info);
	if (ret) {
		goto error;
	}

	cu = g_new0(struct durin_cu, 1);
	if (!cu) {
		goto error;
	}
	cu->dwarf_info = dwarf_info;
	cu->offset = 0;

	return cu;

error:
	return NULL;
}

void durin_cu_destroy(struct durin_cu *cu)
{
	g_free(cu);
}

int durin_cu_next(struct durin_cu *cu)
{
	int ret;
	Dwarf_Unsigned cu_offset;

	if (!cu) {
		goto error;
	}

	ret = durin_cu_next_header(cu->dwarf_info, &cu_offset);
	if (ret) {
		goto error;
	}
	cu->offset = cu_offset;

	return 0;

error:
	return -1;
}

struct durin_die *durin_die_create(struct durin_cu *cu)
{
	int ret;
	struct durin_die *die = NULL;
	Dwarf_Die *dwarf_die = NULL;
	Dwarf_Error error;

	if (!cu) {
		goto error;
	}

	dwarf_die = g_new0(Dwarf_Die, 1);
	if (!dwarf_die) {
		goto error;
	}
	/* dwarf_siblingof on the cu fetches its root DIE. */
	ret = dwarf_siblingof(*cu->dwarf_info, NULL, dwarf_die, &error);
	if (ret != DW_DLV_OK) {
		goto error;
	}
	die = g_new0(struct durin_die, 1);
	if (!die) {
		goto error;
	}
	die->cu = cu;
	die->dwarf_die = dwarf_die;
	die->depth = 0;

	return die;

error:
	if (dwarf_die) {
		dwarf_dealloc(*cu->dwarf_info, *dwarf_die, DW_DLA_DIE);
		g_free(dwarf_die);
	}
	g_free(die);
	return NULL;
}

void durin_die_destroy(struct durin_die *die)
{
	if (!die) {
		return;
	}

	if (die->dwarf_die) {
		dwarf_dealloc(*die->cu->dwarf_info, *die->dwarf_die,
			      DW_DLA_DIE);
		g_free(die->dwarf_die);
	}
	g_free(die);
}

int durin_die_next(struct durin_die *die)
{
	int ret;
	Dwarf_Die *next_die = NULL;
	Dwarf_Error error;

	if (!die) {
		goto error;
	}

	next_die = g_new0(Dwarf_Die, 1);
	if (!next_die) {
		goto error;
	}

	if (die->depth == 0) {
		ret = dwarf_child(*die->dwarf_die, next_die, &error);
		if (ret != DW_DLV_OK) {
			/* No child DIE. */
			goto error;
		}

		die->depth = 1;
	} else {
		ret = dwarf_siblingof(*die->cu->dwarf_info, *die->dwarf_die,
				next_die, &error);
		if (ret != DW_DLV_OK) {
			/* Reached end of DIEs at this depth. */
			goto error;
		}
	}

	dwarf_dealloc(*die->cu->dwarf_info, *die->dwarf_die, DW_DLA_DIE);
	g_free(die->dwarf_die);
	die->dwarf_die = next_die;
	return 0;

error:
	g_free(next_die);
	return -1;
}

int durin_die_get_tag(struct durin_die *die, uint16_t *tag)
{
	int ret;
	uint16_t _tag;
	Dwarf_Error error;

	if (!die || !tag) {
		goto error;
	}

	ret = dwarf_tag(*die->dwarf_die, &_tag, &error);
	if (ret != DW_DLV_OK) {
		goto error;
	}
	*tag = _tag;

	return 0;

error:
	return -1;
}

int durin_die_get_name(struct durin_die *die, char **name)
{
	int ret;
	char *_name;
	Dwarf_Error error;

	ret = dwarf_diename(*die->dwarf_die, &_name, &error);
	if (ret != DW_DLV_OK) {
		goto error;
	}
	*name = _name;

	return 0;

error:
	return -1;
}

int durin_die_contains_addr(struct durin_die *die, uint64_t addr, int *contains)
{
	int ret;
	Dwarf_Addr low_pc, high_pc;
	Dwarf_Half form;
	enum Dwarf_Form_Class class;
	Dwarf_Error error;

	if (!die || !contains) {
		goto error;
	}

	ret = dwarf_lowpc(*die->dwarf_die, &low_pc, &error);
	if (ret == DW_DLV_ERROR) {
		goto error;
	}
	if (ret == DW_DLV_NO_ENTRY) {
		*contains = 0;
		goto end;
	}

	ret = dwarf_highpc_b(*die->dwarf_die, &high_pc, &form, &class, &error);
	if (ret == DW_DLV_ERROR) {
		goto error;
	}
	if (ret == DW_DLV_NO_ENTRY) {
		*contains = 0;
		goto end;
	}

	if (class != DW_FORM_CLASS_ADDRESS) {
		/*
		 * high_pc is an offset relative to low_pc, compute
		 * the absolute address.
		 */
		high_pc += low_pc;
	}
	*contains = low_pc <= addr && addr < high_pc;

end:
	return 0;

error:
	return -1;
}

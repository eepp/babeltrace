#ifndef _BABELTRACE_DURIN_H
#define _BABELTRACE_DURIN_H

/*
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

#include <stdint.h>
#include <stdlib.h>
#include <libdwarf/libdwarf.h>
#include <babeltrace/babeltrace-internal.h>

/*
 * Durin is a wrapper over libdwarf providing a nicer, higher-level
 * interface, to access basic debug information. Durin is also the
 * eldest of the seven Fathers of the Dwarves created by the Vala Aulë
 * in the lore of Tolkien's Middle-earth.
 */

/*
 * This structure corresponds to a single compilation unit (CU) for a
 * given set of debug information (Dwarf_Debug type).
 */
struct durin_cu {
	Dwarf_Debug *dwarf_info;
	/* Offset in bytes in the DWARF file to beginning of CU header. */
	Dwarf_Unsigned offset;
};

/*
 * This structure represents a single debug information entry (DIE),
 * within a compilation unit (CU).
 */
struct durin_die {
	struct durin_cu *cu;
	Dwarf_Die *dwarf_die;
	/*
	 * A depth of 0 represents a root DIE, located in the DWARF
	 * layout on the same level as its corresponding CU entry. Its
	 * children DIEs will have a depth of 1, and so forth. All
	 * "interesting" DIEs for the present use case will be located
	 * at depth 1, however.
	 */
	unsigned int depth;
};

/**
 * Instantiate a structure to access compile units (CU) from a given
 * `dwarf_info`.
 *
 * @param dwarf_info	Dwarf_Debug instance
 * @returns		Pointer to the new durin_cu on success,
 *			NULL on failure.
 */
BT_HIDDEN
struct durin_cu *durin_cu_create(Dwarf_Debug *dwarf_info);

/**
 * Destroy the given durin_cu instance.
 *
 * @param cu	durin_cu instance
 */
BT_HIDDEN
void durin_cu_destroy(struct durin_cu *cu);

/**
 * Advance the compile unit `cu` to the next one.
 *
 * On success, `cu`'s offset is set to that of the current compile
 * unit in the executable. On failure, `cu` remains unchanged.
 *
 * @param cu	durin_cu instance
 * @returns	0 on success, -1 on failure
 */
BT_HIDDEN
int durin_cu_next(struct durin_cu *cu);

/**
 * Instantiate a structure to access debug information entries (DIE)
 * for the given compile unit `cu`.
 *
 * @param cu	durin_cu instance
 * @returns	Pointer to the new durin_die on success,
 *		NULL on failure.
 */
BT_HIDDEN
struct durin_die *durin_die_create(struct durin_cu *cu);

/**
 * Destroy the given durin_die instance.
 *
 * @param die	durin_die instance
 */
BT_HIDDEN
void durin_die_destroy(struct durin_die *die);

/**
 * Advance the debug information entry `die` to the next one.
 *
 * @param die	durin_die instance
 * @returns	0 on success, -1 on failure
 */
BT_HIDDEN
int durin_die_next(struct durin_die *die);

/**
 * Get a DIE's tag.
 *
 * On success, the `tag` out parameter is set to the `die`'s tag's
 * value. On failure it remains unchanged.
 *
 * @param die	durin_die instance
 * @param tag	Out parameter, the DIE's tag value
 * @returns	0 on success, -1 on failure.
 */
BT_HIDDEN
int durin_die_get_tag(struct durin_die *die, uint16_t *tag);

/**
 * Get a DIE's name.
 *
 * @param die	durin_die instance
 * @param name	Out parameter, the DIE's name
 * @returns	0 on succes, -1 on failure
 */
BT_HIDDEN
int durin_die_get_name(struct durin_die *die, char **name);

/**
 * Verifies whether a given DIE contains the virtual memory address
 * `addr`.
 *
 * On success, the out parameter `contains` is set with the boolean
 * value indicating whether the DIE's range covers `addr`. On failure,
 * it remains unchanged.
 *
 * @param die		durin_die instance
 * @param addr		The memory address to verify
 * @param contains	Out parameter, 1 if addr is contained,
 *			0 if not
 * @returns		0 on succes, -1 on failure
 */
BT_HIDDEN
int durin_die_contains_addr(struct durin_die *die, uint64_t addr,
			int *contains);

#endif	/* _BABELTRACE_DURIN_H */

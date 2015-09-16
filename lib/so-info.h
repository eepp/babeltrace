#ifndef _BABELTRACE_SO_INFO_H
#define _BABELTRACE_SO_INFO_H

/*
 * Babeltrace - Executable and Shared Object Debug Info Reader
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
#include <gelf.h>
#include <libdwarf/libdwarf.h>
#include <babeltrace/babeltrace-internal.h>

#define DEFAULT_DEBUG_DIR "/usr/lib/debug"
#define DEBUG_SUBDIR ".debug/"
#define BUILD_ID_SUBDIR ".build-id/"
#define BUILD_ID_SUFFIX ".debug"

struct so_info {
	/* Base virtual memory address. */
	uint64_t low_addr;
	/* Upper bound of exec address space. */
	uint64_t high_addr;
	/* Size of exec address space. */
	uint64_t memsz;
	/* Paths to ELF and DWARF files. */
	char *elf_path;
	char *dwarf_path;
	/* libelf and libdwarf objects representing the files. */
	Elf *elf_file;
	Dwarf_Debug *dwarf_info;
	/* Optional build ID info. */
	uint8_t *build_id;
	size_t build_id_len;
	/* Optional debug link info. */
	char *dbg_link_filename;
	uint32_t dbg_link_crc;
	/* FDs to ELF and DWARF files. */
	int elf_fd;
	int dwarf_fd;
	/* Denotes whether the executable is position independent code. */
	uint8_t is_pic : 1;
	/* Denotes whether the SO only has ELF symbols and no DWARF info. */
	uint8_t is_elf_only : 1;
};

struct source_location {
	long long unsigned int line_no;
	char *filename;
};

/**
 * Initializes the so_info framekwork. Call this before calling
 * anything else.
 *
 * @returns		0 on success, -1 on failure
 */
BT_HIDDEN
int so_info_init(void);

/**
 * Instantiate a structure representing an ELF executable, possibly
 * with DWARF info, located at the given path.
 *
 * @param path		Path to the ELF file
 * @param low_addr	Base address of the executable
 * @param memsz	In-memory size of the executable
 * @returns		Pointer to the new so_info on success,
 *			NULL on failure.
 */
BT_HIDDEN
struct so_info *so_info_create(const char *path, uint64_t low_addr,
			uint64_t memsz);

/**
 * Destroy the given so_info instance
 *
 * @param so	so_info instance to destroy
 */
BT_HIDDEN
void so_info_destroy(struct so_info *so);

/**
 * Sets the build ID information for a given so_info instance.
 *
 * @param so		The so_info instance for which to set
 *			the build ID
 * @param build_id	Array of bytes containing the actual ID
 * @param build_id_len	Length in bytes of the build_id
 * @returns		0 on success, -1 on failure
 */
BT_HIDDEN
int so_info_set_build_id(struct so_info *so, uint8_t *build_id,
			size_t build_id_len);

/**
 * Sets the debug link information for a given so_info instance.
 *
 * @param so		The so_info instance for which to set
 *			the debug link
 * @param filename	Name of the separate debug info file
 * @param crc		Checksum for the debug info file
 * @returns		0 on success, -1 on failure
 */
BT_HIDDEN
int so_info_set_debug_link(struct so_info *so, char *filename, uint32_t crc);

/**
 * Returns whether or not the given SO info \p so contains the address
 * \p addr.
 *
 * @param so		so_info instance
 * @param addr		Address to lookup
 * @returns		1 if \p so contains \p addr, 0 if it does not,
 *			-1 on failure
 */
static inline
int so_info_has_address(struct so_info *so, uint64_t addr)
{
	if (!so) {
		return -1;
	}

	return addr >= so->low_addr && addr <= so->high_addr;
}

/**
 * Get the name of the function containing a given address within an
 * executable.
 *
 * If no DWARF info is available, the function falls back to ELF
 * symbols and the "function name" is in fact the name of the closest
 * symbol, followed by the offset between the symbol and the address.
 *
 * On success, the `found` out parameter is set, indicating whether
 * the function name was found. If found, the out parameter
 * `func_name` is also set. On failure, both remain unchanged.
 *
 * @param so		so_info instance for the executable containing
 *			the address
 * @param addr		Virtual memory address for which to find the
 *			function name
 * @param func_name	Out parameter, the function name
 * @param found	Out parameter, whether the name was found
 * @returns		0 on success, -1 on failure
 */
BT_HIDDEN
int so_info_lookup_function_name(struct so_info *so, uint64_t addr,
				char **func_name, int *found);

/**
 * Get the source location (file name and line number) for a given
 * address within an executable.
 *
 * If no DWARF info is available, the source location cannot be found
 * and the function will return unsuccesfully.
 *
 * On success, the `found` out parameter is set, indicating whether
 * the source location was found. If found, the out parameter
 * `src_loc` is also set. On failure, both remain unchanged.
 *
 * @param so		so_info instance for the executable containing
 *			the address
 * @param addr		Virtual memory address for which to find the
 *			source location
 * @param src_loc	Out parameter, the source location
 * @param found	Out parameter, whether the location was found
 * @returns		0 on success, -1 on failure
 */
BT_HIDDEN
int so_info_lookup_source_location(struct so_info *so, uint64_t addr,
				struct source_location **src_loc, int *found);


/**
 * Destroy the given source_location instance
 *
 * @param src_loc	source_location instance to destroy
 */
BT_HIDDEN
void source_location_destroy(struct source_location *src_loc);

#endif	/* _BABELTRACE_SO_INFO_H */

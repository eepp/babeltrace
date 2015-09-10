/*
 * so-info.c
 *
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

#include <fcntl.h>
#include <math.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libdwarf/dwarf.h>
#include <glib.h>
#include <babeltrace/ctf-ir/crc32.h>
#include <babeltrace/ctf-ir/durin.h>
#include <babeltrace/ctf-ir/so-info.h>

/*
 * An adress printed in hex is at most 20 bytes (16 for 64-bits +
 * leading 0x + optional leading '+' if addr is an offset + null
 * character).
 */
#define ADDR_STR_LEN 20

int so_info_init(void)
{
	int ret = 0;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s\n",
			elf_errmsg(-1));
		ret = -1;
	}

	return ret;
}

struct so_info *so_info_create(const char *path, uint64_t low_addr,
			uint64_t memsz)
{
	struct so_info *so = NULL;
	GElf_Ehdr *ehdr = NULL;

	if (!path) {
		goto error;
	}

	so = g_new0(struct so_info, 1);
	if (!so) {
		goto error;
	}

	so->elf_path = strdup(path);
	if (!so->elf_path) {
		goto error;
	}

	/*
	 * Only set dwarf_info the first time it is read, to avoid
	 * reading it uselessly.
	 */
	so->dwarf_info = NULL;
	so->dwarf_path = NULL;
	so->build_id = NULL;
	so->build_id_len = 0;
	so->dbg_link_filename = NULL;
	so->dbg_link_crc = 0;
	so->is_elf_only = 0;

	so->elf_fd = open(path, O_RDONLY);
	if (so->elf_fd < 0) {
		fprintf(stderr, "Failed to open %s\n", path);
		goto error;
	}

	so->elf_file = elf_begin(so->elf_fd, ELF_C_READ, NULL);
	if (!so->elf_file) {
		fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
		goto error;
	}

	if (elf_kind(so->elf_file) != ELF_K_ELF) {
		fprintf(stderr, "Error: %s is not an ELF object\n", so->elf_path);
		goto error;
	}

	ehdr = g_new0(GElf_Ehdr, 1);
	if (!ehdr) {
		goto error;
	}

	if (!gelf_getehdr(so->elf_file, ehdr)) {
		fprintf(stderr, "Error: couldn't get ehdr for %s\n", so->elf_path);
		goto error;
	}

	/* Position independent code has an e_type value of ET_DYN. */
	so->is_pic = ehdr->e_type == ET_DYN;
	g_free(ehdr);

	so->memsz = memsz;
	so->low_addr = low_addr;
	so->high_addr = so->low_addr + so->memsz;

	return so;

error:
	g_free(ehdr);
	so_info_destroy(so);

	return NULL;
}

void so_info_destroy(struct so_info *so)
{
	if (!so) {
		return;
	}

	if (so->dwarf_info) {
		dwarf_finish(*so->dwarf_info, NULL);
		g_free(so->dwarf_info);
	}

	free(so->elf_path);
	free(so->dwarf_path);
	free(so->build_id);
	free(so->dbg_link_filename);
	elf_end(so->elf_file);
	close(so->elf_fd);
	close(so->dwarf_fd);
	g_free(so);
}

int so_info_set_build_id(struct so_info *so, uint8_t *build_id,
			size_t build_id_len)
{
	if (!so || !build_id) {
		goto error;
	}

	so->build_id = malloc(build_id_len);
	if (!so->build_id) {
		goto error;
	}
	memcpy(so->build_id, build_id, build_id_len);
	so->build_id_len = build_id_len;
	/*
	 * Reset the is_elf_only flag in case it had been set
	 * previously, because we might find separate debug info using
	 * the new build id information.
	 */
	so->is_elf_only = 0;

	return 0;

error:

	return -1;
}

int so_info_set_debug_link(struct so_info *so, char *filename, uint32_t crc)
{
	if (!so || !filename) {
		goto error;
	}

	so->dbg_link_filename = strdup(filename);
	if (!so->dbg_link_filename) {
		goto error;
	}
	so->dbg_link_crc = crc;
	/*
	 * Reset the is_elf_only flag in case it had been set
	 * previously, because we might find separate debug info using
	 * the new build id information.
	 */
	so->is_elf_only = 0;

	return 0;

error:

	return -1;
}

static
int so_info_set_dwarf_info_from_path(struct so_info *so, char *path)
{
	int fd = -1;
	int ret = 0;
	struct durin_cu *cu = NULL;
	Dwarf_Debug *dwarf_info = NULL;

	if (!so || !path) {
		goto error;
	}

	dwarf_info = g_new0(Dwarf_Debug, 1);
	if (!dwarf_info) {
		goto error;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		goto error;
	}

	ret = dwarf_init(fd, DW_DLC_READ, NULL, NULL, dwarf_info, NULL);
	if (ret != DW_DLV_OK) {
		goto error;
	}

	/*
	 * Check if the dwarf info has any CU. If not, the SO's object
	 * file contains no DWARF info.
	 */
	cu = durin_cu_create(dwarf_info);
	if (!cu) {
		goto error;
	}

	so->dwarf_fd = fd;
	so->dwarf_path = strdup(path);
	if (!so->dwarf_path) {
		goto error;
	}
	so->dwarf_info = dwarf_info;
	free(cu);

	return 0;

error:
	close(fd);
	if (dwarf_info) {
		dwarf_finish(*dwarf_info, NULL);
		g_free(dwarf_info);
	}
	free(cu);

	return -1;
}


static
int so_info_set_dwarf_info_build_id(struct so_info *so, char *debug_dir,
				int *found)
{
	int i = 0, ret = 0;
	char *path = NULL;
	char *build_id_file = NULL;
	size_t build_id_file_len;
	size_t path_len;
	int debug_dir_trailing_slash = 0;

	if (!so || !found || !so->build_id) {
		goto error;
	}

	if (!debug_dir) {
		/*
		 * Use current dir if no global debug directory has
		 * been specified. This matches GDB's behaviour.
		 */
		debug_dir = ".";
	}

	debug_dir_trailing_slash = debug_dir[strlen(debug_dir) - 1] == '/';

	/* +2, 1 for '/' and 1 for '\0' */
	build_id_file_len = so->build_id_len + 2;
	build_id_file = malloc(build_id_file_len);
	if (!build_id_file) {
		goto error;
	}
	snprintf(build_id_file, 4, "%02x%02x/", so->build_id[0], so->build_id[1]);
	for (i = 2; i < so->build_id_len; ++i) {
		snprintf(&build_id_file[i], 2, "%02x", so->build_id[i]);
	}

	path_len = strlen(debug_dir) + strlen(BUILD_ID_SUBDIR) +
		strlen(build_id_file) + strlen(BUILD_ID_SUFFIX) + 1;
	if (!debug_dir_trailing_slash) {
		path_len += 1;
	}

	path = malloc(path_len);
	if (!path) {
		goto error;
	}

	strcpy(path, debug_dir);
	if (!debug_dir_trailing_slash) {
		strcat(path, "/");
	}
	strcat(path, BUILD_ID_SUBDIR);
	strcat(path, build_id_file);
	strcat(path, BUILD_ID_SUFFIX);

	ret = so_info_set_dwarf_info_from_path(so, path);
	if (ret) {
		goto error;
	}

	*found = 1;
	free(build_id_file);
	free(path);

	return 0;

error:
	free(build_id_file);
	free(path);

	return -1;
}

/**
 * Tests whether the file located at path exists and has the expected
 * checksum.
 *
 * This predicate is used when looking up separate debug info via the
 * GNU debuglink method. The expected crc can be found .gnu_debuglink
 * section in the original ELF file, along with the filename for the
 * file containing the debug info.
 *
 * @param path	Full path at which to look for the debug file
 * @param crc	Expected checksum for the debug file
 * @returns	1 if the file exists and has the correct checksum,
 *		0 otherwise
 */
static
int is_valid_debug_file(char *path, uint32_t crc)
{
	int ret = 0, fd = -1;
	uint32_t _crc = 0;

	if (!path) {
		goto end;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		goto end;
	}

	ret = crc32(fd, &_crc);
	if (ret) {
		ret = 0;
		goto end;
	}

	ret = crc == _crc;

end:
	close(fd);
	return ret;
}

static
int so_info_set_dwarf_info_debug_link(struct so_info *so, char *debug_dir,
				int *found)
{
	int ret = 0, _found = 0;
	char *so_dir = NULL;
	char *path = NULL;
	size_t max_path_len = 0;

	if (!so || !found) {
		goto error;
	}

	if (!so->dbg_link_filename) {
		goto error;
	}

	if (!debug_dir) {
		/*
		 * Use current dir if no global debug directory has
		 * been specified. This matches GDB's behaviour.
		 */
		debug_dir = ".";
	}

	so_dir = dirname(so->elf_path);
	if (!so_dir) {
		goto error;
	}

	max_path_len = strlen(debug_dir) + strlen(so_dir) +
		strlen(DEBUG_SUBDIR) + strlen(so->dbg_link_filename) + 1;
	path = malloc(max_path_len);
	if (!path) {
		goto error;
	}

	/* First look in the SO's dir */
	strcpy(path, so_dir);
	strcat(path, so->dbg_link_filename);

	_found = is_valid_debug_file(path, so->dbg_link_crc);
	if (_found) {
		goto end;
	}

	/* If not found, look in .debug subdir */
	strcpy(path, so_dir);
	strcat(path, DEBUG_SUBDIR);
	strcat(path, so->dbg_link_filename);

	_found = is_valid_debug_file(path, so->dbg_link_crc);
	if (_found) {
		goto end;
	}

	/* Lastly, look under the global debug directory */
	strcpy(path, debug_dir);
	strcat(path, so_dir);
	strcat(path, so->dbg_link_filename);

	_found = is_valid_debug_file(path, so->dbg_link_crc);
	if (_found) {
		goto end;
	}

end:
	if (_found) {
		ret = so_info_set_dwarf_info_from_path(so, path);
		if (ret) {
			goto error;
		}
	}
	*found = _found;
	free(path);

	return 0;

error:
	free(path);

	return -1;
}

/**
 * Initialize the DWARF info for a given executable.
 *
 * @param so	so_info instance
 * @returns	0 on success, -1 on failure
 */
static
int so_info_set_dwarf_info(struct so_info *so)
{
	int ret = 0, found = 0;

	if (!so) {
		goto error;
	}

	/* First try to set the DWARF info from the ELF file */
	ret = so_info_set_dwarf_info_from_path(so, so->elf_path);
	if (!ret) {
		goto end;
	}

	/*
	 * If that fails, try to find separate debug info via build ID
	 * and debug link.
	 */
	ret = so_info_set_dwarf_info_build_id(so, DEFAULT_DEBUG_DIR, &found);
	if (ret) {
		goto error;
	}
	if (found) {
		goto end;
	}

	ret = so_info_set_dwarf_info_debug_link(so, DEFAULT_DEBUG_DIR, &found);
	if (ret) {
		goto error;
	}
	if (found) {
		goto end;
	}

end:
	return 0;

error:
	return -1;
}

void source_location_destroy(struct source_location *src_loc)
{
	if (!src_loc) {
		return;
	}

	free(src_loc->filename);
	g_free(src_loc);
}

/**
 * Try to find the symbol closest to an address within a given ELF
 * section.
 *
 * Only function symbols are taken into account. The symbol's address
 * must precede `addr`. A symbol with a closer address might exist
 * after `addr` but is irrelevant because it cannot encompass `addr`.
 *
 * On success, the `found` out parameter is set, indicating whether
 * the symbol found. If found, the out parameters `sym` and `shdr` are
 * also set. On failure, all three remain unchanged.
 *
 * @param scn		ELF section in which to look for the address
 * @param addr		Virtual memory address for which to find the
 *			nearest function symbol
 * @param sym		Out parameter, the nearest function symbol
 * @param shdr		Out parameter, the section header for scn
 * @param found	Out parameter, whether the name was found
 * @returns		0 on success, -1 on failure
 */
static
int so_info_get_nearest_symbol_from_section(Elf_Scn *scn, uint64_t addr,
					GElf_Sym **sym, GElf_Shdr **shdr,
					int *found)
{
	int i;
	int _found = 0;
	int symbol_count;
	Elf_Data *data = NULL;
	GElf_Shdr *_shdr = NULL;
	GElf_Sym *nearest_sym = NULL;

	if (!scn || !sym || !shdr || !found) {
		goto error;
	}

	_shdr = gelf_getshdr(scn, NULL);
	if (!_shdr) {
		goto error;
	}
	if (_shdr->sh_type != SHT_SYMTAB) {
		/*
		 * We are only interested in symbol table (symtab)
		 * sections, skip this one.
		 */
		goto end;
	}

	data = elf_getdata(scn, NULL);
	if (!data) {
		goto error;
	}

	symbol_count = _shdr->sh_size / _shdr->sh_entsize;

	for (i = 0; i < symbol_count; ++i) {
		GElf_Sym *cur_sym = NULL;

		cur_sym = gelf_getsym(data, i, NULL);
		if (!cur_sym) {
			goto error;
		}
		if (GELF_ST_TYPE(cur_sym->st_info) != STT_FUNC) {
			/* We're only interested in the functions. */
			continue;
		}

		if (cur_sym->st_value <= addr &&
				(!nearest_sym ||
				cur_sym->st_value > nearest_sym->st_value)) {
			nearest_sym = cur_sym;
			_found = 1;
		}
	}

end:
	if (_found) {
		*sym = nearest_sym;
		*shdr = _shdr;
	}
	*found = _found;

	return 0;

error:
	return -1;
}

/**
 * Get the name of the function containing a given address within an
 * executable using ELF symbols.
 *
 * The function name is in fact the name of the nearest ELF symbol,
 * followed by the offset in bytes between the address and the symbol
 * (in hex), separated by a '+' character.
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
static
int so_info_lookup_elf_function_name(struct so_info *so, uint64_t addr,
				char **func_name, int *found)
{
	/*
	 * TODO (possible optimisation): if an ELF has no symtab
	 * section, it has been stripped. Therefore, it would be wise
	 * to store a flag indicating the stripped status after the
	 * first iteration to prevent further ones.
	 */
	int ret = 0;
	int _found = 0;
	Elf_Scn *scn = NULL;
	GElf_Sym *sym = NULL;
	GElf_Shdr *shdr = NULL;
	char *sym_name = NULL;
	char *_func_name = NULL;
	char offset_str[ADDR_STR_LEN];

	scn = elf_nextscn(so->elf_file, scn);
	if (!scn) {
		goto error;
	}

	while (scn && !_found) {
		ret = so_info_get_nearest_symbol_from_section(
			scn, addr, &sym, &shdr, &_found);
		if (ret) {
			goto error;
		}

		scn = elf_nextscn(so->elf_file, scn);
	}

	if (_found) {
		sym_name = elf_strptr(so->elf_file, shdr->sh_link,
				sym->st_name);
		if (!sym_name) {
			goto error;
		}
		snprintf(offset_str, ADDR_STR_LEN, "+%#018lx",
			addr - sym->st_value);
		_func_name = malloc(strlen(sym_name) + ADDR_STR_LEN);
		if (!_func_name) {
			goto error;
		}
		strcpy(_func_name, sym_name);
		strcat(_func_name, offset_str);
		*func_name = _func_name;
	}
	*found = _found;
	free(sym_name);

	return 0;

error:
	free(sym_name);
	free(_func_name);

	return -1;
}

/**
 * Get the name of the function containing a given address within a
 * given compile unit (CU).
 *
 * On success, the `found` out parameter is set, indicating whether
 * the function name was found. If found, the out parameter
 * `func_name` is also set. On failure, both remain unchanged.
 *
 * @param cu		durin_cu instance which may contain the address
 * @param addr		Virtual memory address for which to find the
 *			function name
 * @param func_name	Out parameter, the function name
 * @param found	Out parameter, whether the name was found
 * @returns		0 on success, -1 on failure
 */
static
int so_info_lookup_cu_function_name(struct durin_cu *cu, uint64_t addr,
				char **func_name, int *found)
{
	int ret;
	int _found = 0;
	char *_func_name;
	struct durin_die *die;

	if (!cu || !func_name || !found) {
		goto error;
	}

	die = durin_die_create(cu);
	if (!die) {
		goto error;
	}

	while (durin_die_next(die) == 0) {
		uint16_t tag;

		ret = durin_die_get_tag(die, &tag);
		if (ret) {
			goto error;
		}
		if (tag == DW_TAG_subprogram) {
			ret = durin_die_contains_addr(die, addr, &_found);
			if (ret) {
				goto error;
			}
			if (_found) {
				break;
			}
		}
	}

	if (_found) {
		ret = durin_die_get_name(die, &_func_name);
		if (ret) {
			goto error;
		}
		*func_name = _func_name;
	}
	*found = _found;
	durin_die_destroy(die);

	return 0;

error:
	durin_die_destroy(die);

	return -1;
}

/**
 * Get the name of the function containing a given address within an
 * executable using DWARF debug info.
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
static
int so_info_lookup_dwarf_function_name(struct so_info *so, uint64_t addr,
				char **func_name, int *found)
{
	int ret = 0;
	int _found = 0;
	char *_func_name = NULL;
	struct durin_cu *cu = NULL;

	if (!so || !func_name || !found) {
		goto error;
	}

	cu = durin_cu_create(so->dwarf_info);
	if (!cu) {
		goto error;
	}

	while (durin_cu_next(cu) == 0) {
		ret = so_info_lookup_cu_function_name(cu, addr, &_func_name,
						&_found);
		if (ret) {
			goto error;
		}
		if (_found) {
			break;
		}
	}

	if (_found) {
		/*
		 * strdup here because libdwarf keeps the ownership of
		 * _func_name.
		 */
		*func_name = strdup(_func_name);
	}
	*found = _found;
	durin_cu_destroy(cu);

	return 0;

error:
	durin_cu_destroy(cu);

	return -1;
}

int so_info_lookup_function_name(struct so_info *so, uint64_t addr,
				char **func_name, int *found)
{
	int ret;
	int _found = 0;
	char *_func_name;

	if (!so || !func_name || !found) {
		goto error;
	}

	/* Set DWARF info if it hasn't been accessed yet. */
	if (!so->dwarf_info && !so->is_elf_only) {
		ret = so_info_set_dwarf_info(so);
		if (ret) {
			/* Failed to set DWARF info, fall back to ELF. */
			so->is_elf_only = 1;
		}
	}

	/*
	 * Addresses in ELF and DWARF are relative to base address for
	 * PIC, so make the address argument relative too if needed.
	 */
	if (so->is_pic) {
		addr -= so->low_addr;
	}

	if (so->is_elf_only) {
		ret = so_info_lookup_elf_function_name(so, addr, &_func_name,
						&_found);
	} else {
		ret = so_info_lookup_dwarf_function_name(so, addr, &_func_name,
							&_found);
	}

	if (ret) {
		goto error;
	}

	if (_found) {
		*func_name = _func_name;
	}
	*found = _found;

	return 0;

error:
	return -1;
}

/**
 * Get the source location (file name and line number) for a given
 * address within a compile unit (CU).
 *
 * On success, the `found` out parameter is set, indicating whether
 * the source location was found. If found, the out parameter
 * `src_loc` is also set. On failure, both remain unchanged.
 *
 * @param so		durin_cu instance for the compile unit which
 *			may contain the address
 * @param addr		Virtual memory address for which to find the
 *			source location
 * @param src_loc	Out parameter, the source location
 * @param found	Out parameter, whether the location was found
 * @returns		0 on success, -1 on failure
 */
static
int so_info_lookup_cu_source_location(struct durin_cu *cu, uint64_t addr,
				struct source_location **src_loc, int *found)
{
	int ret = 0, _found = 0;
	char *_filename = NULL;
	struct durin_die *die = NULL;
	struct source_location *_src_loc = NULL;
	Dwarf_Line *line_buf = NULL;
	Dwarf_Line prev_line = NULL;
	Dwarf_Signed i, line_count;

	if (!cu || !src_loc || !found) {
		goto error;
	}

	die = durin_die_create(cu);
	if (!die) {
		goto error;
	}

	ret = dwarf_srclines(*die->dwarf_die, &line_buf, &line_count, NULL);
	if (ret) {
		goto error;
	}

	for (i = 0; i < line_count; ++i) {
		Dwarf_Line cur_line = line_buf[i];
		Dwarf_Addr low_pc, high_pc, tmp_pc;

		if (!prev_line) {
			prev_line = cur_line;
			continue;
		}

		ret = dwarf_lineaddr(prev_line, &low_pc, NULL);
		if (ret != DW_DLV_OK) {
			goto error;
		}
		ret = dwarf_lineaddr(cur_line, &high_pc, NULL);
		if (ret != DW_DLV_OK) {
			goto error;
		}

		if (low_pc > high_pc) {
			tmp_pc = low_pc;
			low_pc = high_pc;
			high_pc = tmp_pc;
		}

		if (low_pc <= addr && addr <= high_pc) {
			_src_loc = g_new0(struct source_location, 1);
			if (!_src_loc) {
				goto error;
			}
			ret = dwarf_linesrc(prev_line, &_filename, NULL);
			if (ret != DW_DLV_OK) {
				goto error;
			}
			/*
			 * strdup here because libdwarf keeps the ownership of
			 * _filename.
			 */
			_src_loc->filename = strdup(_filename);
			ret = dwarf_lineno(prev_line, &_src_loc->line_no, NULL);
			if (ret != DW_DLV_OK) {
				goto error;
			}
			_found = 1;
			break;
		}

		prev_line = cur_line;
	}

	durin_die_destroy(die);
	if (_found) {
		*src_loc = _src_loc;
	}
	*found = _found;

	return 0;

error:
	source_location_destroy(_src_loc);
	durin_die_destroy(die);

	return -1;
}

int so_info_lookup_source_location(struct so_info *so, uint64_t addr,
				struct source_location **src_loc, int *found)
{
	int _found = 0;
	struct durin_cu *cu = NULL;
	struct source_location *_src_loc = NULL;

	if (!so || !src_loc || !found) {
		goto error;
	}

	/* Set DWARF info if it hasn't been accessed yet. */
	if (!so->dwarf_info && !so->is_elf_only) {
		if (so_info_set_dwarf_info(so)) {
			/* Failed to set DWARF info . */
			so->is_elf_only = 1;
		}
	}

	if (so->is_elf_only) {
		/* We cannot lookup source location without DWARF info. */
		goto error;
	}

	/*
	 * Addresses in ELF and DWARF are relative to base address for
	 * PIC, so make the address argument relative too if needed.
	 */
	if (so->is_pic) {
		addr -= so->low_addr;
	}

	cu = durin_cu_create(so->dwarf_info);
	if (!cu) {
		goto error;
	}

	while (durin_cu_next(cu) == 0) {
		int ret;
		ret = so_info_lookup_cu_source_location(cu, addr, &_src_loc,
						&_found);
		if (ret) {
			goto error;
		}
		if (_found) {
			break;
		}
	}

	durin_cu_destroy(cu);
	if (_found) {
		*src_loc = _src_loc;
	}
	*found = _found;

	return 0;

error:
	source_location_destroy(_src_loc);
	durin_cu_destroy(cu);

	return -1;
}

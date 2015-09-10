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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libdwarf/dwarf.h>
#include <glib.h>
#include <babeltrace/ctf-text/durin.h>
#include <babeltrace/ctf-text/so-info.h>

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

	so->path = path;
	/*
	 * Only set dwarf_info the first time it is read, to avoid
	 * reading it uselessly.
	 */
	so->dwarf_info = NULL;
	so->is_elf_only = 0;
	so->fd = open(path, O_RDONLY);
	if (so->fd < 0) {
		fprintf(stderr, "Failed to open %s\n", path);
		goto error;
	}

	so->elf_file = elf_begin(so->fd, ELF_C_READ, NULL);
	if (!so->elf_file) {
		fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
		goto error;
	}

	if (elf_kind(so->elf_file) != ELF_K_ELF) {
		fprintf(stderr, "Error: %s is not an ELF object\n", so->path);
		goto error;
	}

	ehdr = g_new0(GElf_Ehdr, 1);
	if (!ehdr) {
		goto error;
	}

	if (!gelf_getehdr(so->elf_file, ehdr)) {
		fprintf(stderr, "Error: couldn't get ehdr for %s\n", so->path);
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
	if (so) {
		elf_end(so->elf_file);
		close(so->fd);
		g_free(so);
	}

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
	g_free(so->build_id);
	g_free(so->dbg_link_filename);
	elf_end(so->elf_file);
	close(so->fd);
	g_free(so);
}

int so_info_set_build_id(struct so_info *so, uint8_t *build_id,
			size_t build_id_len)
{
	if (!so || !build_id) {
		goto error;
	}

	/* memcpy? */
	so->build_id = build_id;
	so->build_id_len = build_id_len;

	return 0;

error:

	return -1;
}

int so_info_set_debug_link(struct so_info *so, char *filename, uint32_t crc)
{
	if (!so || !filename) {
		goto error;
	}

	/* strdup? */
	so->dbg_link_filename = filename;
	so->dbg_link_crc = crc;

	return 0;

error:

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
	int ret = 0;
	Dwarf_Debug *dwarf_info = NULL;
	Dwarf_Error error;

	if (!so) {
		goto error;
	}

	dwarf_info = g_new0(Dwarf_Debug, 1);
	if (!dwarf_info) {
		goto error;
	}

	ret = dwarf_init(so->fd, DW_DLC_READ, NULL, NULL, dwarf_info,
			 &error);
	if (ret != DW_DLV_OK) {
		fprintf(stderr, "Failed to initialize DWARF info for %s\n",
			so->path);
		goto error;
	}

	/*
	 * Check if the dwarf info has any CU. If not, the SO's object
	 * file contains no DWARF info.
	 */
	if (!durin_cu_create(dwarf_info)) {
		/*
		 * TODO: try to find separate debug info using
		 * build-id and debuglink methods before failing.
		 */
		goto error;
	}

	so->dwarf_info = dwarf_info;

	return 0;

error:
	if (dwarf_info) {
		dwarf_finish(*dwarf_info, NULL);
		g_free(dwarf_info);
	}

	return -1;
}

void source_location_destroy(struct source_location *src_loc)
{
	if (!src_loc) {
		return;
	}

	/*
	 * The filename field, whose value is obtained from
	 * dwarf_linesrc() is managed by libdwarf and will be freed
	 * upon dwarf_finish() rather than manually.
	 */

	/*
	 * TODO: verify that this claim actually matches the current
	 * libdwarf implementation
	 */

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
		*func_name = _func_name;
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
			ret = dwarf_linesrc(prev_line, &_src_loc->filename,
					NULL);
			if (ret != DW_DLV_OK) {
				goto error;
			}
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
	struct durin_cu *cu;
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

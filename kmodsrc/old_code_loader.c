/*  Copyright (C) 2007-2009  Ksplice, Inc.
 *  Authors: Jeff Arnold, Anders Kaseorg, Tim Abbott
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#ifdef KSPLICE_STANDALONE
#include "ksplice.h"
#else
#include <linux/ksplice.h>
#endif

extern struct ksplice_reloc ksplice_relocs[], ksplice_relocs_end[];
extern struct ksplice_section ksplice_sections[], ksplice_sections_end[];
extern struct ksplice_symbol ksplice_symbols[], ksplice_symbols_end[];
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
extern struct paravirt_patch_site parainstructions[], parainstructions_end[];
#endif
#ifdef KSPLICE_STANDALONE
extern struct ksplice_system_map ksplice_system_map[], ksplice_system_map_end[];
#endif /* KSPLICE_STANDALONE */

/* Defined in new_code_loader.c */
#define change KSPLICE_UNIQ(change)
extern struct ksplice_mod_change change;

static struct ksplice_code old_code = {
	.relocs = ksplice_relocs,
	.relocs_end = ksplice_relocs_end,
	.sections = ksplice_sections,
	.sections_end = ksplice_sections_end,
	.symbols = ksplice_symbols,
	.symbols_end = ksplice_symbols_end,
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	.parainstructions = parainstructions,
	.parainstructions_end = parainstructions_end,
#endif
#ifdef KSPLICE_STANDALONE
	.system_map = ksplice_system_map,
	.system_map_end = ksplice_system_map_end,
#endif /* KSPLICE_STANDALONE */
};

static int init_old_code(void)
{
	change.old_code = old_code;
	return init_ksplice_mod_change(&change);
}

static void cleanup_old_code(void)
{
	cleanup_ksplice_mod_change(&change);
}

module_init(init_old_code);
module_exit(cleanup_old_code);

MODULE_AUTHOR("Ksplice, Inc.");
MODULE_DESCRIPTION("Ksplice rebootless update old code module");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
